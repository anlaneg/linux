// SPDX-License-Identifier: GPL-2.0-only
// 提供virtio bus
#include <linux/virtio.h>
#include <linux/spinlock.h>
#include <linux/virtio_config.h>
#include <linux/virtio_anchor.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <uapi/linux/virtio_ids.h>

/* Unique numbering for virtio devices. */
static DEFINE_IDA(virtio_index_ida);

//显示/sys/bus/virtio/devices/virtio*/device
//显示设备编号
static ssize_t device_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sysfs_emit(buf, "0x%04x\n", dev->id.device);
}

//定义变量指出采用device_show回调（定义device属性）
static DEVICE_ATTR_RO(device);

//显示/sys/bus/virtio/devices/virtio*/vendor
static ssize_t vendor_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sysfs_emit(buf, "0x%04x\n", dev->id.vendor);
}
static DEVICE_ATTR_RO(vendor);//定义vendor属性

//显示/sys/bus/virtio/devices/virtio*/status
static ssize_t status_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sysfs_emit(buf, "0x%08x\n", dev->config->get_status(dev));
}
static DEVICE_ATTR_RO(status);//定义status属性

//显示/sys/bus/virtio/devices/virtio*/modalias
//通过device与vendor合并出来的别名
static ssize_t modalias_show(struct device *_d,
			     struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sysfs_emit(buf, "virtio:d%08Xv%08X\n",
		       dev->id.device, dev->id.vendor);
}
static DEVICE_ATTR_RO(modalias);//模块别名

//显示/sys/bus/virtio/devices/virtio*/features
//按位显示features
static ssize_t features_show(struct device *_d,
			     struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	unsigned int i;
	ssize_t len = 0;

	/* We actually represent this as a bitstring, as it could be
	 * arbitrary length in future. */
	//遍历所有features位，列出当前支持的features
	for (i = 0; i < sizeof(dev->features)*8; i++)
		len += sysfs_emit_at(buf, len, "%c",
			       __virtio_test_bit(dev, i) ? '1' : '0');
	len += sysfs_emit_at(buf, len, "\n");
	return len;
}
static DEVICE_ATTR_RO(features);//功能属性

//定义virtio设备的通用属性数组
static struct attribute *virtio_dev_attrs[] = {
	&dev_attr_device.attr,
	&dev_attr_vendor.attr,
	&dev_attr_status.attr,
	&dev_attr_modalias.attr,
	&dev_attr_features.attr,
	NULL,
};
ATTRIBUTE_GROUPS(virtio_dev);

static inline int virtio_id_match(const struct virtio_device *dev,
				  const struct virtio_device_id *id)
{
	//如果id的device不为any,且id与dev的device不相等，则匹配失败
	if (id->device != dev->id.device && id->device != VIRTIO_DEV_ANY_ID)
		return 0;

	//检查vendor是否相等
	return id->vendor == VIRTIO_DEV_ANY_ID || id->vendor == dev->id.vendor;
}

/* This looks through all the IDs a driver claims to support.  If any of them
 * match, we return 1 and the kernel will call virtio_dev_probe(). */
//virtio bus设备匹配
static int virtio_dev_match(struct device *_dv, struct device_driver *_dr)
{
	unsigned int i;
	struct virtio_device *dev = dev_to_virtio(_dv);
	const struct virtio_device_id *ids;

	//检查drv支持的id_table是否与之匹配
	ids = drv_to_virtio(_dr)->id_table;
	for (i = 0; ids[i].device; i++)
		if (virtio_id_match(dev, &ids[i]))
			return 1;//实现匹配，返回1
	return 0;
}

//virtio添加的uevent环境变量
static int virtio_uevent(const struct device *_dv, struct kobj_uevent_env *env)
{
	const struct virtio_device *dev = dev_to_virtio(_dv);

	//添加设备模块别名
	return add_uevent_var(env, "MODALIAS=virtio:d%08Xv%08X",
			      dev->id.device, dev->id.vendor);
}

//必提供的功能bit,如果未提供则直接挂掉
void virtio_check_driver_offered_feature(const struct virtio_device *vdev,
					 unsigned int fbit)
{
	unsigned int i;
	struct virtio_driver *drv = drv_to_virtio(vdev->dev.driver);

	for (i = 0; i < drv->feature_table_size; i++)
		if (drv->feature_table[i] == fbit)
			return;

	if (drv->feature_table_legacy) {
		for (i = 0; i < drv->feature_table_size_legacy; i++)
			if (drv->feature_table_legacy[i] == fbit)
				return;
	}

	//如果未提供fbit功能，则挂掉
	BUG();
}
EXPORT_SYMBOL_GPL(virtio_check_driver_offered_feature);

static void __virtio_config_changed(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	if (!dev->config_enabled)
		dev->config_change_pending = true;
	else if (drv && drv->config_changed)
		drv->config_changed(dev);
}

//指明virtio device配置改变
void virtio_config_changed(struct virtio_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->config_lock, flags);
	__virtio_config_changed(dev);
	spin_unlock_irqrestore(&dev->config_lock, flags);
}
EXPORT_SYMBOL_GPL(virtio_config_changed);

static void virtio_config_disable(struct virtio_device *dev)
{
	spin_lock_irq(&dev->config_lock);
	dev->config_enabled = false;
	spin_unlock_irq(&dev->config_lock);
}

static void virtio_config_enable(struct virtio_device *dev)
{
	spin_lock_irq(&dev->config_lock);
	dev->config_enabled = true;
	if (dev->config_change_pending)
		__virtio_config_changed(dev);
	dev->config_change_pending = false;
	spin_unlock_irq(&dev->config_lock);
}

//设置新的设备status
void virtio_add_status(struct virtio_device *dev, unsigned int status)
{
	might_sleep();
	dev->config->set_status(dev, dev->config->get_status(dev) | status);
}
EXPORT_SYMBOL_GPL(virtio_add_status);

/* Do some validation, then set FEATURES_OK */
static int virtio_features_ok(struct virtio_device *dev)
{
	unsigned int status;

	might_sleep();

	if (virtio_check_mem_acc_cb(dev)) {
		if (!virtio_has_feature(dev, VIRTIO_F_VERSION_1)) {
			dev_warn(&dev->dev,
				 "device must provide VIRTIO_F_VERSION_1\n");
			return -ENODEV;
		}

		if (!virtio_has_feature(dev, VIRTIO_F_ACCESS_PLATFORM)) {
			dev_warn(&dev->dev,
				 "device must provide VIRTIO_F_ACCESS_PLATFORM\n");
			return -ENODEV;
		}
	}

	//协商为非virtio 1.0,直接返回0
	if (!virtio_has_feature(dev, VIRTIO_F_VERSION_1))
		return 0;

	//置设备与驱动已完成了功能协商
	//EATURES_OK (8) Indicates that the driver has acknowledged all the features it understands, and feature
	//negotiation is complete.
	virtio_add_status(dev, VIRTIO_CONFIG_S_FEATURES_OK);
	status = dev->config->get_status(dev);
	if (!(status & VIRTIO_CONFIG_S_FEATURES_OK)) {
		//设备未成功置“功能协商"ok标记
		dev_err(&dev->dev, "virtio: device refuses features: %x\n",
			status);
		return -ENODEV;
	}
	return 0;
}

/**
 * virtio_reset_device - quiesce device for removal
 * @dev: the device to reset
 *
 * Prevents device from sending interrupts and accessing memory.
 *
 * Generally used for cleanup during driver / device removal.
 *
 * Once this has been invoked, caller must ensure that
 * virtqueue_notify / virtqueue_kick are not in progress.
 *
 * Note: this guarantees that vq callbacks are not in progress, however caller
 * is responsible for preventing access from other contexts, such as a system
 * call/workqueue/bh.  Invoking virtio_break_device then flushing any such
 * contexts is one way to handle that.
 * */
void virtio_reset_device(struct virtio_device *dev)
{
#ifdef CONFIG_VIRTIO_HARDEN_NOTIFICATION
	/*
	 * The below virtio_synchronize_cbs() guarantees that any
	 * interrupt for this line arriving after
	 * virtio_synchronize_vqs() has completed is guaranteed to see
	 * vq->broken as true.
	 */
	virtio_break_device(dev);
	virtio_synchronize_cbs(dev);
#endif

	dev->config->reset(dev);
}
EXPORT_SYMBOL_GPL(virtio_reset_device);

static int virtio_dev_probe(struct device *_d)
{
	int err, i;
    //device类型，实际上是virtio的父类，而dev->dev.driver也是virtio_driver的
    //父类，通过相应函数进行转换
	struct virtio_device *dev = dev_to_virtio(_d);
	//设备的驱动
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	u64 device_features;
	u64 driver_features;
	u64 driver_features_legacy;

	/* We have a driver! */
    //指明此设备已找到匹配的driver
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER);

	/* Figure out what features the device supports. */
    //获得当前设备支持的功能列表
	device_features = dev->config->get_features(dev);

	/* Figure out what features the driver supports. */
	//获得当前驱动支持的功能列表
	driver_features = 0;
	for (i = 0; i < drv->feature_table_size; i++) {
		unsigned int f = drv->feature_table[i];
		BUG_ON(f >= 64);
		driver_features |= (1ULL << f);
	}

	/* Some drivers have a separate feature table for virtio v1.0 */
	//如果driver有legacy table,则获取，否则使用driver_features
	if (drv->feature_table_legacy) {
		driver_features_legacy = 0;
		for (i = 0; i < drv->feature_table_size_legacy; i++) {
			unsigned int f = drv->feature_table_legacy[i];
			BUG_ON(f >= 64);
			driver_features_legacy |= (1ULL << f);
		}
	} else {
		driver_features_legacy = driver_features;
	}

	//如果使能v1.0,则取与操作计算两者合并device与driver获得的features
	if (device_features & (1ULL << VIRTIO_F_VERSION_1))
		dev->features = driver_features & device_features;
	else
		//非1.0版本时，采用legayc驱动功能号与上设备功能号
		dev->features = driver_features_legacy & device_features;

	/* Transport features always preserved to pass to finalize_features. */
	//如果device_features有这些标记，则为dev加上此标记
	for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++)
		if (device_features & (1ULL << i))
			__virtio_set_bit(dev, i);

	err = dev->config->finalize_features(dev);
	if (err)
		goto err;

	//调用driver的validate函数，检查设备功能配置
	if (drv->validate) {
		u64 features = dev->features;

		err = drv->validate(dev);
		if (err)
			goto err;

		/* Did validation change any features? Then write them again. */
		if (features != dev->features) {
			err = dev->config->finalize_features(dev);
			if (err)
				goto err;
		}
	}

	//完成驱动与设备的功能协商
	err = virtio_features_ok(dev);
	if (err)
		goto err;

	if (dev->config->create_avq) {
		err = dev->config->create_avq(dev);
		if (err)
			goto err;
	}

	//驱动探测设备，生成相应设备(例如virtio_net_driver)
	err = drv->probe(dev);
	if (err)
		goto err_probe;

	/* If probe didn't do it, mark device DRIVER_OK ourselves. */
	//检查设备是否已达到driver_ok状态，如果未达到，设置为ok(这里驱动都返回0了）
	if (!(dev->config->get_status(dev) & VIRTIO_CONFIG_S_DRIVER_OK))
		virtio_device_ready(dev);

    //如果驱动支持扫描，则调用scan回调
	if (drv->scan)
		drv->scan(dev);

	virtio_config_enable(dev);

	return 0;

err_probe:
	if (dev->config->destroy_avq)
		dev->config->destroy_avq(dev);
err:
    //标明发生内部错误，驱动失败
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return err;

}

//调用driver的remove函数移除设备
static void virtio_dev_remove(struct device *_d)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	virtio_config_disable(dev);

	drv->remove(dev);

	if (dev->config->destroy_avq)
		dev->config->destroy_avq(dev);

	/* Driver should have reset device. */
	WARN_ON_ONCE(dev->config->get_status(dev));

	/* Acknowledge the device's existence again. */
	//指明设备再次存在
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

	of_node_put(dev->dev.of_node);
}

//虚拟的virtio bus
static struct bus_type virtio_bus = {
	.name  = "virtio",
	//virtio bus的设备匹配函数
	.match = virtio_dev_match,
	//定义virtio bus的设置属性组体现在/sys目录下
	.dev_groups = virtio_dev_groups,
	//virtio bus通知uevent时添加uevent环境变量
	.uevent = virtio_uevent,
	//virtio bus提供的设备probe函数
	.probe = virtio_dev_probe,
	//virtio bus提供设备的remove
	.remove = virtio_dev_remove,
};

//virtio驱动注册(这些驱动均从属于virtio_bus)
int register_virtio_driver(struct virtio_driver *driver)
{
	/* Catch this early. */
	/*feature_table_size不为零时，feature_table必须不为空*/
	BUG_ON(driver->feature_table_size && !driver->feature_table);
	//指明驱动支持的设备从属于virtio_bus
	driver->driver.bus = &virtio_bus;
	return driver_register(&driver->driver);
}
EXPORT_SYMBOL_GPL(register_virtio_driver);

//驱动解注册
void unregister_virtio_driver(struct virtio_driver *driver)
{
	driver_unregister(&driver->driver);
}
EXPORT_SYMBOL_GPL(unregister_virtio_driver);

static int virtio_device_of_init(struct virtio_device *dev)
{
	struct device_node *np, *pnode = dev_of_node(dev->dev.parent);
	char compat[] = "virtio,deviceXXXXXXXX";
	int ret, count;

	if (!pnode)
		return 0;

	count = of_get_available_child_count(pnode);
	if (!count)
		return 0;

	/* There can be only 1 child node */
	if (WARN_ON(count > 1))
		return -EINVAL;

	np = of_get_next_available_child(pnode, NULL);
	if (WARN_ON(!np))
		return -ENODEV;

	ret = snprintf(compat, sizeof(compat), "virtio,device%x", dev->id.device);
	BUG_ON(ret >= sizeof(compat));

	/*
	 * On powerpc/pseries virtio devices are PCI devices so PCI
	 * vendor/device ids play the role of the "compatible" property.
	 * Simply don't init of_node in this case.
	 */
	if (!of_device_is_compatible(np, compat)) {
		ret = 0;
		goto out;
	}

	dev->dev.of_node = np;
	return 0;

out:
	of_node_put(np);
	return ret;
}

/**
 * register_virtio_device - register virtio device
 * @dev        : virtio device to be registered
 *
 * On error, the caller must call put_device on &@dev->dev (and not kfree),
 * as another code path may have obtained a reference to @dev.
 *
 * Returns: 0 on suceess, -error on failure
 */
//virtio设备注册
int register_virtio_device(struct virtio_device *dev)
{
	int err;

	//virtio设备的bus为virtio_bus
	dev->dev.bus = &virtio_bus;
	device_initialize(&dev->dev);

	/* Assign a unique device index and hence name. */
	//为virtio获取设备index
	err = ida_alloc(&virtio_index_ida, GFP_KERNEL);
	if (err < 0)
		goto out;

	dev->index = err;
	err = dev_set_name(&dev->dev, "virtio%u", dev->index);
	if (err)
		goto out_ida_remove;

	err = virtio_device_of_init(dev);
	if (err)
		goto out_ida_remove;

	spin_lock_init(&dev->config_lock);
	dev->config_enabled = false;
	dev->config_change_pending = false;

	INIT_LIST_HEAD(&dev->vqs);
	spin_lock_init(&dev->vqs_list_lock);

	/* We always start by resetting the device, in case a previous
	 * driver messed it up.  This also tests that code path a little. */
	//reset此设备
	virtio_reset_device(dev);

	/* Acknowledge that we've seen the device. */
	//标记此设备已被发现，且有效
	//ACKNOWLEDGE (1) Indicates that the guest OS has found the device and recognized it as a valid virtio
	//device
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

	/*
	 * device_add() causes the bus infrastructure to look for a matching
	 * driver.
	 */
	//将virtio设备注册给系统,将引发查找此设备对应的驱动的过程
	err = device_add(&dev->dev);
	if (err)
		goto out_of_node_put;

	return 0;

out_of_node_put:
	of_node_put(dev->dev.of_node);
out_ida_remove:
	ida_free(&virtio_index_ida, dev->index);
out:
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return err;
}
EXPORT_SYMBOL_GPL(register_virtio_device);

bool is_virtio_device(struct device *dev)
{
	return dev->bus == &virtio_bus;
}
EXPORT_SYMBOL_GPL(is_virtio_device);

void unregister_virtio_device(struct virtio_device *dev)
{
	int index = dev->index; /* save for after device release */

	device_unregister(&dev->dev);
	ida_free(&virtio_index_ida, index);
}
EXPORT_SYMBOL_GPL(unregister_virtio_device);

#ifdef CONFIG_PM_SLEEP
int virtio_device_freeze(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	int ret;

	virtio_config_disable(dev);

	dev->failed = dev->config->get_status(dev) & VIRTIO_CONFIG_S_FAILED;

	if (drv && drv->freeze) {
		ret = drv->freeze(dev);
		if (ret)
			return ret;
	}

	if (dev->config->destroy_avq)
		dev->config->destroy_avq(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_device_freeze);

int virtio_device_restore(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	int ret;

	/* We always start by resetting the device, in case a previous
	 * driver messed it up. */
	virtio_reset_device(dev);

	/* Acknowledge that we've seen the device. */
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

	/* Maybe driver failed before freeze.
	 * Restore the failed status, for debugging. */
	if (dev->failed)
		virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);

	if (!drv)
		return 0;

	/* We have a driver! */
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER);

	ret = dev->config->finalize_features(dev);
	if (ret)
		goto err;

	ret = virtio_features_ok(dev);
	if (ret)
		goto err;

	if (dev->config->create_avq) {
		ret = dev->config->create_avq(dev);
		if (ret)
			goto err;
	}

	if (drv->restore) {
		ret = drv->restore(dev);
		if (ret)
			goto err_restore;
	}

	/* If restore didn't do it, mark device DRIVER_OK ourselves. */
	if (!(dev->config->get_status(dev) & VIRTIO_CONFIG_S_DRIVER_OK))
		virtio_device_ready(dev);

	virtio_config_enable(dev);

	return 0;

err_restore:
	if (dev->config->destroy_avq)
		dev->config->destroy_avq(dev);
err:
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return ret;
}
EXPORT_SYMBOL_GPL(virtio_device_restore);
#endif

//注册virtio_bus
static int virtio_init(void)
{
    /*为系统注册virtio bus*/
	if (bus_register(&virtio_bus) != 0)
		panic("virtio bus registration failed");
	return 0;
}

static void __exit virtio_exit(void)
{
	bus_unregister(&virtio_bus);
	ida_destroy(&virtio_index_ida);
}
core_initcall(virtio_init);
module_exit(virtio_exit);

MODULE_LICENSE("GPL");
