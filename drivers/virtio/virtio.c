#include <linux/virtio.h>
#include <linux/spinlock.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <uapi/linux/virtio_ids.h>

/* Unique numbering for virtio devices. */
static DEFINE_IDA(virtio_index_ida);

//显示device
static ssize_t device_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "0x%04x\n", dev->id.device);
}

//定义变量指出采用device_show回调（定义device属性）
static DEVICE_ATTR_RO(device);

//显示vendor
static ssize_t vendor_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "0x%04x\n", dev->id.vendor);
}
static DEVICE_ATTR_RO(vendor);//定义vendor属性

static ssize_t status_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "0x%08x\n", dev->config->get_status(dev));
}
static DEVICE_ATTR_RO(status);//定义status属性

static ssize_t modalias_show(struct device *_d,
			     struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "virtio:d%08Xv%08X\n",
		       dev->id.device, dev->id.vendor);
}
static DEVICE_ATTR_RO(modalias);//模块别名

static ssize_t features_show(struct device *_d,
			     struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	unsigned int i;
	ssize_t len = 0;

	/* We actually represent this as a bitstring, as it could be
	 * arbitrary length in future. */
	for (i = 0; i < sizeof(dev->features)*8; i++)
		len += sprintf(buf+len, "%c",
			       __virtio_test_bit(dev, i) ? '1' : '0');
	len += sprintf(buf+len, "\n");
	return len;
}
static DEVICE_ATTR_RO(features);//功能属性

//定义virtio的属性数组
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
//virtio设备匹配
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

static int virtio_uevent(struct device *_dv, struct kobj_uevent_env *env)
{
	struct virtio_device *dev = dev_to_virtio(_dv);

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

//指明配置改变
void virtio_config_changed(struct virtio_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->config_lock, flags);
	__virtio_config_changed(dev);
	spin_unlock_irqrestore(&dev->config_lock, flags);
}
EXPORT_SYMBOL_GPL(virtio_config_changed);

void virtio_config_disable(struct virtio_device *dev)
{
	spin_lock_irq(&dev->config_lock);
	dev->config_enabled = false;
	spin_unlock_irq(&dev->config_lock);
}
EXPORT_SYMBOL_GPL(virtio_config_disable);

void virtio_config_enable(struct virtio_device *dev)
{
	spin_lock_irq(&dev->config_lock);
	dev->config_enabled = true;
	if (dev->config_change_pending)
		__virtio_config_changed(dev);
	dev->config_change_pending = false;
	spin_unlock_irq(&dev->config_lock);
}
EXPORT_SYMBOL_GPL(virtio_config_enable);

void virtio_add_status(struct virtio_device *dev, unsigned int status)
{
	dev->config->set_status(dev, dev->config->get_status(dev) | status);
}
EXPORT_SYMBOL_GPL(virtio_add_status);

int virtio_finalize_features(struct virtio_device *dev)
{
	int ret = dev->config->finalize_features(dev);
	unsigned status;

	if (ret)
		return ret;

	if (!virtio_has_feature(dev, VIRTIO_F_VERSION_1))
		return 0;

	//置设备完成了功能协商
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
EXPORT_SYMBOL_GPL(virtio_finalize_features);

static int virtio_dev_probe(struct device *_d)
{
	int err, i;
    //device类型，实际上是virtio的父类，而dev->dev.driver也是virtio_driver的
    //父类，通过相应函数进行转换
	struct virtio_device *dev = dev_to_virtio(_d);
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	u64 device_features;
	u64 driver_features;
	u64 driver_features_legacy;

	/* We have a driver! */
    //指明此设备已找到匹配的driver
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER);

	/* Figure out what features the device supports. */
    //获得当前设备支持的功能
	device_features = dev->config->get_features(dev);

	/* Figure out what features the driver supports. */
	//获得当前驱动支持的功能
	driver_features = 0;
	for (i = 0; i < drv->feature_table_size; i++) {
		unsigned int f = drv->feature_table[i];
		BUG_ON(f >= 64);
		driver_features |= (1ULL << f);
	}

	/* Some drivers have a separate feature table for virtio v1.0 */
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

    //如果使能v1.0,则取与操作计算两者合并获得的features
	if (device_features & (1ULL << VIRTIO_F_VERSION_1))
		dev->features = driver_features & device_features;
	else
		//非1。0版本，0.95版本认为是legacy
		dev->features = driver_features_legacy & device_features;

	/* Transport features always preserved to pass to finalize_features. */
	//如果device_features有这些标记，则为dev加上此标记
	for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++)
		if (device_features & (1ULL << i))
			__virtio_set_bit(dev, i);

	if (drv->validate) {
		err = drv->validate(dev);
		if (err)
			goto err;
	}

	err = virtio_finalize_features(dev);
	if (err)
		goto err;

    //驱动探测设备(例如virtio_net_driver)
	err = drv->probe(dev);
	if (err)
		goto err;

	/* If probe didn't do it, mark device DRIVER_OK ourselves. */
	if (!(dev->config->get_status(dev) & VIRTIO_CONFIG_S_DRIVER_OK))
		virtio_device_ready(dev);

    //如果驱动支持扫描，则调用scan回调
	if (drv->scan)
		drv->scan(dev);

	virtio_config_enable(dev);

	return 0;
err:
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return err;

}

//调用driver的remove函数移除设备
static int virtio_dev_remove(struct device *_d)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	virtio_config_disable(dev);

	drv->remove(dev);

	/* Driver should have reset device. */
	WARN_ON_ONCE(dev->config->get_status(dev));

	/* Acknowledge the device's existence again. */
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);
	return 0;
}

//虚拟的virtio bus
static struct bus_type virtio_bus = {
	.name  = "virtio",
	.match = virtio_dev_match,
	.dev_groups = virtio_dev_groups,//定义virtio的sysfs属性组
	.uevent = virtio_uevent,//构造此设备的事件
	//此probe将在探测virtio设备时首先被调用，然后由此函数负调用用类似virtio-net驱动的probe
	.probe = virtio_dev_probe,
	.remove = virtio_dev_remove,
};

//virtio驱动注册(这些驱动均从属于virtio_bus)
int register_virtio_driver(struct virtio_driver *driver)
{
	/* Catch this early. */
	BUG_ON(driver->feature_table_size && !driver->feature_table);
	driver->driver.bus = &virtio_bus;//指明驱动支持的设备从属于virtio_bus
	return driver_register(&driver->driver);
}
EXPORT_SYMBOL_GPL(register_virtio_driver);

//驱动解注册
void unregister_virtio_driver(struct virtio_driver *driver)
{
	driver_unregister(&driver->driver);
}
EXPORT_SYMBOL_GPL(unregister_virtio_driver);

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
	err = ida_simple_get(&virtio_index_ida, 0, 0, GFP_KERNEL);
	if (err < 0)
		goto out;

	dev->index = err;
	dev_set_name(&dev->dev, "virtio%u", dev->index);

	spin_lock_init(&dev->config_lock);
	dev->config_enabled = false;
	dev->config_change_pending = false;

	/* We always start by resetting the device, in case a previous
	 * driver messed it up.  This also tests that code path a little. */
	dev->config->reset(dev);

	/* Acknowledge that we've seen the device. */
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

	INIT_LIST_HEAD(&dev->vqs);

	/*
	 * device_add() causes the bus infrastructure to look for a matching
	 * driver.
	 */
	//将virtio设备注册给系统
	err = device_add(&dev->dev);
	if (err)
		ida_simple_remove(&virtio_index_ida, dev->index);
out:
	if (err)
		virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return err;
}
EXPORT_SYMBOL_GPL(register_virtio_device);

void unregister_virtio_device(struct virtio_device *dev)
{
	int index = dev->index; /* save for after device release */

	device_unregister(&dev->dev);
	ida_simple_remove(&virtio_index_ida, index);
}
EXPORT_SYMBOL_GPL(unregister_virtio_device);

#ifdef CONFIG_PM_SLEEP
int virtio_device_freeze(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	virtio_config_disable(dev);

	dev->failed = dev->config->get_status(dev) & VIRTIO_CONFIG_S_FAILED;

	if (drv && drv->freeze)
		return drv->freeze(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_device_freeze);

int virtio_device_restore(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	int ret;

	/* We always start by resetting the device, in case a previous
	 * driver messed it up. */
	dev->config->reset(dev);

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

	ret = virtio_finalize_features(dev);
	if (ret)
		goto err;

	if (drv->restore) {
		ret = drv->restore(dev);
		if (ret)
			goto err;
	}

	/* Finally, tell the device we're all set */
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER_OK);

	virtio_config_enable(dev);

	return 0;

err:
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return ret;
}
EXPORT_SYMBOL_GPL(virtio_device_restore);
#endif

//注册virtio_bus
static int virtio_init(void)
{
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
