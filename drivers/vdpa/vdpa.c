// SPDX-License-Identifier: GPL-2.0-only
/*
 * vDPA bus.
 *
 * Copyright (c) 2020, Red Hat. All rights reserved.
 *     Author: Jason Wang <jasowang@redhat.com>
 *
 */

#include <linux/module.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/vdpa.h>

/*负责vdpa设备的index分配*/
static DEFINE_IDA(vdpa_index_ida);

//执行vdpa设备与vdpa驱动适配
static int vdpa_dev_probe(struct device *d)
{
    /*设备为vdpa设备*/
	struct vdpa_device *vdev = dev_to_vdpa(d);
	/*驱动为vdpa驱动*/
	struct vdpa_driver *drv = drv_to_vdpa(vdev->dev.driver);
	int ret = 0;

	/*采用vdpa驱动probe此vdpa设备*/
	if (drv && drv->probe)
		ret = drv->probe(vdev);

	return ret;
}

/*指定d对应的vdpa驱动移除设备*/
static int vdpa_dev_remove(struct device *d)
{
	struct vdpa_device *vdev = dev_to_vdpa(d);
	struct vdpa_driver *drv = drv_to_vdpa(vdev->dev.driver);

	if (drv && drv->remove)
		drv->remove(vdev);

	return 0;
}

/*vdpa对应的虚拟bus*/
static struct bus_type vdpa_bus = {
	.name  = "vdpa",
	.probe = vdpa_dev_probe,
	.remove = vdpa_dev_remove,
};

/*vdpa设备释放*/
static void vdpa_release_dev(struct device *d)
{
	struct vdpa_device *vdev = dev_to_vdpa(d);
	const struct vdpa_config_ops *ops = vdev->config;

	/*释放此vdpa设备*/
	if (ops->free)
		ops->free(vdev);

	/*归还vdpa设备对应的index*/
	ida_simple_remove(&vdpa_index_ida, vdev->index);
	kfree(vdev);
}

/**
 * __vdpa_alloc_device - allocate and initilaize a vDPA device
 * This allows driver to some prepartion after device is
 * initialized but before registered.
 * @parent: the parent device
 * @config: the bus operations that is supported by this device
 * @nvqs: number of virtqueues supported by this device
 * @size: size of the parent structure that contains private data
 *
 * Driver should use vdpa_alloc_device() wrapper macro instead of
 * using this directly.
 *
 * Returns an error when parent/config/dma_dev is not set or fail to get
 * ida.
 */
struct vdpa_device *__vdpa_alloc_device(struct device *parent/*父设备*/,
					const struct vdpa_config_ops *config/*vdpa操作集*/,
					int nvqs/*虚队列数*/,
					size_t size/*vdpa设备空间大小（含私有空间）*/)
{
    //vdap设备申请及初始化
	struct vdpa_device *vdev;
	int err = -EINVAL;

	if (!config)
		goto err;

	/*dma_map与dma_unmap必须成对出现*/
	if (!!config->dma_map != !!config->dma_unmap)
		goto err;

	/*申请vdpa空间*/
	err = -ENOMEM;
	vdev = kzalloc(size, GFP_KERNEL);
	if (!vdev)
		goto err;

	/*申请空闲id号做为设备索引*/
	err = ida_alloc(&vdpa_index_ida, GFP_KERNEL);
	if (err < 0)
		goto err_ida;

	vdev->dev.bus = &vdpa_bus;/*vdpa虚拟总线*/
	vdev->dev.parent = parent;
	vdev->dev.release = vdpa_release_dev;
	vdev->index = err;
	vdev->config = config;/*设置vdpa设备操作集*/
	vdev->features_valid = false;
	vdev->nvqs = nvqs;

	//设置vdpa设备名称
	err = dev_set_name(&vdev->dev, "vdpa%u", vdev->index);
	if (err)
		goto err_name;

	device_initialize(&vdev->dev);

	return vdev;

err_name:
    /*释放为此dev申请的index*/
	ida_simple_remove(&vdpa_index_ida, vdev->index);
err_ida:
	kfree(vdev);
err:
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(__vdpa_alloc_device);

/**
 * vdpa_register_device - register a vDPA device
 * Callers must have a succeed call of vdpa_alloc_device() before.
 * @vdev: the vdpa device to be registered to vDPA bus
 *
 * Returns an error when fail to add to vDPA bus
 */
int vdpa_register_device(struct vdpa_device *vdev)
{
    /*添加此device到sysfs*/
	return device_add(&vdev->dev);
}
EXPORT_SYMBOL_GPL(vdpa_register_device);

/**
 * vdpa_unregister_device - unregister a vDPA device
 * @vdev: the vdpa device to be unregisted from vDPA bus
 */
void vdpa_unregister_device(struct vdpa_device *vdev)
{
	device_unregister(&vdev->dev);
}
EXPORT_SYMBOL_GPL(vdpa_unregister_device);

/**
 * __vdpa_register_driver - register a vDPA device driver
 * @drv: the vdpa device driver to be registered
 * @owner: module owner of the driver
 *
 * Returns an err when fail to do the registration
 */
int __vdpa_register_driver(struct vdpa_driver *drv, struct module *owner)
{
    //vdpa驱动注册
	drv->driver.bus = &vdpa_bus;
	drv->driver.owner = owner;

	return driver_register(&drv->driver);
}
EXPORT_SYMBOL_GPL(__vdpa_register_driver);

/**
 * vdpa_unregister_driver - unregister a vDPA device driver
 * @drv: the vdpa device driver to be unregistered
 */
void vdpa_unregister_driver(struct vdpa_driver *drv)
{
	driver_unregister(&drv->driver);
}
EXPORT_SYMBOL_GPL(vdpa_unregister_driver);

static int vdpa_init(void)
{
    /*注册vdpa bus*/
	return bus_register(&vdpa_bus);
}

static void __exit vdpa_exit(void)
{
	bus_unregister(&vdpa_bus);
	ida_destroy(&vdpa_index_ida);
}
core_initcall(vdpa_init);
module_exit(vdpa_exit);

MODULE_AUTHOR("Jason Wang <jasowang@redhat.com>");
MODULE_LICENSE("GPL v2");
