// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO based driver for Mediated device
 *
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *     Author: Neo Jia <cjia@nvidia.com>
 *             Kirti Wankhede <kwankhede@nvidia.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vfio.h>
#include <linux/mdev.h>

#include "mdev_private.h"

//调用mdev_parent指明的open函数
static int vfio_mdev_open_device(struct vfio_device *core_vdev)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (unlikely(!parent->ops->open_device))
		return 0;

	return parent->ops->open_device(mdev);
}

//调用mdev_parent指明的release函数
static void vfio_mdev_close_device(struct vfio_device *core_vdev)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (likely(parent->ops->close_device))
		parent->ops->close_device(mdev);
}

//调用mdev_parent指明的ioctl函数
static long vfio_mdev_unlocked_ioctl(struct vfio_device *core_vdev,
				     unsigned int cmd, unsigned long arg)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (unlikely(!parent->ops->ioctl))
		return 0;

	return parent->ops->ioctl(mdev, cmd, arg);
}

//调用mdev_parent指明的read函数
static ssize_t vfio_mdev_read(struct vfio_device *core_vdev, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (unlikely(!parent->ops->read))
		return -EINVAL;

	return parent->ops->read(mdev, buf, count, ppos);
}

//调用mdev_parent指明的write函数
static ssize_t vfio_mdev_write(struct vfio_device *core_vdev,
			       const char __user *buf, size_t count,
			       loff_t *ppos)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (unlikely(!parent->ops->write))
		return -EINVAL;

	return parent->ops->write(mdev, buf, count, ppos);
}

//调用mdev_parent指明的mmap函数
static int vfio_mdev_mmap(struct vfio_device *core_vdev,
			  struct vm_area_struct *vma)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (unlikely(!parent->ops->mmap))
		return -EINVAL;

	return parent->ops->mmap(mdev, vma);
}

static void vfio_mdev_request(struct vfio_device *core_vdev, unsigned int count)
{
	struct mdev_device *mdev = to_mdev_device(core_vdev->dev);
	struct mdev_parent *parent = mdev->type->parent;

	if (parent->ops->request)
		parent->ops->request(mdev, count);
	else if (count == 0)
		dev_notice(mdev_dev(mdev),
			   "No mdev vendor driver request callback support, blocked until released by user\n");
}

//vfio-mdev设备，总是通过mdev_parent设备提供的ops完成操作
static const struct vfio_device_ops vfio_mdev_dev_ops = {
	.name		= "vfio-mdev",
	.open_device	= vfio_mdev_open_device,
	.close_device	= vfio_mdev_close_device,
	.ioctl		= vfio_mdev_unlocked_ioctl,
	.read		= vfio_mdev_read,
	.write		= vfio_mdev_write,
	.mmap		= vfio_mdev_mmap,
	.request	= vfio_mdev_request,
};

static int vfio_mdev_probe(struct mdev_device *mdev)
{
	struct vfio_device *vdev;
	int ret;

	//创建mdev设备对应的vfio_dev
	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;

	vfio_init_group_dev(vdev, &mdev->dev, &vfio_mdev_dev_ops);
	ret = vfio_register_emulated_iommu_dev(vdev);
	if (ret)
		goto out_uninit;

	dev_set_drvdata(&mdev->dev, vdev);
	return 0;

out_uninit:
	vfio_uninit_group_dev(vdev);
	kfree(vdev);
	return ret;
}

static void vfio_mdev_remove(struct mdev_device *mdev)
{
	struct vfio_device *vdev = dev_get_drvdata(&mdev->dev);

	vfio_unregister_group_dev(vdev);
	vfio_uninit_group_dev(vdev);
	kfree(vdev);
}

//vfio_mdev设备驱动
struct mdev_driver vfio_mdev_driver = {
	.driver = {
		.name = "vfio_mdev",
		.owner = THIS_MODULE,
		.mod_name = KBUILD_MODNAME,
	},
	.probe	= vfio_mdev_probe,
	.remove	= vfio_mdev_remove,
};
