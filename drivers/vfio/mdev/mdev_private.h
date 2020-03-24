/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Mediated device interal definitions
 *
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *     Author: Neo Jia <cjia@nvidia.com>
 *             Kirti Wankhede <kwankhede@nvidia.com>
 */

#ifndef MDEV_PRIVATE_H
#define MDEV_PRIVATE_H

int  mdev_bus_register(void);
void mdev_bus_unregister(void);

struct mdev_parent {
	struct device *dev;/*从属于mdev的设备*/
	const struct mdev_parent_ops *ops;
	struct kref ref;
	struct list_head next;
	struct kset *mdev_types_kset;
	struct list_head type_list;/*记录支持的一组mdev_type*/
	/* Synchronize device creation/removal with parent unregistration */
	struct rw_semaphore unreg_sem;
};

struct mdev_device {
	struct device dev;
	struct mdev_parent *parent;
	guid_t uuid;
	void *driver_data;
	struct list_head next;
	struct kobject *type_kobj;
	struct device *iommu_device;
	bool active;
};

//将device转换为mdev_deivce
#define to_mdev_device(dev)	container_of(dev, struct mdev_device, dev)
//检查dev是否为mdev(如果其bus类型为mdev_bus,则认为是mdev)
#define dev_is_mdev(d)		((d)->bus == &mdev_bus_type)

struct mdev_type {
	struct kobject kobj;/*类型为mdev_type_ktype的kobj*/
	struct kobject *devices_kobj;/*this->kobj下的名称为devices的kobject*/
	struct mdev_parent *parent;/*所属的mdev_parent*/
	struct list_head next;
	struct attribute_group *group;/*对应的属性组*/
};

#define to_mdev_type_attr(_attr)	\
	container_of(_attr, struct mdev_type_attribute, attr)
/*由kobj取mdev_type*/
#define to_mdev_type(_kobj)		\
	container_of(_kobj, struct mdev_type, kobj)

int  parent_create_sysfs_files(struct mdev_parent *parent);
void parent_remove_sysfs_files(struct mdev_parent *parent);

int  mdev_create_sysfs_files(struct device *dev, struct mdev_type *type);
void mdev_remove_sysfs_files(struct device *dev, struct mdev_type *type);

int  mdev_device_create(struct kobject *kobj,
			struct device *dev, const guid_t *uuid);
int  mdev_device_remove(struct device *dev);

#endif /* MDEV_PRIVATE_H */
