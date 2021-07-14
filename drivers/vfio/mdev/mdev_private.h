/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Mediated device internal definitions
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
	struct device *dev;/*mdev_parent关联的设备*/
	const struct mdev_parent_ops *ops;/*操作集*/
	struct kref ref;//引用计数
	struct list_head next;//用于串连在链表parent_list上
	struct kset *mdev_types_kset;
	struct list_head type_list;/*记录支持的一组mdev_type*/
	/* Synchronize device creation/removal with parent unregistration */
	struct rw_semaphore unreg_sem;
};

struct mdev_type {
	struct kobject kobj;/*类型为mdev_type_ktype的kobj*/
	struct kobject *devices_kobj;/*this->kobj下的名称为devices的kobject*/
	struct mdev_parent *parent;/*所属的mdev_parent*/
	struct list_head next;
	unsigned int type_group_id;
};

#define to_mdev_type_attr(_attr)	\
	container_of(_attr, struct mdev_type_attribute, attr)
/*由kobj取mdev_type*/
#define to_mdev_type(_kobj)		\
	container_of(_kobj, struct mdev_type, kobj)

extern struct mdev_driver vfio_mdev_driver;

int  parent_create_sysfs_files(struct mdev_parent *parent);
void parent_remove_sysfs_files(struct mdev_parent *parent);

int  mdev_create_sysfs_files(struct mdev_device *mdev);
void mdev_remove_sysfs_files(struct mdev_device *mdev);

int mdev_device_create(struct mdev_type *kobj, const guid_t *uuid);
int  mdev_device_remove(struct mdev_device *dev);

void mdev_release_parent(struct kref *kref);

static inline void mdev_get_parent(struct mdev_parent *parent)
{
	kref_get(&parent->ref);
}

static inline void mdev_put_parent(struct mdev_parent *parent)
{
	kref_put(&parent->ref, mdev_release_parent);
}

#endif /* MDEV_PRIVATE_H */
