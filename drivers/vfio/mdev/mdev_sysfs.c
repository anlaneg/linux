// SPDX-License-Identifier: GPL-2.0-only
/*
 * File attributes for Mediated devices
 *
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *     Author: Neo Jia <cjia@nvidia.com>
 *             Kirti Wankhede <kwankhede@nvidia.com>
 */

#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/mdev.h>

#include "mdev_private.h"

struct mdev_type_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mdev_type *mtype,
			struct mdev_type_attribute *attr, char *buf);
	ssize_t (*store)(struct mdev_type *mtype,
			 struct mdev_type_attribute *attr, const char *buf,
			 size_t count);
};

#define MDEV_TYPE_ATTR_RO(_name) \
	struct mdev_type_attribute mdev_type_attr_##_name = __ATTR_RO(_name)
#define MDEV_TYPE_ATTR_WO(_name) \
	struct mdev_type_attribute mdev_type_attr_##_name = __ATTR_WO(_name)

static ssize_t mdev_type_attr_show(struct kobject *kobj,
				     struct attribute *__attr, char *buf)
{
    //执行mdev_type属性显示，调用attrbute对应的show函数完成
	struct mdev_type_attribute *attr = to_mdev_type_attr(__attr);
	struct mdev_type *type = to_mdev_type(kobj);
	ssize_t ret = -EIO;

	if (attr->show)
		ret = attr->show(type, attr, buf);
	return ret;
}

static ssize_t mdev_type_attr_store(struct kobject *kobj,
				      struct attribute *__attr,
				      const char *buf, size_t count)
{
    //执行mdev_type属性设置，调用attrbute对应的store函数完成
	struct mdev_type_attribute *attr = to_mdev_type_attr(__attr);
	struct mdev_type *type = to_mdev_type(kobj);
	ssize_t ret = -EIO;

	if (attr->store)
		ret = attr->store(type, attr, buf, count);
	return ret;
}

//mdev type对应的sysfs操作函数
static const struct sysfs_ops mdev_type_sysfs_ops = {
	.show = mdev_type_attr_show,
	.store = mdev_type_attr_store,
};

//处理mdev_device 'create'属性的设置操作
static ssize_t create_store(struct mdev_type *mtype,
			    struct mdev_type_attribute *attr, const char *buf,
			    size_t count)
{
	char *str;
	guid_t uuid;
	int ret;

	if ((count < UUID_STRING_LEN) || (count > UUID_STRING_LEN + 1))
		return -EINVAL;

	//复制用户输入
	str = kstrndup(buf, count, GFP_KERNEL);
	if (!str)
		return -ENOMEM;

	//将str解析为uuid buffer
	ret = guid_parse(str, &uuid);
	kfree(str);
	if (ret)
		return ret;

	//创建dev对应的mdev设备，并指出mdev设备uuid
	ret = mdev_device_create(mtype, &uuid);
	if (ret)
		return ret;

	return count;
}
static MDEV_TYPE_ATTR_WO(create);

static ssize_t device_api_show(struct mdev_type *mtype,
			       struct mdev_type_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", mtype->parent->mdev_driver->device_api);
}
static MDEV_TYPE_ATTR_RO(device_api);

static ssize_t name_show(struct mdev_type *mtype,
			 struct mdev_type_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n",
		mtype->pretty_name ? mtype->pretty_name : mtype->sysfs_name);
}

static MDEV_TYPE_ATTR_RO(name);

static ssize_t available_instances_show(struct mdev_type *mtype,
					struct mdev_type_attribute *attr,
					char *buf)
{
	struct mdev_driver *drv = mtype->parent->mdev_driver;

	if (drv->get_available)
		return sysfs_emit(buf, "%u\n", drv->get_available(mtype));
	return sysfs_emit(buf, "%u\n",
			  atomic_read(&mtype->parent->available_instances));
}
static MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t description_show(struct mdev_type *mtype,
				struct mdev_type_attribute *attr,
				char *buf)
{
	return mtype->parent->mdev_driver->show_description(mtype, buf);
}
static MDEV_TYPE_ATTR_RO(description);

static struct attribute *mdev_types_core_attrs[] = {
	&mdev_type_attr_create.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_name.attr,
	&mdev_type_attr_available_instances.attr,
	&mdev_type_attr_description.attr,
	NULL,
};

static umode_t mdev_types_core_is_visible(struct kobject *kobj,
					  struct attribute *attr, int n)
{
	if (attr == &mdev_type_attr_description.attr &&
	    !to_mdev_type(kobj)->parent->mdev_driver->show_description)
		return 0;
	return attr->mode;
}

static struct attribute_group mdev_type_core_group = {
	.attrs = mdev_types_core_attrs,
	.is_visible = mdev_types_core_is_visible,
};

static const struct attribute_group *mdev_type_groups[] = {
	&mdev_type_core_group,
	NULL,
};

//mdev_type obj释放
static void mdev_type_release(struct kobject *kobj)
{
	struct mdev_type *type = to_mdev_type(kobj);

	pr_debug("Releasing group %s\n", kobj->name);
	/* Pairs with the get in add_mdev_supported_type() */
	put_device(type->parent->dev);
}

//定义mdev_type的kobj类型
static struct kobj_type mdev_type_ktype = {
	.sysfs_ops	= &mdev_type_sysfs_ops,
	.release	= mdev_type_release,
	.default_groups	= mdev_type_groups,
};

/*创建mdev_type,并设置mdev_type对应的parent*/
static int mdev_type_add(struct mdev_parent *parent, struct mdev_type *type)
{
	int ret;

	type->kobj.kset = parent->mdev_types_kset;
	type->parent = parent;
	/* Pairs with the put in mdev_type_release() */
	get_device(parent->dev);

	//初始化mdev_type对应的kobj,并指定其obj type为mdev_type_ktype
	ret = kobject_init_and_add(&type->kobj, &mdev_type_ktype, NULL/*父节点为空*/,
				   "%s-%s", dev_driver_string(parent->dev),
				   type->sysfs_name);
	if (ret) {
		kobject_put(&type->kobj);
		return ret;
	}

	//在type->kobj下创建devices文件
	type->devices_kobj = kobject_create_and_add("devices", &type->kobj);
	if (!type->devices_kobj) {
		ret = -ENOMEM;
		goto attr_devices_failed;
	}

	return 0;

attr_devices_failed:
	kobject_del(&type->kobj);
	kobject_put(&type->kobj);
	return ret;
}

static void mdev_type_remove(struct mdev_type *type)
{
	kobject_put(type->devices_kobj);
	kobject_del(&type->kobj);
	kobject_put(&type->kobj);
}

/* mdev sysfs functions */
void parent_remove_sysfs_files(struct mdev_parent *parent)
{
	int i;

	for (i = 0; i < parent->nr_types; i++)
		mdev_type_remove(parent->types[i]);
	kset_unregister(parent->mdev_types_kset);
}

/*创建mdev_parent对应的sysfs文件*/
int parent_create_sysfs_files(struct mdev_parent *parent)
{
	int ret, i;

	/*创建指定名称kset,并指定其对应的父obj*/
	parent->mdev_types_kset = kset_create_and_add("mdev_supported_types",
					       NULL, &parent->dev->kobj);
	if (!parent->mdev_types_kset)
		return -ENOMEM;

	for (i = 0; i < parent->nr_types; i++) {
		ret = mdev_type_add(parent, parent->types[i]);
		if (ret)
			goto out_err;
	}
	return 0;

out_err:
	while (--i >= 0)
		mdev_type_remove(parent->types[i]);
	return 0;
}

//写'remove'文件触发
static ssize_t remove_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct mdev_device *mdev = to_mdev_device(dev);
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val && device_remove_file_self(dev, attr)) {
		int ret;

		ret = mdev_device_remove(mdev);
		if (ret)
			return ret;
	}

	return count;
}

static DEVICE_ATTR_WO(remove);

//定义mdev设备的'remove'文件，只写属性
static struct attribute *mdev_device_attrs[] = {
	&dev_attr_remove.attr,
	NULL,
};

static const struct attribute_group mdev_device_group = {
	.attrs = mdev_device_attrs,
};

const struct attribute_group *mdev_device_groups[] = {
	&mdev_device_group,
	NULL
};

int mdev_create_sysfs_files(struct mdev_device *mdev)
{
	struct mdev_type *type = mdev->type;
	struct kobject *kobj = &mdev->dev.kobj;
	int ret;

	ret = sysfs_create_link(type->devices_kobj, kobj, dev_name(&mdev->dev));
	if (ret)
		return ret;

	ret = sysfs_create_link(kobj, &type->kobj, "mdev_type");
	if (ret)
		goto type_link_failed;
	return ret;

type_link_failed:
	sysfs_remove_link(mdev->type->devices_kobj, dev_name(&mdev->dev));
	return ret;
}

void mdev_remove_sysfs_files(struct mdev_device *mdev)
{
	struct kobject *kobj = &mdev->dev.kobj;

	//移除'mdev_type'链接
	sysfs_remove_link(kobj, "mdev_type");
	//移除dev名称的链接
	sysfs_remove_link(mdev->type->devices_kobj, dev_name(&mdev->dev));
}
