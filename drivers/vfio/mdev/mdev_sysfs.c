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
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/mdev.h>

#include "mdev_private.h"

/* Static functions */

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

//mdev_type obj释放
static void mdev_type_release(struct kobject *kobj)
{
	struct mdev_type *type = to_mdev_type(kobj);

	pr_debug("Releasing group %s\n", kobj->name);
	/* Pairs with the get in add_mdev_supported_type() */
	mdev_put_parent(type->parent);
	kfree(type);
}

//定义mdev_type的kobj类型
static struct kobj_type mdev_type_ktype = {
	.sysfs_ops = &mdev_type_sysfs_ops,
	.release = mdev_type_release,
};

/*创建mdev_type,并设置mdev_type对应的parent*/
static struct mdev_type *add_mdev_supported_type(struct mdev_parent *parent,
						 unsigned int type_group_id)
{
	struct mdev_type *type;
	struct attribute_group *group =
		parent->ops->supported_type_groups[type_group_id];
	int ret;

	if (!group->name) {
	    //group名称不能为空
		pr_err("%s: Type name empty!\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	//申请mdev_type
	type = kzalloc(sizeof(*type), GFP_KERNEL);
	if (!type)
		return ERR_PTR(-ENOMEM);

	type->kobj.kset = parent->mdev_types_kset;
	type->parent = parent;
	/* Pairs with the put in mdev_type_release() */
	mdev_get_parent(parent);
	type->type_group_id = type_group_id;

	//初始化mdev_type对应的kobj,并指定其obj type为mdev_type_ktype
	ret = kobject_init_and_add(&type->kobj, &mdev_type_ktype, NULL/*父节点为空*/,
				   "%s-%s", dev_driver_string(parent->dev),
				   group->name);
	if (ret) {
		kobject_put(&type->kobj);
		return ERR_PTR(ret);
	}

	//创建type对应文件，并创建"create"属性文件
	ret = sysfs_create_file(&type->kobj, &mdev_type_attr_create.attr);
	if (ret)
		goto attr_create_failed;

	//在type->kobj下创建devices文件
	type->devices_kobj = kobject_create_and_add("devices", &type->kobj);
	if (!type->devices_kobj) {
		ret = -ENOMEM;
		goto attr_devices_failed;
	}

	//创建type->kobj对应的sysfs同组属性文件
	ret = sysfs_create_files(&type->kobj,
				 (const struct attribute **)group->attrs);
	if (ret) {
		ret = -ENOMEM;
		goto attrs_failed;
	}
	return type;

attrs_failed:
	kobject_put(type->devices_kobj);
attr_devices_failed:
	sysfs_remove_file(&type->kobj, &mdev_type_attr_create.attr);
attr_create_failed:
	kobject_del(&type->kobj);
	kobject_put(&type->kobj);
	return ERR_PTR(ret);
}

static void remove_mdev_supported_type(struct mdev_type *type)
{
	struct attribute_group *group =
		type->parent->ops->supported_type_groups[type->type_group_id];

	sysfs_remove_files(&type->kobj,
			   (const struct attribute **)group->attrs);
	kobject_put(type->devices_kobj);
	sysfs_remove_file(&type->kobj, &mdev_type_attr_create.attr);
	kobject_del(&type->kobj);
	kobject_put(&type->kobj);
}

static int add_mdev_supported_type_groups(struct mdev_parent *parent)
{
	int i;

	//遍历parent支持的type group,创建所有mdev_type
	for (i = 0; parent->ops->supported_type_groups[i]; i++) {
		struct mdev_type *type;

		type = add_mdev_supported_type(parent, i);
		if (IS_ERR(type)) {
		    /*添加失败，移除已经成功添加的项*/
			struct mdev_type *ltype, *tmp;

			list_for_each_entry_safe(ltype, tmp, &parent->type_list,
						  next) {
				list_del(&ltype->next);
				remove_mdev_supported_type(ltype);
			}
			return PTR_ERR(type);
		}
		//记录已经成功添加的项
		list_add(&type->next, &parent->type_list);
	}
	return 0;
}

/* mdev sysfs functions */
void parent_remove_sysfs_files(struct mdev_parent *parent)
{
	struct mdev_type *type, *tmp;

	list_for_each_entry_safe(type, tmp, &parent->type_list, next) {
		list_del(&type->next);
		remove_mdev_supported_type(type);
	}

	sysfs_remove_groups(&parent->dev->kobj, parent->ops->dev_attr_groups);
	kset_unregister(parent->mdev_types_kset);
}

/*创建mdev_parent对应的sysfs文件*/
int parent_create_sysfs_files(struct mdev_parent *parent)
{
	int ret;

	/*创建指定名称kset,并指定其对应的父obj*/
	parent->mdev_types_kset = kset_create_and_add("mdev_supported_types",
					       NULL, &parent->dev->kobj);

	if (!parent->mdev_types_kset)
		return -ENOMEM;

	INIT_LIST_HEAD(&parent->type_list);

	/*为dev创建mdev_parent定义的所有属性组*/
	ret = sysfs_create_groups(&parent->dev->kobj,
				  parent->ops->dev_attr_groups);
	if (ret)
		goto create_err;

	ret = add_mdev_supported_type_groups(parent);
	if (ret)
	    /*添加type group失败，移除刚创建的属性组*/
		sysfs_remove_groups(&parent->dev->kobj,
				    parent->ops->dev_attr_groups);
	else
		return ret;

create_err:
	kset_unregister(parent->mdev_types_kset);
	return ret;
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
static const struct attribute *mdev_device_attrs[] = {
	&dev_attr_remove.attr,
	NULL,
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

	ret = sysfs_create_files(kobj, mdev_device_attrs);
	if (ret)
		goto create_files_failed;

	return ret;

create_files_failed:
	sysfs_remove_link(kobj, "mdev_type");
type_link_failed:
	sysfs_remove_link(mdev->type->devices_kobj, dev_name(&mdev->dev));
	return ret;
}

void mdev_remove_sysfs_files(struct mdev_device *mdev)
{
	struct kobject *kobj = &mdev->dev.kobj;

    //移除'remove‘文件
	sysfs_remove_files(kobj, mdev_device_attrs);
	//移除'mdev_type'链接
	sysfs_remove_link(kobj, "mdev_type");
	//移除dev名称的链接
	sysfs_remove_link(mdev->type->devices_kobj, dev_name(&mdev->dev));
}
