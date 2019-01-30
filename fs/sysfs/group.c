// SPDX-License-Identifier: GPL-2.0
/*
 * fs/sysfs/group.c - Operations for adding/removing multiple files at once.
 *
 * Copyright (c) 2003 Patrick Mochel
 * Copyright (c) 2003 Open Source Development Lab
 * Copyright (c) 2013 Greg Kroah-Hartman
 * Copyright (c) 2013 The Linux Foundation
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/err.h>
#include "sysfs.h"

//移除一组文件
static void remove_files(struct kernfs_node *parent,
			 const struct attribute_group *grp)
{
	struct attribute *const *attr;
	struct bin_attribute *const *bin_attr;

	if (grp->attrs)
		for (attr = grp->attrs; *attr; attr++)
			kernfs_remove_by_name(parent, (*attr)->name);
	if (grp->bin_attrs)
		for (bin_attr = grp->bin_attrs; *bin_attr; bin_attr++)
			kernfs_remove_by_name(parent, (*bin_attr)->attr.name);
}

//分类型，创建一组文本文件和一组二进制文件
static int create_files(struct kernfs_node *parent, struct kobject *kobj,
			kuid_t uid, kgid_t gid,
			const struct attribute_group *grp, int update/*如果此值为真，则先删除后添加*/)
{
	struct attribute *const *attr;
	struct bin_attribute *const *bin_attr;
	int error = 0, i;

	if (grp->attrs) {
		/*遍历group中所有属性，针对每一个属性，创建其对应的文件，并将其置于parent下*/
		for (i = 0, attr = grp->attrs; *attr && !error; i++, attr++) {
			umode_t mode = (*attr)->mode;

			/*
			 * In update mode, we're changing the permissions or
			 * visibility.  Do this by first removing then
			 * re-adding (if required) the file.
			 */
			if (update)
				//如果此值为真，则先删除后添加
				kernfs_remove_by_name(parent, (*attr)->name);
			if (grp->is_visible) {
				//如果有visible回调，则调用is_visible,决定是否创建
				mode = grp->is_visible(kobj, *attr, i);
				if (!mode)
					continue;
			}

			WARN(mode & ~(SYSFS_PREALLOC | 0664),
			     "Attribute %s: Invalid permissions 0%o\n",
			     (*attr)->name, mode);

			//规则化mode,并创建相就能文件
			mode &= SYSFS_PREALLOC | 0664;
			error = sysfs_add_file_mode_ns(parent, *attr, false,
						       mode, uid, gid, NULL);
			if (unlikely(error))
				break;
		}
		//如果出错，则移除掉所有已创建的文件
		if (error) {
			remove_files(parent, grp);
			goto exit;
		}
	}

	//二进制属性处理
	if (grp->bin_attrs) {
		for (i = 0, bin_attr = grp->bin_attrs; *bin_attr; i++, bin_attr++) {
			umode_t mode = (*bin_attr)->attr.mode;

			if (update)
				kernfs_remove_by_name(parent,
						(*bin_attr)->attr.name);
			if (grp->is_bin_visible) {
				mode = grp->is_bin_visible(kobj, *bin_attr, i);
				if (!mode)
					continue;
			}

			WARN(mode & ~(SYSFS_PREALLOC | 0664),
			     "Attribute %s: Invalid permissions 0%o\n",
			     (*bin_attr)->attr.name, mode);

			mode &= SYSFS_PREALLOC | 0664;
			error = sysfs_add_file_mode_ns(parent,
					&(*bin_attr)->attr, true,
					mode,
					uid, gid, NULL);
			if (error)
				break;
		}
		if (error)
			remove_files(parent, grp);
	}
exit:
	return error;
}

//按组创建group目录及文件（ns=NULL)
static int internal_create_group(struct kobject *kobj, int update,
				 const struct attribute_group *grp)
{
	struct kernfs_node *kn;
	kuid_t uid;
	kgid_t gid;
	int error;

	if (WARN_ON(!kobj || (!update && !kobj->sd)))
		return -EINVAL;

	/* Updates may happen before the object has been instantiated */
	//参数合法性检查
	if (unlikely(update && !kobj->sd))
		return -EINVAL;
	if (!grp->attrs && !grp->bin_attrs) {
		WARN(1, "sysfs: (bin_)attrs not set by subsystem for group: %s/%s\n",
			kobj->name, grp->name ?: "");
		return -EINVAL;
	}
	kobject_get_ownership(kobj, &uid, &gid);
	if (grp->name) {
		if (update) {
			/*如果update为真，则先查找此group是否已创建kernfs node,如果没有创建，则报错*/
			kn = kernfs_find_and_get(kobj->sd, grp->name);
			if (!kn) {
				pr_warn("Can't update unknown attr grp name: %s/%s\n",
					kobj->name, grp->name);
				return -EINVAL;
			}
		} else {
			/*如果非update,则直接创建相应的group->name目录名*/
			kn = kernfs_create_dir_ns(kobj->sd, grp->name,
						  S_IRWXU | S_IRUGO | S_IXUGO,
						  uid, gid, kobj/*kobj为目录的私有数据*/, NULL);
			if (IS_ERR(kn)) {
				if (PTR_ERR(kn) == -EEXIST)
					sysfs_warn_dup(kobj->sd, grp->name);
				return PTR_ERR(kn);
			}
		}
	} else
		kn = kobj->sd;//如果未指定名称，则取kobj中对应的kernfs节点
	kernfs_get(kn);
	//创建group下所有文件
	error = create_files(kn, kobj, uid, gid, grp, update);
	if (error) {
		if (grp->name)
			kernfs_remove(kn);
	}
	kernfs_put(kn);

	if (grp->name && update)
		kernfs_put(kn);

	return error;
}

/**
 * sysfs_create_group - given a directory kobject, create an attribute group
 * @kobj:	The kobject to create the group on
 * @grp:	The attribute group to create
 *
 * This function creates a group for the first time.  It will explicitly
 * warn and error if any of the attribute files being created already exist.
 *
 * Returns 0 on success or error code on failure.
 */
//创建grp->name对应的目录，并创建其attr对应的所有文件
int sysfs_create_group(struct kobject *kobj,
		       const struct attribute_group *grp)
{
	//创建group(不更新）
	return internal_create_group(kobj, 0, grp);
}
EXPORT_SYMBOL_GPL(sysfs_create_group);

/**
 * sysfs_create_groups - given a directory kobject, create a bunch of attribute groups
 * @kobj:	The kobject to create the group on
 * @groups:	The attribute groups to create, NULL terminated
 *
 * This function creates a bunch of attribute groups.  If an error occurs when
 * creating a group, all previously created groups will be removed, unwinding
 * everything back to the original state when this function was called.
 * It will explicitly warn and error if any of the attribute files being
 * created already exist.
 *
 * Returns 0 on success or error code from sysfs_create_group on failure.
 */
//调用sysfs_create_group创建多个属性组（如果创建失败，则均会删除）
int sysfs_create_groups(struct kobject *kobj,
			const struct attribute_group **groups)
{
	int error = 0;
	int i;

	if (!groups)
		return 0;

	for (i = 0; groups[i]; i++) {
		error = sysfs_create_group(kobj, groups[i]);
		if (error) {
			while (--i >= 0)
				sysfs_remove_group(kobj, groups[i]);
			break;
		}
	}
	return error;
}
EXPORT_SYMBOL_GPL(sysfs_create_groups);

/**
 * sysfs_update_group - given a directory kobject, update an attribute group
 * @kobj:	The kobject to update the group on
 * @grp:	The attribute group to update
 *
 * This function updates an attribute group.  Unlike
 * sysfs_create_group(), it will explicitly not warn or error if any
 * of the attribute files being created already exist.  Furthermore,
 * if the visibility of the files has changed through the is_visible()
 * callback, it will update the permissions and add or remove the
 * relevant files. Changing a group's name (subdirectory name under
 * kobj's directory in sysfs) is not allowed.
 *
 * The primary use for this function is to call it after making a change
 * that affects group visibility.
 *
 * Returns 0 on success or error code on failure.
 */
int sysfs_update_group(struct kobject *kobj,
		       const struct attribute_group *grp)
{
	/*更新group,要求grp对应的目录已存在*/
	return internal_create_group(kobj, 1, grp);
}
EXPORT_SYMBOL_GPL(sysfs_update_group);

/**
 * sysfs_remove_group: remove a group from a kobject
 * @kobj:	kobject to remove the group from
 * @grp:	group to remove
 *
 * This function removes a group of attributes from a kobject.  The attributes
 * previously have to have been created for this group, otherwise it will fail.
 */
//删除grop对应的所有属性组
void sysfs_remove_group(struct kobject *kobj,
			const struct attribute_group *grp)
{
	struct kernfs_node *parent = kobj->sd;
	struct kernfs_node *kn;

	if (grp->name) {
		kn = kernfs_find_and_get(parent, grp->name);
		if (!kn) {
			WARN(!kn, KERN_WARNING
			     "sysfs group '%s' not found for kobject '%s'\n",
			     grp->name, kobject_name(kobj));
			return;
		}
	} else {
		kn = parent;
		kernfs_get(kn);
	}

	remove_files(kn, grp);
	if (grp->name)
		kernfs_remove(kn);

	kernfs_put(kn);
}
EXPORT_SYMBOL_GPL(sysfs_remove_group);

/**
 * sysfs_remove_groups - remove a list of groups
 *
 * @kobj:	The kobject for the groups to be removed from
 * @groups:	NULL terminated list of groups to be removed
 *
 * If groups is not NULL, remove the specified groups from the kobject.
 */
//一次性删除多个属性组
void sysfs_remove_groups(struct kobject *kobj,
			 const struct attribute_group **groups)
{
	int i;

	if (!groups)
		return;
	for (i = 0; groups[i]; i++)
		sysfs_remove_group(kobj, groups[i]);
}
EXPORT_SYMBOL_GPL(sysfs_remove_groups);

/**
 * sysfs_merge_group - merge files into a pre-existing attribute group.
 * @kobj:	The kobject containing the group.
 * @grp:	The files to create and the attribute group they belong to.
 *
 * This function returns an error if the group doesn't exist or any of the
 * files already exist in that group, in which case none of the new files
 * are created.
 */
//尝试着向kobj->sd中添加文件，如果添加失败，则全部移除
int sysfs_merge_group(struct kobject *kobj,
		       const struct attribute_group *grp)
{
	struct kernfs_node *parent;
	kuid_t uid;
	kgid_t gid;
	int error = 0;
	struct attribute *const *attr;
	int i;

	parent = kernfs_find_and_get(kobj->sd, grp->name);
	if (!parent)
		return -ENOENT;

	kobject_get_ownership(kobj, &uid, &gid);

	for ((i = 0, attr = grp->attrs); *attr && !error; (++i, ++attr))
		//在添加时，如果已存在，会返回失败，并继而导致将之前添加的删除
		error = sysfs_add_file_mode_ns(parent, *attr, false,
					       (*attr)->mode, uid, gid, NULL);
	if (error) {
		while (--i >= 0)
			kernfs_remove_by_name(parent, (*--attr)->name);
	}
	kernfs_put(parent);

	return error;
}
EXPORT_SYMBOL_GPL(sysfs_merge_group);

/**
 * sysfs_unmerge_group - remove files from a pre-existing attribute group.
 * @kobj:	The kobject containing the group.
 * @grp:	The files to remove and the attribute group they belong to.
 */
//删除kobj->sd中由grp指定的文件
void sysfs_unmerge_group(struct kobject *kobj,
		       const struct attribute_group *grp)
{
	struct kernfs_node *parent;
	struct attribute *const *attr;

	parent = kernfs_find_and_get(kobj->sd, grp->name);
	if (parent) {
		for (attr = grp->attrs; *attr; ++attr)
			kernfs_remove_by_name(parent, (*attr)->name);
		kernfs_put(parent);
	}
}
EXPORT_SYMBOL_GPL(sysfs_unmerge_group);

/**
 * sysfs_add_link_to_group - add a symlink to an attribute group.
 * @kobj:	The kobject containing the group.
 * @group_name:	The name of the group.
 * @target:	The target kobject of the symlink to create.
 * @link_name:	The name of the symlink to create.
 */
int sysfs_add_link_to_group(struct kobject *kobj, const char *group_name,
			    struct kobject *target, const char *link_name)
{
	struct kernfs_node *parent;
	int error = 0;

	parent = kernfs_find_and_get(kobj->sd, group_name);
	if (!parent)
		return -ENOENT;

	error = sysfs_create_link_sd(parent, target, link_name);
	kernfs_put(parent);

	return error;
}
EXPORT_SYMBOL_GPL(sysfs_add_link_to_group);

/**
 * sysfs_remove_link_from_group - remove a symlink from an attribute group.
 * @kobj:	The kobject containing the group.
 * @group_name:	The name of the group.
 * @link_name:	The name of the symlink to remove.
 */
void sysfs_remove_link_from_group(struct kobject *kobj, const char *group_name,
				  const char *link_name)
{
	struct kernfs_node *parent;

	parent = kernfs_find_and_get(kobj->sd, group_name);
	if (parent) {
		kernfs_remove_by_name(parent, link_name);
		kernfs_put(parent);
	}
}
EXPORT_SYMBOL_GPL(sysfs_remove_link_from_group);

/**
 * __compat_only_sysfs_link_entry_to_kobj - add a symlink to a kobject pointing
 * to a group or an attribute
 * @kobj:		The kobject containing the group.
 * @target_kobj:	The target kobject.
 * @target_name:	The name of the target group or attribute.
 */
int __compat_only_sysfs_link_entry_to_kobj(struct kobject *kobj,
				      struct kobject *target_kobj,
				      const char *target_name)
{
	struct kernfs_node *target;
	struct kernfs_node *entry;
	struct kernfs_node *link;

	/*
	 * We don't own @target_kobj and it may be removed at any time.
	 * Synchronize using sysfs_symlink_target_lock. See sysfs_remove_dir()
	 * for details.
	 */
	spin_lock(&sysfs_symlink_target_lock);
	target = target_kobj->sd;
	if (target)
		kernfs_get(target);
	spin_unlock(&sysfs_symlink_target_lock);
	if (!target)
		return -ENOENT;

	entry = kernfs_find_and_get(target_kobj->sd, target_name);
	if (!entry) {
		kernfs_put(target);
		return -ENOENT;
	}

	link = kernfs_create_link(kobj->sd, target_name, entry);
	if (IS_ERR(link) && PTR_ERR(link) == -EEXIST)
		sysfs_warn_dup(kobj->sd, target_name);

	kernfs_put(entry);
	kernfs_put(target);
	return PTR_ERR_OR_ZERO(link);
}
EXPORT_SYMBOL_GPL(__compat_only_sysfs_link_entry_to_kobj);
