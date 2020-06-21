// SPDX-License-Identifier: GPL-2.0
/*
 * fs/sysfs/file.c - sysfs regular (text) file implementation
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * Please see Documentation/filesystems/sysfs.rst for more information.
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>

#include "sysfs.h"

/*
 * Determine ktype->sysfs_ops for the given kernfs_node.  This function
 * must be called while holding an active reference.
 */
//针对kernfs_node来返回sysfs_ops
static const struct sysfs_ops *sysfs_file_ops(struct kernfs_node *kn)
{
	struct kobject *kobj = kn->parent->priv;

	if (kn->flags & KERNFS_LOCKDEP)
		lockdep_assert_held(kn);
	return kobj->ktype ? kobj->ktype->sysfs_ops : NULL;
}

/*
 * Reads on sysfs are handled through seq_file, which takes care of hairy
 * details like buffering and seeking.  The following function pipes
 * sysfs_ops->show() result through seq_file.
 */
static int sysfs_kf_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct kobject *kobj = of->kn->parent->priv;
	const struct sysfs_ops *ops = sysfs_file_ops(of->kn);
	ssize_t count;
	char *buf;

	/* acquire buffer and ensure that it's >= PAGE_SIZE and clear */
	count = seq_get_buf(sf, &buf);
	if (count < PAGE_SIZE) {
		//可以写的长度小于一个页大小，使m->count=m->size
		seq_commit(sf, -1);
		return 0;
	}

	//可用内存大于一个page_size，先将此页清0
	memset(buf, 0, PAGE_SIZE);

	/*
	 * Invoke show().  Control may reach here via seq file lseek even
	 * if @ops->show() isn't implemented.
	 */
	if (ops->show) {
		//调用sysfs_ops的show方法，将内容格式化到buf中
		count = ops->show(kobj, of->kn->priv, buf);
		if (count < 0)
			//写失败，返回错误信息
			return count;
	}

	/*
	 * The code works fine with PAGE_SIZE return but it's likely to
	 * indicate truncated result or overflow in normal use cases.
	 */
	//写的内容大于一个页
	if (count >= (ssize_t)PAGE_SIZE) {
		printk("fill_read_buffer: %pS returned bad count\n",
				ops->show);
		/* Try to struggle along */
		count = PAGE_SIZE - 1;
	}
	//增加sf->count+=count
	seq_commit(sf, count);
	return 0;
}

static ssize_t sysfs_kf_bin_read(struct kernfs_open_file *of, char *buf,
				 size_t count, loff_t pos)
{
	struct bin_attribute *battr = of->kn->priv;
	struct kobject *kobj = of->kn->parent->priv;
	loff_t size = file_inode(of->file)->i_size;

	if (!count)
		return 0;

	if (size) {
		if (pos >= size)
			return 0;
		if (pos + count > size)
			count = size - pos;
	}

	if (!battr->read)
		return -EIO;

	//通过二进制属性的read函数进行处理
	return battr->read(of->file, kobj, battr, buf, pos, count);
}

/* kernfs read callback for regular sysfs files with pre-alloc */
static ssize_t sysfs_kf_read(struct kernfs_open_file *of, char *buf,
			     size_t count, loff_t pos)
{
    //取文件对应的sysfs_ops
	const struct sysfs_ops *ops = sysfs_file_ops(of->kn);
	struct kobject *kobj = of->kn->parent->priv;
	ssize_t len;

	/*
	 * If buf != of->prealloc_buf, we don't know how
	 * large it is, so cannot safely pass it to ->show
	 */
	if (WARN_ON_ONCE(buf != of->prealloc_buf))
		return 0;
	//需要全部的数据（不支持offset的情况）
	len = ops->show(kobj, of->kn->priv, buf);
	if (len < 0)
		return len;
	if (pos) {
		if (len <= pos)
			return 0;
		len -= pos;
		//然后将pos位置向后的数据向前移
		memmove(buf, buf + pos, len);
	}
	return min_t(ssize_t, count, len);
}

/* kernfs write callback for regular sysfs files */
//调用store将buf中的内容设置到of对应的obj里
static ssize_t sysfs_kf_write(struct kernfs_open_file *of, char *buf,
			      size_t count, loff_t pos)
{
	const struct sysfs_ops *ops = sysfs_file_ops(of->kn);
	struct kobject *kobj = of->kn->parent->priv;

	if (!count)
		return 0;

	return ops->store(kobj, of->kn->priv, buf, count);
}

/* kernfs write callback for bin sysfs files */
static ssize_t sysfs_kf_bin_write(struct kernfs_open_file *of, char *buf,
				  size_t count, loff_t pos)
{
	struct bin_attribute *battr = of->kn->priv;
	struct kobject *kobj = of->kn->parent->priv;
	loff_t size = file_inode(of->file)->i_size;

	if (size) {
		if (size <= pos)
			return -EFBIG;
		count = min_t(ssize_t, count, size - pos);
	}
	if (!count)
		return 0;

	if (!battr->write)
		return -EIO;

	//二进制调用battr的write进行写
	return battr->write(of->file, kobj, battr, buf, pos, count);
}

static int sysfs_kf_bin_mmap(struct kernfs_open_file *of,
			     struct vm_area_struct *vma)
{
	struct bin_attribute *battr = of->kn->priv;
	struct kobject *kobj = of->kn->parent->priv;

	//二进制调用mmap来进行读写
	return battr->mmap(of->file, kobj, battr, vma);
}

//支持notify接口
void sysfs_notify(struct kobject *kobj, const char *dir, const char *attr)
{
	struct kernfs_node *kn = kobj->sd, *tmp;

	if (kn && dir)
		kn = kernfs_find_and_get(kn, dir);
	else
		kernfs_get(kn);

	if (kn && attr) {
		tmp = kernfs_find_and_get(kn, attr);
		kernfs_put(kn);
		kn = tmp;
	}

	if (kn) {
		kernfs_notify(kn);
		kernfs_put(kn);
	}
}
EXPORT_SYMBOL_GPL(sysfs_notify);

//不可读，不可写的操作集
static const struct kernfs_ops sysfs_file_kfops_empty = {
};

//文本只读操作集
static const struct kernfs_ops sysfs_file_kfops_ro = {
	.seq_show	= sysfs_kf_seq_show,
};

//文本只写操作集
static const struct kernfs_ops sysfs_file_kfops_wo = {
	.write		= sysfs_kf_write,
};

//文本读写操作集
static const struct kernfs_ops sysfs_file_kfops_rw = {
	.seq_show	= sysfs_kf_seq_show,
	.write		= sysfs_kf_write,
};

//预申请读操作集
static const struct kernfs_ops sysfs_prealloc_kfops_ro = {
	.read		= sysfs_kf_read,
	.prealloc	= true,
};

//预申请写操作集
static const struct kernfs_ops sysfs_prealloc_kfops_wo = {
	.write		= sysfs_kf_write,
	.prealloc	= true,
};

//预申请读写操作集
static const struct kernfs_ops sysfs_prealloc_kfops_rw = {
	.read		= sysfs_kf_read,
	.write		= sysfs_kf_write,
	.prealloc	= true,
};

//二进制读
static const struct kernfs_ops sysfs_bin_kfops_ro = {
	.read		= sysfs_kf_bin_read,
};

//二进制写
static const struct kernfs_ops sysfs_bin_kfops_wo = {
	.write		= sysfs_kf_bin_write,
};

//二进制读写
static const struct kernfs_ops sysfs_bin_kfops_rw = {
	.read		= sysfs_kf_bin_read,
	.write		= sysfs_kf_bin_write,
};

static const struct kernfs_ops sysfs_bin_kfops_mmap = {
	.read		= sysfs_kf_bin_read,
	.write		= sysfs_kf_bin_write,
	.mmap		= sysfs_kf_bin_mmap,
};

//向sysfs添加一个文件
int sysfs_add_file_mode_ns(struct kernfs_node *parent,
			   const struct attribute *attr/*要创建的文件的私有数据*/, bool is_bin/*是否为二进制文件*/,
			   umode_t mode/*文件的权限位*/, kuid_t uid/*用户id*/, kgid_t gid/*组id*/, const void *ns)
{
	struct lock_class_key *key = NULL;
	const struct kernfs_ops *ops;
	struct kernfs_node *kn;
	loff_t size;

	if (!is_bin) {
		struct kobject *kobj = parent->priv;
		const struct sysfs_ops *sysfs_ops = kobj->ktype->sysfs_ops;

		/* every kobject with an attribute needs a ktype assigned */
		if (WARN(!sysfs_ops, KERN_ERR
			 "missing sysfs attribute operations for kobject: %s\n",
			 kobject_name(kobj)))
			return -EINVAL;

		if (sysfs_ops->show && sysfs_ops->store) {
            //可读可写
			if (mode & SYSFS_PREALLOC)
				ops = &sysfs_prealloc_kfops_rw;
			else
				ops = &sysfs_file_kfops_rw;
		} else if (sysfs_ops->show) {
            //可读
			if (mode & SYSFS_PREALLOC)
				ops = &sysfs_prealloc_kfops_ro;
			else
				ops = &sysfs_file_kfops_ro;
		} else if (sysfs_ops->store) {
            //仅可写
			if (mode & SYSFS_PREALLOC)
				ops = &sysfs_prealloc_kfops_wo;
			else
				ops = &sysfs_file_kfops_wo;
		} else
            //不可读，不可写
			ops = &sysfs_file_kfops_empty;

		size = PAGE_SIZE;/*文本类型占一个页*/
	} else {
        //二进制属性,考虑读写权限
		struct bin_attribute *battr = (void *)attr;

		if (battr->mmap)
			//支持map操作
			ops = &sysfs_bin_kfops_mmap;
		else if (battr->read && battr->write)
			//支持读写操作
			ops = &sysfs_bin_kfops_rw;
		else if (battr->read)
			//支持只读
			ops = &sysfs_bin_kfops_ro;
		else if (battr->write)
			//支持只写
			ops = &sysfs_bin_kfops_wo;
		else
			ops = &sysfs_file_kfops_empty;

		size = battr->size;/*二进制类型占为属性大小*/
	}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	if (!attr->ignore_lockdep)
		key = attr->key ?: (struct lock_class_key *)&attr->skey;
#endif
	//调用文件创建,使mode仅9个bit生效
	//使用“操作集","属性“
	kn = __kernfs_create_file(parent, attr->name, mode & 0777, uid, gid,
				  size/*文件大小*/, ops/*文件操作集*/, (void *)attr/*文件私有数据*/, ns, key);
	if (IS_ERR(kn)) {
		if (PTR_ERR(kn) == -EEXIST)
			sysfs_warn_dup(parent, attr->name);
		return PTR_ERR(kn);
	}
	return 0;
}

/**
 * sysfs_create_file_ns - create an attribute file for an object with custom ns
 * @kobj: object we're creating for
 * @attr: attribute descriptor
 * @ns: namespace the new file should belong to
 */
int sysfs_create_file_ns(struct kobject *kobj, const struct attribute *attr,
			 const void *ns)
{
	kuid_t uid;
	kgid_t gid;

	if (WARN_ON(!kobj || !kobj->sd || !attr))
		return -EINVAL;

	//创建文件（非二进制文件）
	kobject_get_ownership(kobj, &uid, &gid);
	return sysfs_add_file_mode_ns(kobj->sd, attr, false, attr->mode,
				      uid, gid, ns);
}
EXPORT_SYMBOL_GPL(sysfs_create_file_ns);

//创建多个文件
int sysfs_create_files(struct kobject *kobj, const struct attribute * const *ptr)
{
	int err = 0;
	int i;

	for (i = 0; ptr[i] && !err; i++)
		err = sysfs_create_file(kobj, ptr[i]);
	if (err)
		//如果创建有失败，则删除掉已创建成功的文件
		while (--i >= 0)
			sysfs_remove_file(kobj, ptr[i]);
	return err;
}
EXPORT_SYMBOL_GPL(sysfs_create_files);

/**
 * sysfs_add_file_to_group - add an attribute file to a pre-existing group.
 * @kobj: object we're acting for.
 * @attr: attribute descriptor.
 * @group: group name.
 */
int sysfs_add_file_to_group(struct kobject *kobj,
		const struct attribute *attr, const char *group)
{
	struct kernfs_node *parent;
	kuid_t uid;
	kgid_t gid;
	int error;

	if (group) {
		//在kobj下查找名称为group的目录
		parent = kernfs_find_and_get(kobj->sd, group);
	} else {
		//未提定group，则直接使用kobj
		parent = kobj->sd;
		kernfs_get(parent);
	}

	if (!parent)
		return -ENOENT;

	kobject_get_ownership(kobj, &uid, &gid);
	//将文件存入parent中（非2进制文件）
	error = sysfs_add_file_mode_ns(parent, attr, false,
				       attr->mode, uid, gid, NULL);
	kernfs_put(parent);

	return error;
}
EXPORT_SYMBOL_GPL(sysfs_add_file_to_group);

/**
 * sysfs_chmod_file - update the modified mode value on an object attribute.
 * @kobj: object we're acting for.
 * @attr: attribute descriptor.
 * @mode: file permissions.
 *
 */
int sysfs_chmod_file(struct kobject *kobj, const struct attribute *attr,
		     umode_t mode)
{
	//文件权限变更
	struct kernfs_node *kn;
	struct iattr newattrs;
	int rc;

	kn = kernfs_find_and_get(kobj->sd, attr->name);
	if (!kn)
		return -ENOENT;

	//构造新属性
	newattrs.ia_mode = (mode & S_IALLUGO) | (kn->mode & ~S_IALLUGO);//只容许修改权限位＋sticky+有效用户＋有效位位
	newattrs.ia_valid = ATTR_MODE;

	//使新的属性生效
	rc = kernfs_setattr(kn, &newattrs);

	kernfs_put(kn);
	return rc;
}
EXPORT_SYMBOL_GPL(sysfs_chmod_file);

/**
 * sysfs_break_active_protection - break "active" protection
 * @kobj: The kernel object @attr is associated with.
 * @attr: The attribute to break the "active" protection for.
 *
 * With sysfs, just like kernfs, deletion of an attribute is postponed until
 * all active .show() and .store() callbacks have finished unless this function
 * is called. Hence this function is useful in methods that implement self
 * deletion.
 */
struct kernfs_node *sysfs_break_active_protection(struct kobject *kobj,
						  const struct attribute *attr)
{
	struct kernfs_node *kn;

	kobject_get(kobj);
	kn = kernfs_find_and_get(kobj->sd, attr->name);
	if (kn)
		kernfs_break_active_protection(kn);
	return kn;
}
EXPORT_SYMBOL_GPL(sysfs_break_active_protection);

/**
 * sysfs_unbreak_active_protection - restore "active" protection
 * @kn: Pointer returned by sysfs_break_active_protection().
 *
 * Undo the effects of sysfs_break_active_protection(). Since this function
 * calls kernfs_put() on the kernfs node that corresponds to the 'attr'
 * argument passed to sysfs_break_active_protection() that attribute may have
 * been removed between the sysfs_break_active_protection() and
 * sysfs_unbreak_active_protection() calls, it is not safe to access @kn after
 * this function has returned.
 */
void sysfs_unbreak_active_protection(struct kernfs_node *kn)
{
	struct kobject *kobj = kn->parent->priv;

	kernfs_unbreak_active_protection(kn);
	kernfs_put(kn);
	kobject_put(kobj);
}
EXPORT_SYMBOL_GPL(sysfs_unbreak_active_protection);

/**
 * sysfs_remove_file_ns - remove an object attribute with a custom ns tag
 * @kobj: object we're acting for
 * @attr: attribute descriptor
 * @ns: namespace tag of the file to remove
 *
 * Hash the attribute name and namespace tag and kill the victim.
 */
void sysfs_remove_file_ns(struct kobject *kobj, const struct attribute *attr,
			  const void *ns)
{
	struct kernfs_node *parent = kobj->sd;

	kernfs_remove_by_name_ns(parent, attr->name, ns);
}
EXPORT_SYMBOL_GPL(sysfs_remove_file_ns);

/**
 * sysfs_remove_file_self - remove an object attribute from its own method
 * @kobj: object we're acting for
 * @attr: attribute descriptor
 *
 * See kernfs_remove_self() for details.
 */
bool sysfs_remove_file_self(struct kobject *kobj, const struct attribute *attr)
{
	struct kernfs_node *parent = kobj->sd;
	struct kernfs_node *kn;
	bool ret;

	kn = kernfs_find_and_get(parent, attr->name);
	if (WARN_ON_ONCE(!kn))
		return false;

	ret = kernfs_remove_self(kn);

	kernfs_put(kn);
	return ret;
}
EXPORT_SYMBOL_GPL(sysfs_remove_file_self);

//一次移除多个文件
void sysfs_remove_files(struct kobject *kobj, const struct attribute * const *ptr)
{
	int i;

	for (i = 0; ptr[i]; i++)
		sysfs_remove_file(kobj, ptr[i]);
}
EXPORT_SYMBOL_GPL(sysfs_remove_files);

/**
 * sysfs_remove_file_from_group - remove an attribute file from a group.
 * @kobj: object we're acting for.
 * @attr: attribute descriptor.
 * @group: group name.
 */
void sysfs_remove_file_from_group(struct kobject *kobj,
		const struct attribute *attr, const char *group)
{
	struct kernfs_node *parent;

	if (group) {
		//如果指定了group，则在kobj下查找对应的目录
		parent = kernfs_find_and_get(kobj->sd, group);
	} else {
		parent = kobj->sd;
		kernfs_get(parent);
	}

	if (parent) {
		//将指定名称自parent中移除
		kernfs_remove_by_name(parent, attr->name);
		kernfs_put(parent);
	}
}
EXPORT_SYMBOL_GPL(sysfs_remove_file_from_group);

/**
 *	sysfs_create_bin_file - create binary file for object.
 *	@kobj:	object.
 *	@attr:	attribute descriptor.
 */
int sysfs_create_bin_file(struct kobject *kobj,
			  const struct bin_attribute *attr)
{
	kuid_t uid;
	kgid_t gid;

	if (WARN_ON(!kobj || !kobj->sd || !attr))
		return -EINVAL;

	kobject_get_ownership(kobj, &uid, &gid);
	//添加二进制文件到kobj->sd
	return sysfs_add_file_mode_ns(kobj->sd, &attr->attr, true,
				      attr->attr.mode, uid, gid, NULL);
}
EXPORT_SYMBOL_GPL(sysfs_create_bin_file);

/**
 *	sysfs_remove_bin_file - remove binary file for object.
 *	@kobj:	object.
 *	@attr:	attribute descriptor.
 */
void sysfs_remove_bin_file(struct kobject *kobj,
			   const struct bin_attribute *attr)
{
	//移除二进制文件
	kernfs_remove_by_name(kobj->sd, attr->attr.name);
}
EXPORT_SYMBOL_GPL(sysfs_remove_bin_file);

static int internal_change_owner(struct kernfs_node *kn, kuid_t kuid,
				 kgid_t kgid)
{
	struct iattr newattrs = {
		.ia_valid = ATTR_UID | ATTR_GID,
		.ia_uid = kuid,
		.ia_gid = kgid,
	};
	return kernfs_setattr(kn, &newattrs);
}

/**
 *	sysfs_link_change_owner - change owner of a sysfs file.
 *	@kobj:	object of the kernfs_node the symlink is located in.
 *	@targ:	object of the kernfs_node the symlink points to.
 *	@name:	name of the link.
 *	@kuid:	new owner's kuid
 *	@kgid:	new owner's kgid
 *
 * This function looks up the sysfs symlink entry @name under @kobj and changes
 * the ownership to @kuid/@kgid. The symlink is looked up in the namespace of
 * @targ.
 *
 * Returns 0 on success or error code on failure.
 */
int sysfs_link_change_owner(struct kobject *kobj, struct kobject *targ,
			    const char *name, kuid_t kuid, kgid_t kgid)
{
	struct kernfs_node *kn = NULL;
	int error;

	if (!name || !kobj->state_in_sysfs || !targ->state_in_sysfs)
		return -EINVAL;

	error = -ENOENT;
	kn = kernfs_find_and_get_ns(kobj->sd, name, targ->sd->ns);
	if (!kn)
		goto out;

	error = -EINVAL;
	if (kernfs_type(kn) != KERNFS_LINK)
		goto out;
	if (kn->symlink.target_kn->priv != targ)
		goto out;

	error = internal_change_owner(kn, kuid, kgid);

out:
	kernfs_put(kn);
	return error;
}

/**
 *	sysfs_file_change_owner - change owner of a sysfs file.
 *	@kobj:	object.
 *	@name:	name of the file to change.
 *	@kuid:	new owner's kuid
 *	@kgid:	new owner's kgid
 *
 * This function looks up the sysfs entry @name under @kobj and changes the
 * ownership to @kuid/@kgid.
 *
 * Returns 0 on success or error code on failure.
 */
int sysfs_file_change_owner(struct kobject *kobj, const char *name, kuid_t kuid,
			    kgid_t kgid)
{
	struct kernfs_node *kn;
	int error;

	if (!name)
		return -EINVAL;

	if (!kobj->state_in_sysfs)
		return -EINVAL;

	kn = kernfs_find_and_get(kobj->sd, name);
	if (!kn)
		return -ENOENT;

	error = internal_change_owner(kn, kuid, kgid);

	kernfs_put(kn);

	return error;
}
EXPORT_SYMBOL_GPL(sysfs_file_change_owner);

/**
 *	sysfs_change_owner - change owner of the given object.
 *	@kobj:	object.
 *	@kuid:	new owner's kuid
 *	@kgid:	new owner's kgid
 *
 * Change the owner of the default directory, files, groups, and attributes of
 * @kobj to @kuid/@kgid. Note that sysfs_change_owner mirrors how the sysfs
 * entries for a kobject are added by driver core. In summary,
 * sysfs_change_owner() takes care of the default directory entry for @kobj,
 * the default attributes associated with the ktype of @kobj and the default
 * attributes associated with the ktype of @kobj.
 * Additional properties not added by driver core have to be changed by the
 * driver or subsystem which created them. This is similar to how
 * driver/subsystem specific entries are removed.
 *
 * Returns 0 on success or error code on failure.
 */
int sysfs_change_owner(struct kobject *kobj, kuid_t kuid, kgid_t kgid)
{
	int error;
	const struct kobj_type *ktype;

	if (!kobj->state_in_sysfs)
		return -EINVAL;

	/* Change the owner of the kobject itself. */
	error = internal_change_owner(kobj->sd, kuid, kgid);
	if (error)
		return error;

	ktype = get_ktype(kobj);
	if (ktype) {
		struct attribute **kattr;

		/*
		 * Change owner of the default attributes associated with the
		 * ktype of @kobj.
		 */
		for (kattr = ktype->default_attrs; kattr && *kattr; kattr++) {
			error = sysfs_file_change_owner(kobj, (*kattr)->name,
							kuid, kgid);
			if (error)
				return error;
		}

		/*
		 * Change owner of the default groups associated with the
		 * ktype of @kobj.
		 */
		error = sysfs_groups_change_owner(kobj, ktype->default_groups,
						  kuid, kgid);
		if (error)
			return error;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(sysfs_change_owner);
