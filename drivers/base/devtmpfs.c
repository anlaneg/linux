// SPDX-License-Identifier: GPL-2.0
/*
 * devtmpfs - kernel-maintained tmpfs-based /dev
 *
 * Copyright (C) 2009, Kay Sievers <kay.sievers@vrfy.org>
 *
 * During bootup, before any driver core device is registered,
 * devtmpfs, a tmpfs-based filesystem is created. Every driver-core
 * device which requests a device node, will add a node in this
 * filesystem.
 * By default, all devices are named after the name of the device,
 * owned by root and have a default mode of 0600. Subsystems can
 * overwrite the default setting if needed.
 */

#define pr_fmt(fmt) "devtmpfs: " fmt

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>
#include <linux/ramfs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/init_syscalls.h>
#include <uapi/linux/mount.h>
#include "base.h"

#ifdef CONFIG_DEVTMPFS_SAFE
#define DEVTMPFS_MFLAGS       (MS_SILENT | MS_NOEXEC | MS_NOSUID)
#else
#define DEVTMPFS_MFLAGS       (MS_SILENT)
#endif

static struct task_struct *thread;

static int __initdata mount_dev = IS_ENABLED(CONFIG_DEVTMPFS_MOUNT);

static DEFINE_SPINLOCK(req_lock);

static struct req {
	struct req *next;
	struct completion done;
	int err;
	const char *name;
	umode_t mode;	/* 0 => delete */
	kuid_t uid;
	kgid_t gid;
	struct device *dev;
} *requests;

static int __init mount_param(char *str)
{
	mount_dev = simple_strtoul(str, NULL, 0);
	return 1;
}
__setup("devtmpfs.mount=", mount_param);

static struct vfsmount *mnt;

//devtmpfs文件系统mount回调
static struct dentry *public_dev_mount(struct file_system_type *fs_type, int flags,
		      const char *dev_name, void *data)
{
	/*取devtmpfs文件系统对应的super block*/
	struct super_block *s = mnt->mnt_sb;
	int err;

	atomic_inc(&s->s_active);
	down_write(&s->s_umount);
	err = reconfigure_single(s, flags, data);
	if (err < 0) {
		deactivate_locked_super(s);
		return ERR_PTR(err);
	}
	return dget(s->s_root);/*返回root dentry*/
}

static struct file_system_type internal_fs_type = {
	.name = "devtmpfs",
#ifdef CONFIG_TMPFS
	.init_fs_context = shmem_init_fs_context,
#else
	.init_fs_context = ramfs_init_fs_context,
#endif
	.kill_sb = kill_litter_super,
};

//定义devtmpfs文件系统
static struct file_system_type dev_fs_type = {
	.name = "devtmpfs",
	.mount = public_dev_mount,/*注：针对devtmpfs挂载时，并不重新创建挂载点*/
};

/*向requests上添加req,并唤醒kernel thread，执行请求*/
static int devtmpfs_submit_req(struct req *req, const char *tmp)
{
	init_completion(&req->done);

	spin_lock(&req_lock);
	req->next = requests;
	requests = req;/*将req串至requests链表上*/
	spin_unlock(&req_lock);

	wake_up_process(thread);
	wait_for_completion(&req->done);/*等待请求完成*/

	kfree(tmp);

	return req->err;
}

/*创建dev对应的文件*/
int devtmpfs_create_node(struct device *dev)
{
	const char *tmp = NULL;
	struct req req;

	if (!thread)
		return 0;

	req.mode = 0;/*初始化mode为0*/
	req.uid = GLOBAL_ROOT_UID;
	req.gid = GLOBAL_ROOT_GID;
	//获取要创建的dev名称，mode,uid,gid等
	req.name = device_get_devnode(dev, &req.mode, &req.uid, &req.gid, &tmp);
	if (!req.name)
		/*对于为空的，取消对设备的创建*/
		return -ENOMEM;

	if (req.mode == 0)
		req.mode = 0600;/*使用默认mode*/
	if (is_blockdev(dev))
		req.mode |= S_IFBLK;/*指明node为块设备*/
	else
		req.mode |= S_IFCHR;/*如未明确指出为块设备,则指明node为字符设备*/

	req.dev = dev;

	//向thread提交，并等待thread完成创建工作
	return devtmpfs_submit_req(&req, tmp);
}

/*删除dev对应的文件*/
int devtmpfs_delete_node(struct device *dev)
{
	const char *tmp = NULL;
	struct req req;

	if (!thread)
		return 0;

	req.name = device_get_devnode(dev, NULL, NULL, NULL, &tmp);
	if (!req.name)
		return -ENOMEM;

	req.mode = 0;/*标明为删除工作*/
	req.dev = dev;

	//向thread提交，并等待thread完成删除工作
	return devtmpfs_submit_req(&req, tmp);
}

static int dev_mkdir(const char *name, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	err = vfs_mkdir(&nop_mnt_idmap, d_inode(path.dentry), dentry, mode);
	if (!err)
		/* mark as kernel-created inode */
		d_inode(dentry)->i_private = &thread;
	done_path_create(&path, dentry);
	return err;
}

static int create_path(const char *nodepath)
{
	char *path;
	char *s;
	int err = 0;

	/* parent directories do not exist, create them */
	path = kstrdup(nodepath, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	s = path;
	for (;;) {
		s = strchr(s, '/');
		if (!s)
			break;
		s[0] = '\0';
		err = dev_mkdir(path, 0755);
		if (err && err != -EEXIST)
			break;
		s[0] = '/';
		s++;
	}
	kfree(path);
	return err;
}

static int handle_create(const char *nodename, umode_t mode, kuid_t uid,
			 kgid_t gid, struct device *dev)
{
	struct dentry *dentry;
	struct path path;
	int err;

	/*当前目录创建dentry*/
	dentry = kern_path_create(AT_FDCWD, nodename, &path, 0);
	if (dentry == ERR_PTR(-ENOENT)) {
		/*此dentry不存在，创建它*/
		create_path(nodename);
		dentry = kern_path_create(AT_FDCWD, nodename, &path, 0);
	}
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	/*dentry创建成功，调用vfs_mknode创建此文件*/
	err = vfs_mknod(&nop_mnt_idmap, d_inode(path.dentry), dentry, mode,
			dev->devt);
	if (!err) {
		struct iattr newattrs;

		newattrs.ia_mode = mode;
		newattrs.ia_uid = uid;
		newattrs.ia_gid = gid;
		newattrs.ia_valid = ATTR_MODE|ATTR_UID|ATTR_GID;
		inode_lock(d_inode(dentry));
		notify_change(&nop_mnt_idmap, dentry, &newattrs, NULL);
		inode_unlock(d_inode(dentry));

		/* mark as kernel-created inode */
		d_inode(dentry)->i_private = &thread;
	}
	done_path_create(&path, dentry);
	return err;
}

static int dev_rmdir(const char *name)
{
	struct path parent;
	struct dentry *dentry;
	int err;

	dentry = kern_path_locked(name, &parent);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	if (d_really_is_positive(dentry)) {
		if (d_inode(dentry)->i_private == &thread)
			err = vfs_rmdir(&nop_mnt_idmap, d_inode(parent.dentry),
					dentry);
		else
			err = -EPERM;
	} else {
		err = -ENOENT;
	}
	dput(dentry);
	inode_unlock(d_inode(parent.dentry));
	path_put(&parent);
	return err;
}

static int delete_path(const char *nodepath)
{
	char *path;
	int err = 0;

	path = kstrdup(nodepath, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	for (;;) {
		char *base;

		base = strrchr(path, '/');
		if (!base)
			break;
		base[0] = '\0';
		err = dev_rmdir(path);
		if (err)
			break;
	}

	kfree(path);
	return err;
}

static int dev_mynode(struct device *dev, struct inode *inode, struct kstat *stat)
{
	/* did we create it */
	if (inode->i_private != &thread)
		return 0;

	/* does the dev_t match */
	if (is_blockdev(dev)) {
		if (!S_ISBLK(stat->mode))
			return 0;
	} else {
		if (!S_ISCHR(stat->mode))
			return 0;
	}
	if (stat->rdev != dev->devt)
		return 0;

	/* ours */
	return 1;
}

static int handle_remove(const char *nodename, struct device *dev)
{
	struct path parent;
	struct dentry *dentry;
	int deleted = 0;
	int err;

	dentry = kern_path_locked(nodename, &parent);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (d_really_is_positive(dentry)) {
		struct kstat stat;
		struct path p = {.mnt = parent.mnt, .dentry = dentry};
		err = vfs_getattr(&p, &stat, STATX_TYPE | STATX_MODE,
				  AT_STATX_SYNC_AS_STAT);
		if (!err && dev_mynode(dev, d_inode(dentry), &stat)) {
			struct iattr newattrs;
			/*
			 * before unlinking this node, reset permissions
			 * of possible references like hardlinks
			 */
			newattrs.ia_uid = GLOBAL_ROOT_UID;
			newattrs.ia_gid = GLOBAL_ROOT_GID;
			newattrs.ia_mode = stat.mode & ~0777;
			newattrs.ia_valid =
				ATTR_UID|ATTR_GID|ATTR_MODE;
			inode_lock(d_inode(dentry));
			notify_change(&nop_mnt_idmap, dentry, &newattrs, NULL);
			inode_unlock(d_inode(dentry));
			/*移除此文件*/
			err = vfs_unlink(&nop_mnt_idmap, d_inode(parent.dentry),
					 dentry, NULL);
			if (!err || err == -ENOENT)
				deleted = 1;
		}
	} else {
		err = -ENOENT;
	}
	dput(dentry);
	inode_unlock(d_inode(parent.dentry));

	path_put(&parent);
	if (deleted && strchr(nodename, '/'))
		delete_path(nodename);
	return err;
}

/*
 * If configured, or requested by the commandline, devtmpfs will be
 * auto-mounted after the kernel mounted the root filesystem.
 */
int __init devtmpfs_mount(void)
{
	int err;

	if (!mount_dev)
		return 0;

	if (!thread)
		return 0;

	//直接调用mount，将devtmpfs文件系统挂接在mntdir
	err = init_mount("devtmpfs", "dev", "devtmpfs", DEVTMPFS_MFLAGS, NULL);
	if (err)
		pr_info("error mounting %d\n", err);
	else
		pr_info("mounted\n");
	return err;
}

static __initdata DECLARE_COMPLETION(setup_done);

static int handle(const char *name, umode_t mode, kuid_t uid, kgid_t gid,
		  struct device *dev)
{
	if (mode)
		/*mode不为0，则认为创建*/
		return handle_create(name, mode, uid, gid, dev);
	else
		/*mode为0，则处理为删除*/
		return handle_remove(name, dev);
}

//devtmpfs内核线程入口（利用handle函数处理requests链表上所有请求）
static void __noreturn devtmpfs_work_loop(void)
{
	while (1) {
		spin_lock(&req_lock);
		while (requests) {
			/*用req保存requests*/
			struct req *req = requests;
			requests = NULL;
			spin_unlock(&req_lock);
			/*遍历所有req*/
			while (req) {
				struct req *next = req->next;/*指向下一个*/
				/*处理请求*/
				req->err = handle(req->name, req->mode,
						  req->uid, req->gid, req->dev);
				/*标记完成*/
				complete(&req->done);
				req = next;
			}
			spin_lock(&req_lock);
		}
		__set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&req_lock);
		schedule();
	}
}

static noinline int __init devtmpfs_setup(void *p)
{
	int err;

	err = ksys_unshare(CLONE_NEWNS);
	if (err)
		goto out;
	err = init_mount("devtmpfs", "/", "devtmpfs", DEVTMPFS_MFLAGS, NULL);
	if (err)
		goto out;
	init_chdir("/.."); /* will traverse into overmounted root */
	init_chroot(".");
out:
	*(int *)p = err;
	return err;
}

/*
 * The __ref is because devtmpfs_setup needs to be __init for the routines it
 * calls.  That call is done while devtmpfs_init, which is marked __init,
 * synchronously waits for it to complete.
 */
static int __ref devtmpfsd(void *p)
{
	int err = devtmpfs_setup(p);

	complete(&setup_done);
	if (err)
		return err;
	devtmpfs_work_loop();
	return 0;
}

/*
 * Create devtmpfs instance, driver-core devices will add their device
 * nodes here.
 */
int __init devtmpfs_init(void)
{
	char opts[] = "mode=0755";
	int err;

	/*挂载internal_fs_type文件系统,初始化mnt(挂载点），注：并不注册此文件系统*/
	mnt = vfs_kern_mount(&internal_fs_type, 0, "devtmpfs", opts);
	if (IS_ERR(mnt)) {
		pr_err("unable to create devtmpfs %ld\n", PTR_ERR(mnt));
		return PTR_ERR(mnt);
	}

	//注册devtmpfs文件系统
	err = register_filesystem(&dev_fs_type);
	if (err) {
		pr_err("unable to register devtmpfs type %d\n", err);
		return err;
	}

	//创建kdevtmpfs内核线程
	thread = kthread_run(devtmpfsd, &err, "kdevtmpfs");
	if (!IS_ERR(thread)) {
		wait_for_completion(&setup_done);
	} else {
		err = PTR_ERR(thread);
		thread = NULL;
	}

	if (err) {
		pr_err("unable to create devtmpfs %d\n", err);
		unregister_filesystem(&dev_fs_type);
		thread = NULL;
		return err;
	}

	pr_info("initialized\n");
	return 0;
}
