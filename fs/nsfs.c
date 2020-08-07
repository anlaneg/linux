// SPDX-License-Identifier: GPL-2.0
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/magic.h>
#include <linux/ktime.h>
#include <linux/seq_file.h>
#include <linux/user_namespace.h>
#include <linux/nsfs.h>
#include <linux/uaccess.h>

#include "internal.h"

static struct vfsmount *nsfs_mnt;/*nsfs文件系统对应的vfsmount*/

static long ns_ioctl(struct file *filp, unsigned int ioctl,
			unsigned long arg);
/*nsfs对应的文件操作集*/
static const struct file_operations ns_file_operations = {
	.llseek		= no_llseek,
	.unlocked_ioctl = ns_ioctl,
};

static char *ns_dname(struct dentry *dentry, char *buffer, int buflen)
{
	struct inode *inode = d_inode(dentry);
	const struct proc_ns_operations *ns_ops = dentry->d_fsdata;

	return dynamic_dname(dentry, buffer, buflen, "%s:[%lu]",
		ns_ops->name, inode->i_ino);
}

static void ns_prune_dentry(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	if (inode) {
		struct ns_common *ns = inode->i_private;
		atomic_long_set(&ns->stashed, 0);
	}
}

const struct dentry_operations ns_dentry_operations =
{
	.d_prune	= ns_prune_dentry,
	.d_delete	= always_delete_dentry,
	.d_dname	= ns_dname,
};

static void nsfs_evict(struct inode *inode)
{
	struct ns_common *ns = inode->i_private;
	clear_inode(inode);
	ns->ops->put(ns);
}

//针对此ns构造与其对应的path，并填充此path的mnt及dentry
static int __ns_get_path(struct path *path, struct ns_common *ns)
{
	struct vfsmount *mnt = nsfs_mnt;
	struct dentry *dentry;
	struct inode *inode;
	unsigned long d;

	rcu_read_lock();
	d = atomic_long_read(&ns->stashed);
	if (!d)
	    /*如果stashed没有设置，则创建dentry并设置*/
		goto slow;
	dentry = (struct dentry *)d;
	if (!lockref_get_not_dead(&dentry->d_lockref))
		goto slow;
	rcu_read_unlock();
	ns->ops->put(ns);
got_it:
    /*设置此path对应的mnt及对应的dentry*/
	path->mnt = mntget(mnt);
	path->dentry = dentry;
	return 0;
slow:
	rcu_read_unlock();
	/*按superblock申请inode*/
	inode = new_inode_pseudo(mnt->mnt_sb);
	if (!inode) {
		ns->ops->put(ns);
		return -ENOMEM;
	}
	/*使inode与ns编号一致*/
	inode->i_ino = ns->inum;
	/*更新inode的创建，修改，访问时间*/
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_flags |= S_IMMUTABLE;
	/*指明此inode为普通文件，给设置权限*/
	inode->i_mode = S_IFREG | S_IRUGO;
	/*指明此inode对应的文件操作函数集*/
	inode->i_fop = &ns_file_operations;
	/*指明inode的私有数据为namespace*/
	inode->i_private = ns;

	/*申请dentry并与此inode相关联*/
	dentry = d_alloc_anon(mnt->mnt_sb);
	if (!dentry) {
		iput(inode);
		return -ENOMEM;
	}
	d_instantiate(dentry, inode);
	/*设置dentry的私有数据为ns的ops函数集*/
	dentry->d_fsdata = (void *)ns->ops;
	/*在ns的stashed中存放dentry的指针*/
	d = atomic_long_cmpxchg(&ns->stashed, 0, (unsigned long)dentry);
	if (d) {
		d_delete(dentry);	/* make sure ->d_prune() does nothing */
		dput(dentry);
		cpu_relax();
		return -EAGAIN;
	}
	goto got_it;
}

int ns_get_path_cb(struct path *path, ns_get_path_helper_t *ns_get_cb,
		     void *private_data)
{
	int ret;

	do {
		struct ns_common *ns = ns_get_cb(private_data);
		if (!ns)
			return -ENOENT;
		ret = __ns_get_path(path, ns);
	} while (ret == -EAGAIN);

	return ret;
}

struct ns_get_path_task_args {
	const struct proc_ns_operations *ns_ops;
	struct task_struct *task;
};

static struct ns_common *ns_get_path_task(void *private_data)
{
	struct ns_get_path_task_args *args = private_data;

	/*增加args->ns_ops中对应ns_common的引用计数*/
	return args->ns_ops->get(args->task);
}

/*取进程task的ns_ops指定类型的ns,并构造与其关联的path*/
int ns_get_path(struct path *path, struct task_struct *task,
		  const struct proc_ns_operations *ns_ops)
{
	struct ns_get_path_task_args args = {
		.ns_ops	= ns_ops,
		.task	= task,
	};

	return ns_get_path_cb(path, ns_get_path_task, &args);
}

/*构造一个ns对应的file对象，并返回此file对应的fd*/
int open_related_ns(struct ns_common *ns,
		   struct ns_common *(*get_ns)(struct ns_common *ns))
{
	struct path path = {};
	struct file *f;
	int err;
	int fd;

	//获取一个没有使用的fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	do {
		struct ns_common *relative;

		relative = get_ns(ns);
		if (IS_ERR(relative)) {
			put_unused_fd(fd);
			return PTR_ERR(relative);
		}

		/*构造填充path,使其与ns_common相关联*/
		err = __ns_get_path(&path, relative);
	} while (err == -EAGAIN);

	if (err) {
		put_unused_fd(fd);
		return err;
	}

	/*打开path指明的文件*/
	f = dentry_open(&path, O_RDONLY, current_cred());
	path_put(&path);
	if (IS_ERR(f)) {
		put_unused_fd(fd);
		fd = PTR_ERR(f);
	} else
	    /*实现此fd与file的关联*/
		fd_install(fd, f);

	return fd;
}
EXPORT_SYMBOL_GPL(open_related_ns);

//支持ns文件系统的ioctl系统调用
static long ns_ioctl(struct file *filp, unsigned int ioctl,
			unsigned long arg)
{
	struct user_namespace *user_ns;
	struct ns_common *ns = get_proc_ns(file_inode(filp));
	uid_t __user *argp;
	uid_t uid;

	switch (ioctl) {
	case NS_GET_USERNS:
		return open_related_ns(ns, ns_get_owner);
	case NS_GET_PARENT:
		if (!ns->ops->get_parent)
			return -EINVAL;
		return open_related_ns(ns, ns->ops->get_parent);
	case NS_GET_NSTYPE:
		return ns->ops->type;
	case NS_GET_OWNER_UID:
		if (ns->ops->type != CLONE_NEWUSER)
			return -EINVAL;
		user_ns = container_of(ns, struct user_namespace, ns);
		argp = (uid_t __user *) arg;
		uid = from_kuid_munged(current_user_ns(), user_ns->owner);
		return put_user(uid, argp);
	default:
		return -ENOTTY;
	}
}

int ns_get_name(char *buf, size_t size, struct task_struct *task,
			const struct proc_ns_operations *ns_ops)
{
	struct ns_common *ns;
	int res = -ENOENT;
	const char *name;
	ns = ns_ops->get(task);
	if (ns) {
		name = ns_ops->real_ns_name ? : ns_ops->name;
		res = snprintf(buf, size, "%s:[%u]", name, ns->inum);
		ns_ops->put(ns);
	}
	return res;
}

/*检查此文件是否为ns文件*/
bool proc_ns_file(const struct file *file)
{
	return file->f_op == &ns_file_operations;
}

struct file *proc_ns_fget(int fd)
{
	struct file *file;

	//取fd对应的文件
	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	//此文件的操作集必须为ns_file_operations
	if (file->f_op != &ns_file_operations)
		goto out_invalid;

	return file;

out_invalid:
	fput(file);
	return ERR_PTR(-EINVAL);
}

/**
 * ns_match() - Returns true if current namespace matches dev/ino provided.
 * @ns_common: current ns
 * @dev: dev_t from nsfs that will be matched against current nsfs
 * @ino: ino_t from nsfs that will be matched against current nsfs
 *
 * Return: true if dev and ino matches the current nsfs.
 */
bool ns_match(const struct ns_common *ns, dev_t dev, ino_t ino)
{
	return (ns->inum == ino) && (nsfs_mnt->mnt_sb->s_dev == dev);
}


static int nsfs_show_path(struct seq_file *seq, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	const struct proc_ns_operations *ns_ops = dentry->d_fsdata;

	seq_printf(seq, "%s:[%lu]", ns_ops->name, inode->i_ino);
	return 0;
}

static const struct super_operations nsfs_ops = {
	.statfs = simple_statfs,
	.evict_inode = nsfs_evict,
	.show_path = nsfs_show_path,
};

/*nsfs定制的fs_context结构体初始化函数*/
static int nsfs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, NSFS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	ctx->ops = &nsfs_ops;
	ctx->dops = &ns_dentry_operations;
	return 0;
}

static struct file_system_type nsfs = {
	.name = "nsfs",
	.init_fs_context = nsfs_init_fs_context,
	.kill_sb = kill_anon_super,
};

void __init nsfs_init(void)
{
    //挂载nsfs文件系统
	nsfs_mnt = kern_mount(&nsfs);
	if (IS_ERR(nsfs_mnt))
		panic("can't set nsfs up\n");
	nsfs_mnt->mnt_sb->s_flags &= ~SB_NOUSER;
}
