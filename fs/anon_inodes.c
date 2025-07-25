// SPDX-License-Identifier: GPL-2.0-only
/*
 *  fs/anon_inodes.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 *  Thanks to Arnd Bergmann for code review and suggestions.
 *  More changes for Thomas Gleixner suggestions.
 *
 */

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/anon_inodes.h>
#include <linux/pseudo_fs.h>

#include <linux/uaccess.h>

/*匿名文件挂载点*/
static struct vfsmount *anon_inode_mnt __ro_after_init;
static struct inode *anon_inode_inode __ro_after_init;

/*
 * anon_inodefs_dname() is called from d_path().
 */
static char *anon_inodefs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(buffer, buflen, "anon_inode:%s",
				dentry->d_name.name);
}

static const struct dentry_operations anon_inodefs_dentry_operations = {
	.d_dname	= anon_inodefs_dname,
};

static int anon_inodefs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, ANON_INODE_FS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	ctx->dops = &anon_inodefs_dentry_operations;
	return 0;
}

/*匿名文件对应的fs*/
static struct file_system_type anon_inode_fs_type = {
	.name		= "anon_inodefs",
	.init_fs_context = anon_inodefs_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static struct inode *anon_inode_make_secure_inode(
	const char *name,
	const struct inode *context_inode)
{
	struct inode *inode;
	const struct qstr qname = QSTR_INIT(name, strlen(name));
	int error;

	inode = alloc_anon_inode(anon_inode_mnt->mnt_sb);
	if (IS_ERR(inode))
		return inode;
	inode->i_flags &= ~S_PRIVATE;
	error =	security_inode_init_security_anon(inode, &qname, context_inode);
	if (error) {
		iput(inode);
		return ERR_PTR(error);
	}
	return inode;
}

/*申请匿名文件*/
static struct file *__anon_inode_getfile(const char *name/*文件名称*/,
					 const struct file_operations *fops/*文件操作集*/,
					 void *priv/*私有数据*/, int flags,
					 const struct inode *context_inode,
					 bool make_inode/*是否要创建inode*/)
{
	struct inode *inode;
	struct file *file;

	if (fops->owner && !try_module_get(fops->owner))
		return ERR_PTR(-ENOENT);

	if (make_inode) {
		inode =	anon_inode_make_secure_inode(name, context_inode);
		if (IS_ERR(inode)) {
			file = ERR_CAST(inode);
			goto err;
		}
	} else {
		/*不需要创建inode,使用匿名inode(总使此node的计数大于零，则不会被释放)*/
		inode =	anon_inode_inode;
		if (IS_ERR(inode)) {
			file = ERR_PTR(-ENODEV);
			goto err;
		}
		/*
		 * We know the anon_inode inode count is always
		 * greater than zero, so ihold() is safe.
		 */
		ihold(inode);
	}

	//申请虚假文件
	file = alloc_file_pseudo(inode, anon_inode_mnt, name,
				 flags & (O_ACCMODE | O_NONBLOCK), fops/*虚假文件操作集*/);
	if (IS_ERR(file))
		goto err_iput;

	file->f_mapping = inode->i_mapping;

	//记录文件的私有数据
	file->private_data = priv;

	return file;

err_iput:
	iput(inode);
err:
	module_put(fops->owner);
	return file;
}

/**
 * anon_inode_getfile - creates a new file instance by hooking it up to an
 *                      anonymous inode, and a dentry that describe the "class"
 *                      of the file
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 *
 * Creates a new file by hooking it on a single inode. This is useful for files
 * that do not need to have a full-fledged inode in order to operate correctly.
 * All the files created with anon_inode_getfile() will share a single inode,
 * hence saving memory and avoiding code duplication for the file/inode/dentry
 * setup.  Returns the newly created file* or an error pointer.
 */
struct file *anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv/*文件私有数据*/, int flags)
{
	/*申请匿名文件*/
	return __anon_inode_getfile(name/*文件名称*/, fops/*文件关联的fops*/, priv, flags, NULL, false/*不创建inode*/);
}
EXPORT_SYMBOL_GPL(anon_inode_getfile);

/**
 * anon_inode_create_getfile - Like anon_inode_getfile(), but creates a new
 *                             !S_PRIVATE anon inode rather than reuse the
 *                             singleton anon inode and calls the
 *                             inode_init_security_anon() LSM hook.
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 * @context_inode:
 *           [in]    the logical relationship with the new inode (optional)
 *
 * Create a new anonymous inode and file pair.  This can be done for two
 * reasons:
 *
 * - for the inode to have its own security context, so that LSMs can enforce
 *   policy on the inode's creation;
 *
 * - if the caller needs a unique inode, for example in order to customize
 *   the size returned by fstat()
 *
 * The LSM may use @context_inode in inode_init_security_anon(), but a
 * reference to it is not held.
 *
 * Returns the newly created file* or an error pointer.
 */
struct file *anon_inode_create_getfile(const char *name,
				       const struct file_operations *fops,
				       void *priv, int flags,
				       const struct inode *context_inode)
{
	return __anon_inode_getfile(name, fops, priv, flags,
				    context_inode, true);
}
EXPORT_SYMBOL_GPL(anon_inode_create_getfile);

static int __anon_inode_getfd(const char *name,
			      const struct file_operations *fops,
			      void *priv, int flags,
			      const struct inode *context_inode,
			      bool make_inode)
{
	int error, fd;
	struct file *file;

	//申请未用的fd
	error = get_unused_fd_flags(flags);
	if (error < 0)
		return error;
	fd = error;

	//创建虚假文件，并指定文件fops
	file = __anon_inode_getfile(name, fops, priv, flags, context_inode,
				    make_inode);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_put_unused_fd;
	}

	/*实现文件与fd之间的映射*/
	fd_install(fd, file);

	return fd;

err_put_unused_fd:
	put_unused_fd(fd);
	return error;
}

/**
 * anon_inode_getfd - creates a new file instance by hooking it up to
 *                    an anonymous inode and a dentry that describe
 *                    the "class" of the file
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 *
 * Creates a new file by hooking it on a single inode. This is
 * useful for files that do not need to have a full-fledged inode in
 * order to operate correctly.  All the files created with
 * anon_inode_getfd() will use the same singleton inode, reducing
 * memory use and avoiding code duplication for the file/inode/dentry
 * setup.  Returns a newly created file descriptor or an error code.
 */
int anon_inode_getfd(const char *name, const struct file_operations *fops,
		     void *priv, int flags)
{
	return __anon_inode_getfd(name, fops, priv, flags, NULL, false);
}
EXPORT_SYMBOL_GPL(anon_inode_getfd);

/**
 * anon_inode_create_getfd - Like anon_inode_getfd(), but creates a new
 * !S_PRIVATE anon inode rather than reuse the singleton anon inode, and calls
 * the inode_init_security_anon() LSM hook.
 *
 * @name:    [in]    name of the "class" of the new file
 * @fops:    [in]    file operations for the new file
 * @priv:    [in]    private data for the new file (will be file's private_data)
 * @flags:   [in]    flags
 * @context_inode:
 *           [in]    the logical relationship with the new inode (optional)
 *
 * Create a new anonymous inode and file pair.  This can be done for two
 * reasons:
 *
 * - for the inode to have its own security context, so that LSMs can enforce
 *   policy on the inode's creation;
 *
 * - if the caller needs a unique inode, for example in order to customize
 *   the size returned by fstat()
 *
 * The LSM may use @context_inode in inode_init_security_anon(), but a
 * reference to it is not held.
 *
 * Returns a newly created file descriptor or an error code.
 */
int anon_inode_create_getfd(const char *name, const struct file_operations *fops,
			    void *priv, int flags,
			    const struct inode *context_inode)
{
	return __anon_inode_getfd(name, fops, priv, flags, context_inode, true);
}

static int __init anon_inode_init(void)
{
	anon_inode_mnt = kern_mount(&anon_inode_fs_type);
	if (IS_ERR(anon_inode_mnt))
		panic("anon_inode_init() kernel mount failed (%ld)\n", PTR_ERR(anon_inode_mnt));

	anon_inode_inode = alloc_anon_inode(anon_inode_mnt->mnt_sb);
	if (IS_ERR(anon_inode_inode))
		panic("anon_inode_init() inode allocation failed (%ld)\n", PTR_ERR(anon_inode_inode));

	return 0;
}

fs_initcall(anon_inode_init);

