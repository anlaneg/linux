#ifndef __LINUX_PSEUDO_FS__
#define __LINUX_PSEUDO_FS__

#include <linux/fs_context.h>

/*pseudo-fs对应的context*/
struct pseudo_fs_context {
	/*用于指明super block的ops*/
	const struct super_operations *ops;
	const struct export_operations *eops;
	const struct xattr_handler * const *xattr;
	/*对pseudo-fs而言，此dentry ops将被赋给dentry*/
	const struct dentry_operations *dops;
	unsigned long magic;/*文件系统magic*/
};

struct pseudo_fs_context *init_pseudo(struct fs_context *fc,
				      unsigned long magic);

#endif
