/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/path.h>
#include <linux/fcntl.h>
#include <linux/errno.h>

enum { MAX_NESTED_LINKS = 8 };

#define MAXSYMLINKS 40

/*
 * Type of the last component on LOOKUP_PARENT
 */
enum {LAST_NORM/*普通文件*/, LAST_ROOT/*根节点*/, LAST_DOT/*名称为'.'的文件*/, LAST_DOTDOT/*名称为'..'的文件*/};

/* pathwalk mode */
#define LOOKUP_FOLLOW		0x0001	/* follow links at the end */
/*标志查询的是目录*/
#define LOOKUP_DIRECTORY	0x0002	/* require a directory */
#define LOOKUP_AUTOMOUNT	0x0004  /* force terminal automount */
/*容许空的文件路径名称*/
#define LOOKUP_EMPTY		0x4000	/* accept empty path [user_... only] */
#define LOOKUP_DOWN		0x8000	/* follow mounts in the starting point */
#define LOOKUP_MOUNTPOINT	0x0080	/* follow mounts in the end */

#define LOOKUP_REVAL		0x0020	/* tell ->d_revalidate() to trust no cache */
#define LOOKUP_RCU		0x0040	/* RCU pathwalk mode; semi-internal */

/* These tell filesystem methods that we are dealing with the final component... */
#define LOOKUP_OPEN		0x0100	/* ... in open */
#define LOOKUP_CREATE		0x0200	/* ... in object creation */
#define LOOKUP_EXCL		0x0400	/* ... in exclusive creation */
#define LOOKUP_RENAME_TARGET	0x0800	/* ... in destination of rename() */

/* internal use only */
#define LOOKUP_PARENT		0x0010

/* Scoping flags for lookup. */
#define LOOKUP_NO_SYMLINKS	0x010000 /* No symlink crossing. */
#define LOOKUP_NO_MAGICLINKS	0x020000 /* No nd_jump_link() crossing. */
#define LOOKUP_NO_XDEV		0x040000 /* No mountpoint crossing. */
#define LOOKUP_BENEATH		0x080000 /* No escaping from starting point. */
#define LOOKUP_IN_ROOT		0x100000 /* Treat dirfd as fs root. */
#define LOOKUP_CACHED		0x200000 /* Only do cached lookup */
/* LOOKUP_* flags which do scope-related checks based on the dirfd. */
#define LOOKUP_IS_SCOPED (LOOKUP_BENEATH | LOOKUP_IN_ROOT)

extern int path_pts(struct path *path);

extern int user_path_at_empty(int, const char __user *, unsigned, struct path *, int *empty);

static inline int user_path_at(int dfd, const char __user *name/*路径名称*/, unsigned flags,
		 struct path *path/*出参，确定路径对应的dentry*/)
{
	return user_path_at_empty(dfd, name, flags, path, NULL);
}

struct dentry *lookup_one_qstr_excl(const struct qstr *name,
				    struct dentry *base,
				    unsigned int flags);
extern int kern_path(const char *, unsigned, struct path *);

extern struct dentry *kern_path_create(int, const char *, struct path *, unsigned int);
extern struct dentry *user_path_create(int, const char __user *, struct path *, unsigned int);
extern void done_path_create(struct path *, struct dentry *);
extern struct dentry *kern_path_locked(const char *, struct path *);
extern struct dentry *user_path_locked_at(int , const char __user *, struct path *);
int vfs_path_parent_lookup(struct filename *filename, unsigned int flags,
			   struct path *parent, struct qstr *last, int *type,
			   const struct path *root);
int vfs_path_lookup(struct dentry *, struct vfsmount *, const char *,
		    unsigned int, struct path *);

extern struct dentry *try_lookup_one_len(const char *, struct dentry *, int);
extern struct dentry *lookup_one_len(const char *, struct dentry *, int);
extern struct dentry *lookup_one_len_unlocked(const char *, struct dentry *, int);
extern struct dentry *lookup_positive_unlocked(const char *, struct dentry *, int);
struct dentry *lookup_one(struct mnt_idmap *, const char *, struct dentry *, int);
struct dentry *lookup_one_unlocked(struct mnt_idmap *idmap,
				   const char *name, struct dentry *base,
				   int len);
struct dentry *lookup_one_positive_unlocked(struct mnt_idmap *idmap,
					    const char *name,
					    struct dentry *base, int len);

extern int follow_down_one(struct path *);
extern int follow_down(struct path *path, unsigned int flags);
extern int follow_up(struct path *);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern struct dentry *lock_rename_child(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

/**
 * mode_strip_umask - handle vfs umask stripping
 * @dir:	parent directory of the new inode
 * @mode:	mode of the new inode to be created in @dir
 *
 * In most filesystems, umask stripping depends on whether or not the
 * filesystem supports POSIX ACLs. If the filesystem doesn't support it umask
 * stripping is done directly in here. If the filesystem does support POSIX
 * ACLs umask stripping is deferred until the filesystem calls
 * posix_acl_create().
 *
 * Some filesystems (like NFSv4) also want to avoid umask stripping by the
 * VFS, but don't support POSIX ACLs. Those filesystems can set SB_I_NOUMASK
 * to get this effect without declaring that they support POSIX ACLs.
 *
 * Returns: mode
 */
static inline umode_t __must_check mode_strip_umask(const struct inode *dir, umode_t mode)
{
	if (!IS_POSIXACL(dir) && !(dir->i_sb->s_iflags & SB_I_NOUMASK))
		mode &= ~current_umask();
	return mode;
}

extern int __must_check nd_jump_link(const struct path *path);

static inline void nd_terminate_link(void *name, size_t len, size_t maxlen)
{
	((char *) name)[min(len, maxlen)] = '\0';
}

/**
 * retry_estale - determine whether the caller should retry an operation
 * @error: the error that would currently be returned
 * @flags: flags being used for next lookup attempt
 *
 * Check to see if the error code was -ESTALE, and then determine whether
 * to retry the call based on whether "flags" already has LOOKUP_REVAL set.
 *
 * Returns true if the caller should try the operation again.
 */
static inline bool
retry_estale(const long error, const unsigned int flags)
{
	return unlikely(error == -ESTALE && !(flags & LOOKUP_REVAL));
}

#endif /* _LINUX_NAMEI_H */
