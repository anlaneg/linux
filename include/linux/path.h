/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

struct path {
	struct vfsmount *mnt;//path对应的挂载点信息
	struct dentry *dentry;//path对应的dentry
} __randomize_layout;

extern void path_get(const struct path *);
extern void path_put(const struct path *);

//检查两个path是否相等
static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

static inline void path_put_init(struct path *path)
{
	path_put(path);
	*path = (struct path) { };
}

#endif  /* _LINUX_PATH_H */
