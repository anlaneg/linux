// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal file system backend for holding eBPF maps and programs,
 * used by bpf(2) object pinning.
 *
 * Authors:
 *
 *	Daniel Borkmann <daniel@iogearbox.net>
 */

#include <linux/init.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/kdev_t.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include "preload/bpf_preload.h"

enum bpf_type {
	BPF_TYPE_UNSPEC	= 0,
	BPF_TYPE_PROG,
	BPF_TYPE_MAP,
	BPF_TYPE_LINK,
};

//按bpf类型，对相应结构引用计数加1
static void *bpf_any_get(void *raw, enum bpf_type type)
{
	switch (type) {
	case BPF_TYPE_PROG:
		bpf_prog_inc(raw);
		break;
	case BPF_TYPE_MAP:
		bpf_map_inc_with_uref(raw);
		break;
	case BPF_TYPE_LINK:
		bpf_link_inc(raw);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	return raw;
}

//按bpf类型，对相应结构引用计数减1
static void bpf_any_put(void *raw, enum bpf_type type)
{
	switch (type) {
	case BPF_TYPE_PROG:
		bpf_prog_put(raw);
		break;
	case BPF_TYPE_MAP:
		bpf_map_put_with_uref(raw);
		break;
	case BPF_TYPE_LINK:
		bpf_link_put(raw);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}

/*通过fd获取对应的对象*/
static void *bpf_fd_probe_obj(u32 ufd, enum bpf_type *type/*出参，获取fd对应的对象类型*/)
{
	void *raw;

	raw = bpf_map_get_with_uref(ufd);
	if (!IS_ERR(raw)) {
	    /*查询map成功*/
		*type = BPF_TYPE_MAP;
		return raw;
	}

	raw = bpf_prog_get(ufd);
	if (!IS_ERR(raw)) {
	    /*查询bpf程序成功*/
		*type = BPF_TYPE_PROG;
		return raw;
	}

	raw = bpf_link_get_from_fd(ufd);
	if (!IS_ERR(raw)) {
	    /*查询bpf link成功*/
		*type = BPF_TYPE_LINK;
		return raw;
	}

	return ERR_PTR(-EINVAL);
}

static const struct inode_operations bpf_dir_iops;

static const struct inode_operations bpf_prog_iops = { };
static const struct inode_operations bpf_map_iops  = { };
static const struct inode_operations bpf_link_iops  = { };

static struct inode *bpf_get_inode(struct super_block *sb,
				   const struct inode *dir,
				   umode_t mode)
{
	struct inode *inode;

	switch (mode & S_IFMT) {
	case S_IFDIR:
	case S_IFREG:
	case S_IFLNK:
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	//申请一个inode
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOSPC);

	inode->i_ino = get_next_ino();
	simple_inode_init_ts(inode);

	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);

	return inode;
}

/*由inode获得bpf类型*/
static int bpf_inode_type(const struct inode *inode, enum bpf_type *type/*出参，bpf类型*/)
{
	*type = BPF_TYPE_UNSPEC;
	if (inode->i_op == &bpf_prog_iops)
		*type = BPF_TYPE_PROG;/*bpf程序*/
	else if (inode->i_op == &bpf_map_iops)
		*type = BPF_TYPE_MAP;/*bpf映射表*/
	else if (inode->i_op == &bpf_link_iops)
		*type = BPF_TYPE_LINK;
	else
		return -EACCES;

	return 0;
}

static void bpf_dentry_finalize(struct dentry *dentry, struct inode *inode,
				struct inode *dir)
{
	d_instantiate(dentry, inode);
	dget(dentry);

	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
}

static int bpf_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		     struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	inode = bpf_get_inode(dir->i_sb, dir, mode | S_IFDIR);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &bpf_dir_iops;
	inode->i_fop = &simple_dir_operations;

	inc_nlink(inode);
	inc_nlink(dir);

	bpf_dentry_finalize(dentry, inode, dir);
	return 0;
}

struct map_iter {
	void *key;
	bool done;
};

static struct map_iter *map_iter(struct seq_file *m)
{
	return m->private;
}

static struct bpf_map *seq_file_to_map(struct seq_file *m)
{
	return file_inode(m->file)->i_private;
}

static void map_iter_free(struct map_iter *iter)
{
	if (iter) {
		kfree(iter->key);
		kfree(iter);
	}
}

static struct map_iter *map_iter_alloc(struct bpf_map *map)
{
	struct map_iter *iter;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL | __GFP_NOWARN);
	if (!iter)
		goto error;

	iter->key = kzalloc(map->key_size, GFP_KERNEL | __GFP_NOWARN);
	if (!iter->key)
		goto error;

	return iter;

error:
	map_iter_free(iter);
	return NULL;
}

/*访问下一个map key*/
static void *map_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct bpf_map *map = seq_file_to_map(m);
	void *key = map_iter(m)->key;
	void *prev_key;

	(*pos)++;
	if (map_iter(m)->done)
		return NULL;

	/*区分是否首次遍历*/
	if (unlikely(v == SEQ_START_TOKEN))
		prev_key = NULL;
	else
		prev_key = key;

	rcu_read_lock();
	/*获取下一个key*/
	if (map->ops->map_get_next_key(map, prev_key, key)) {
	    /*遍历结束*/
		map_iter(m)->done = true;
		key = NULL;
	}
	rcu_read_unlock();
	return key;
}

/*初始化map_iter*/
static void *map_seq_start(struct seq_file *m, loff_t *pos)
{
	if (map_iter(m)->done)
		return NULL;

	return *pos ? map_iter(m)->key : SEQ_START_TOKEN;
}

/*访问结束*/
static void map_seq_stop(struct seq_file *m, void *v)
{
}

/*显示当前key对应的value*/
static int map_seq_show(struct seq_file *m, void *v)
{
	struct bpf_map *map = seq_file_to_map(m);
	void *key = map_iter(m)->key;

	if (unlikely(v == SEQ_START_TOKEN)) {
		seq_puts(m, "# WARNING!! The output is for debug purpose only\n");
		seq_puts(m, "# WARNING!! The output format will change\n");
	} else {
	    /*为seq file显示map中key对应的value*/
		map->ops->map_seq_show_elem(map, key, m);
	}

	return 0;
}

static const struct seq_operations bpffs_map_seq_ops = {
	.start	= map_seq_start,
	.next	= map_seq_next,
	.show	= map_seq_show,
	.stop	= map_seq_stop,
};

static int bpffs_map_open(struct inode *inode, struct file *file)
{
	struct bpf_map *map = inode->i_private;
	struct map_iter *iter;
	struct seq_file *m;
	int err;

	iter = map_iter_alloc(map);
	if (!iter)
		return -ENOMEM;

	/*打开seq文件*/
	err = seq_open(file, &bpffs_map_seq_ops);
	if (err) {
		map_iter_free(iter);
		return err;
	}

	m = file->private_data;
	m->private = iter;

	return 0;
}

static int bpffs_map_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	map_iter_free(map_iter(m));

	return seq_release(inode, file);
}

/* bpffs_map_fops should only implement the basic
 * read operation for a BPF map.  The purpose is to
 * provide a simple user intuitive way to do
 * "cat bpffs/pathto/a-pinned-map".
 *
 * Other operations (e.g. write, lookup...) should be realized by
 * the userspace tools (e.g. bpftool) through the
 * BPF_OBJ_GET_INFO_BY_FD and the map's lookup/update
 * interface.
 */
static const struct file_operations bpffs_map_fops = {
	.open		= bpffs_map_open,
	.read		= seq_read,
	.release	= bpffs_map_release,
};

static int bpffs_obj_open(struct inode *inode, struct file *file)
{
	return -EIO;
}

static const struct file_operations bpffs_obj_fops = {
	.open		= bpffs_obj_open,
};

static int bpf_mkobj_ops(struct dentry *dentry, umode_t mode, void *raw,
			 const struct inode_operations *iops,
			 const struct file_operations *fops)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct inode *inode = bpf_get_inode(dir->i_sb, dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = iops;
	inode->i_fop = fops;
	inode->i_private = raw;

	bpf_dentry_finalize(dentry, inode, dir);
	return 0;
}

static int bpf_mkprog(struct dentry *dentry, umode_t mode, void *arg)
{
	return bpf_mkobj_ops(dentry, mode, arg, &bpf_prog_iops,
			     &bpffs_obj_fops);
}

static int bpf_mkmap(struct dentry *dentry, umode_t mode, void *arg)
{
	struct bpf_map *map = arg;

	return bpf_mkobj_ops(dentry, mode, arg, &bpf_map_iops,
			     bpf_map_support_seq_show(map) ?
			     &bpffs_map_fops/*支持seq file的*/ : &bpffs_obj_fops/*不支持seq file的，则返回打开文件失败*/);
}

static int bpf_mklink(struct dentry *dentry, umode_t mode, void *arg)
{
	struct bpf_link *link = arg;

	return bpf_mkobj_ops(dentry, mode, arg, &bpf_link_iops,
			     bpf_link_is_iter(link) ?
			     &bpf_iter_fops : &bpffs_obj_fops);
}

static struct dentry *
bpf_lookup(struct inode *dir, struct dentry *dentry, unsigned flags)
{
	/* Dots in names (e.g. "/sys/fs/bpf/foo.bar") are reserved for future
	 * extensions. That allows popoulate_bpffs() create special files.
	 */
	if ((dir->i_mode & S_IALLUGO) &&
	    strchr(dentry->d_name.name, '.'))
		return ERR_PTR(-EPERM);

	return simple_lookup(dir, dentry, flags);
}

static int bpf_symlink(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *dentry, const char *target)
{
	char *link = kstrdup(target, GFP_USER | __GFP_NOWARN);
	struct inode *inode;

	if (!link)
		return -ENOMEM;

	inode = bpf_get_inode(dir->i_sb, dir, S_IRWXUGO | S_IFLNK);
	if (IS_ERR(inode)) {
		kfree(link);
		return PTR_ERR(inode);
	}

	inode->i_op = &simple_symlink_inode_operations;
	inode->i_link = link;

	bpf_dentry_finalize(dentry, inode, dir);
	return 0;
}

static const struct inode_operations bpf_dir_iops = {
	.lookup		= bpf_lookup,
	.mkdir		= bpf_mkdir,
	.symlink	= bpf_symlink,
	.rmdir		= simple_rmdir,
	.rename		= simple_rename,
	.link		= simple_link,
	.unlink		= simple_unlink,
};

/* pin iterator link into bpffs */
static int bpf_iter_link_pin_kernel(struct dentry *parent,
				    const char *name, struct bpf_link *link)
{
	umode_t mode = S_IFREG | S_IRUSR;
	struct dentry *dentry;
	int ret;

	inode_lock(parent->d_inode);
	dentry = lookup_one_len(name, parent, strlen(name));
	if (IS_ERR(dentry)) {
		inode_unlock(parent->d_inode);
		return PTR_ERR(dentry);
	}
	ret = bpf_mkobj_ops(dentry, mode, link, &bpf_link_iops,
			    &bpf_iter_fops);
	dput(dentry);
	inode_unlock(parent->d_inode);
	return ret;
}

static int bpf_obj_do_pin(int path_fd, const char __user *pathname/*路径名*/, void *raw/*bpf对象*/,
			  enum bpf_type type/*bpf对象类型*/)
{
	struct dentry *dentry;
	struct inode *dir;
	struct path path;
	umode_t mode;
	int ret;

	/*查询此path对应的dentry*/
	dentry = user_path_create(path_fd, pathname, &path, 0);
	if (IS_ERR(dentry))
		/*查询失败*/
		return PTR_ERR(dentry);

	/*path必须使用bpf fs，且必须为dir*/
	dir = d_inode(path.dentry);
	if (dir->i_op != &bpf_dir_iops) {
		ret = -EPERM;
		goto out;
	}

	mode = S_IFREG | ((S_IRUSR | S_IWUSR) & ~current_umask());
	ret = security_path_mknod(&path, dentry, mode, 0);
	if (ret)
		goto out;

	switch (type) {
	case BPF_TYPE_PROG:
		ret = vfs_mkobj(dentry, mode, bpf_mkprog, raw);
		break;
	case BPF_TYPE_MAP:
	    /*按路径创建文件，并支持文件内容读取*/
		ret = vfs_mkobj(dentry, mode, bpf_mkmap, raw);
		break;
	case BPF_TYPE_LINK:
		ret = vfs_mkobj(dentry, mode, bpf_mklink, raw);
		break;
	default:
		ret = -EPERM;
	}
out:
	done_path_create(&path, dentry);
	return ret;
}

int bpf_obj_pin_user(u32 ufd, int path_fd, const char __user *pathname)
{
	enum bpf_type type;
	void *raw;
	int ret;

	/*依据fd获取bpf对象*/
	raw = bpf_fd_probe_obj(ufd, &type);
	if (IS_ERR(raw))
		return PTR_ERR(raw);

	ret = bpf_obj_do_pin(path_fd, pathname, raw, type);
	if (ret != 0)
		bpf_any_put(raw, type);

	return ret;
}

/*通过pathname获知其对应的bpf object type*/
static void *bpf_obj_do_get(int path_fd, const char __user *pathname,
			    enum bpf_type *type, int flags)
{
	struct inode *inode;
	struct path path;
	void *raw;
	int ret;

	ret = user_path_at(path_fd, pathname, LOOKUP_FOLLOW, &path);
	if (ret)
		return ERR_PTR(ret);

	inode = d_backing_inode(path.dentry);
	ret = path_permission(&path, ACC_MODE(flags));
	if (ret)
		goto out;

	/*获取bpf类型*/
	ret = bpf_inode_type(inode, type);
	if (ret)
		goto out;

	/*增加引用*/
	raw = bpf_any_get(inode->i_private, *type);
	if (!IS_ERR(raw))
		touch_atime(&path);

	path_put(&path);
	return raw;
out:
	path_put(&path);
	return ERR_PTR(ret);
}

int bpf_obj_get_user(int path_fd, const char __user *pathname, int flags)
{
	enum bpf_type type = BPF_TYPE_UNSPEC;
	int f_flags;
	void *raw;
	int ret;

	//默认读写权限
	f_flags = bpf_get_file_flag(flags);
	if (f_flags < 0)
		return f_flags;

	raw = bpf_obj_do_get(path_fd, pathname, &type, f_flags);
	if (IS_ERR(raw))
		return PTR_ERR(raw);

	/*按程序类构造file并与相应raw进行映射*/
	if (type == BPF_TYPE_PROG)
		ret = bpf_prog_new_fd(raw);
	else if (type == BPF_TYPE_MAP)
		ret = bpf_map_new_fd(raw, f_flags);
	else if (type == BPF_TYPE_LINK)
		ret = (f_flags != O_RDWR) ? -EINVAL : bpf_link_new_fd(raw);
	else
		return -ENOENT;/*这里是一个bug,不能直接返回*/

	if (ret < 0)
		bpf_any_put(raw, type);
	return ret;
}

static struct bpf_prog *__get_prog_inode(struct inode *inode, enum bpf_prog_type type)
{
	struct bpf_prog *prog;
	int ret = inode_permission(&nop_mnt_idmap, inode, MAY_READ);
	if (ret)
		return ERR_PTR(ret);

	if (inode->i_op == &bpf_map_iops)
		return ERR_PTR(-EINVAL);
	if (inode->i_op == &bpf_link_iops)
		return ERR_PTR(-EINVAL);
	if (inode->i_op != &bpf_prog_iops)
		return ERR_PTR(-EACCES);

	prog = inode->i_private;

	ret = security_bpf_prog(prog);
	if (ret < 0)
		return ERR_PTR(ret);

	if (!bpf_prog_get_ok(prog, &type, false))
		return ERR_PTR(-EINVAL);

	bpf_prog_inc(prog);
	return prog;
}

struct bpf_prog *bpf_prog_get_type_path(const char *name, enum bpf_prog_type type)
{
	struct bpf_prog *prog;
	struct path path;
	int ret = kern_path(name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ERR_PTR(ret);
	prog = __get_prog_inode(d_backing_inode(path.dentry), type);
	if (!IS_ERR(prog))
		touch_atime(&path);
	path_put(&path);
	return prog;
}
EXPORT_SYMBOL(bpf_prog_get_type_path);

/*
 * Display the mount options in /proc/mounts.
 */
static int bpf_show_options(struct seq_file *m, struct dentry *root)
{
	struct inode *inode = d_inode(root);
	umode_t mode = inode->i_mode & S_IALLUGO & ~S_ISVTX;

	if (!uid_eq(inode->i_uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
			   from_kuid_munged(&init_user_ns, inode->i_uid));
	if (!gid_eq(inode->i_gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
			   from_kgid_munged(&init_user_ns, inode->i_gid));
	if (mode != S_IRWXUGO)
		seq_printf(m, ",mode=%o", mode);
	return 0;
}

static void bpf_free_inode(struct inode *inode)
{
	enum bpf_type type;

	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	if (!bpf_inode_type(inode, &type))
		bpf_any_put(inode->i_private, type);
	free_inode_nonrcu(inode);
}

static const struct super_operations bpf_super_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= bpf_show_options,
	.free_inode	= bpf_free_inode,
};

enum {
	OPT_UID,
	OPT_GID,
	OPT_MODE,
};

//定义支持的参数
static const struct fs_parameter_spec bpf_fs_parameters[] = {
	fsparam_u32	("uid",				OPT_UID),
	fsparam_u32	("gid",				OPT_GID),
	fsparam_u32oct	("mode",			OPT_MODE),
	{}
};

struct bpf_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

static int bpf_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct bpf_mount_opts *opts = fc->fs_private;
	struct fs_parse_result result;
	kuid_t uid;
	kgid_t gid;
	int opt;

	//解析bpf参数
	opt = fs_parse(fc, bpf_fs_parameters, param, &result);
	if (opt < 0) {
		/* We might like to report bad mount options here, but
		 * traditionally we've ignored all mount options, so we'd
		 * better continue to ignore non-existing options for bpf.
		 */
		if (opt == -ENOPARAM) {
			opt = vfs_parse_fs_param_source(fc, param);
			if (opt != -ENOPARAM)
				return opt;

			return 0;
		}

		if (opt < 0)
			return opt;
	}

	switch (opt) {
	case OPT_UID:
		uid = make_kuid(current_user_ns(), result.uint_32);
		if (!uid_valid(uid))
			goto bad_value;

		/*
		 * The requested uid must be representable in the
		 * filesystem's idmapping.
		 */
		if (!kuid_has_mapping(fc->user_ns, uid))
			goto bad_value;

		opts->uid = uid;
		break;
	case OPT_GID:
		gid = make_kgid(current_user_ns(), result.uint_32);
		if (!gid_valid(gid))
			goto bad_value;

		/*
		 * The requested gid must be representable in the
		 * filesystem's idmapping.
		 */
		if (!kgid_has_mapping(fc->user_ns, gid))
			goto bad_value;

		opts->gid = gid;
		break;
	case OPT_MODE:
	    //按参数设置mode
		opts->mode = result.uint_32 & S_IALLUGO;
		break;
	}

	return 0;
bad_value:
	return invalfc(fc, "Bad value for '%s'", param->key);
}

struct bpf_preload_ops *bpf_preload_ops;
EXPORT_SYMBOL_GPL(bpf_preload_ops);

static bool bpf_preload_mod_get(void)
{
	/* If bpf_preload.ko wasn't loaded earlier then load it now.
	 * When bpf_preload is built into vmlinux the module's __init
	 * function will populate it.
	 */
	if (!bpf_preload_ops) {
		request_module("bpf_preload");
		if (!bpf_preload_ops)
			return false;
	}
	/* And grab the reference, so the module doesn't disappear while the
	 * kernel is interacting with the kernel module and its UMD.
	 */
	if (!try_module_get(bpf_preload_ops->owner)) {
		pr_err("bpf_preload module get failed.\n");
		return false;
	}
	return true;
}

static void bpf_preload_mod_put(void)
{
	if (bpf_preload_ops)
		/* now user can "rmmod bpf_preload" if necessary */
		module_put(bpf_preload_ops->owner);
}

static DEFINE_MUTEX(bpf_preload_lock);

static int populate_bpffs(struct dentry *parent)
{
	struct bpf_preload_info objs[BPF_PRELOAD_LINKS] = {};
	int err = 0, i;

	/* grab the mutex to make sure the kernel interactions with bpf_preload
	 * are serialized
	 */
	mutex_lock(&bpf_preload_lock);

	/* if bpf_preload.ko wasn't built into vmlinux then load it */
	if (!bpf_preload_mod_get())
		goto out;

	err = bpf_preload_ops->preload(objs);
	if (err)
		goto out_put;
	for (i = 0; i < BPF_PRELOAD_LINKS; i++) {
		bpf_link_inc(objs[i].link);
		err = bpf_iter_link_pin_kernel(parent,
					       objs[i].link_name, objs[i].link);
		if (err) {
			bpf_link_put(objs[i].link);
			goto out_put;
		}
	}
out_put:
	bpf_preload_mod_put();
out:
	mutex_unlock(&bpf_preload_lock);
	return err;
}

static int bpf_fill_super(struct super_block *sb, struct fs_context *fc)
{
	static const struct tree_descr bpf_rfiles[] = { { "" } };
	struct bpf_mount_opts *opts = fc->fs_private;
	struct inode *inode;
	int ret;

	ret = simple_fill_super(sb, BPF_FS_MAGIC, bpf_rfiles);
	if (ret)
		return ret;

	sb->s_op = &bpf_super_ops;

	inode = sb->s_root->d_inode;
	inode->i_uid = opts->uid;
	inode->i_gid = opts->gid;
	inode->i_op = &bpf_dir_iops;
	inode->i_mode &= ~S_IALLUGO;
	populate_bpffs(sb->s_root);
	inode->i_mode |= S_ISVTX | opts->mode;
	return 0;
}

static int bpf_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, bpf_fill_super);
}

//释放bpf文件系统的私有结构（fs_private，其上记录了bpf_mount_opts）
static void bpf_free_fc(struct fs_context *fc)
{
	kfree(fc->fs_private);
}

static const struct fs_context_operations bpf_context_ops = {
	.free		= bpf_free_fc,
	.parse_param	= bpf_parse_param,
	.get_tree	= bpf_get_tree,
};

/*
 * Set up the filesystem mount context.
 */
static int bpf_init_fs_context(struct fs_context *fc)
{
    //申请bpf_mount_opts，并将其记录在fs_private上
	struct bpf_mount_opts *opts;

	opts = kzalloc(sizeof(struct bpf_mount_opts), GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	opts->mode = S_IRWXUGO;
	opts->uid = current_fsuid();
	opts->gid = current_fsgid();

	fc->fs_private = opts;
	fc->ops = &bpf_context_ops;
	return 0;
}

//定义bpf文件系统类型
static struct file_system_type bpf_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bpf",
	.init_fs_context = bpf_init_fs_context,
	.parameters	= bpf_fs_parameters,
	.kill_sb	= kill_litter_super,
};

static int __init bpf_init(void)
{
	int ret;

	//在sys/fs下创建bpf目录
	ret = sysfs_create_mount_point(fs_kobj, "bpf");
	if (ret)
		return ret;

	//注册bpf文件系统
	ret = register_filesystem(&bpf_fs_type);
	if (ret)
		sysfs_remove_mount_point(fs_kobj, "bpf");

	return ret;
}
fs_initcall(bpf_init);
