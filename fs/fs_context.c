// SPDX-License-Identifier: GPL-2.0-or-later
/* Provide a way to create a superblock configuration context within the kernel
 * that allows a superblock to be set up prior to mounting.
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/security.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <asm/sections.h>
#include "mount.h"
#include "internal.h"

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS,
	LEGACY_FS_MONOLITHIC_PARAMS,
	LEGACY_FS_INDIVIDUAL_PARAMS,
};

struct legacy_fs_context {
	/*mount时传入的选项参数*/
	char			*legacy_data;	/* Data page for legacy filesystems */
	size_t			data_size;/*legacy_data参数长度*/
	enum legacy_fs_param	param_type;/*legacy_parse_param函数对应的为LEGACY_FS_INDIVIDUAL_PARAMS类型*/
};

static int legacy_init_fs_context(struct fs_context *fc);

static const struct constant_table common_set_sb_flag[] = {
	{ "dirsync",	SB_DIRSYNC },
	{ "lazytime",	SB_LAZYTIME },
	{ "mand",	SB_MANDLOCK },
	{ "ro",		SB_RDONLY },
	{ "sync",	SB_SYNCHRONOUS },
	{ },
};

static const struct constant_table common_clear_sb_flag[] = {
	{ "async",	SB_SYNCHRONOUS },
	{ "nolazytime",	SB_LAZYTIME },
	{ "nomand",	SB_MANDLOCK },
	{ "rw",		SB_RDONLY },
	{ },
};

/*
 * Check for a common mount option that manipulates s_flags.
 */
static int vfs_parse_sb_flag(struct fs_context *fc, const char *key)
{
    //检查key是否为sb_flags的控制命令
	unsigned int token;

	//检查common_set_sb_flag table中是否包含此key,如不包含返回0，否则返回key对应的value
	token = lookup_constant(common_set_sb_flag, key, 0);
	if (token) {
	    //被命中，设置sb_flags标记,通过sb_flags_mask展示设置了哪些flags
		fc->sb_flags |= token;
		fc->sb_flags_mask |= token;
		return 0;
	}

	//检查common_set_sb_flag table中是否包含key,如不包含返回0，否则返回key对应的value
	token = lookup_constant(common_clear_sb_flag, key, 0);
	if (token) {
	    //被命中，清除sb_flags标记
		fc->sb_flags &= ~token;
		fc->sb_flags_mask |= token;
		return 0;
	}

	return -ENOPARAM;
}

/**
 * vfs_parse_fs_param_source - Handle setting "source" via parameter
 * @fc: The filesystem context to modify
 * @param: The parameter
 *
 * This is a simple helper for filesystems to verify that the "source" they
 * accept is sane.
 *
 * Returns 0 on success, -ENOPARAM if this is not  "source" parameter, and
 * -EINVAL otherwise. In the event of failure, supplementary error information
 *  is logged.
 */
int vfs_parse_fs_param_source(struct fs_context *fc, struct fs_parameter *param)
{
    /*param的key不为source时，此函数不处理*/
	if (strcmp(param->key, "source") != 0)
		return -ENOPARAM;

	/*source的value必须为字符串类型*/
	if (param->type != fs_value_is_string)
		return invalf(fc, "Non-string source");

	/*source参数必须只出现一次*/
	if (fc->source)
		return invalf(fc, "Multiple sources");

	/*设置source*/
	fc->source = param->string;
	param->string = NULL;
	return 0;
}
EXPORT_SYMBOL(vfs_parse_fs_param_source);

/**
 * vfs_parse_fs_param - Add a single parameter to a superblock config
 * @fc: The filesystem context to modify
 * @param: The parameter
 *
 * A single mount option in string form is applied to the filesystem context
 * being set up.  Certain standard options (for example "ro") are translated
 * into flag bits without going to the filesystem.  The active security module
 * is allowed to observe and poach options.  Any other options are passed over
 * to the filesystem to parse.
 *
 * This may be called multiple times for a context.
 *
 * Returns 0 on success and a negative error code on failure.  In the event of
 * failure, supplementary error information may have been set.
 */
int vfs_parse_fs_param(struct fs_context *fc, struct fs_parameter *param)
{
	int ret;

	//param必须包含key
	if (!param->key)
		return invalf(fc, "Unnamed parameter\n");

	//检查param是否为super block flags控制参数
	ret = vfs_parse_sb_flag(fc, param->key);
	if (ret != -ENOPARAM)
	    /*为sb_flags控制参数，已处理，返回*/
		return ret;

	/*param->key处理时，返回了NOPARAM*/
	ret = security_fs_context_parse_param(fc, param);
	if (ret != -ENOPARAM)
		/* Param belongs to the LSM or is disallowed by the LSM; so
		 * don't pass to the FS.
		 */
		return ret;

	//如果fs指定了参数解析函数，则调用
	if (fc->ops->parse_param) {
		ret = fc->ops->parse_param(fc, param);
		if (ret != -ENOPARAM)
			return ret;
	}

	/* If the filesystem doesn't take any arguments, give it the
	 * default handling of source.
	 */
	ret = vfs_parse_fs_param_source(fc, param);/*容许默认source参数（各fs可以不添加）*/
	if (ret != -ENOPARAM)
		/*遇到source参数，但解析成功或出错*/
		return ret;

	/*遇到了不认识的参数*/
	return invalf(fc, "%s: Unknown parameter '%s'",
		      fc->fs_type->name, param->key);
}
EXPORT_SYMBOL(vfs_parse_fs_param);

/**
 * vfs_parse_fs_string - Convenience function to just parse a string.
 * @fc: Filesystem context.
 * @key: Parameter name.
 * @value: Default value.
 * @v_size: Maximum number of bytes in the value.
 */
int vfs_parse_fs_string(struct fs_context *fc, const char *key,
			const char *value, size_t v_size/*value长度*/)
{
	int ret;

	/*构造解析用key*/
	struct fs_parameter param = {
		.key	= key,
		.type	= fs_value_is_flag,
		.size	= v_size,
	};

	/*复制value字符串*/
	if (value) {
		param.string = kmemdup_nul(value, v_size, GFP_KERNEL);
		if (!param.string)
			return -ENOMEM;
		param.type = fs_value_is_string;
	}

	//解析fs参数key
	ret = vfs_parse_fs_param(fc, &param);
	kfree(param.string);
	return ret;
}
EXPORT_SYMBOL(vfs_parse_fs_string);

/**
 * vfs_parse_monolithic_sep - Parse key[=val][,key[=val]]* mount data
 * @fc: The superblock configuration to fill in.
 * @data: The data to parse
 * @sep: callback for separating next option
 *
 * Parse a blob of data that's in key[=val][,key[=val]]* form with a custom
 * option separator callback.
 *
 * Returns 0 on success or the error returned by the ->parse_option() fs_context
 * operation on failure.
 */
int vfs_parse_monolithic_sep(struct fs_context *fc, void *data/*整块的参数*/,
			     char *(*sep)(char **))
{
	char *options = data, *key;
	int ret = 0;

	if (!options)
	    /*无选顶，返回*/
		return 0;

	ret = security_sb_eat_lsm_opts(options, &fc->security);
	if (ret)
		return ret;

	//按','号分隔options,并进行遍历
	while ((key = sep(&options)) != NULL) {
		if (*key) {
			size_t v_len = 0;
			char *value = strchr(key, '=');

			if (value) {
			    //忽略掉以'='开头的选项
				if (value == key)
					continue;
				*value++ = 0;
				v_len = strlen(value);
			}
			//解析单个key,value参数
			ret = vfs_parse_fs_string(fc, key, value, v_len);
			if (ret < 0)
				break;
		}
	}

	return ret;
}
EXPORT_SYMBOL(vfs_parse_monolithic_sep);

static char *vfs_parse_comma_sep(char **s)
{
	return strsep(s/*入出参*/, ",");/*按','分隔字符串s*/
}

/**
 * generic_parse_monolithic - Parse key[=val][,key[=val]]* mount data
 * @fc: The superblock configuration to fill in.
 * @data: The data to parse
 *
 * Parse a blob of data that's in key[=val][,key[=val]]* form.  This can be
 * called from the ->monolithic_mount_data() fs_context operation.
 *
 * Returns 0 on success or the error returned by the ->parse_option() fs_context
 * operation on failure.
 */
int generic_parse_monolithic(struct fs_context *fc, void *data)
{
	/*分隔data,采用fc->ops->parse_param遍历并解析参数*/
	return vfs_parse_monolithic_sep(fc, data, vfs_parse_comma_sep);
}
EXPORT_SYMBOL(generic_parse_monolithic);

/**
 * alloc_fs_context - Create a filesystem context.
 * @fs_type: The filesystem type.
 * @reference: The dentry from which this one derives (or NULL)
 * @sb_flags: Filesystem/superblock flags (SB_*)
 * @sb_flags_mask: Applicable members of @sb_flags
 * @purpose: The purpose that this configuration shall be used for.
 *
 * Open a filesystem and create a mount context.  The mount context is
 * initialised with the supplied flags and, if a submount/automount from
 * another superblock (referred to by @reference) is supplied, may have
 * parameters such as namespaces copied across from that superblock.
 */
static struct fs_context *alloc_fs_context(struct file_system_type *fs_type,
				      struct dentry *reference,
				      unsigned int sb_flags,
				      unsigned int sb_flags_mask,
				      enum fs_context_purpose purpose)
{
	/*创建并初始化fs_context*/
	int (*init_fs_context)(struct fs_context *);
	struct fs_context *fc;
	int ret = -ENOMEM;

	//申请fs context
	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	fc->purpose	= purpose;
	fc->sb_flags	= sb_flags;
	fc->sb_flags_mask = sb_flags_mask;
	//引用fc对应的fs_type
	fc->fs_type	= get_filesystem(fs_type);
	fc->cred	= get_current_cred();
	fc->net_ns	= get_net(current->nsproxy->net_ns);
	fc->log.prefix	= fs_type->name;/*前缀为文件系统名称*/

	mutex_init(&fc->uapi_mutex);

	/*依据不同目的设置user_ns*/
	switch (purpose) {
	case FS_CONTEXT_FOR_MOUNT:
		fc->user_ns = get_user_ns(fc->cred->user_ns);
		break;
	case FS_CONTEXT_FOR_SUBMOUNT:
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		break;
	case FS_CONTEXT_FOR_RECONFIGURE:
		atomic_inc(&reference->d_sb->s_active);
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		fc->root = dget(reference);
		break;
	}

	/* TODO: Make all filesystems support this unconditionally */
	init_fs_context = fc->fs_type->init_fs_context;
	if (!init_fs_context)
	    /*如果文件系统(fs_type)未提供此回调，则使用默认值*/
		init_fs_context = legacy_init_fs_context;

	/*通过函数使各fs初始化刚申请的fc*/
	ret = init_fs_context(fc);
	if (ret < 0)
		goto err_fc;
	//标记需要调用ops->free函数
	fc->need_free = true;
	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}

struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
					unsigned int sb_flags)
{
	/*为指定文件系统创建fs_context(目的是mount用）*/
	return alloc_fs_context(fs_type, NULL, sb_flags, 0,
					FS_CONTEXT_FOR_MOUNT);
}
EXPORT_SYMBOL(fs_context_for_mount);

struct fs_context *fs_context_for_reconfigure(struct dentry *dentry,
					unsigned int sb_flags,
					unsigned int sb_flags_mask)
{
	/*为指定文件系统创建fs_context(目的是reconfigure用）*/
	return alloc_fs_context(dentry->d_sb->s_type, dentry, sb_flags,
				sb_flags_mask, FS_CONTEXT_FOR_RECONFIGURE);
}
EXPORT_SYMBOL(fs_context_for_reconfigure);

/**
 * fs_context_for_submount: allocate a new fs_context for a submount
 * @type: file_system_type of the new context
 * @reference: reference dentry from which to copy relevant info
 *
 * Allocate a new fs_context suitable for a submount. This also ensures that
 * the fc->security object is inherited from @reference (if needed).
 */
struct fs_context *fs_context_for_submount(struct file_system_type *type,
					   struct dentry *reference)
{
	struct fs_context *fc;
	int ret;

	fc = alloc_fs_context(type, reference, 0, 0, FS_CONTEXT_FOR_SUBMOUNT);
	if (IS_ERR(fc))
		return fc;

	ret = security_fs_context_submount(fc, reference->d_sb);
	if (ret) {
		put_fs_context(fc);
		return ERR_PTR(ret);
	}

	return fc;
}
EXPORT_SYMBOL(fs_context_for_submount);

void fc_drop_locked(struct fs_context *fc)
{
	struct super_block *sb = fc->root->d_sb;
	dput(fc->root);
	fc->root = NULL;
	deactivate_locked_super(sb);
}

static void legacy_fs_context_free(struct fs_context *fc);

/**
 * vfs_dup_fs_context - Duplicate a filesystem context.
 * @src_fc: The context to copy.
 */
struct fs_context *vfs_dup_fs_context(struct fs_context *src_fc)
{
	struct fs_context *fc;
	int ret;

	//如果未提供dup回调，则返回不支持
	if (!src_fc->ops->dup)
		return ERR_PTR(-EOPNOTSUPP);

	//先制作一个src_fc副本
	fc = kmemdup(src_fc, sizeof(struct fs_context), GFP_KERNEL);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	mutex_init(&fc->uapi_mutex);

	fc->fs_private	= NULL;
	fc->s_fs_info	= NULL;
	fc->source	= NULL;
	fc->security	= NULL;
	get_filesystem(fc->fs_type);
	get_net(fc->net_ns);
	get_user_ns(fc->user_ns);
	get_cred(fc->cred);
	if (fc->log.log)
		refcount_inc(&fc->log.log->usage);

	/* Can't call put until we've called ->dup */
	//fs自定义的私有数据副本制作函数
	ret = fc->ops->dup(fc, src_fc);
	if (ret < 0)
		goto err_fc;

	ret = security_fs_context_dup(fc, src_fc);
	if (ret < 0)
		goto err_fc;
	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(vfs_dup_fs_context);

/**
 * logfc - Log a message to a filesystem context
 * @log: The filesystem context to log to, or NULL to use printk.
 * @prefix: A string to prefix the output with, or NULL.
 * @level: 'w' for a warning, 'e' for an error.  Anything else is a notice.
 * @fmt: The format of the buffer.
 */
void logfc(struct fc_log *log, const char *prefix, char level, const char *fmt, ...)
{
	va_list va;
	struct va_format vaf = {.fmt = fmt, .va = &va};

	va_start(va, fmt);
	if (!log) {
		switch (level) {
		case 'w':
			printk(KERN_WARNING "%s%s%pV\n", prefix ? prefix : "",
						prefix ? ": " : "", &vaf);
			break;
		case 'e':
			printk(KERN_ERR "%s%s%pV\n", prefix ? prefix : "",
						prefix ? ": " : "", &vaf);
			break;
		default:
			printk(KERN_NOTICE "%s%s%pV\n", prefix ? prefix : "",
						prefix ? ": " : "", &vaf);
			break;
		}
	} else {
		unsigned int logsize = ARRAY_SIZE(log->buffer);
		u8 index;
		char *q = kasprintf(GFP_KERNEL, "%c %s%s%pV\n", level,
						prefix ? prefix : "",
						prefix ? ": " : "", &vaf);

		index = log->head & (logsize - 1);
		BUILD_BUG_ON(sizeof(log->head) != sizeof(u8) ||
			     sizeof(log->tail) != sizeof(u8));
		if ((u8)(log->head - log->tail) == logsize) {
			/* The buffer is full, discard the oldest message */
			if (log->need_free & (1 << index))
				kfree(log->buffer[index]);
			log->tail++;
		}

		log->buffer[index] = q ? q : "OOM: Can't store error string";
		if (q)
			log->need_free |= 1 << index;
		else
			log->need_free &= ~(1 << index);
		log->head++;
	}
	va_end(va);
}
EXPORT_SYMBOL(logfc);

/*
 * Free a logging structure.
 */
static void put_fc_log(struct fs_context *fc)
{
	struct fc_log *log = fc->log.log;
	int i;

	if (log) {
		if (refcount_dec_and_test(&log->usage)) {
			fc->log.log = NULL;
			for (i = 0; i <= 7; i++)
				if (log->need_free & (1 << i))
					kfree(log->buffer[i]);
			kfree(log);
		}
	}
}

/**
 * put_fs_context - Dispose of a superblock configuration context.
 * @fc: The context to dispose of.
 */
void put_fs_context(struct fs_context *fc)
{
	struct super_block *sb;

	if (fc->root) {
		sb = fc->root->d_sb;
		dput(fc->root);
		fc->root = NULL;
		deactivate_super(sb);
	}

	//如有必要调用fs的自定义free
	if (fc->need_free && fc->ops && fc->ops->free)
		fc->ops->free(fc);

	security_free_mnt_opts(&fc->security);
	put_net(fc->net_ns);
	put_user_ns(fc->user_ns);
	put_cred(fc->cred);
	put_fc_log(fc);
	put_filesystem(fc->fs_type);
	kfree(fc->source);
	//释放fs context
	kfree(fc);
}
EXPORT_SYMBOL(put_fs_context);

/*
 * Free the config for a filesystem that doesn't support fs_context.
 */
static void legacy_fs_context_free(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;

	if (ctx) {
		if (ctx->param_type == LEGACY_FS_INDIVIDUAL_PARAMS)
			kfree(ctx->legacy_data);
		kfree(ctx);
	}
}

/*
 * Duplicate a legacy config.
 */
static int legacy_fs_context_dup(struct fs_context *fc, struct fs_context *src_fc)
{
	struct legacy_fs_context *ctx;
	struct legacy_fs_context *src_ctx = src_fc->fs_private;

	ctx = kmemdup(src_ctx, sizeof(*src_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	if (ctx->param_type == LEGACY_FS_INDIVIDUAL_PARAMS) {
		/*复制legacy_data(挂载参数）*/
		ctx->legacy_data = kmemdup(src_ctx->legacy_data,
					   src_ctx->data_size, GFP_KERNEL);
		if (!ctx->legacy_data) {
			kfree(ctx);
			return -ENOMEM;
		}
	}

	fc->fs_private = ctx;
	return 0;
}

/*
 * Add a parameter to a legacy config.  We build up a comma-separated list of
 * options.
 */
static int legacy_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	unsigned int size = ctx->data_size;
	size_t len = 0;
	int ret;

	/*处理source参数用*/
	ret = vfs_parse_fs_param_source(fc, param);
	if (ret != -ENOPARAM)
		return ret;

	/*不得为此类型*/
	if (ctx->param_type == LEGACY_FS_MONOLITHIC_PARAMS)
		return invalf(fc, "VFS: Legacy: Can't mix monolithic and individual options");

	switch (param->type) {
	case fs_value_is_string:
		len = 1 + param->size;
		fallthrough;
	case fs_value_is_flag:
		len += strlen(param->key);
		break;
	default:
		/*只容许以上两种参数类型*/
		return invalf(fc, "VFS: Legacy: Parameter type for '%s' not supported",
			      param->key);
	}

	if (size + len + 2 > PAGE_SIZE)
		/*参数内容过长*/
		return invalf(fc, "VFS: Legacy: Cumulative options too large");
	if (strchr(param->key, ',') ||
	    (param->type == fs_value_is_string &&
	     memchr(param->string, ',', param->size)))
		/*key，value中不得包含有','符*/
		return invalf(fc, "VFS: Legacy: Option '%s' contained comma",
			      param->key);

	/*初始化legacy_data*/
	if (!ctx->legacy_data) {
		ctx->legacy_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!ctx->legacy_data)
			return -ENOMEM;
	}

	if (size)
		ctx->legacy_data[size++] = ',';
	len = strlen(param->key);
	memcpy(ctx->legacy_data + size, param->key, len);/*将key写入到ctx->legacy_data*/
	size += len;
	if (param->type == fs_value_is_string) {
		ctx->legacy_data[size++] = '=';
		memcpy(ctx->legacy_data + size, param->string, param->size);/*将value写入到ctx->legacy_data*/
		size += param->size;
	}
	ctx->legacy_data[size] = '\0';
	ctx->data_size = size;
	ctx->param_type = LEGACY_FS_INDIVIDUAL_PARAMS;
	return 0;
}

/*
 * Add monolithic mount data.
 */
static int legacy_parse_monolithic(struct fs_context *fc, void *data)
{
	struct legacy_fs_context *ctx = fc->fs_private;

	if (ctx->param_type != LEGACY_FS_UNSET_PARAMS) {
		pr_warn("VFS: Can't mix monolithic and individual options\n");
		return -EINVAL;
	}

	ctx->legacy_data = data;
	ctx->param_type = LEGACY_FS_MONOLITHIC_PARAMS;
	if (!ctx->legacy_data)
		return 0;

	if (fc->fs_type->fs_flags & FS_BINARY_MOUNTDATA)
		return 0;
	return security_sb_eat_lsm_opts(ctx->legacy_data, &fc->security);
}

/*
 * Get a mountable root with the legacy mount command.
 */
static int legacy_get_tree(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	struct super_block *sb;
	struct dentry *root;

	//调用fs_type的mount函数进行挂载并返回root节点
	root = fc->fs_type->mount(fc->fs_type, fc->sb_flags,
				      fc->source, ctx->legacy_data);
	if (IS_ERR(root))
		return PTR_ERR(root);

	/*sb必须为非空*/
	sb = root->d_sb;
	BUG_ON(!sb);

	/*填充root节点*/
	fc->root = root;
	return 0;
}

/*
 * Handle remount.
 */
static int legacy_reconfigure(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	struct super_block *sb = fc->root->d_sb;

	if (!sb->s_op->remount_fs)
		/*super block如无remount_fs回调，则直接返回*/
		return 0;

	/*触发remount_fs*/
	return sb->s_op->remount_fs(sb, &fc->sb_flags,
				    ctx ? ctx->legacy_data : NULL);
}

/*系统默认的fs_context操作变量*/
const struct fs_context_operations legacy_fs_context_ops = {
	.free			= legacy_fs_context_free,
	.dup			= legacy_fs_context_dup,
	/*解析文件系统挂载参数（单个，默认）*/
	.parse_param		= legacy_parse_param,
	/*解析文件系统挂载参数（整体，默认）*/
	.parse_monolithic	= legacy_parse_monolithic,
	/*获取并填充文件系统的root节点，此函数会调用fc->fs_type->mount*/
	.get_tree		= legacy_get_tree,
	/*此函数会触发sb->s_op->remount_fs*/
	.reconfigure		= legacy_reconfigure,
};

/*
 * Initialise a legacy context for a filesystem that doesn't support
 * fs_context.
 */
static int legacy_init_fs_context(struct fs_context *fc)
{
	//默认fs context初始化函数
	fc->fs_private = kzalloc(sizeof(struct legacy_fs_context), GFP_KERNEL_ACCOUNT);
	if (!fc->fs_private)
		return -ENOMEM;
	fc->ops = &legacy_fs_context_ops;
	return 0;
}

/*解析mount传入的整块data*/
int parse_monolithic_mount_data(struct fs_context *fc, void *data)
{
	int (*monolithic_mount_data)(struct fs_context *, void *);

	monolithic_mount_data = fc->ops->parse_monolithic;
	if (!monolithic_mount_data)
	    /*未提供回调，使用默认回调*/
		monolithic_mount_data = generic_parse_monolithic;

	/*解析data参数，一次性传入整块*/
	return monolithic_mount_data(fc, data);
}

/*
 * Clean up a context after performing an action on it and put it into a state
 * from where it can be used to reconfigure a superblock.
 *
 * Note that here we do only the parts that can't fail; the rest is in
 * finish_clean_context() below and in between those fs_context is marked
 * FS_CONTEXT_AWAITING_RECONF.  The reason for splitup is that after
 * successful mount or remount we need to report success to userland.
 * Trying to do full reinit (for the sake of possible subsequent remount)
 * and failing to allocate memory would've put us into a nasty situation.
 * So here we only discard the old state and reinitialization is left
 * until we actually try to reconfigure.
 */
void vfs_clean_context(struct fs_context *fc)
{
	if (fc->need_free && fc->ops && fc->ops->free)
		fc->ops->free(fc);
	fc->need_free = false;
	fc->fs_private = NULL;
	fc->s_fs_info = NULL;
	fc->sb_flags = 0;
	security_free_mnt_opts(&fc->security);
	kfree(fc->source);
	fc->source = NULL;
	fc->exclusive = false;

	fc->purpose = FS_CONTEXT_FOR_RECONFIGURE;
	fc->phase = FS_CONTEXT_AWAITING_RECONF;
}

int finish_clean_context(struct fs_context *fc)
{
	int error;

	if (fc->phase != FS_CONTEXT_AWAITING_RECONF)
		return 0;

	if (fc->fs_type->init_fs_context)
		error = fc->fs_type->init_fs_context(fc);
	else
		error = legacy_init_fs_context(fc);
	if (unlikely(error)) {
		fc->phase = FS_CONTEXT_FAILED;
		return error;
	}
	fc->need_free = true;
	fc->phase = FS_CONTEXT_RECONF_PARAMS;
	return 0;
}
