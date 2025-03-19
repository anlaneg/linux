/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/fs_context.h>
#include <linux/fs_parser.h>

struct ovl_fs;
struct ovl_config;

extern const struct fs_parameter_spec ovl_parameter_spec[];
extern const struct constant_table ovl_parameter_redirect_dir[];

/* The set of options that user requested explicitly via mount options */
struct ovl_opt_set {
	bool metacopy;
	bool redirect;
	bool nfs_export;
	bool index;
};

#define OVL_MAX_STACK 500

struct ovl_fs_context_layer {
	char *name;/*目录路径*/
	struct path path;/*名称对应的path*/
};

struct ovl_fs_context {
	struct path upper;/* 对应upperdir参数指明的路径值对应的path*/
	struct path work;/*  对应workdir 参数指明的路径值对应的path*/
	size_t capacity;/*lower数组有效长度（动态增长）*/
	size_t nr; /* includes nr_data 总layer数目，包括data layer*/
	size_t nr_data;/*data layer的数目*/
	struct ovl_opt_set set;
	struct ovl_fs_context_layer *lower;/*数组，有效长度为capacity，用于存储lowerdir（包含data layer)*/
	/*保存用户在挂载期间提供的lowerdir配置*/
	char *lowerdir_all; /* user provided lowerdir string */
};

int ovl_init_fs_context(struct fs_context *fc);
void ovl_free_fs(struct ovl_fs *ofs);
int ovl_fs_params_verify(const struct ovl_fs_context *ctx,
			 struct ovl_config *config);
int ovl_show_options(struct seq_file *m, struct dentry *dentry);
const char *ovl_xino_mode(struct ovl_config *config);
