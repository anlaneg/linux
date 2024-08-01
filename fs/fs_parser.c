// SPDX-License-Identifier: GPL-2.0-or-later
/* Filesystem parameter parser.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/namei.h>
#include "internal.h"

static const struct constant_table bool_names[] = {
	{ "0",		false },
	{ "1",		true },
	{ "false",	false },
	{ "no",		false },
	{ "true",	true },
	{ "yes",	true },
	{ },
};

//查询常量表，按name匹配，一旦有表项命中，则返回表项,否则返回NULL
static const struct constant_table *
__lookup_constant(const struct constant_table *tbl, const char *name)
{
	for ( ; tbl->name; tbl++)
		if (strcmp(name, tbl->name) == 0)
			return tbl;
	return NULL;
}

/**
 * lookup_constant - Look up a constant by name in an ordered table
 * @tbl: The table of constants to search.
 * @name: The name to look up.
 * @not_found: The value to return if the name is not found.
 */
int lookup_constant(const struct constant_table *tbl/*常量字符串表*/, const char *name/*要查询的内容*/, int not_found/*失配对应的返回值*/)
{
    //查询常量表，如果有命中，则返回表项对应的value,否则返回失配值（not_found)
	const struct constant_table *p = __lookup_constant(tbl, name);

	return p ? p->value : not_found;
}
EXPORT_SYMBOL(lookup_constant);

//是否flag参数
static inline bool is_flag(const struct fs_parameter_spec *p)
{
	return p->type == NULL;
}

//检查param由哪个fs_parameter_spec定义
static const struct fs_parameter_spec *fs_lookup_key(
	const struct fs_parameter_spec *desc/*支持的参数列表*/,
	struct fs_parameter *param/*待匹配的参数*/, bool *negated/*出参，指明是否反选项*/)
{
	const struct fs_parameter_spec *p, *other = NULL;
	const char *name = param->key;/*取参数名称*/
	bool want_flag = param->type == fs_value_is_flag;

	*negated = false;
	/*遍历支持的fs参数列表*/
	for (p = desc; p->name; p++) {
	    //跳过参数名称不匹配的项
		if (strcmp(p->name, name) != 0)
			continue;
		if (likely(is_flag(p) == want_flag))
		    /*是flag,且名称匹配，直接返回*/
			return p;
		/*记录最后一个匹配的项做为备选项*/
		other = p;
	}
	if (want_flag) {
	    /*期待flag,但没有匹配，尝试匹配相反选项noXXX*/
		if (name[0] == 'n' && name[1] == 'o' && name[2]) {
			for (p = desc; p->name; p++) {
				if (strcmp(p->name, name + 2) != 0)
					continue;
				//跳过无反选项的参数
				if (!(p->flags & fs_param_neg_with_no))
					continue;
				*negated = true;
				return p;
			}
		}
	}
	/*返回命中的选项*/
	return other;
}

/*
 * fs_parse - Parse a filesystem configuration parameter
 * @fc: The filesystem context to log errors through.
 * @desc: The parameter description to use.
 * @param: The parameter.
 * @result: Where to place the result of the parse
 *
 * Parse a filesystem configuration parameter and attempt a conversion for a
 * simple parameter for which this is requested.  If successful, the determined
 * parameter ID is placed into @result->key, the desired type is indicated in
 * @result->t and any converted value is placed into an appropriate member of
 * the union in @result.
 *
 * The function returns the parameter number if the parameter was matched,
 * -ENOPARAM if it wasn't matched and @desc->ignore_unknown indicated that
 * unknown parameters are okay and -EINVAL if there was a conversion issue or
 * the parameter wasn't recognised and unknowns aren't okay.
 */
int __fs_parse(struct p_log *log,
	     const struct fs_parameter_spec *desc/*fs参数结构体说明列表，最后一项为NULL*/,
	     struct fs_parameter *param/*入参，当前待解析的参数*/,
	     struct fs_parse_result *result/*出参，转换后的参数值*/)
{
	const struct fs_parameter_spec *p;

	result->uint_64 = 0;

	p = fs_lookup_key(desc, param, &result->negated);
	if (!p)
	    /*未查找到此参数*/
		return -ENOPARAM;

	/*告警，不建议再使用此参数*/
	if (p->flags & fs_param_deprecated)
		warn_plog(log, "Deprecated parameter '%s'", param->key);

	/* Try to turn the type we were given into the type desired by the
	 * parameter and give an error if we can't.
	 */
	if (is_flag(p)) {
	    /*命中的参数要求是flag,但参数并不是flags*/
		if (param->type != fs_value_is_flag)
			return inval_plog(log, "Unexpected value for '%s'",
				      param->key);
		result->boolean = !result->negated;
	} else  {
	    /*完成type回调，实现参数到result的配置转换*/
		int ret = p->type(log, p, param, result);
		if (ret)
			return ret;
	}
	return p->opt;
}
EXPORT_SYMBOL(__fs_parse);

/**
 * fs_lookup_param - Look up a path referred to by a parameter
 * @fc: The filesystem context to log errors through.
 * @param: The parameter.
 * @want_bdev: T if want a blockdev
 * @flags: Pathwalk flags passed to filename_lookup()
 * @_path: The result of the lookup
 */
int fs_lookup_param(struct fs_context *fc,
		    struct fs_parameter *param,
		    bool want_bdev,
		    unsigned int flags,
		    struct path *_path)
{
	struct filename *f;
	bool put_f;
	int ret;

	switch (param->type) {
	case fs_value_is_string:
		f = getname_kernel(param->string);
		if (IS_ERR(f))
			return PTR_ERR(f);
		put_f = true;
		break;
	case fs_value_is_filename:
		f = param->name;
		put_f = false;
		break;
	default:
		return invalf(fc, "%s: not usable as path", param->key);
	}

	ret = filename_lookup(param->dirfd, f, flags, _path, NULL);
	if (ret < 0) {
		errorf(fc, "%s: Lookup failure for '%s'", param->key, f->name);
		goto out;
	}

	if (want_bdev &&
	    !S_ISBLK(d_backing_inode(_path->dentry)->i_mode)) {
		path_put(_path);
		_path->dentry = NULL;
		_path->mnt = NULL;
		errorf(fc, "%s: Non-blockdev passed as '%s'",
		       param->key, f->name);
		ret = -ENOTBLK;
	}

out:
	if (put_f)
		putname(f);
	return ret;
}
EXPORT_SYMBOL(fs_lookup_param);

static int fs_param_bad_value(struct p_log *log, struct fs_parameter *param)
{
	return inval_plog(log, "Bad value for '%s'", param->key);
}

/*文件系统参数转bool类型*/
int fs_param_is_bool(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	int b;
	if (param->type != fs_value_is_string)
		return fs_param_bad_value(log, param);
	if (!*param->string && (p->flags & fs_param_can_be_empty))
		return 0;
	b = lookup_constant(bool_names, param->string, -1);
	if (b == -1)
		return fs_param_bad_value(log, param);
	result->boolean = b;
	return 0;
}
EXPORT_SYMBOL(fs_param_is_bool);

/*文件系统参数转u32类型*/
int fs_param_is_u32(struct p_log *log, const struct fs_parameter_spec *p/*转换源的元数据*/,
		    struct fs_parameter *param/*转换源*/, struct fs_parse_result *result/*转换结果*/)
{
	/*此情况下data用于表示数据基数*/
	int base = (unsigned long)p->data;
	if (param->type != fs_value_is_string)
		/*必须为string类型*/
		return fs_param_bad_value(log, param);
	if (!*param->string && (p->flags & fs_param_can_be_empty))
		/*容许为空时，采用0*/
		return 0;
	if (kstrtouint(param->string, base, &result->uint_32) < 0)
		return fs_param_bad_value(log, param);
	return 0;
}
EXPORT_SYMBOL(fs_param_is_u32);

/*文件系统参数转s32类型*/
int fs_param_is_s32(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	if (param->type != fs_value_is_string)
		return fs_param_bad_value(log, param);
	if (!*param->string && (p->flags & fs_param_can_be_empty))
		return 0;
	if (kstrtoint(param->string, 0, &result->int_32) < 0)
		return fs_param_bad_value(log, param);
	return 0;
}
EXPORT_SYMBOL(fs_param_is_s32);

/*文件系统参数转u64类型*/
int fs_param_is_u64(struct p_log *log, const struct fs_parameter_spec *p,
		    struct fs_parameter *param, struct fs_parse_result *result)
{
	if (param->type != fs_value_is_string)
		return fs_param_bad_value(log, param);
	if (!*param->string && (p->flags & fs_param_can_be_empty))
		return 0;
	if (kstrtoull(param->string, 0, &result->uint_64) < 0)
		return fs_param_bad_value(log, param);
	return 0;
}
EXPORT_SYMBOL(fs_param_is_u64);

/*文件系统参数值转枚举类型*/
int fs_param_is_enum(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	const struct constant_table *c;
	if (param->type != fs_value_is_string)
		return fs_param_bad_value(log, param);
	if (!*param->string && (p->flags & fs_param_can_be_empty))
		return 0;
	/*此时p->data是一个常量字符串table*/
	c = __lookup_constant(p->data, param->string);
	if (!c)
		return fs_param_bad_value(log, param);
	result->uint_32 = c->value;
	return 0;
}
EXPORT_SYMBOL(fs_param_is_enum);

/*文件系统参数转字符串类型*/
int fs_param_is_string(struct p_log *log, const struct fs_parameter_spec *p,
		       struct fs_parameter *param, struct fs_parse_result *result)
{
	if (param->type != fs_value_is_string ||
	    (!*param->string && !(p->flags & fs_param_can_be_empty)))
		return fs_param_bad_value(log, param);
	return 0;
}
EXPORT_SYMBOL(fs_param_is_string);

int fs_param_is_blob(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	if (param->type != fs_value_is_blob)
		return fs_param_bad_value(log, param);
	return 0;
}
EXPORT_SYMBOL(fs_param_is_blob);

int fs_param_is_fd(struct p_log *log, const struct fs_parameter_spec *p,
		  struct fs_parameter *param, struct fs_parse_result *result)
{
	switch (param->type) {
	case fs_value_is_string:
		if ((!*param->string && !(p->flags & fs_param_can_be_empty)) ||
		    kstrtouint(param->string, 0, &result->uint_32) < 0)
			break;
		if (result->uint_32 <= INT_MAX)
			return 0;
		break;
	case fs_value_is_file:
		result->uint_32 = param->dirfd;
		if (result->uint_32 <= INT_MAX)
			return 0;
		break;
	default:
		break;
	}
	return fs_param_bad_value(log, param);
}
EXPORT_SYMBOL(fs_param_is_fd);

int fs_param_is_blockdev(struct p_log *log, const struct fs_parameter_spec *p,
		  struct fs_parameter *param, struct fs_parse_result *result)
{
	return 0;
}
EXPORT_SYMBOL(fs_param_is_blockdev);

int fs_param_is_path(struct p_log *log, const struct fs_parameter_spec *p,
		     struct fs_parameter *param, struct fs_parse_result *result)
{
	return 0;
}
EXPORT_SYMBOL(fs_param_is_path);

#ifdef CONFIG_VALIDATE_FS_PARSER
/**
 * validate_constant_table - Validate a constant table
 * @tbl: The constant table to validate.
 * @tbl_size: The size of the table.
 * @low: The lowest permissible value.
 * @high: The highest permissible value.
 * @special: One special permissible value outside of the range.
 */
bool validate_constant_table(const struct constant_table *tbl, size_t tbl_size,
			     int low, int high, int special)
{
	size_t i;
	bool good = true;

	if (tbl_size == 0) {
		pr_warn("VALIDATE C-TBL: Empty\n");
		return true;
	}

	for (i = 0; i < tbl_size; i++) {
		if (!tbl[i].name) {
			pr_err("VALIDATE C-TBL[%zu]: Null\n", i);
			good = false;
		} else if (i > 0 && tbl[i - 1].name) {
			int c = strcmp(tbl[i-1].name, tbl[i].name);

			if (c == 0) {
				pr_err("VALIDATE C-TBL[%zu]: Duplicate %s\n",
				       i, tbl[i].name);
				good = false;
			}
			if (c > 0) {
				pr_err("VALIDATE C-TBL[%zu]: Missorted %s>=%s\n",
				       i, tbl[i-1].name, tbl[i].name);
				good = false;
			}
		}

		if (tbl[i].value != special &&
		    (tbl[i].value < low || tbl[i].value > high)) {
			pr_err("VALIDATE C-TBL[%zu]: %s->%d const out of range (%d-%d)\n",
			       i, tbl[i].name, tbl[i].value, low, high);
			good = false;
		}
	}

	return good;
}

/**
 * fs_validate_description - Validate a parameter description
 * @name: The parameter name to search for.
 * @desc: The parameter description to validate.
 */
bool fs_validate_description(const char *name,
	const struct fs_parameter_spec *desc)
{
	const struct fs_parameter_spec *param, *p2;
	bool good = true;

	for (param = desc; param->name; param++) {
		/* Check for duplicate parameter names */
		for (p2 = desc; p2 < param; p2++) {
			if (strcmp(param->name, p2->name) == 0) {
				if (is_flag(param) != is_flag(p2))
					continue;
				pr_err("VALIDATE %s: PARAM[%s]: Duplicate\n",
				       name, param->name);
				good = false;
			}
		}
	}
	return good;
}
#endif /* CONFIG_VALIDATE_FS_PARSER */
