/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Filesystem parameter description and parser
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_FS_PARSER_H
#define _LINUX_FS_PARSER_H

#include <linux/fs_context.h>

struct path;

struct constant_table {
	const char	*name;
	int		value;
};

struct fs_parameter_spec;
struct fs_parse_result;
typedef int fs_param_type(struct p_log *,
			  const struct fs_parameter_spec *,
			  struct fs_parameter *,
			  struct fs_parse_result *);
/*
 * The type of parameter expected.
 */
fs_param_type fs_param_is_bool, fs_param_is_u32, fs_param_is_s32, fs_param_is_u64,
	fs_param_is_enum, fs_param_is_string, fs_param_is_blob, fs_param_is_blockdev,
	fs_param_is_path, fs_param_is_fd;

/*
 * Specification of the type of value a parameter wants.
 *
 * Note that the fsparam_flag(), fsparam_string(), fsparam_u32(), ... macros
 * should be used to generate elements of this type.
 */
struct fs_parameter_spec {
	/*文件参数名称*/
	const char		*name;
	//此值为NULL时，标记是一个flag参数，否则表示回调函数，用于完成字符串参数到值的转换
	fs_param_type		*type;	/* The desired parameter type */
	//选项编号
	u8			opt;	/* Option number (returned by fs_parse()) */
	/*文件参数标记，如下示，例如容许为空*/
	unsigned short		flags;
	//指明noxxx是反选项
#define fs_param_neg_with_no	0x0002	/* "noxxx" is negative param */
	/*容许value值为空*/
#define fs_param_can_be_empty	0x0004	/* "xxx=" is allowed */
	/*指明是不在推荐的参数*/
#define fs_param_deprecated	0x0008	/* The param is deprecated */
	const void		*data;/*各type回调进行解释，例如u32类型时，可表示数据基数，例如10进制*/
};

/*
 * Result of parse.
 */
struct fs_parse_result {
    //是否指明的为反选项
	bool			negated;	/* T if param was "noxxx" */
	union {
	    //boolean类型取值
		bool		boolean;	/* For spec_bool */
		int		int_32;		/* For spec_s32/spec_enum */
		unsigned int	uint_32;	/* For spec_u32{,_octal,_hex}/spec_enum */
		u64		uint_64;	/* For spec_u64 */
	};
};

extern int __fs_parse(struct p_log *log,
		    const struct fs_parameter_spec *desc,
		    struct fs_parameter *value,
		    struct fs_parse_result *result);

static inline int fs_parse(struct fs_context *fc,
	     const struct fs_parameter_spec *desc/*fs参数结构体说明列表，最后一项为NULL*/,
	     struct fs_parameter *param/*入参，当前待解析的参数*/,
	     struct fs_parse_result *result/*出参，param被转换后结果*/)
{
	/*在desc列表中查找param参数，如果命中，result用于记录param被转换后的结果*/
	return __fs_parse(&fc->log, desc, param, result);
}

extern int fs_lookup_param(struct fs_context *fc,
			   struct fs_parameter *param,
			   bool want_bdev,
			   unsigned int flags,
			   struct path *_path);

extern int lookup_constant(const struct constant_table tbl[], const char *name, int not_found);

#ifdef CONFIG_VALIDATE_FS_PARSER
extern bool validate_constant_table(const struct constant_table *tbl, size_t tbl_size,
				    int low, int high, int special);
extern bool fs_validate_description(const char *name,
				    const struct fs_parameter_spec *desc);
#else
static inline bool validate_constant_table(const struct constant_table *tbl, size_t tbl_size,
					   int low, int high, int special)
{ return true; }
static inline bool fs_validate_description(const char *name,
					   const struct fs_parameter_spec *desc)
{ return true; }
#endif

/*
 * Parameter type, name, index and flags element constructors.  Use as:
 *
 *  fsparam_xxxx("foo", Opt_foo)
 *
 * If existing helpers are not enough, direct use of __fsparam() would
 * work, but any such case is probably a sign that new helper is needed.
 * Helpers will remain stable; low-level implementation may change.
 */
#define __fsparam(TYPE, NAME, OPT, FLAGS, DATA) \
	{ \
		.name = NAME/*参数名称*/, \
		.opt = OPT/*参数对应的选项id*/, \
		.type = TYPE/*参数对应的类型回调*/, \
		.flags = FLAGS/*参数对应的flags*/, \
		.data = DATA /*叁数对应的data*/\
	}

#define fsparam_flag(NAME, OPT)	__fsparam(NULL, NAME, OPT, 0, NULL)
#define fsparam_flag_no(NAME/*参数名称*/, OPT/*参数对应的选项id*/) \
			__fsparam(NULL/*type置为NULL*/, NAME, OPT, fs_param_neg_with_no, NULL)
#define fsparam_bool(NAME, OPT)	__fsparam(fs_param_is_bool, NAME, OPT, 0, NULL)
#define fsparam_u32(NAME/*参数名称*/, OPT/*参数对应的选项id*/)	__fsparam(fs_param_is_u32/*参数值转u32*/, NAME, OPT, 0, NULL)
#define fsparam_u32oct(NAME, OPT) \
			__fsparam(fs_param_is_u32, NAME, OPT, 0, (void *)8/*指明为8进制*/)
#define fsparam_u32hex(NAME, OPT) \
			__fsparam(fs_param_is_u32_hex, NAME, OPT, 0, (void *)16/*指明为8进制*/)
#define fsparam_s32(NAME, OPT)	__fsparam(fs_param_is_s32, NAME, OPT, 0, NULL)
#define fsparam_u64(NAME, OPT)	__fsparam(fs_param_is_u64, NAME, OPT, 0, NULL)
#define fsparam_enum(NAME, OPT, array)	__fsparam(fs_param_is_enum/*参数值为enum类型*/, NAME, OPT, 0, array/*类型为enum,array为enum的常量字符串表形式*/)
#define fsparam_string(NAME, OPT) \
				__fsparam(fs_param_is_string, NAME, OPT, 0, NULL)
#define fsparam_blob(NAME, OPT)	__fsparam(fs_param_is_blob, NAME, OPT, 0, NULL)
#define fsparam_bdev(NAME, OPT)	__fsparam(fs_param_is_blockdev, NAME, OPT, 0, NULL)
#define fsparam_path(NAME, OPT)	__fsparam(fs_param_is_path, NAME, OPT, 0, NULL)
#define fsparam_fd(NAME, OPT)	__fsparam(fs_param_is_fd, NAME, OPT, 0, NULL)

#endif /* _LINUX_FS_PARSER_H */
