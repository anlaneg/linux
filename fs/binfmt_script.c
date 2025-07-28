// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/binfmt_script.c
 *
 *  Copyright (C) 1996  Martin von Löwis
 *  original #!-checking implemented by tytso.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/binfmts.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/err.h>
#include <linux/fs.h>

static inline bool spacetab(char c) { return c == ' ' || c == '\t'; }
static inline const char *next_non_spacetab(const char *first, const char *last)
{
    /*从first到last查找首个非空格/非table字符并返回其对应的位置*/
	for (; first <= last; first++)
		if (!spacetab(*first))
			return first;
	return NULL;
}
static inline const char *next_terminator(const char *first, const char *last)
{
	for (; first <= last; first++)
		if (spacetab(*first) || !*first)
			return first;
	return NULL;
}

/*实现脚本加载*/
static int load_script(struct linux_binprm *bprm)
{
	const char *i_name, *i_sep, *i_arg, *i_end, *buf_end;
	struct file *file;
	int retval;

	/* Not ours to exec if we don't start with "#!". */
	//如果不以"#!"开头，则无法处理
	if ((bprm->buf[0] != '#') || (bprm->buf[1] != '!'))
		return -ENOEXEC;

	/*
	 * This section handles parsing the #! line into separate
	 * interpreter path and argument strings. We must be careful
	 * because bprm->buf is not yet guaranteed to be NUL-terminated
	 * (though the buffer will have trailing NUL padding when the
	 * file size was smaller than the buffer size).
	 *
	 * We do not want to exec a truncated interpreter path, so either
	 * we find a newline (which indicates nothing is truncated), or
	 * we find a space/tab/NUL after the interpreter path (which
	 * itself may be preceded by spaces/tabs). Truncating the
	 * arguments is fine: the interpreter can re-read the script to
	 * parse them on its own.
	 */
	/*指向buffer结尾部分*/
	buf_end = bprm->buf + sizeof(bprm->buf) - 1;
	/*在buffer中查找'\n'符*/
	i_end = strnchr(bprm->buf, sizeof(bprm->buf), '\n');
	if (!i_end) {
	    /*没有找到换行符，自buf[2]开始，至buf_end，查找首个非（空格，TAB）字符，定义为i_end*/
		i_end = next_non_spacetab(bprm->buf + 2, buf_end);
		if (!i_end)
		    /*没有找到i_end,即整个buf全是TAB与空格*/
			return -ENOEXEC; /* Entire buf is spaces/tabs */
		/*
		 * If there is no later space/tab/NUL we must assume the
		 * interpreter path is truncated.
		 */
		if (!next_terminator(i_end, buf_end))
		    /*i_end与buf_end间不存在（空格，TAB，'\0')字符，失败*/
			return -ENOEXEC;
		/*bprm->buf中存储的文字，没有包含换行符，但存在两个terminal字符，
		 * 这种情况下i_end指向字符串结尾*/
		i_end = buf_end;
	}

	/* Trim any trailing spaces/tabs from i_end */
	while (spacetab(i_end[-1]))
		i_end--;/*回退到最后一个非（空格，TAB）字符*/

	/* Skip over leading spaces/tabs */
	/*跳过前导的空字符，获得解析器名称起始位置*/
	i_name = next_non_spacetab(bprm->buf+2, i_end);
	if (!i_name || (i_name == i_end))
		return -ENOEXEC; /* No interpreter name found */

	/* Is there an optional argument? */
	i_arg = NULL;
	i_sep = next_terminator(i_name, i_end);
	if (i_sep && (*i_sep != '\0'))
	    /*i_sep存在，则在i_sep,i_end之间取解析器参数*/
		i_arg = next_non_spacetab(i_sep, i_end);

	/*
	 * If the script filename will be inaccessible after exec, typically
	 * because it is a "/dev/fd/<fd>/.." path against an O_CLOEXEC fd, give
	 * up now (on the assumption that the interpreter will want to load
	 * this file).
	 */
	if (bprm->interp_flags & BINPRM_FLAGS_PATH_INACCESSIBLE)
		return -ENOENT;

	/*
	 * OK, we've parsed out the interpreter name and
	 * (optional) argument.
	 * Splice in (1) the interpreter's name for argv[0]
	 *           (2) (optional) argument to interpreter
	 *           (3) filename of shell script (replace argv[0])
	 *
	 * This is done in reverse order, because of how the
	 * user environment and arguments are stored.
	 */
	retval = remove_arg_zero(bprm);
	if (retval)
		return retval;
	retval = copy_string_kernel(bprm->interp, bprm);
	if (retval < 0)
		return retval;
	bprm->argc++;
	*((char *)i_end) = '\0';
	if (i_arg) {
		*((char *)i_sep) = '\0';
		retval = copy_string_kernel(i_arg, bprm);
		if (retval < 0)
			return retval;
		bprm->argc++;
	}
	retval = copy_string_kernel(i_name, bprm);
	if (retval)
		return retval;
	bprm->argc++;
	/*变更解析器(interp)为i_name*/
	retval = bprm_change_interp(i_name, bprm);
	if (retval < 0)
		return retval;

	/*
	 * OK, now restart the process with the interpreter's dentry.
	 */
	file = open_exec(i_name);/*重新执行i_name文件*/
	if (IS_ERR(file))
		return PTR_ERR(file);

	bprm->interpreter = file;
	return 0;
}

static struct linux_binfmt script_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_script,//脚本加载
};

static int __init init_script_binfmt(void)
{
    /*注册script可执行文件格式*/
	register_binfmt(&script_format);
	return 0;
}

static void __exit exit_script_binfmt(void)
{
    /*移除script可执行文件格式*/
	unregister_binfmt(&script_format);
}

core_initcall(init_script_binfmt);
module_exit(exit_script_binfmt);
MODULE_DESCRIPTION("Kernel support for scripts starting with #!");
MODULE_LICENSE("GPL");
