// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdarg.h>
#include "debug.h"
#include "debug-internal.h"

/*默认通过vfprintf进行日志输出*/
static int __base_pr(const char *format, ...)
{
	va_list args;
	int err;

	va_start(args, format);
	err = vfprintf(stderr, format, args);
	va_end(args);
	return err;
}

libapi_print_fn_t __pr_warn    = __base_pr;
libapi_print_fn_t __pr_info    = __base_pr;
libapi_print_fn_t __pr_debug;

/*设置warn,info,debug日志函数*/
void libapi_set_print(libapi_print_fn_t warn,
		      libapi_print_fn_t info,
		      libapi_print_fn_t debug)
{
	__pr_warn    = warn;
	__pr_info    = info;
	__pr_debug   = debug;
}
