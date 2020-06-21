// SPDX-License-Identifier: GPL-2.0-only

#define __printf(a, b)  __attribute__((format(printf, a, b)))

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <linux/compiler.h>
#include <perf/core.h>
#include <internal/lib.h>
#include "internal.h"

//提供默认的日志输出函数
static int __base_pr(enum libperf_print_level level __maybe_unused, const char *format,
		     va_list args)
{
	return vfprintf(stderr, format, args);
}

//记录注册的日志输出函数
static libperf_print_fn_t __libperf_pr = __base_pr;

/*调用libperf的日志输出函数完成内容输出*/
__printf(2, 3)
void libperf_print(enum libperf_print_level level, const char *format, ...)
{
	va_list args;

	if (!__libperf_pr)
		return;

	va_start(args, format);
	__libperf_pr(level, format, args);
	va_end(args);
}

/*注册perf的输出函数*/
void libperf_init(libperf_print_fn_t fn)
{
	page_size = sysconf(_SC_PAGE_SIZE);
	__libperf_pr = fn;
}
