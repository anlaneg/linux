#ifndef _LINUX_CONST_H
#define _LINUX_CONST_H

#include <vdso/const.h>

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
//这里对此宏有详细解释：https://stackoverflow.com/questions/49481217/linux-kernels-is-constexpr-macro
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#endif /* _LINUX_CONST_H */
