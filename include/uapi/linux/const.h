/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* const.h: Macros for dealing with constants.  */

#ifndef _UAPI_LINUX_CONST_H
#define _UAPI_LINUX_CONST_H

/* Some constant macros are used in both assembler and
 * C code.  Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally.  We
 * use the following macros to deal with this.
 *
 * Similarly, _AT() will cast an expression with a type in C, but
 * leave it unchanged in asm.
 */

#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))

#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
/*x按照mask进行对齐*/
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

/*先使n按d进行对齐，再除以d,取其的整数商（向上取整）
 * 例如n=3,d=2 有3/2=1.5
 * 应用本函数后，(3+(2-1))/2 = 4/2 = 2
 * */
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#endif /* _UAPI_LINUX_CONST_H */
