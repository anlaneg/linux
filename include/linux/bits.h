/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITS_H
#define __LINUX_BITS_H

#include <linux/const.h>
#include <vdso/bits.h>
#include <asm/bitsperlong.h>

#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
/*一个字节占用多少bits*/
#define BITS_PER_BYTE		8

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#if !defined(__ASSEMBLY__)
#include <linux/build_bug.h>
/*校验l<h,否则报错*/
#define GENMASK_INPUT_CHECK(h, l) \
	(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
		__is_constexpr((l) > (h)), (l) > (h), 0)))
#else
/*
 * BUILD_BUG_ON_ZERO is not available in h files included from asm files,
 * disable the input check if that is the case.
 */
#define GENMASK_INPUT_CHECK(h, l) 0
#endif

/*保证l(low)位到h(high)位全为1*/
#define __GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) /*将l位后面全部清为0，l位前面全置为1*/& \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h)))/*将h位前面全置为0*/)
/*使用_GENMASK构造(l,h)之间bit全为1*/
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))

#define __GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK_ULL(h, l))

#endif	/* __LINUX_BITS_H */
