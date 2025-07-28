/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_FLS_H_
#define _ASM_GENERIC_BITOPS_FLS_H_

/**
 * generic_fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */

//找最高位'１'的bit编号，自１开始编号，０表示没有‘１’
static __always_inline int generic_fls(unsigned int x)
{
	int r = 32;

	if (!x)
		return 0;//x为０，此时没有'1'，返回０
	if (!(x & 0xffff0000u)) {
		//高16位及其以上没有'1'
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		//高24位及其以上没有'1'
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		//高28位及其以上没有'1'
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		//高30位及其以上没有'1'
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		//32位没有‘1’
		x <<= 1;
		r -= 1;
	}
	return r;
}

#ifndef __HAVE_ARCH_FLS
#define fls(x) generic_fls(x)
#endif

#endif /* _ASM_GENERIC_BITOPS_FLS_H_ */
