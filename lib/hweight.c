// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/bitops.h>
#include <asm/types.h>

/**
 * hweightN - returns the hamming weight of a N-bit word
 * @x: the word to weigh
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 */

unsigned int __sw_hweight32(unsigned int w)
{
#ifdef CONFIG_ARCH_HAS_FAST_MULTIPLIER
	w -= (w >> 1) & 0x55555555;
	w =  (w & 0x33333333) + ((w >> 2) & 0x33333333);
	w =  (w + (w >> 4)) & 0x0f0f0f0f;
	return (w * 0x01010101) >> 24;
#else
	unsigned int res = w - ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
#endif
}
EXPORT_SYMBOL(__sw_hweight32);

unsigned int __sw_hweight16(unsigned int w)
{
	unsigned int res = w - ((w >> 1) & 0x5555);
	res = (res & 0x3333) + ((res >> 2) & 0x3333);
	res = (res + (res >> 4)) & 0x0F0F;
	return (res + (res >> 8)) & 0x00FF;
}
EXPORT_SYMBOL(__sw_hweight16);

unsigned int __sw_hweight8(unsigned int w)
{
    /*
     * https://www.cnblogs.com/graphics/archive/2010/06/21/1752421.html
     * 已知w是一个8bits的值，将它的每一位都看成是一个未知数。
     * （即有a,b,c,d,e,f,g,h 共八未知数，未知数取值只能是{0,1})
     * 则有w=128a+64b+32c+16d+8e+4f+2g+h
     *    w>>1 即为 (w>>1)=64a+32b+16c+8d+4e+2f+g
     *    res=w-((w>>1) & 0x55) = (128a+64b+32c+16d+8e+4f+2g+h) - (64a+16c+4e+g)\
     *                      = 64a+64b+16c+16d+4e+4f+g+h (此操作下，a,b,c,d,e...8个未知数仍在）
     *    res = (res & 0x33) + ((res >> 2) & 0x33) =
     *      (16c+16d+g+h) + ((16a+16b+4c+4d+e+f) & 0x33)
     *      = (16c+16d+g+h) + (16a+16b+e+f) = 16a+16b+16c+16d+e+f+g+h
     *
     *    (res + (res >> 4)) & 0x0f =
     *      ((16a+16b+16c+16d+e+f+g+h) + (a+b+c+d)) & 0x0f
     *      = （16a+16b+16c+16d+(a+b+c+d+e+f+g+h)）& 0x0f
     *   通过讨论可知道，如果a，b，c，d中有‘1’,则结果会大于16，与0xf与可清除这部分计算
     *      = a+b+c+d+e+f+g+h 即获得w中有多少个1
     * */
	unsigned int res = w - ((w >> 1) & 0x55);
	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res + (res >> 4)) & 0x0F;
}
EXPORT_SYMBOL(__sw_hweight8);

unsigned long __sw_hweight64(__u64 w)
{
#if BITS_PER_LONG == 32
	return __sw_hweight32((unsigned int)(w >> 32)) +
	       __sw_hweight32((unsigned int)w);
#elif BITS_PER_LONG == 64
#ifdef CONFIG_ARCH_HAS_FAST_MULTIPLIER
	w -= (w >> 1) & 0x5555555555555555ul;
	w =  (w & 0x3333333333333333ul) + ((w >> 2) & 0x3333333333333333ul);
	w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0ful;
	return (w * 0x0101010101010101ul) >> 56;
#else
	__u64 res = w - ((w >> 1) & 0x5555555555555555ul);
	res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
	res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
	res = res + (res >> 8);
	res = res + (res >> 16);
	return (res + (res >> 32)) & 0x00000000000000FFul;
#endif
#endif
}
EXPORT_SYMBOL(__sw_hweight64);
