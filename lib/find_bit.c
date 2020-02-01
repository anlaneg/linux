// SPDX-License-Identifier: GPL-2.0-or-later
/* bit search implementation
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Copyright (C) 2008 IBM Corporation
 * 'find_last_bit' is written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's find_next_bit implementation)
 *
 * Rewritten by Yury Norov <yury.norov@gmail.com> to decrease
 * size and improve performance, 2015.
 */

#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/kernel.h>

#if !defined(find_next_bit) || !defined(find_next_zero_bit) ||			\
	!defined(find_next_bit_le) || !defined(find_next_zero_bit_le) ||	\
	!defined(find_next_and_bit)
/*
 * This is a common helper function for find_next_bit, find_next_zero_bit, and
 * find_next_and_bit. The differences are:
 *  - The "invert" argument, which is XORed with each fetched word before
 *    searching it for one bits.
 *  - The optional "addr2", which is anded with "addr1" if present.
 */
//找一个bit是1的，自start位置开始，最大有nbits位，addr是考虑了掩码情况
//invert是考虑了bitmap中实现时，支持需要找‘0’的情况
static unsigned long _find_next_bit(const unsigned long *addr1,
		const unsigned long *addr2, unsigned long nbits,
		unsigned long start, unsigned long invert, unsigned long le)
{
	unsigned long tmp, mask;

	if (unlikely(start >= nbits))
		return nbits;//start已超限，返回最大值（无空闲）

	tmp = addr1[start / BITS_PER_LONG];//取start对应的位置
	if (addr2)
		tmp &= addr2[start / BITS_PER_LONG];
	tmp ^= invert;//如果invert为全1，则tmp会反转，否则tmp不反转

	/* Handle 1st word. */
	//将start位以下的bit置为0
	mask = BITMAP_FIRST_WORD_MASK(start);
	if (le)
		mask = swab(mask);

	tmp &= mask;

	//假如BITS_PER_LONG=64,则start的低5位被置为0（2^6=64)
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		//如果tmp为0，则说明此段已完全分配出去了，则start向后移动一个
		//BITS_PER_LONG长度，并继续查找
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr1[start / BITS_PER_LONG];
		if (addr2)
			tmp &= addr2[start / BITS_PER_LONG];
		tmp ^= invert;
	}

	if (le)
		tmp = swab(tmp);

	//此时要么查找了，要么查找失败（故最小返回）
	//__ffs返回tmp中第一个1所在的位号
	return min(start + __ffs(tmp), nbits);
}
#endif

#ifndef find_next_bit
/*
 * Find the next set bit in a memory region.
 */
unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, 0UL, 0);
}
EXPORT_SYMBOL(find_next_bit);
#endif

#ifndef find_next_zero_bit
//addr是一个bit数组，size是数组的长度，offset是我们开始查找的起始点
unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, ~0UL, 0);
}
EXPORT_SYMBOL(find_next_zero_bit);
#endif

#if !defined(find_next_and_bit)
unsigned long find_next_and_bit(const unsigned long *addr1,
		const unsigned long *addr2, unsigned long size,
		unsigned long offset)
{
	return _find_next_bit(addr1, addr2, size, offset, 0UL, 0);
}
EXPORT_SYMBOL(find_next_and_bit);
#endif

#ifndef find_first_bit
/*
 * Find the first set bit in a memory region.
 */
unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return min(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}
EXPORT_SYMBOL(find_first_bit);
#endif

#ifndef find_first_zero_bit
/*
 * Find the first cleared bit in a memory region.
 */
unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		//addr[idx]不为全1，则可以从中找到个为0的bit
		if (addr[idx] != ~0UL)
			return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}
EXPORT_SYMBOL(find_first_zero_bit);
#endif

#ifndef find_last_bit
unsigned long find_last_bit(const unsigned long *addr, unsigned long size)
{
	if (size) {
		unsigned long val = BITMAP_LAST_WORD_MASK(size);
		unsigned long idx = (size-1) / BITS_PER_LONG;

		do {
			val &= addr[idx];
			if (val)
				return idx * BITS_PER_LONG + __fls(val);

			val = ~0ul;
		} while (idx--);
	}
	return size;
}
EXPORT_SYMBOL(find_last_bit);
#endif

#ifdef __BIG_ENDIAN

#ifndef find_next_zero_bit_le
unsigned long find_next_zero_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, ~0UL, 1);
}
EXPORT_SYMBOL(find_next_zero_bit_le);
#endif

#ifndef find_next_bit_le
unsigned long find_next_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, 0UL, 1);
}
EXPORT_SYMBOL(find_next_bit_le);
#endif

#endif /* __BIG_ENDIAN */

unsigned long find_next_clump8(unsigned long *clump, const unsigned long *addr,
			       unsigned long size, unsigned long offset)
{
	offset = find_next_bit(addr, size, offset);
	if (offset == size)
		return size;

	offset = round_down(offset, 8);
	*clump = bitmap_get_value8(addr, offset);

	return offset;
}
EXPORT_SYMBOL(find_next_clump8);
