// SPDX-License-Identifier: GPL-2.0-only
/*
 * A generic implementation of binary search for the Linux kernel
 *
 * Copyright (C) 2008-2009 Ksplice, Inc.
 * Author: Tim Abbott <tabbott@ksplice.com>
 */

#include <linux/export.h>
#include <linux/bsearch.h>
#include <linux/kprobes.h>

/*
 * bsearch - binary search an array of elements
 * @key: pointer to item being searched for
 * @base: pointer to first element to search
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 *
 * This function does a binary search on the given array.  The
 * contents of the array should already be in ascending sorted order
 * under the provided comparison function.
 *
 * Note that the key need not have the same type as the elements in
 * the array, e.g. key could be a string and the comparison function
 * could compare the string with the struct's name field.  However, if
 * the key and elements in the array are of the same type, you can use
 * the same comparison function for both sort() and bsearch().
 */
void *bsearch(const void *key, const void *base, size_t num, size_t size/*元素大小*/,
	      cmp_func_t cmp)
{
	const char *pivot;
	int result;

	while (num > 0) {
		pivot = base + (num >> 1) * size;
		//通过比对函数对key,pivot进行比对
		result = cmp(key, pivot);

		//找到相同的
		if (result == 0)
			return (void *)pivot;

		if (result > 0) {
		    //key > pivot,base右移
			base = pivot + size;
			num--;
		}
		num >>= 1;
	}

	return NULL;
}
EXPORT_SYMBOL(bsearch);
NOKPROBE_SYMBOL(bsearch);
