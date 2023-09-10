/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>

/*
 * pfn_t: encapsulates a page-frame number that is optionally backed
 * by memmap (struct page).  Whether a pfn_t has a 'struct page'
 * backing is indicated by flags in the high bits of the value.
 */
typedef struct {
	u64 val;
} pfn_t;
#endif

/*物理地址按页对齐*/
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
/*物理地址按页对齐（up形式)*/
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
/*物理地址按页对齐（down形式)*/
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
/*由pfn获得其page首地址*/
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
/*由物理地址获得pfn*/
#define PHYS_PFN(x)	((unsigned long)((x) >> PAGE_SHIFT))

#endif
