/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_SH_MMZONE_H
#define __ASM_SH_MMZONE_H

#ifdef CONFIG_NUMA
#include <linux/numa.h>

/*用于记录系统中各NUMA node对应内存布局(由各体系结构自已填充定义)*/
extern struct pglist_data *node_data[];
/*取nid号NUMA node对应的pglist_data,每个NUMA node下的内存布局由pglist_data进行描述*/
#define NODE_DATA(nid)		(node_data[nid])

static inline int pfn_to_nid(unsigned long pfn)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++)
		if (pfn >= node_start_pfn(nid) && pfn <= node_end_pfn(nid))
			break;

	return nid;
}

static inline struct pglist_data *pfn_to_pgdat(unsigned long pfn)
{
	return NODE_DATA(pfn_to_nid(pfn));
}

/* arch/sh/mm/numa.c */
void __init setup_bootmem_node(int nid, unsigned long start, unsigned long end);
#else
static inline void
setup_bootmem_node(int nid, unsigned long start, unsigned long end)
{
}
#endif /* CONFIG_NUMA */

/* Platform specific mem init */
void __init plat_mem_setup(void);

/* arch/sh/kernel/setup.c */
void __init __add_active_range(unsigned int nid, unsigned long start_pfn,
			       unsigned long end_pfn);
/* arch/sh/mm/init.c */
void __init allocate_pgdat(unsigned int nid);

#endif /* __ASM_SH_MMZONE_H */
