/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_DMA_MAPPING_H
#define _ASM_X86_DMA_MAPPING_H

/*
 * IOMMU interface. See Documentation/DMA-API-HOWTO.txt and
 * Documentation/DMA-API.txt for documentation.
 */

#include <linux/scatterlist.h>
#include <linux/dma-debug.h>
#include <asm/io.h>
#include <asm/swiotlb.h>
#include <linux/dma-contiguous.h>

extern int iommu_merge;
extern int panic_on_overflow;

extern const struct dma_map_ops *dma_ops;

//直接返回dma_ops变量(例如x86下pci-dma.c)
static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return dma_ops;
}

#endif
