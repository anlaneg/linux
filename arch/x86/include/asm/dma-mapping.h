/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_DMA_MAPPING_H
#define _ASM_X86_DMA_MAPPING_H

extern const struct dma_map_ops *dma_ops;

//直接返回dma_ops变量(例如x86下pci-dma.c)
static inline const struct dma_map_ops *get_arch_dma_ops(void)
{
	return dma_ops;
}

#endif
