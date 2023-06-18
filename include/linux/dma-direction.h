/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DMA_DIRECTION_H
#define _LINUX_DMA_DIRECTION_H

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,/*双向*/
	DMA_TO_DEVICE = 1,/*去往设备*/
	DMA_FROM_DEVICE = 2,/*来自设备*/
	DMA_NONE = 3,/*方向无效*/
};

/*检查dma方向是否有效（只容许三种）*/
static inline int valid_dma_direction(enum dma_data_direction dir)
{
	return dir == DMA_BIDIRECTIONAL || dir == DMA_TO_DEVICE ||
		dir == DMA_FROM_DEVICE;
}

#endif /* _LINUX_DMA_DIRECTION_H */
