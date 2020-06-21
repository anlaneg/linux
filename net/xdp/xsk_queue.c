// SPDX-License-Identifier: GPL-2.0
/* XDP user-space ring structure
 * Copyright(c) 2018 Intel Corporation.
 */

#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/overflow.h>
#include <net/xdp_sock_drv.h>

#include "xsk_queue.h"


//计算ring需要的内存大小
static size_t xskq_get_ring_size(struct xsk_queue *q, bool umem_queue)
{
	struct xdp_umem_ring *umem_ring;
	struct xdp_rxtx_ring *rxtx_ring;

	if (umem_queue)
	    //umem_ring结构体后 + q->nentries * desc个元素
		return struct_size(umem_ring, desc, q->nentries);
	//rxtx_ring结构体后 + q->nentries * desc个元素
	return struct_size(rxtx_ring, desc, q->nentries);
}

//创建指定大小的xsk队列
struct xsk_queue *xskq_create(u32 nentries, bool umem_queue/*是否umem队列*/)
{
	struct xsk_queue *q;
	gfp_t gfp_flags;
	size_t size;

	/*申请队列*/
	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return NULL;

	q->nentries = nentries;
	q->ring_mask = nentries - 1;

	gfp_flags = GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN |
		    __GFP_COMP  | __GFP_NORETRY;
	/*确认ring内存大小*/
	size = xskq_get_ring_size(q, umem_queue);

	/*为ring申请对应的内存*/
	q->ring = (struct xdp_ring *)__get_free_pages(gfp_flags,
						      get_order(size));
	if (!q->ring) {
		kfree(q);
		return NULL;
	}

	return q;
}

void xskq_destroy(struct xsk_queue *q)
{
	if (!q)
		return;

	page_frag_free(q->ring);
	kfree(q);
}
