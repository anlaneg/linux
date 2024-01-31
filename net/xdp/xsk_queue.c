// SPDX-License-Identifier: GPL-2.0
/* XDP user-space ring structure
 * Copyright(c) 2018 Intel Corporation.
 */

#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/overflow.h>
#include <linux/vmalloc.h>
#include <net/xdp_sock_drv.h>

#include "xsk_queue.h"


//计算创建不同的ring需要的内存大小（非umem_queue队列为rxtx_ring)
static size_t xskq_get_ring_size(struct xsk_queue *q, bool umem_queue/*是否为umem queue*/)
{
	struct xdp_umem_ring *umem_ring;
	struct xdp_rxtx_ring *rxtx_ring;

	if (umem_queue)
	    //umem_ring结构体后包含desc个q->nentries[0]元素，需要多少字节
		//即 struct_size = sizeof(umem_ring) + (sizeof(umem_ring->desc[0])* q->nentries)
		return struct_size(umem_ring, desc, q->nentries);

	//非umem_queue,则为rxtx_ring结构体后 + q->nentries * sizeof(rxtx_ring->desc[0])
	return struct_size(rxtx_ring, desc, q->nentries);
}

//创建指定大小的xsk队列
struct xsk_queue *xskq_create(u32 nentries/*队列长度*/, bool umem_queue/*是否为umem队列*/)
{
	struct xsk_queue *q;
	size_t size;

	/*申请xsk_queue*/
	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return NULL;

	q->nentries = nentries;
	q->ring_mask = nentries - 1;

	/*确认要创建的ring内存大小，且大小需要以页对齐*/
	size = xskq_get_ring_size(q, umem_queue);

	/* size which is overflowing or close to SIZE_MAX will become 0 in
	 * PAGE_ALIGN(), checking SIZE_MAX is enough due to the previous
	 * is_power_of_2(), the rest will be handled by vmalloc_user()
	 */
	if (unlikely(size == SIZE_MAX)) {
		kfree(q);
		return NULL;
	}

	size = PAGE_ALIGN(size);

	/*为ring申请对应的内存*/
	q->ring = vmalloc_user(size);
	if (!q->ring) {
		kfree(q);
		return NULL;
	}

	q->ring_vmalloc_size = size;
	return q;
}

/*销毁指定queue*/
void xskq_destroy(struct xsk_queue *q)
{
	if (!q)
		return;

	vfree(q->ring);
	kfree(q);
}
