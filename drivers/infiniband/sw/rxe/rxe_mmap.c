// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <rdma/uverbs_ioctl.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"

void rxe_mmap_release(struct kref *ref)
{
	struct rxe_mmap_info *ip = container_of(ref,
					struct rxe_mmap_info, ref);
	struct rxe_dev *rxe = to_rdev(ip->context->device);

	spin_lock_bh(&rxe->pending_lock);

	if (!list_empty(&ip->pending_mmaps))
		list_del(&ip->pending_mmaps);

	spin_unlock_bh(&rxe->pending_lock);

	vfree(ip->obj);		/* buf */
	kfree(ip);
}

/*
 * open and close keep track of how many times the memory region is mapped,
 * to avoid releasing it.
 */
static void rxe_vma_open(struct vm_area_struct *vma)
{
	struct rxe_mmap_info *ip = vma->vm_private_data;

	kref_get(&ip->ref);
}

static void rxe_vma_close(struct vm_area_struct *vma)
{
	struct rxe_mmap_info *ip = vma->vm_private_data;

	kref_put(&ip->ref, rxe_mmap_release);
}

static const struct vm_operations_struct rxe_vm_ops = {
	.open = rxe_vma_open,
	.close = rxe_vma_close,
};

/**
 * rxe_mmap - create a new mmap region
 * @context: the IB user context of the process making the mmap() call
 * @vma: the VMA to be initialized
 * Return zero if the mmap is OK. Otherwise, return an errno.
 */
int rxe_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	struct rxe_dev *rxe = to_rdev(context->device);
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;/*映射起始位置*/
	unsigned long size = vma->vm_end - vma->vm_start;/*映射长度*/
	struct rxe_mmap_info *ip, *pp;
	int ret;

	/*
	 * Search the device's list of objects waiting for a mmap call.
	 * Normally, this list is very short since a call to create a
	 * CQ, QP, or SRQ is soon followed by a call to mmap().
	 */
	spin_lock_bh(&rxe->pending_lock);
	/*遍历待执行mmap的rxe_mmap_info*/
	list_for_each_entry_safe(ip, pp, &rxe->pending_mmaps, pending_mmaps) {
		if (context != ip->context || (__u64)offset != ip->info.offset)
			/*context或者offset不同，不是在mmap这个，忽略*/
			continue;

		/* Don't allow a mmap larger than the object. */
		if (size > ip->info.size) {
			/*mmap的内存过大*/
			rxe_dbg_dev(rxe, "mmap region is larger than the object!\n");
			spin_unlock_bh(&rxe->pending_lock);
			ret = -EINVAL;
			goto done;
		}

		goto found_it;
	}
	rxe_dbg_dev(rxe, "unable to find pending mmap info\n");
	spin_unlock_bh(&rxe->pending_lock);
	ret = -EINVAL;
	goto done;

found_it:
	/*自pending链表上移除此项*/
	list_del_init(&ip->pending_mmaps);
	spin_unlock_bh(&rxe->pending_lock);

	/*映射此内存给用户态*/
	ret = remap_vmalloc_range(vma, ip->obj/*起始地址*/, 0/*偏移量*/);
	if (ret) {
		rxe_dbg_dev(rxe, "err %d from remap_vmalloc_range\n", ret);
		goto done;
	}

	vma->vm_ops = &rxe_vm_ops;
	vma->vm_private_data = ip;
	rxe_vma_open(vma);
done:
	return ret;
}

/*
 * Allocate information for rxe_mmap
 */
struct rxe_mmap_info *rxe_create_mmap_info(struct rxe_dev *rxe, u32 size/*内存大小*/,
					   struct ib_udata *udata, void *obj/*要映射的起始位置*/)
{
	struct rxe_mmap_info *ip;

	if (!udata)
		/*必须提供udata参数*/
		return ERR_PTR(-EINVAL);

	ip = kmalloc(sizeof(*ip), GFP_KERNEL);
	if (!ip)
		return ERR_PTR(-ENOMEM);

	size = PAGE_ALIGN(size);/*使内存大小按页对齐*/

	spin_lock_bh(&rxe->mmap_offset_lock);/*防止并发调用本函数*/

	if (rxe->mmap_offset == 0)
		/*初始化mmap_offset*/
		rxe->mmap_offset = ALIGN(PAGE_SIZE, SHMLBA);

	/*为此块内存分配offset（沿用上次的offset)*/
	ip->info.offset = rxe->mmap_offset;
	/*更新mmap offset(位于本次的结尾）,以便下次使用*/
	rxe->mmap_offset += ALIGN(size, SHMLBA);

	spin_unlock_bh(&rxe->mmap_offset_lock);

	INIT_LIST_HEAD(&ip->pending_mmaps);
	ip->info.size = size;/*映射内存大小*/
	ip->context =
		container_of(udata, struct uverbs_attr_bundle, driver_udata)
			->context;
	ip->obj = obj;/*起始地址*/
	kref_init(&ip->ref);

	return ip;
}
