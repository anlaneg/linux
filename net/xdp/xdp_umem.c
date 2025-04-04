// SPDX-License-Identifier: GPL-2.0
/* XDP user-space packet buffer
 * Copyright(c) 2018 Intel Corporation.
 */

#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/idr.h>
#include <linux/vmalloc.h>

#include "xdp_umem.h"
#include "xsk_queue.h"

//管理umem内存块的id分配
static DEFINE_IDA(umem_ida);

static void xdp_umem_unpin_pages(struct xdp_umem *umem)
{
	unpin_user_pages_dirty_lock(umem->pgs, umem->npgs, true);

	kvfree(umem->pgs);
	umem->pgs = NULL;
}

static void xdp_umem_unaccount_pages(struct xdp_umem *umem)
{
	if (umem->user) {
		atomic_long_sub(umem->npgs, &umem->user->locked_vm);
		free_uid(umem->user);
	}
}

static void xdp_umem_addr_unmap(struct xdp_umem *umem)
{
	vunmap(umem->addrs);
	umem->addrs = NULL;
}

static int xdp_umem_addr_map(struct xdp_umem *umem, struct page **pages,
			     u32 nr_pages)
{
	umem->addrs = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!umem->addrs)
		return -ENOMEM;
	return 0;
}

static void xdp_umem_release(struct xdp_umem *umem)
{
	umem->zc = false;
	ida_free(&umem_ida, umem->id);

	xdp_umem_addr_unmap(umem);
	xdp_umem_unpin_pages(umem);

	xdp_umem_unaccount_pages(umem);
	kfree(umem);
}

static void xdp_umem_release_deferred(struct work_struct *work)
{
	struct xdp_umem *umem = container_of(work, struct xdp_umem, work);

	xdp_umem_release(umem);
}

void xdp_get_umem(struct xdp_umem *umem)
{
	refcount_inc(&umem->users);
}

void xdp_put_umem(struct xdp_umem *umem, bool defer_cleanup)
{
	if (!umem)
		return;

	if (refcount_dec_and_test(&umem->users)) {
		if (defer_cleanup) {
			INIT_WORK(&umem->work, xdp_umem_release_deferred);
			schedule_work(&umem->work);
		} else {
			xdp_umem_release(umem);
		}
	}
}

static int xdp_umem_pin_pages(struct xdp_umem *umem, unsigned long address)
{
	unsigned int gup_flags = FOLL_WRITE;
	long npgs;
	int err;

	/*申请一组page指针*/
	umem->pgs = kvcalloc(umem->npgs, sizeof(*umem->pgs), GFP_KERNEL | __GFP_NOWARN);
	if (!umem->pgs)
		return -ENOMEM;

	mmap_read_lock(current->mm);
	/*获取用户内存的每个页指针，将其pin在内存里*/
	npgs = pin_user_pages(address, umem->npgs,
			      gup_flags | FOLL_LONGTERM, &umem->pgs[0]/*出参，各页指针*/);
	mmap_read_unlock(current->mm);

	/*注册的内存未完全pin住，报错*/
	if (npgs != umem->npgs) {
		if (npgs >= 0) {
			umem->npgs = npgs;
			err = -ENOMEM;
			goto out_pin;
		}
		err = npgs;
		goto out_pgs;
	}
	return 0;

out_pin:
	xdp_umem_unpin_pages(umem);
out_pgs:
	kvfree(umem->pgs);
	umem->pgs = NULL;
	return err;
}

static int xdp_umem_account_pages(struct xdp_umem *umem)
{
	unsigned long lock_limit, new_npgs, old_npgs;

	if (capable(CAP_IPC_LOCK))
		return 0;

	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	umem->user = get_uid(current_user());

	do {
		old_npgs = atomic_long_read(&umem->user->locked_vm);
		new_npgs = old_npgs + umem->npgs;
		if (new_npgs > lock_limit) {
			free_uid(umem->user);
			umem->user = NULL;
			return -ENOBUFS;
		}
	} while (atomic_long_cmpxchg(&umem->user->locked_vm, old_npgs,
				     new_npgs) != old_npgs);
	return 0;
}

#define XDP_UMEM_FLAGS_VALID ( \
		XDP_UMEM_UNALIGNED_CHUNK_FLAG | \
		XDP_UMEM_TX_SW_CSUM | \
	0)

//注册用户态的内存
static int xdp_umem_reg(struct xdp_umem *umem, struct xdp_umem_reg *mr/*用户传入的mr*/)
{
	/*是否为不对齐的chunks*/
	bool unaligned_chunks = mr->flags & XDP_UMEM_UNALIGNED_CHUNK_FLAG;
	/*chunk大小及headroom大小*/
	u32 chunk_size = mr->chunk_size, headroom = mr->headroom;
	/*用户态传入的memory起始地址及长度*/
	u64 addr = mr->addr, size = mr->len;
	u32 chunks_rem, npgs_rem;
	u64 chunks, npgs;
	int err;

	/*chunk_size过小或过大检查*/
	if (chunk_size < XDP_UMEM_MIN_CHUNK_SIZE || chunk_size > PAGE_SIZE) {
		/* Strictly speaking we could support this, if:
		 * - huge pages, or*
		 * - using an IOMMU, or
		 * - making sure the memory area is consecutive
		 * but for now, we simply say "computer says no".
		 */
		return -EINVAL;
	}

	//检查是否遇到不支持的flags,例如当前仅支持unaligned一种标记
	if (mr->flags & ~XDP_UMEM_FLAGS_VALID)
		return -EINVAL;

	/*如果未指明chunk对齐，则要求chunk_size必须为2的N次幂取值*/
	if (!unaligned_chunks && !is_power_of_2(chunk_size))
		return -EINVAL;

	/*addr必面按page对齐*/
	if (!PAGE_ALIGNED(addr)) {
		/* Memory area has to be page size aligned. For
		 * simplicity, this might change.
		 */
		return -EINVAL;
	}

	//防地址绕回
	if ((addr + size) < addr)
		return -EINVAL;

	/*注册的内存占用多少页（npgs)*/
	npgs = div_u64_rem(size, PAGE_SIZE, &npgs_rem/*保存余数*/);
	if (npgs_rem)
		npgs++;
	if (npgs > U32_MAX)
		return -EINVAL;

	/*注册的内存共包含多少chunk*/
	chunks = div_u64_rem(size, chunk_size, &chunks_rem);
	if (!chunks || chunks > U32_MAX)
		return -EINVAL;

	/*没有指明“不对齐”情况下，不容许有余数*/
	if (!unaligned_chunks && chunks_rem)
		return -EINVAL;

	/*检查headroom配置，可用于存放实际报文的大小不得为0
	 * （减去headroom,减去xdp packet headroom)*/
	if (headroom >= chunk_size - XDP_PACKET_HEADROOM)
		return -EINVAL;

	if (mr->tx_metadata_len >= 256 || mr->tx_metadata_len % 8)
		return -EINVAL;

	umem->size = size;
	umem->headroom = headroom;
	umem->chunk_size = chunk_size;
	umem->chunks = chunks;
	umem->npgs = npgs;
	umem->pgs = NULL;
	umem->user = NULL;
	umem->flags = mr->flags;
	umem->tx_metadata_len = mr->tx_metadata_len;

	INIT_LIST_HEAD(&umem->xsk_dma_list);
	refcount_set(&umem->users, 1);

	/*检查是否触发memory limit*/
	err = xdp_umem_account_pages(umem);
	if (err)
		return err;

	/*pin用户态注册的内存*/
	err = xdp_umem_pin_pages(umem, (unsigned long)addr);
	if (err)
		goto out_account;

	/*映射umem_page与用户内存的映射，内核可使用的虚地址*/
	err = xdp_umem_addr_map(umem, umem->pgs, umem->npgs);
	if (err)
		goto out_unpin;

	return 0;

out_unpin:
	xdp_umem_unpin_pages(umem);
out_account:
	xdp_umem_unaccount_pages(umem);
	return err;
}

struct xdp_umem *xdp_umem_create(struct xdp_umem_reg *mr)
{
	struct xdp_umem *umem;
	int err;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	//为umem分配id号
	err = ida_alloc(&umem_ida, GFP_KERNEL);
	if (err < 0) {
		kfree(umem);
		return ERR_PTR(err);
	}
	umem->id = err;

	/*注册此内存区域*/
	err = xdp_umem_reg(umem, mr);
	if (err) {
	    /*注册失败，释放此id*/
		ida_free(&umem_ida, umem->id);
		kfree(umem);
		return ERR_PTR(err);
	}

	return umem;
}
