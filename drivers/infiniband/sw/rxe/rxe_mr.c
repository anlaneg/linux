// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/libnvdimm.h>

#include "rxe.h"
#include "rxe_loc.h"

/* Return a random 8 bit key value that is
 * different than the last_key. Set last_key to -1
 * if this is the first key for an MR or MW
 */
u8 rxe_get_next_key(u32 last_key)
{
    /*生成一个随机的与last_key不同的key*/
	u8 key;

	do {
		get_random_bytes(&key, 1);
	} while (key == last_key);

	return key;
}

int mr_check_range(struct rxe_mr *mr, u64 iova, size_t length)
{
	switch (mr->ibmr.type) {
	case IB_MR_TYPE_DMA:
		/*此类型无条件通过*/
		return 0;

	case IB_MR_TYPE_USER:
	case IB_MR_TYPE_MEM_REG:
		if (iova < mr->ibmr.iova/*iova地址左侧不在此range中*/ ||
		    iova + length > mr->ibmr.iova + mr->ibmr.length/*iova地址右侧不在此range中*/) {
			rxe_dbg_mr(mr, "iova/length out of range\n");/*此iova地址不在mr中*/
			return -EINVAL;
		}
		/*校验能过*/
		return 0;

	default:
		/*不支持其它类型的mr*/
		rxe_dbg_mr(mr, "mr type not supported\n");
		return -EINVAL;
	}
}

/*初始化mr*/
void rxe_mr_init(int access, struct rxe_mr *mr)
{
    /*本端key为index | 随机值,生成key*/
	u32 key = mr->elem.index << 8 | rxe_get_next_key(-1);

	/* set ibmr->l/rkey and also copy into private l/rkey
	 * for user MRs these will always be the same
	 * for cases where caller 'owns' the key portion
	 * they may be different until REG_MR WQE is executed.
	 */
	mr->lkey = mr->ibmr.lkey = key;/*指明此mr在本端的key*/
	mr->rkey = mr->ibmr.rkey = key;/*指明此mr在对端的key*/

	mr->access = access;/*记录此mr访问权限*/
	mr->ibmr.page_size = PAGE_SIZE;/*mr对应的页大小*/
	mr->page_mask = PAGE_MASK;
	mr->page_shift = PAGE_SHIFT;
	mr->state = RXE_MR_STATE_INVALID;/*标记此mr当前无效*/
}

void rxe_mr_init_dma(int access, struct rxe_mr *mr)
{
	rxe_mr_init(access, mr);

	/*初始化状态有效*/
	mr->state = RXE_MR_STATE_VALID;
	mr->ibmr.type = IB_MR_TYPE_DMA;
}

static unsigned long rxe_mr_iova_to_index(struct rxe_mr *mr, u64 iova)
{
	/*取此iova地址相对于mr->ibmr.iova的页数偏移量
	 * （mr->ibmr.iova中保存的为此mr的首iova地址。
	 * 换句话说，偏移多少页可以从mr->ibmr.iova地址所在页偏移到iova所在页）*/
	return (iova >> mr->page_shift) - (mr->ibmr.iova >> mr->page_shift);
}

static unsigned long rxe_mr_iova_to_page_offset(struct rxe_mr *mr, u64 iova)
{
	/*iova地址在page中的偏移量*/
	return iova & (mr_page_size(mr) - 1);
}

static bool is_pmem_page(struct page *pg)
{
	unsigned long paddr = page_to_phys(pg);

	return REGION_INTERSECTS ==
	       region_intersects(paddr, PAGE_SIZE, IORESOURCE_MEM,
				 IORES_DESC_PERSISTENT_MEMORY);
}

static int rxe_mr_fill_pages_from_sgt(struct rxe_mr *mr, struct sg_table *sgt)
{
	XA_STATE(xas, &mr->page_list, 0);
	struct sg_page_iter sg_iter;
	struct page *page;
	bool persistent = !!(mr->access & IB_ACCESS_FLUSH_PERSISTENT);

	__sg_page_iter_start(&sg_iter, sgt->sgl, sgt->orig_nents, 0);
	if (!__sg_page_iter_next(&sg_iter))
		return 0;

	do {
		xas_lock(&xas);
		while (true) {
			page = sg_page_iter_page(&sg_iter);

			if (persistent && !is_pmem_page(page)) {
				rxe_dbg_mr(mr, "Page can't be persistent\n");
				xas_set_err(&xas, -EINVAL);
				break;
			}

			xas_store(&xas, page);
			if (xas_error(&xas))
				break;
			xas_next(&xas);
			if (!__sg_page_iter_next(&sg_iter))
				break;
		}
		xas_unlock(&xas);
	} while (xas_nomem(&xas, GFP_KERNEL));

	return xas_error(&xas);
}

int rxe_mr_init_user(struct rxe_dev *rxe, u64 start/*内存起始地址*/, u64 length/*内存长度*/,
		     int access, struct rxe_mr *mr)
{
	struct ib_umem *umem;
	int err;

	rxe_mr_init(access, mr);/*初始化mr*/

	xa_init(&mr->page_list);

	/*pin这一段地址，并获得这一段地址对应的一组物理page*/
	umem = ib_umem_get(&rxe->ib_dev, start, length, access);
	if (IS_ERR(umem)) {
		rxe_dbg_mr(mr, "Unable to pin memory region err = %d\n",
			(int)PTR_ERR(umem));
		return PTR_ERR(umem);
	}

	/*将这组物理page映射关系设置到mr,后续从mr读取或者向mr写入时需要这些信息*/
	err = rxe_mr_fill_pages_from_sgt(mr, &umem->sgt_append.sgt);
	if (err) {
		ib_umem_release(umem);
		return err;
	}

	mr->umem = umem;
	mr->ibmr.type = IB_MR_TYPE_USER;/*指明此为用户态mr*/
	mr->state = RXE_MR_STATE_VALID;

	return 0;
}

static int rxe_mr_alloc(struct rxe_mr *mr, int num_buf)
{
	/*定义struct xa_state类型变量*/
	XA_STATE(xas, &mr->page_list, 0);
	int i = 0;
	int err;

	xa_init(&mr->page_list);

	do {
		xas_lock(&xas);
		while (i != num_buf) {
			/*在xas中存入XA_ZERO_ENTRY*/
			xas_store(&xas, XA_ZERO_ENTRY);
			if (xas_error(&xas))
				break;
			/*切换到下一个索引位置*/
			xas_next(&xas);
			i++;/*元素数增加*/
		}
		xas_unlock(&xas);
	} while (xas_nomem(&xas, GFP_KERNEL));

	err = xas_error(&xas);
	if (err)
		return err;

	mr->num_buf = num_buf;/*记录buffer数*/

	return 0;
}

int rxe_mr_init_fast(int max_pages, struct rxe_mr *mr)
{
	int err;

	/* always allow remote access for FMRs */
	rxe_mr_init(RXE_ACCESS_REMOTE, mr);

	/*初始化page_lists(注意此时并没有申请page,只是进行了数组占位）*/
	err = rxe_mr_alloc(mr, max_pages);
	if (err)
		goto err1;

	mr->state = RXE_MR_STATE_FREE;
	mr->ibmr.type = IB_MR_TYPE_MEM_REG;

	return 0;

err1:
	return err;
}

static int rxe_set_page(struct ib_mr *ibmr, u64 dma_addr)
{
	struct rxe_mr *mr = to_rmr(ibmr);
	struct page *page = ib_virt_dma_to_page(dma_addr);
	bool persistent = !!(mr->access & IB_ACCESS_FLUSH_PERSISTENT);
	int err;

	if (persistent && !is_pmem_page(page)) {
		rxe_dbg_mr(mr, "Page cannot be persistent\n");
		return -EINVAL;
	}

	if (unlikely(mr->nbuf == mr->num_buf))
		return -ENOMEM;

	err = xa_err(xa_store(&mr->page_list, mr->nbuf, page, GFP_KERNEL));
	if (err)
		return err;

	mr->nbuf++;
	return 0;
}

int rxe_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sgl,
		  int sg_nents, unsigned int *sg_offset)
{
	struct rxe_mr *mr = to_rmr(ibmr);
	unsigned int page_size = mr_page_size(mr);

	mr->nbuf = 0;
	mr->page_shift = ilog2(page_size);
	mr->page_mask = ~((u64)page_size - 1);
	mr->page_offset = mr->ibmr.iova & (page_size - 1);

	return ib_sg_to_pages(ibmr, sgl, sg_nents, sg_offset, rxe_set_page);
}

static int rxe_mr_copy_xarray(struct rxe_mr *mr, u64 iova/*数据源或数据目的*/, void *addr/*数据目的或者数据源*/,
			      unsigned int length/*复制长度*/, enum rxe_mr_copy_dir dir/*指明复制方向*/)
{
	/*取此iova地址在页中的偏移量*/
	unsigned int page_offset = rxe_mr_iova_to_page_offset(mr, iova);
	/*页号偏移量*/
	unsigned long index = rxe_mr_iova_to_index(mr, iova);
	unsigned int bytes;
	struct page *page;
	void *va;

	while (length) {
		/*取此mr中index号页对应的page结构体*/
		page = xa_load(&mr->page_list, index);
		if (!page)
			return -EFAULT;

		/*此轮（本页）可复制的字节长度*/
		bytes = min_t(unsigned int, length,
				mr_page_size(mr) - page_offset);
		/*此page对应的kernel虚地址*/
		va = kmap_local_page(page);
		if (dir == RXE_FROM_MR_OBJ)
			/*从va+page_offset复制bytes字节，并填充到addr(从mr到addr复制)*/
			memcpy(addr, va + page_offset, bytes);
		else
			/*从addr复制内容bytes字节，并填充到va+page_offset（从addr到mr复制)*/
			memcpy(va + page_offset, addr, bytes);
		kunmap_local(va);

		page_offset = 0;
		addr += bytes;
		length -= bytes;
		index++;/*下一个页*/
	}

	return 0;
}

/*dma类型内存复制*/
static void rxe_mr_copy_dma(struct rxe_mr *mr, u64 dma_addr/*地址2*/, void *addr/*地址1*/,
			    unsigned int length/*复制长度*/, enum rxe_mr_copy_dir dir/*复制方向*/)
{
	unsigned int page_offset = dma_addr & (PAGE_SIZE - 1);/*dma地址在页内的偏移量*/
	unsigned int bytes;
	struct page *page;
	u8 *va;

	while (length) {
		/*取dma地址对应的page*/
		page = ib_virt_dma_to_page(dma_addr);
		bytes = min_t(unsigned int, length,
				PAGE_SIZE - page_offset);/*本次能复制的bytes数（dma是物理地址，其和虚拟地址映射间可能不连续）*/
		va = kmap_local_page(page);/*取此页对应的起始虚拟地址*/

		/*按方向确定src,dst*/
		if (dir == RXE_TO_MR_OBJ)
			/*即从addr写到va指向的位置*/
			memcpy(va + page_offset, addr, bytes);
		else
			/*即从va指向的位置写到addr中*/
			memcpy(addr, va + page_offset, bytes);

		kunmap_local(va);
		page_offset = 0;/*如果需要写下一页，则offset需要归零*/
		dma_addr += bytes;/*dma地址向后移动bytes*/
		addr += bytes;/*buffer向后移动bytes*/
		length -= bytes;/*剩余待复制内容减少bytes*/
	}
}

int rxe_mr_copy(struct rxe_mr *mr, u64 iova/*起始地址1*/, void *addr/*起始地址2（源）*/,
		unsigned int length/*复制内容长度*/, enum rxe_mr_copy_dir dir/*复制方向*/)
{
	int err;

	if (length == 0)
		/*长度为零，直接返回*/
		return 0;

	if (WARN_ON(!mr))
		/*必须提供mr*/
		return -EINVAL;

	/*dma类型内存复制*/
	if (mr->ibmr.type == IB_MR_TYPE_DMA) {
		rxe_mr_copy_dma(mr, iova, addr, length, dir);
		return 0;
	}

	/*检查iova到iova+length这个区间包含在mr中*/
	err = mr_check_range(mr, iova, length);
	if (unlikely(err)) {
		rxe_dbg_mr(mr, "iova out of range\n");
		return err;
	}

	/*完成复制*/
	if (is_odp_mr(mr))
		return rxe_odp_mr_copy(mr, iova, addr, length, dir);
	else
		return rxe_mr_copy_xarray(mr, iova, addr, length, dir);
}

/* copy data in or out of a wqe, i.e. sg list
 * under the control of a dma descriptor
 */
int copy_data(
	struct rxe_pd		*pd,
	int			access,
	struct rxe_dma_info	*dma/*dma内存*/,
	void			*addr/*buffer起始地址*/,
	int			length/*buffer长度*/,
	enum rxe_mr_copy_dir	dir/*复制方向*/)
{
	int			bytes;
	/*取当前待操作的sge*/
	struct rxe_sge		*sge	= &dma->sge[dma->cur_sge];
	/*取此sge的起点偏移量*/
	int			offset	= dma->sge_offset;
	/*总可用长度*/
	int			resid	= dma->resid;
	struct rxe_mr		*mr	= NULL;
	u64			iova;
	int			err;

	if (length == 0)
		/*要复制的buffer长度为零，无论读写均不需要操作*/
		return 0;

	if (length > resid) {
		/*要求的读写长度超过可提供的，报错*/
		err = -EINVAL;
		goto err2;
	}

	if (sge->length && (offset < sge->length)) {
		/*检查sge对应的mr是否存在*/
		mr = lookup_mr(pd, access, sge->lkey, RXE_LOOKUP_LOCAL);
		if (!mr) {
			err = -EINVAL;
			goto err1;
		}
	}

	while (length > 0) {
		bytes = length;

		if (offset >= sge->length) {
			/*当前offset超过此seg能提供的length，切换mr*/
			if (mr) {
				rxe_put(mr);/*归还当前mr*/
				mr = NULL;
			}
			sge++;/*指针切换到下一个sge*/
			dma->cur_sge++;/*下标切换到下一个sge*/
			offset = 0;/*offset回归到零*/

			if (dma->cur_sge >= dma->num_sge) {
				/*cur_seg超过sge总数，则buffer不足被填充，报错*/
				err = -ENOSPC;
				goto err2;
			}

			if (sge->length) {
				/*这个sge有内容，利用sge->lkey查询此mr，检查此mr是否存在*/
				mr = lookup_mr(pd, access, sge->lkey,
					       RXE_LOOKUP_LOCAL);
				if (!mr) {
					/*没有查询到mr，报错*/
					err = -EINVAL;
					goto err1;
				}
			} else {
				/*这个sge内容为空，跳过,忽略此sge*/
				continue;
			}
		}

		/*获取本轮可最大复制的字节数*/
		if (bytes > sge->length - offset)
			bytes = sge->length - offset;

		if (bytes > 0) {
			/*这种自mr中读写，确认mr中复制/读取起始地址iova,需复制/读取的bytes字节*/
			iova = sge->addr + offset;
			err = rxe_mr_copy(mr, iova/*mr中的地址*/, addr/*buffer中地址*/, bytes/*复制字节数*/, dir);
			if (err)
				goto err2;

			/*上面已完成了此mr的复制，准备参数，检查是否要切sge*/
			offset	+= bytes;
			resid	-= bytes;
			length	-= bytes;
			addr	+= bytes;
		}
	}

	dma->sge_offset = offset;/*更新cur_sge的可复制内容的起始偏移*/
	dma->resid	= resid;/*更新资源长度*/

	if (mr)
		rxe_put(mr);

	return 0;

err2:
	if (mr)
		rxe_put(mr);
err1:
	return err;
}

static int rxe_mr_flush_pmem_iova(struct rxe_mr *mr, u64 iova, unsigned int length)
{
	unsigned int page_offset;
	unsigned long index;
	struct page *page;
	unsigned int bytes;
	int err;
	u8 *va;

	err = mr_check_range(mr, iova, length);
	if (err)
		return err;

	while (length > 0) {
		index = rxe_mr_iova_to_index(mr, iova);
		page = xa_load(&mr->page_list, index);
		page_offset = rxe_mr_iova_to_page_offset(mr, iova);
		if (!page)
			return -EFAULT;
		bytes = min_t(unsigned int, length,
			      mr_page_size(mr) - page_offset);

		va = kmap_local_page(page);
		arch_wb_cache_pmem(va + page_offset, bytes);
		kunmap_local(va);

		length -= bytes;
		iova += bytes;
		page_offset = 0;
	}

	return 0;
}

int rxe_flush_pmem_iova(struct rxe_mr *mr, u64 start, unsigned int length)
{
	int err;

	/* mr must be valid even if length is zero */
	if (WARN_ON(!mr))
		return -EINVAL;

	if (length == 0)
		return 0;

	if (mr->ibmr.type == IB_MR_TYPE_DMA)
		return -EFAULT;

	if (is_odp_mr(mr))
		err = rxe_odp_flush_pmem_iova(mr, start, length);
	else
		err = rxe_mr_flush_pmem_iova(mr, start, length);

	return err;
}

/* Guarantee atomicity of atomic operations at the machine level. */
DEFINE_SPINLOCK(atomic_ops_lock);

enum resp_states rxe_mr_do_atomic_op(struct rxe_mr *mr, u64 iova, int opcode,
				     u64 compare, u64 swap_add, u64 *orig_val)
{
	unsigned int page_offset;
	struct page *page;
	u64 value;
	u64 *va;

	if (unlikely(mr->state != RXE_MR_STATE_VALID)) {
		rxe_dbg_mr(mr, "mr not in valid state\n");
		return RESPST_ERR_RKEY_VIOLATION;
	}

	if (mr->ibmr.type == IB_MR_TYPE_DMA) {
		page_offset = iova & (PAGE_SIZE - 1);
		page = ib_virt_dma_to_page(iova);
	} else {
		unsigned long index;
		int err;

		err = mr_check_range(mr, iova, sizeof(value));
		if (err) {
			rxe_dbg_mr(mr, "iova out of range\n");
			return RESPST_ERR_RKEY_VIOLATION;
		}
		page_offset = rxe_mr_iova_to_page_offset(mr, iova);
		index = rxe_mr_iova_to_index(mr, iova);
		page = xa_load(&mr->page_list, index);/*取index号页*/
		if (!page)
			return RESPST_ERR_RKEY_VIOLATION;
	}

	if (unlikely(page_offset & 0x7)) {
		rxe_dbg_mr(mr, "iova not aligned\n");
		return RESPST_ERR_MISALIGNED_ATOMIC;
	}

	va = kmap_local_page(page);/*取此页对应的kernel va地址*/

	spin_lock_bh(&atomic_ops_lock);
	value = *orig_val = va[page_offset >> 3];

	if (opcode == IB_OPCODE_RC_COMPARE_SWAP) {
		if (value == compare)
			va[page_offset >> 3] = swap_add;
	} else {
		value += swap_add;
		va[page_offset >> 3] = value;
	}
	spin_unlock_bh(&atomic_ops_lock);

	kunmap_local(va);

	return RESPST_NONE;
}

enum resp_states rxe_mr_do_atomic_write(struct rxe_mr *mr, u64 iova, u64 value)
{
	unsigned int page_offset;
	struct page *page;
	u64 *va;

	if (mr->ibmr.type == IB_MR_TYPE_DMA) {
		page_offset = iova & (PAGE_SIZE - 1);
		page = ib_virt_dma_to_page(iova);
	} else {
		unsigned long index;
		int err;

		/* See IBA oA19-28 */
		err = mr_check_range(mr, iova, sizeof(value));
		if (unlikely(err)) {
			rxe_dbg_mr(mr, "iova out of range\n");
			return RESPST_ERR_RKEY_VIOLATION;
		}
		page_offset = rxe_mr_iova_to_page_offset(mr, iova);
		index = rxe_mr_iova_to_index(mr, iova);
		page = xa_load(&mr->page_list, index);
		if (!page)
			return RESPST_ERR_RKEY_VIOLATION;
	}

	/* See IBA A19.4.2 */
	if (unlikely(page_offset & 0x7)) {
		rxe_dbg_mr(mr, "misaligned address\n");
		return RESPST_ERR_MISALIGNED_ATOMIC;
	}

	va = kmap_local_page(page);
	/* Do atomic write after all prior operations have completed */
	smp_store_release(&va[page_offset >> 3], value);
	kunmap_local(va);

	return RESPST_NONE;
}

/*由于dma->sge[dma->cur_sge]位置的buffer已有length长度被发送了,更新dma->cur_sge,dma->sge_offset,dma->resid*/
int advance_dma_data(struct rxe_dma_info *dma, unsigned int length)
{
	struct rxe_sge		*sge	= &dma->sge[dma->cur_sge];
	int			offset	= dma->sge_offset;
	int			resid	= dma->resid;

	while (length) {
		unsigned int bytes;

		if (offset >= sge->length) {
			/*offset要大于sge->length,则跳sge索引*/
			sge++;
			dma->cur_sge++;
			offset = 0;
			if (dma->cur_sge >= dma->num_sge)
				return -ENOSPC;
		}

		bytes = length;

		if (bytes > sge->length - offset)
			bytes = sge->length - offset;

		offset	+= bytes;
		resid	-= bytes;
		length	-= bytes;
	}

	dma->sge_offset = offset;
	dma->resid	= resid;

	return 0;
}

/*查询mr*/
struct rxe_mr *lookup_mr(struct rxe_pd *pd, int access/*访问权限*/, u32 key,
			 enum rxe_mr_lookup_type type)
{
	struct rxe_mr *mr;
	struct rxe_dev *rxe = to_rdev(pd->ibpd.device);/*获得对应的rxe设备*/
	int index = key >> 8;/*key是一个u32的大端数，丢掉低8位，做为index*/

	/*通过key查询mr（index指的是elem->index)*/
	mr = rxe_pool_get_index(&rxe->mr_pool, index);
	if (!mr)
		return NULL;

	/*如果查询的是local,则匹配lkey,否则查询的是remote,则匹配rkey*/
	if (unlikely((type == RXE_LOOKUP_LOCAL && mr->lkey != key) ||
		     (type == RXE_LOOKUP_REMOTE && mr->rkey != key) ||
		     mr_pd(mr) != pd/*pd必须匹配（用于实现隔离，使mr在pd范围内有效）*/ || ((access & mr->access) != access)/*必须支持此访问权限*/ ||
		     mr->state != RXE_MR_STATE_VALID/*mr状态必须是有效的*/)) {
		/*对查询出来的mr进行校验，校验不通过。*/
		rxe_put(mr);
		mr = NULL;
	}

	return mr;/*通过key查找到mr*/
}

/*按key来指明对应的mr无效*/
int rxe_invalidate_mr(struct rxe_qp *qp, u32 key)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_mr *mr;
	int remote;
	int ret;

	/*通过key取mr*/
	mr = rxe_pool_get_index(&rxe->mr_pool, key >> 8);
	if (!mr) {
		rxe_dbg_qp(qp, "No MR for key %#x\n", key);
		ret = -EINVAL;
		goto err;
	}

	/*是否匹配remote 访问权限*/
	remote = mr->access & RXE_ACCESS_REMOTE;
	if (remote ? (key != mr->rkey) : (key != mr->lkey)) {
		/*key命中失败*/
		rxe_dbg_mr(mr, "wr key (%#x) doesn't match mr key (%#x)\n",
			key, (remote ? mr->rkey : mr->lkey));
		ret = -EINVAL;
		goto err_drop_ref;
	}

	if (atomic_read(&mr->num_mw) > 0) {
		rxe_dbg_mr(mr, "Attempt to invalidate an MR while bound to MWs\n");
		ret = -EINVAL;
		goto err_drop_ref;
	}

	if (unlikely(mr->ibmr.type != IB_MR_TYPE_MEM_REG)) {
		/*只有IB_MR_TYPE_MEM_REG类型的mr可以被置为无效*/
		rxe_dbg_mr(mr, "Type (%d) is wrong\n", mr->ibmr.type);
		ret = -EINVAL;
		goto err_drop_ref;
	}

	/*指明此mr状态为free*/
	mr->state = RXE_MR_STATE_FREE;
	ret = 0;

err_drop_ref:
	rxe_put(mr);
err:
	return ret;
}

/* user can (re)register fast MR by executing a REG_MR WQE.
 * user is expected to hold a reference on the ib mr until the
 * WQE completes.
 * Once a fast MR is created this is the only way to change the
 * private keys. It is the responsibility of the user to maintain
 * the ib mr keys in sync with rxe mr keys.
 */
int rxe_reg_fast_mr(struct rxe_qp *qp, struct rxe_send_wqe *wqe)
{
	struct rxe_mr *mr = to_rmr(wqe->wr.wr.reg.mr);
	u32 key = wqe->wr.wr.reg.key;
	u32 access = wqe->wr.wr.reg.access;

	/* user can only register MR in free state */
	if (unlikely(mr->state != RXE_MR_STATE_FREE)) {
		rxe_dbg_mr(mr, "mr->lkey = 0x%x not free\n", mr->lkey);
		return -EINVAL;
	}

	/* user can only register mr with qp in same protection domain */
	if (unlikely(qp->ibqp.pd != mr->ibmr.pd)) {
		rxe_dbg_mr(mr, "qp->pd and mr->pd don't match\n");
		return -EINVAL;
	}

	/* user is only allowed to change key portion of l/rkey */
	if (unlikely((mr->lkey & ~0xff) != (key & ~0xff))) {
		rxe_dbg_mr(mr, "key = 0x%x has wrong index mr->lkey = 0x%x\n",
			key, mr->lkey);
		return -EINVAL;
	}

	/*更新此mr,并将mr置为有效*/
	mr->access = access;
	mr->lkey = key;
	mr->rkey = key;
	mr->ibmr.iova = wqe->wr.wr.reg.mr->iova;
	mr->state = RXE_MR_STATE_VALID;

	return 0;
}

void rxe_mr_cleanup(struct rxe_pool_elem *elem)
{
	struct rxe_mr *mr = container_of(elem, typeof(*mr), elem);

	rxe_put(mr_pd(mr));
	ib_umem_release(mr->umem);

	if (mr->ibmr.type != IB_MR_TYPE_DMA)
		xa_destroy(&mr->page_list);
}
