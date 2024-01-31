// SPDX-License-Identifier: GPL-2.0
/* XDP sockets
 *
 * AF_XDP sockets allows a channel between XDP programs and userspace
 * applications.
 * Copyright(c) 2018 Intel Corporation.
 *
 * Author(s): Björn Töpel <bjorn.topel@intel.com>
 *	      Magnus Karlsson <magnus.karlsson@intel.com>
 */

#define pr_fmt(fmt) "AF_XDP: %s: " fmt, __func__

#include <linux/if_xdp.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <net/xdp_sock_drv.h>
#include <net/busy_poll.h>
#include <net/netdev_rx_queue.h>
#include <net/xdp.h>

#include "xsk_queue.h"
#include "xdp_umem.h"
#include "xsk.h"

#define TX_BATCH_SIZE 32
#define MAX_PER_SOCKET_BUDGET (TX_BATCH_SIZE)

static DEFINE_PER_CPU(struct list_head, xskmap_flush_list);

/*设置rx方向需要wakeup*/
void xsk_set_rx_need_wakeup(struct xsk_buff_pool *pool)
{
	if (pool->cached_need_wakeup & XDP_WAKEUP_RX)
		/*已置此标记，直接返回*/
		return;

	pool->fq->ring->flags |= XDP_RING_NEED_WAKEUP;
	pool->cached_need_wakeup |= XDP_WAKEUP_RX;
}
EXPORT_SYMBOL(xsk_set_rx_need_wakeup);

/*设置tx方向需要wakeup*/
void xsk_set_tx_need_wakeup(struct xsk_buff_pool *pool)
{
	struct xdp_sock *xs;

	if (pool->cached_need_wakeup & XDP_WAKEUP_TX)
		/*已置此标记，直接返回*/
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		xs->tx->ring->flags |= XDP_RING_NEED_WAKEUP;
	}
	rcu_read_unlock();

	pool->cached_need_wakeup |= XDP_WAKEUP_TX;
}
EXPORT_SYMBOL(xsk_set_tx_need_wakeup);

/*清除rx方向需要wakeup的标记*/
void xsk_clear_rx_need_wakeup(struct xsk_buff_pool *pool)
{
	if (!(pool->cached_need_wakeup & XDP_WAKEUP_RX))
		return;

	pool->fq->ring->flags &= ~XDP_RING_NEED_WAKEUP;
	pool->cached_need_wakeup &= ~XDP_WAKEUP_RX;
}
EXPORT_SYMBOL(xsk_clear_rx_need_wakeup);

/*清除tx方向需要wakeup的标记*/
void xsk_clear_tx_need_wakeup(struct xsk_buff_pool *pool)
{
	struct xdp_sock *xs;

	if (!(pool->cached_need_wakeup & XDP_WAKEUP_TX))
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		xs->tx->ring->flags &= ~XDP_RING_NEED_WAKEUP;
	}
	rcu_read_unlock();

	pool->cached_need_wakeup &= ~XDP_WAKEUP_TX;
}
EXPORT_SYMBOL(xsk_clear_tx_need_wakeup);

/*检查此pool是否需要wakeup(不论rx/tx方向）*/
bool xsk_uses_need_wakeup(struct xsk_buff_pool *pool)
{
	return pool->uses_need_wakeup;
}
EXPORT_SYMBOL(xsk_uses_need_wakeup);

struct xsk_buff_pool *xsk_get_pool_from_qid(struct net_device *dev,
					    u16 queue_id)
{
	/*通过queue_id获取对应的pool(rx的queue_id与tx的queue_id是连续的，且tx queue_id更大）*/
	if (queue_id < dev->real_num_rx_queues)
		return dev->_rx[queue_id].pool;
	if (queue_id < dev->real_num_tx_queues)
		return dev->_tx[queue_id].pool;

	return NULL;
}
EXPORT_SYMBOL(xsk_get_pool_from_qid);

/*移除指定queue_id对应的pool*/
void xsk_clear_pool_at_qid(struct net_device *dev, u16 queue_id)
{
	if (queue_id < dev->num_rx_queues)
		dev->_rx[queue_id].pool = NULL;
	if (queue_id < dev->num_tx_queues)
		dev->_tx[queue_id].pool = NULL;
}

/* The buffer pool is stored both in the _rx struct and the _tx struct as we do
 * not know if the device has more tx queues than rx, or the opposite.
 * This might also change during run time.
 */
int xsk_reg_pool_at_qid(struct net_device *dev, struct xsk_buff_pool *pool,
			u16 queue_id)
{
	if (queue_id >= max_t(unsigned int,
			      dev->real_num_rx_queues,
			      dev->real_num_tx_queues))
		/*queue_id不超过设备rx/tx队列数*/
		return -EINVAL;

	/*更新rx或tx对应的xdp pool*/
	if (queue_id < dev->real_num_rx_queues)
		dev->_rx[queue_id].pool = pool;
	if (queue_id < dev->real_num_tx_queues)
		dev->_tx[queue_id].pool = pool;

	return 0;
}

static int __xsk_rcv_zc(struct xdp_sock *xs, struct xdp_buff_xsk *xskb, u32 len,
			u32 flags)
{
	u64 addr;
	int err;

	addr = xp_get_handle(xskb);
	err = xskq_prod_reserve_desc(xs->rx, addr, len, flags);
	if (err) {
		/*队列为满*/
		xs->rx_queue_full++;
		return err;
	}

	xp_release(xskb);
	return 0;
}

//xsocket对应的zero copy收包函数
static int xsk_rcv_zc(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
	struct xdp_buff_xsk *xskb = container_of(xdp, struct xdp_buff_xsk, xdp);
	u32 frags = xdp_buff_has_frags(xdp);
	struct xdp_buff_xsk *pos, *tmp;
	struct list_head *xskb_list;
	u32 contd = 0;
	int err;

	if (frags)
		contd = XDP_PKT_CONTD;

	err = __xsk_rcv_zc(xs, xskb, len, contd);
	if (err)
		goto err;
	if (likely(!frags))
		return 0;

	xskb_list = &xskb->pool->xskb_list;
	list_for_each_entry_safe(pos, tmp, xskb_list, xskb_list_node) {
		if (list_is_singular(xskb_list))
			contd = 0;
		len = pos->xdp.data_end - pos->xdp.data;
		err = __xsk_rcv_zc(xs, pos, len, contd);
		if (err)
			goto err;
		list_del(&pos->xskb_list_node);
	}

	return 0;
err:
	xsk_buff_free(xdp);
	return err;
}

static void *xsk_copy_xdp_start(struct xdp_buff *from)
{
	if (unlikely(xdp_data_meta_unsupported(from)))
		/*此buffer不包含meta,故metalen为0*/
		return from->data;
	else
		/*支持meta,自data_meta位置开始copy*/
		return from->data_meta;
}

static u32 xsk_copy_xdp(void *to, void **from, u32 to_len,
			u32 *from_len, skb_frag_t **frag, u32 rem)
{
	u32 copied = 0;

	while (1) {
		u32 copy_len = min_t(u32, *from_len, to_len);

		memcpy(to, *from, copy_len);
		copied += copy_len;
		if (rem == copied)
			return copied;

		if (*from_len == copy_len) {
			*from = skb_frag_address(*frag);
			*from_len = skb_frag_size((*frag)++);
		} else {
			*from += copy_len;
			*from_len -= copy_len;
		}
		if (to_len == copy_len)
			return copied;

		to_len -= copy_len;
		to += copy_len;
	}
}

static int __xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
	u32 frame_size = xsk_pool_get_rx_frame_size(xs->pool);
	void *copy_from = xsk_copy_xdp_start(xdp), *copy_to;
	u32 from_len, meta_len, rem, num_desc;
	struct xdp_buff_xsk *xskb;
	struct xdp_buff *xsk_xdp;
	skb_frag_t *frag;

	from_len = xdp->data_end - copy_from;
	meta_len = xdp->data - copy_from;
	rem = len + meta_len;

	if (len <= frame_size && !xdp_buff_has_frags(xdp)) {
		int err;

		xsk_xdp = xsk_buff_alloc(xs->pool);
		if (!xsk_xdp) {
			xs->rx_dropped++;
			return -ENOMEM;
		}
		memcpy(xsk_xdp->data - meta_len, copy_from, rem);
		xskb = container_of(xsk_xdp, struct xdp_buff_xsk, xdp);
		err = __xsk_rcv_zc(xs, xskb, len, 0);
		if (err) {
			xsk_buff_free(xsk_xdp);
			return err;
		}

		return 0;
	}

	num_desc = (len - 1) / frame_size + 1;

	if (!xsk_buff_can_alloc(xs->pool, num_desc)) {
		xs->rx_dropped++;
		return -ENOMEM;
	}
	if (xskq_prod_nb_free(xs->rx, num_desc) < num_desc) {
		xs->rx_queue_full++;
		return -ENOBUFS;
	}

	if (xdp_buff_has_frags(xdp)) {
		struct skb_shared_info *sinfo;

		sinfo = xdp_get_shared_info_from_buff(xdp);
		frag =  &sinfo->frags[0];
	}

	do {
		u32 to_len = frame_size + meta_len;
		u32 copied;

		xsk_xdp = xsk_buff_alloc(xs->pool);
		copy_to = xsk_xdp->data - meta_len;

		copied = xsk_copy_xdp(copy_to, &copy_from, to_len, &from_len, &frag, rem);
		rem -= copied;

		xskb = container_of(xsk_xdp, struct xdp_buff_xsk, xdp);
		__xsk_rcv_zc(xs, xskb, copied - meta_len, rem ? XDP_PKT_CONTD : 0);
		meta_len = 0;
	} while (rem);

	return 0;
}

static bool xsk_tx_writeable(struct xdp_sock *xs)
{
	if (xskq_cons_present_entries(xs->tx) > xs->tx->nentries / 2)
		return false;

	return true;
}

static bool xsk_is_bound(struct xdp_sock *xs)
{
	if (READ_ONCE(xs->state) == XSK_BOUND) {
		/* Matches smp_wmb() in bind(). */
		smp_rmb();
		return true;
	}
	return false;
}

static int xsk_rcv_check(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
	if (!xsk_is_bound(xs))
		return -ENXIO;

	//dev与queue_id必须与xd的元数组一致
	if (xs->dev != xdp->rxq->dev || xs->queue_id != xdp->rxq->queue_index)
		return -EINVAL;

	if (len > xsk_pool_get_rx_frame_size(xs->pool) && !xs->sg) {
		/*报文过长，此pool无法收取，丢包*/
		xs->rx_dropped++;
		return -ENOSPC;
	}

	sk_mark_napi_id_once_xdp(&xs->sk, xdp);
	return 0;
}

static void xsk_flush(struct xdp_sock *xs)
{
	xskq_prod_submit(xs->rx);
	__xskq_cons_release(xs->pool->fq);
	sock_def_readable(&xs->sk);
}

int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	u32 len = xdp_get_buff_len(xdp);
	int err;

	spin_lock_bh(&xs->rx_lock);
	err = xsk_rcv_check(xs, xdp, len);
	if (!err) {
		/*收取此xdp*/
		err = __xsk_rcv(xs, xdp, len);
		/*更新位置*/
		xsk_flush(xs);
	}
	spin_unlock_bh(&xs->rx_lock);
	return err;
}

//xsokcet收包入口
static int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	u32 len = xdp_get_buff_len(xdp);
	int err;

	//不转发给未bound的socket
	err = xsk_rcv_check(xs, xdp, len);
	if (err)
		return err;

	if (xdp->rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL) {
		//报文长度
		len = xdp->data_end - xdp->data;
		//将xdp存放在rx队列中
		return xsk_rcv_zc(xs, xdp, len);
	}

	/*复制并存放到rx队列中*/
	err = __xsk_rcv(xs, xdp, len);
	if (!err)
		xdp_return_buff(xdp);
	return err;
}

//将报文送给指定的xdp socket
int __xsk_map_redirect(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	struct list_head *flush_list = this_cpu_ptr(&xskmap_flush_list);
	int err;

	//走xdp socket收包流程
	err = xsk_rcv(xs, xdp);
	if (err)
		return err;

	/*将此xs加入到flush_list中*/
	if (!xs->flush_node.prev)
		list_add(&xs->flush_node, flush_list);

	return 0;
}

void __xsk_map_flush(void)
{
	struct list_head *flush_list = this_cpu_ptr(&xskmap_flush_list);
	struct xdp_sock *xs, *tmp;

	list_for_each_entry_safe(xs, tmp, flush_list, flush_node) {
		xsk_flush(xs);
		__list_del_clearprev(&xs->flush_node);
	}
}

#ifdef CONFIG_DEBUG_NET
bool xsk_map_check_flush(void)
{
	if (list_empty(this_cpu_ptr(&xskmap_flush_list)))
		return false;
	__xsk_map_flush();
	return true;
}
#endif

void xsk_tx_completed(struct xsk_buff_pool *pool, u32 nb_entries)
{
	/*生产者一次性提交nb_entries个元素*/
	xskq_prod_submit_n(pool->cq, nb_entries);
}
EXPORT_SYMBOL(xsk_tx_completed);

void xsk_tx_release(struct xsk_buff_pool *pool)
{
	struct xdp_sock *xs;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		__xskq_cons_release(xs->tx);
		if (xsk_tx_writeable(xs))
			xs->sk.sk_write_space(&xs->sk);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(xsk_tx_release);

bool xsk_tx_peek_desc(struct xsk_buff_pool *pool, struct xdp_desc *desc)
{
	bool budget_exhausted = false;
	struct xdp_sock *xs;

	rcu_read_lock();
again:
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		if (xs->tx_budget_spent >= MAX_PER_SOCKET_BUDGET) {
			budget_exhausted = true;
			continue;
		}

		if (!xskq_cons_peek_desc(xs->tx, desc, pool)) {
			if (xskq_has_descs(xs->tx))
				xskq_cons_release(xs->tx);
			continue;
		}

		xs->tx_budget_spent++;

		/* This is the backpressure mechanism for the Tx path.
		 * Reserve space in the completion queue and only proceed
		 * if there is space in it. This avoids having to implement
		 * any buffering in the Tx path.
		 */
		if (xskq_prod_reserve_addr(pool->cq, desc->addr))
			goto out;

		xskq_cons_release(xs->tx);
		rcu_read_unlock();
		return true;
	}

	if (budget_exhausted) {
		list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list)
			xs->tx_budget_spent = 0;

		budget_exhausted = false;
		goto again;
	}

out:
	rcu_read_unlock();
	return false;
}
EXPORT_SYMBOL(xsk_tx_peek_desc);

static u32 xsk_tx_peek_release_fallback(struct xsk_buff_pool *pool, u32 max_entries)
{
	struct xdp_desc *descs = pool->tx_descs;
	u32 nb_pkts = 0;

	while (nb_pkts < max_entries && xsk_tx_peek_desc(pool, &descs[nb_pkts]))
		nb_pkts++;

	xsk_tx_release(pool);
	return nb_pkts;
}

u32 xsk_tx_peek_release_desc_batch(struct xsk_buff_pool *pool, u32 nb_pkts)
{
	struct xdp_sock *xs;

	rcu_read_lock();
	if (!list_is_singular(&pool->xsk_tx_list)) {
		/* Fallback to the non-batched version */
		rcu_read_unlock();
		return xsk_tx_peek_release_fallback(pool, nb_pkts);
	}

	xs = list_first_or_null_rcu(&pool->xsk_tx_list, struct xdp_sock, tx_list);
	if (!xs) {
		nb_pkts = 0;
		goto out;
	}

	nb_pkts = xskq_cons_nb_entries(xs->tx, nb_pkts);

	/* This is the backpressure mechanism for the Tx path. Try to
	 * reserve space in the completion queue for all packets, but
	 * if there are fewer slots available, just process that many
	 * packets. This avoids having to implement any buffering in
	 * the Tx path.
	 */
	nb_pkts = xskq_prod_nb_free(pool->cq, nb_pkts);
	if (!nb_pkts)
		goto out;

	nb_pkts = xskq_cons_read_desc_batch(xs->tx, pool, nb_pkts);
	if (!nb_pkts) {
		xs->tx->queue_empty_descs++;
		goto out;
	}

	__xskq_cons_release(xs->tx);
	xskq_prod_write_addr_batch(pool->cq, pool->tx_descs, nb_pkts);
	xs->sk.sk_write_space(&xs->sk);

out:
	rcu_read_unlock();
	return nb_pkts;
}
EXPORT_SYMBOL(xsk_tx_peek_release_desc_batch);

//唤醒设备进行处理
static int xsk_wakeup(struct xdp_sock *xs, u8 flags)
{
	struct net_device *dev = xs->dev;

	return dev->netdev_ops->ndo_xsk_wakeup(dev, xs->queue_id, flags);
}

static int xsk_cq_reserve_addr_locked(struct xdp_sock *xs, u64 addr)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&xs->pool->cq_lock, flags);
	ret = xskq_prod_reserve_addr(xs->pool->cq, addr);
	spin_unlock_irqrestore(&xs->pool->cq_lock, flags);

	return ret;
}

static void xsk_cq_submit_locked(struct xdp_sock *xs, u32 n)
{
	unsigned long flags;

	spin_lock_irqsave(&xs->pool->cq_lock, flags);
	xskq_prod_submit_n(xs->pool->cq, n);
	spin_unlock_irqrestore(&xs->pool->cq_lock, flags);
}

static void xsk_cq_cancel_locked(struct xdp_sock *xs, u32 n)
{
	unsigned long flags;

	spin_lock_irqsave(&xs->pool->cq_lock, flags);
	xskq_prod_cancel_n(xs->pool->cq, n);
	spin_unlock_irqrestore(&xs->pool->cq_lock, flags);
}

static u32 xsk_get_num_desc(struct sk_buff *skb)
{
	return skb ? (long)skb_shinfo(skb)->destructor_arg : 0;
}

static void xsk_destruct_skb(struct sk_buff *skb)
{
	struct xsk_tx_metadata_compl *compl = &skb_shinfo(skb)->xsk_meta;

	if (compl->tx_timestamp) {
		/* sw completion timestamp, not a real one */
		*compl->tx_timestamp = ktime_get_tai_fast_ns();
	}

	xsk_cq_submit_locked(xdp_sk(skb->sk), xsk_get_num_desc(skb));
	sock_wfree(skb);
}

static void xsk_set_destructor_arg(struct sk_buff *skb)
{
	long num = xsk_get_num_desc(xdp_sk(skb->sk)->skb) + 1;

	skb_shinfo(skb)->destructor_arg = (void *)num;
}

static void xsk_consume_skb(struct sk_buff *skb)
{
	struct xdp_sock *xs = xdp_sk(skb->sk);

	skb->destructor = sock_wfree;
	xsk_cq_cancel_locked(xs, xsk_get_num_desc(skb));
	/* Free skb without triggering the perf drop trace */
	consume_skb(skb);
	xs->skb = NULL;
}

static void xsk_drop_skb(struct sk_buff *skb)
{
	xdp_sk(skb->sk)->tx->invalid_descs += xsk_get_num_desc(skb);
	xsk_consume_skb(skb);
}

static struct sk_buff *xsk_build_skb_zerocopy(struct xdp_sock *xs,
					      struct xdp_desc *desc)
{
	struct xsk_buff_pool *pool = xs->pool;
	u32 hr, len, ts, offset, copy, copied;
	struct sk_buff *skb = xs->skb;
	struct page *page;
	void *buffer;
	int err, i;
	u64 addr;

	if (!skb) {
		hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(xs->dev->needed_headroom));

		skb = sock_alloc_send_skb(&xs->sk, hr, 1, &err);
		if (unlikely(!skb))
			return ERR_PTR(err);

		skb_reserve(skb, hr);
	}

	addr = desc->addr;
	len = desc->len;
	ts = pool->unaligned ? len : pool->chunk_size;

	buffer = xsk_buff_raw_get_data(pool, addr);
	offset = offset_in_page(buffer);
	addr = buffer - pool->addrs;

	for (copied = 0, i = skb_shinfo(skb)->nr_frags; copied < len; i++) {
		if (unlikely(i >= MAX_SKB_FRAGS))
			return ERR_PTR(-EOVERFLOW);

		page = pool->umem->pgs[addr >> PAGE_SHIFT];
		get_page(page);

		copy = min_t(u32, PAGE_SIZE - offset, len - copied);
		skb_fill_page_desc(skb, i, page, offset, copy);

		copied += copy;
		addr += copy;
		offset = 0;
	}

	skb->len += len;
	skb->data_len += len;
	skb->truesize += ts;

	refcount_add(ts, &xs->sk.sk_wmem_alloc);

	return skb;
}

/*利用xdp描述符构造skb*/
static struct sk_buff *xsk_build_skb(struct xdp_sock *xs,
				     struct xdp_desc *desc)
{
	struct xsk_tx_metadata *meta = NULL;
	struct net_device *dev = xs->dev;
	struct sk_buff *skb = xs->skb;
	bool first_frag = false;
	int err;

	if (dev->priv_flags & IFF_TX_SKB_NO_LINEAR) {
		skb = xsk_build_skb_zerocopy(xs, desc);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			goto free_err;
		}
	} else {
		u32 hr, tr, len;
		void *buffer;

		buffer = xsk_buff_raw_get_data(xs->pool, desc->addr);
		len = desc->len;

		if (!skb) {
			hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(dev->needed_headroom));
			tr = dev->needed_tailroom;
			skb = sock_alloc_send_skb(&xs->sk, hr + len + tr, 1, &err);
			if (unlikely(!skb))
				goto free_err;

			skb_reserve(skb, hr);
			skb_put(skb, len);

			err = skb_store_bits(skb, 0, buffer, len);
			if (unlikely(err)) {
				kfree_skb(skb);
				goto free_err;
			}

			first_frag = true;
		} else {
			int nr_frags = skb_shinfo(skb)->nr_frags;
			struct page *page;
			u8 *vaddr;

			if (unlikely(nr_frags == (MAX_SKB_FRAGS - 1) && xp_mb_desc(desc))) {
				err = -EOVERFLOW;
				goto free_err;
			}

			page = alloc_page(xs->sk.sk_allocation);
			if (unlikely(!page)) {
				err = -EAGAIN;
				goto free_err;
			}

			vaddr = kmap_local_page(page);
			memcpy(vaddr, buffer, len);
			kunmap_local(vaddr);

			skb_add_rx_frag(skb, nr_frags, page, 0, len, 0);
		}

		if (first_frag && desc->options & XDP_TX_METADATA) {
			if (unlikely(xs->pool->tx_metadata_len == 0)) {
				err = -EINVAL;
				goto free_err;
			}

			meta = buffer - xs->pool->tx_metadata_len;
			if (unlikely(!xsk_buff_valid_tx_metadata(meta))) {
				err = -EINVAL;
				goto free_err;
			}

			if (meta->flags & XDP_TXMD_FLAGS_CHECKSUM) {
				if (unlikely(meta->request.csum_start +
					     meta->request.csum_offset +
					     sizeof(__sum16) > len)) {
					err = -EINVAL;
					goto free_err;
				}

				skb->csum_start = hr + meta->request.csum_start;
				skb->csum_offset = meta->request.csum_offset;
				skb->ip_summed = CHECKSUM_PARTIAL;

				if (unlikely(xs->pool->tx_sw_csum)) {
					err = skb_checksum_help(skb);
					if (err)
						goto free_err;
				}
			}
		}
	}

	skb->dev = dev;
	skb->priority = READ_ONCE(xs->sk.sk_priority);
	skb->mark = READ_ONCE(xs->sk.sk_mark);
	skb->destructor = xsk_destruct_skb;
	xsk_tx_metadata_to_compl(meta, &skb_shinfo(skb)->xsk_meta);
	xsk_set_destructor_arg(skb);

	return skb;

free_err:
	if (err == -EOVERFLOW) {
		/* Drop the packet */
		xsk_set_destructor_arg(xs->skb);
		xsk_drop_skb(xs->skb);
		xskq_cons_release(xs->tx);
	} else {
		/* Let application retry */
		xsk_cq_cancel_locked(xs, 1);
	}

	return ERR_PTR(err);
}

/*取tx描述符，构造skb并执行发送，发送如果失败，用户态需要retry*/
static int __xsk_generic_xmit(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);
	u32 max_batch = TX_BATCH_SIZE;
	bool sent_frame = false;
	struct xdp_desc desc;
	struct sk_buff *skb;
	int err = 0;

	mutex_lock(&xs->mutex);

	/* Since we dropped the RCU read lock, the socket state might have changed. */
	if (unlikely(!xsk_is_bound(xs))) {
		err = -ENXIO;
		goto out;
	}

	if (xs->queue_id >= xs->dev->real_num_tx_queues)
		/*队列id异常，退出*/
		goto out;

	/*自tx队列中取一个描述符*/
	while (xskq_cons_peek_desc(xs->tx, &desc, xs->pool)) {
		if (max_batch-- == 0) {
			/*tx队列中仍有报文，但batch用尽,需要用户态重新尝试发送，故返回EAGAIN*/
			err = -EAGAIN;
			goto out;
		}

		/* This is the backpressure mechanism for the Tx path.
		 * Reserve space in the completion queue and only proceed
		 * if there is space in it. This avoids having to implement
		 * any buffering in the Tx path.
		 */
		if (xsk_cq_reserve_addr_locked(xs, desc.addr))
			goto out;

		/*利用描述符中的信息构造skb*/
		skb = xsk_build_skb(xs, &desc);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			if (err != -EOVERFLOW)
				goto out;
			err = 0;
			continue;
		}

		xskq_cons_release(xs->tx);

		if (xp_mb_desc(&desc)) {
			xs->skb = skb;
			continue;
		}

		/*将构造好的skb自xs->queue_id号队列发出*/
		err = __dev_direct_xmit(skb, xs->queue_id);
		if  (err == NETDEV_TX_BUSY) {
			/*遇这种错误，需要重新尝试发送，故返回EAGAIN*/
			/* Tell user-space to retry the send */
			xskq_cons_cancel_n(xs->tx, xsk_get_num_desc(skb));
			xsk_consume_skb(skb);
			err = -EAGAIN;
			goto out;
		}

		/* Ignore NET_XMIT_CN as packet might have been sent */
		if (err == NET_XMIT_DROP) {
			/* SKB completed but not sent */
			err = -EBUSY;
			xs->skb = NULL;
			goto out;
		}

		sent_frame = true;
		xs->skb = NULL;
	}

	if (xskq_has_descs(xs->tx)) {
		if (xs->skb)
			xsk_drop_skb(xs->skb);
		xskq_cons_release(xs->tx);
	}

out:
	if (sent_frame)
		if (xsk_tx_writeable(xs))
			sk->sk_write_space(sk);

	mutex_unlock(&xs->mutex);
	return err;
}

/*非零copy的xdp socket发送流程（用于将tx队列中的报文申请skb后，并给dev)*/
static int xsk_generic_xmit(struct sock *sk)
{
	int ret;

	/* Drop the RCU lock since the SKB path might sleep. */
	rcu_read_unlock();
	/*通过描述符生成skb,并发送*/
	ret = __xsk_generic_xmit(sk);
	/* Reaquire RCU lock before going into common code. */
	rcu_read_lock();

	return ret;
}

/*是否跳过wakeup*/
static bool xsk_no_wakeup(struct sock *sk)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	/* Prefer busy-polling, skip the wakeup. */
	return READ_ONCE(sk->sk_prefer_busy_poll) && READ_ONCE(sk->sk_ll_usec) &&
		READ_ONCE(sk->sk_napi_id) >= MIN_NAPI_ID;
#else
	return false;
#endif
}

static int xsk_check_common(struct xdp_sock *xs)
{
	if (unlikely(!xsk_is_bound(xs)))
		return -ENXIO;
	if (unlikely(!(xs->dev->flags & IFF_UP)))
		/*底层设备需要up*/
		return -ENETDOWN;

	return 0;
}

static int __xsk_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	/*用户态是否在等待*/
	bool need_wait = !(m->msg_flags & MSG_DONTWAIT);
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct xsk_buff_pool *pool;
	int err;

	err = xsk_check_common(xs);
	if (err)
		return err;
	if (unlikely(need_wait))
		/*当前不支持等待*/
		return -EOPNOTSUPP;
	if (unlikely(!xs->tx))
		/*tx队列不存在，无法发送*/
		return -ENOBUFS;

	/*如果socket容许，则执行busy poll*/
	if (sk_can_busy_loop(sk)) {
		if (xs->zc)
			__sk_mark_napi_id_once(sk, xsk_pool_get_napi_id(xs->pool));
		sk_busy_loop(sk, 1); /* only support non-blocking sockets */
	}

	if (xs->zc && xsk_no_wakeup(sk))
		return 0;

	pool = xs->pool;
	if (pool->cached_need_wakeup & XDP_WAKEUP_TX) {
		if (xs->zc)
			/*支持零copy情况下，唤醒设备执行tx*/
			return xsk_wakeup(xs, XDP_WAKEUP_TX);
		/*不支持零copy,走一般发送流程*/
		return xsk_generic_xmit(sk);
	}
	return 0;
}

static int xsk_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	int ret;

	rcu_read_lock();
	ret = __xsk_sendmsg(sock, m, total_len);
	rcu_read_unlock();

	return ret;
}

static int __xsk_recvmsg(struct socket *sock, struct msghdr *m, size_t len, int flags)
{
	bool need_wait = !(flags & MSG_DONTWAIT);
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int err;

	err = xsk_check_common(xs);
	if (err)
		return err;
	if (unlikely(!xs->rx))
		return -ENOBUFS;
	if (unlikely(need_wait))
		return -EOPNOTSUPP;

	if (sk_can_busy_loop(sk))
		sk_busy_loop(sk, 1); /* only support non-blocking sockets */

	if (xsk_no_wakeup(sk))
		return 0;

	if (xs->pool->cached_need_wakeup & XDP_WAKEUP_RX && xs->zc)
		return xsk_wakeup(xs, XDP_WAKEUP_RX);
	return 0;
}

static int xsk_recvmsg(struct socket *sock, struct msghdr *m, size_t len, int flags)
{
	int ret;

	rcu_read_lock();
	ret = __xsk_recvmsg(sock, m, len, flags);
	rcu_read_unlock();

	return ret;
}

//检测xdp socket poll事件
static __poll_t xsk_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	__poll_t mask = 0;
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct xsk_buff_pool *pool;

	sock_poll_wait(file, sock, wait);

	rcu_read_lock();
	if (xsk_check_common(xs))
		goto out;

	pool = xs->pool;

	if (pool->cached_need_wakeup) {
		if (xs->zc)
			xsk_wakeup(xs, pool->cached_need_wakeup);
		else if (xs->tx)
			/* Poll needs to drive Tx also in copy mode */
			xsk_generic_xmit(sk);
	}

	//如果rx队列不为空，则返回可读
	if (xs->rx && !xskq_prod_is_empty(xs->rx))
		mask |= EPOLLIN | EPOLLRDNORM;
	//如果tx队列不为空，则返回可写
	if (xs->tx && xsk_tx_writeable(xs))
		mask |= EPOLLOUT | EPOLLWRNORM;
out:
	rcu_read_unlock();
	return mask;
}

/*初始化xsk queue*/
static int xsk_init_queue(u32 entries/*队列长度*/, struct xsk_queue **queue/*出参，返回创建好的队列*/,
			  bool umem_queue/*是否为umem queue*/)
{
	struct xsk_queue *q;

	//队列长度不得为0，且必须为2的N次幂
	if (entries == 0 || *queue || !is_power_of_2(entries))
		return -EINVAL;

	q = xskq_create(entries, umem_queue);
	if (!q)
		return -ENOMEM;

	/* Make sure queue is ready before it can be seen by others */
	smp_wmb();
	//设置创建好的队列
	WRITE_ONCE(*queue, q);
	return 0;
}

static void xsk_unbind_dev(struct xdp_sock *xs)
{
	struct net_device *dev = xs->dev;

	if (xs->state != XSK_BOUND)
		return;
	WRITE_ONCE(xs->state, XSK_UNBOUND);

	/* Wait for driver to stop using the xdp socket. */
	xp_del_xsk(xs->pool, xs);
	synchronize_net();
	dev_put(dev);
}

static struct xsk_map *xsk_get_map_list_entry(struct xdp_sock *xs,
					      struct xdp_sock __rcu ***map_entry)
{
	struct xsk_map *map = NULL;
	struct xsk_map_node *node;

	*map_entry = NULL;

	spin_lock_bh(&xs->map_list_lock);
	node = list_first_entry_or_null(&xs->map_list, struct xsk_map_node,
					node);
	if (node) {
		bpf_map_inc(&node->map->map);
		map = node->map;
		*map_entry = node->map_entry;
	}
	spin_unlock_bh(&xs->map_list_lock);
	return map;
}

static void xsk_delete_from_maps(struct xdp_sock *xs)
{
	/* This function removes the current XDP socket from all the
	 * maps it resides in. We need to take extra care here, due to
	 * the two locks involved. Each map has a lock synchronizing
	 * updates to the entries, and each socket has a lock that
	 * synchronizes access to the list of maps (map_list). For
	 * deadlock avoidance the locks need to be taken in the order
	 * "map lock"->"socket map list lock". We start off by
	 * accessing the socket map list, and take a reference to the
	 * map to guarantee existence between the
	 * xsk_get_map_list_entry() and xsk_map_try_sock_delete()
	 * calls. Then we ask the map to remove the socket, which
	 * tries to remove the socket from the map. Note that there
	 * might be updates to the map between
	 * xsk_get_map_list_entry() and xsk_map_try_sock_delete().
	 */
	struct xdp_sock __rcu **map_entry = NULL;
	struct xsk_map *map;

	while ((map = xsk_get_map_list_entry(xs, &map_entry))) {
		xsk_map_try_sock_delete(map, xs, map_entry);
		bpf_map_put(&map->map);
	}
}

static int xsk_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct net *net;

	if (!sk)
		return 0;

	net = sock_net(sk);

	if (xs->skb)
		xsk_drop_skb(xs->skb);

	mutex_lock(&net->xdp.lock);
	sk_del_node_init_rcu(sk);
	mutex_unlock(&net->xdp.lock);

	sock_prot_inuse_add(net, sk->sk_prot, -1);

	xsk_delete_from_maps(xs);
	mutex_lock(&xs->mutex);
	xsk_unbind_dev(xs);
	mutex_unlock(&xs->mutex);

	xskq_destroy(xs->rx);
	xskq_destroy(xs->tx);
	xskq_destroy(xs->fq_tmp);
	xskq_destroy(xs->cq_tmp);

	sock_orphan(sk);
	sock->sk = NULL;

	sock_put(sk);

	return 0;
}

/*通过fd取其对应的af_xdp socket*/
static struct socket *xsk_lookup_xsk_from_fd(int fd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	if (sock->sk->sk_family != PF_XDP) {
		sockfd_put(sock);
		return ERR_PTR(-ENOPROTOOPT);
	}

	return sock;
}

static bool xsk_validate_queues(struct xdp_sock *xs)
{
	return xs->fq_tmp && xs->cq_tmp;
}

static int xsk_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_xdp *sxdp = (struct sockaddr_xdp *)addr;
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct net_device *dev;
	int bound_dev_if;
	u32 flags, qid;
	int err = 0;

	if (addr_len < sizeof(struct sockaddr_xdp))
		return -EINVAL;

	if (sxdp->sxdp_family != AF_XDP)
		/*socket必须为af_xdp*/
		return -EINVAL;

	/*当前支持的flags检查*/
	flags = sxdp->sxdp_flags;
	if (flags & ~(XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY |
		      XDP_USE_NEED_WAKEUP | XDP_USE_SG))
		return -EINVAL;

	bound_dev_if = READ_ONCE(sk->sk_bound_dev_if);
	if (bound_dev_if && bound_dev_if != sxdp->sxdp_ifindex)
		return -EINVAL;

	rtnl_lock();
	mutex_lock(&xs->mutex);
	/*socket必须处于ready状态*/
	if (xs->state != XSK_READY) {
		err = -EBUSY;
		goto out_release;
	}

	//通过ifindex获取要绑定的netdev
	dev = dev_get_by_index(sock_net(sk), sxdp->sxdp_ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out_release;
	}

	/*绑定时，rx,tx队列必须已完成初始化*/
	if (!xs->rx && !xs->tx) {
		err = -EINVAL;
		goto out_unlock;
	}

	//取要关联的queue id
	qid = sxdp->sxdp_queue_id;

	if (flags & XDP_SHARED_UMEM) {
		struct xdp_sock *umem_xs;
		struct socket *sock;

		if ((flags & XDP_COPY) || (flags & XDP_ZEROCOPY) ||
		    (flags & XDP_USE_NEED_WAKEUP) || (flags & XDP_USE_SG)) {
			/* Cannot specify flags for shared sockets. */
			err = -EINVAL;
			goto out_unlock;
		}

		if (xs->umem) {
			/* We have already our own. */
			err = -EINVAL;
			goto out_unlock;
		}

		/*通过fd查找要share的af_xdp socket*/
		sock = xsk_lookup_xsk_from_fd(sxdp->sxdp_shared_umem_fd);
		if (IS_ERR(sock)) {
			err = PTR_ERR(sock);
			goto out_unlock;
		}

		umem_xs = xdp_sk(sock->sk);
		if (!xsk_is_bound(umem_xs)) {
			err = -EBADF;
			sockfd_put(sock);
			goto out_unlock;
		}

		if (umem_xs->queue_id != qid || umem_xs->dev != dev) {
			/* Share the umem with another socket on another qid
			 * and/or device.
			 */
			xs->pool = xp_create_and_assign_umem(xs,
							     umem_xs->umem);
			if (!xs->pool) {
				err = -ENOMEM;
				sockfd_put(sock);
				goto out_unlock;
			}

			err = xp_assign_dev_shared(xs->pool, umem_xs, dev,
						   qid);
			if (err) {
				xp_destroy(xs->pool);
				xs->pool = NULL;
				sockfd_put(sock);
				goto out_unlock;
			}
		} else {
			/* Share the buffer pool with the other socket. */
			if (xs->fq_tmp || xs->cq_tmp) {
				/* Do not allow setting your own fq or cq. */
				err = -EINVAL;
				sockfd_put(sock);
				goto out_unlock;
			}

			xp_get_pool(umem_xs->pool);
			xs->pool = umem_xs->pool;

			/* If underlying shared umem was created without Tx
			 * ring, allocate Tx descs array that Tx batching API
			 * utilizes
			 */
			if (xs->tx && !xs->pool->tx_descs) {
				err = xp_alloc_tx_descs(xs->pool, xs);
				if (err) {
					xp_put_pool(xs->pool);
					xs->pool = NULL;
					sockfd_put(sock);
					goto out_unlock;
				}
			}
		}

		xdp_get_umem(umem_xs->umem);
		WRITE_ONCE(xs->umem, umem_xs->umem);
		sockfd_put(sock);
	} else if (!xs->umem || !xsk_validate_queues(xs)) {
		err = -EINVAL;
		goto out_unlock;
	} else {
		/* This xsk has its own umem. */
		xs->pool = xp_create_and_assign_umem(xs, xs->umem);/*创建pool*/
		if (!xs->pool) {
			err = -ENOMEM;
			goto out_unlock;
		}

		/*将xs pool赋给netdev,这要求网卡驱动支持ndo_bpf接口*/
		err = xp_assign_dev(xs->pool, dev, qid, flags);
		if (err) {
			xp_destroy(xs->pool);
			xs->pool = NULL;
			goto out_unlock;
		}
	}

	/* FQ and CQ are now owned by the buffer pool and cleaned up with it. */
	xs->fq_tmp = NULL;
	xs->cq_tmp = NULL;

	xs->dev = dev;
	xs->zc = xs->umem->zc;
	xs->sg = !!(xs->umem->flags & XDP_UMEM_SG_FLAG);
	xs->queue_id = qid;
	xp_add_xsk(xs->pool, xs);

out_unlock:
	if (err) {
		dev_put(dev);
	} else {
		/* Matches smp_rmb() in bind() for shared umem
		 * sockets, and xsk_is_bound().
		 */
		smp_wmb();
		WRITE_ONCE(xs->state, XSK_BOUND);
	}
out_release:
	mutex_unlock(&xs->mutex);
	rtnl_unlock();
	return err;
}

struct xdp_umem_reg_v1 {
	__u64 addr; /* Start of packet data area */
	__u64 len; /* Length of packet data area */
	__u32 chunk_size;
	__u32 headroom;
};

struct xdp_umem_reg_v2 {
	__u64 addr; /* Start of packet data area */
	__u64 len; /* Length of packet data area */
	__u32 chunk_size;
	__u32 headroom;
	__u32 flags;
};

//AF_XDP支持的setsockopt函数
static int xsk_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int err;

	//level必须为SOL_XDP
	if (level != SOL_XDP)
		return -ENOPROTOOPT;

	switch (optname) {
	case XDP_RX_RING:
	case XDP_TX_RING:
	{
		//创建XDP socket对应的RX,TX RING
		struct xsk_queue **q;
		int entries;

		//提供的参数必须为int型
		if (optlen < sizeof(entries))
			return -EINVAL;
		if (copy_from_sockptr(&entries, optval, sizeof(entries)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		//socket必须处理ready状态
		if (xs->state != XSK_READY) {
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}
		/*依据optname确认要初始化的queue类型*/
		q = (optname == XDP_TX_RING) ? &xs->tx : &xs->rx;
		err = xsk_init_queue(entries, q, false/*由于创建的非umem queue,故传入false*/);
		if (!err && optname == XDP_TX_RING)
			/* Tx needs to be explicitly woken up the first time */
			xs->tx->ring->flags |= XDP_RING_NEED_WAKEUP;/*指明tx需要被wakeup*/
		mutex_unlock(&xs->mutex);
		return err;
	}
	case XDP_UMEM_REG:
	{
	    //注册用户态内存
		size_t mr_size = sizeof(struct xdp_umem_reg);
		struct xdp_umem_reg mr = {};
		struct xdp_umem *umem;

		if (optlen < sizeof(struct xdp_umem_reg_v1))
			/*提供的内容过短，报错*/
			return -EINVAL;
		else if (optlen < sizeof(struct xdp_umem_reg_v2))
			/*提供的内容为v1版本的注册信息*/
			mr_size = sizeof(struct xdp_umem_reg_v1);
		else if (optlen < sizeof(mr))
			mr_size = sizeof(struct xdp_umem_reg_v2);

		//获取用户态传入的umem
		if (copy_from_sockptr(&mr, optval, mr_size))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (xs->state != XSK_READY || xs->umem) {
			/*必须在ready情况下配置，且xs->umem未初始化(重复注册）*/
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}

		/*注册用户态传入的umem*/
		umem = xdp_umem_create(&mr);
		if (IS_ERR(umem)) {
			mutex_unlock(&xs->mutex);
			return PTR_ERR(umem);
		}

		/* Make sure umem is ready before it can be seen by others */
		smp_wmb();
		WRITE_ONCE(xs->umem, umem);
		mutex_unlock(&xs->mutex);
		return 0;
	}
	case XDP_UMEM_FILL_RING:
	    //创建 fill ring（与complete ring流程一致）
	case XDP_UMEM_COMPLETION_RING:
	{
	    //创建 complete ring
		struct xsk_queue **q;
		int entries;

		/*取用户态传入的ring长度*/
		if (copy_from_sockptr(&entries, optval, sizeof(entries)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (xs->state != XSK_READY) {
			/*socket必须处于ready状态*/
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}

		//按不同opt取对应的xsk_queue（fill ring与complte ring)
		q = (optname == XDP_UMEM_FILL_RING) ? &xs->fq_tmp :
			&xs->cq_tmp;

		//初始化对应的umem_queue
		err = xsk_init_queue(entries/*queue长度*/, q, true);
		mutex_unlock(&xs->mutex);
		return err;
	}
	default:
		break;
	}

	return -ENOPROTOOPT;
}

//获取rxtx ring格式对应的各成员在内存中位置offset
static void xsk_enter_rxtx_offsets(struct xdp_ring_offset_v1 *ring)
{
	ring->producer = offsetof(struct xdp_rxtx_ring, ptrs.producer);
	ring->consumer = offsetof(struct xdp_rxtx_ring, ptrs.consumer);
	ring->desc = offsetof(struct xdp_rxtx_ring, desc);
}

//获取umem ring格式对应的各成员在内存中位置offset
static void xsk_enter_umem_offsets(struct xdp_ring_offset_v1 *ring)
{
	ring->producer = offsetof(struct xdp_umem_ring, ptrs.producer);
	ring->consumer = offsetof(struct xdp_umem_ring, ptrs.consumer);
	ring->desc = offsetof(struct xdp_umem_ring, desc);
}

struct xdp_statistics_v1 {
	__u64 rx_dropped;
	__u64 rx_invalid_descs;
	__u64 tx_invalid_descs;
};

//xsocket获取socket opt
static int xsk_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int len;

	//level必须为SOL_XDP
	if (level != SOL_XDP)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case XDP_STATISTICS:
	{
		struct xdp_statistics stats = {};
		bool extra_stats = true;
		size_t stats_size;

		if (len < sizeof(struct xdp_statistics_v1)) {
			return -EINVAL;
		} else if (len < sizeof(stats)) {
			extra_stats = false;
			stats_size = sizeof(struct xdp_statistics_v1);
		} else {
			stats_size = sizeof(stats);
		}

		mutex_lock(&xs->mutex);
		stats.rx_dropped = xs->rx_dropped;
		if (extra_stats) {
			stats.rx_ring_full = xs->rx_queue_full;
			stats.rx_fill_ring_empty_descs =
				xs->pool ? xskq_nb_queue_empty_descs(xs->pool->fq) : 0;
			stats.tx_ring_empty_descs = xskq_nb_queue_empty_descs(xs->tx);
		} else {
			stats.rx_dropped += xs->rx_queue_full;
		}
		stats.rx_invalid_descs = xskq_nb_invalid_descs(xs->rx);
		stats.tx_invalid_descs = xskq_nb_invalid_descs(xs->tx);
		mutex_unlock(&xs->mutex);

		if (copy_to_user(optval, &stats, stats_size))
			return -EFAULT;
		if (put_user(stats_size, optlen))
			return -EFAULT;

		return 0;
	}
	case XDP_MMAP_OFFSETS:
	{
	    //获取成员间offset，用于与kernel间数据结构对齐
		struct xdp_mmap_offsets off;
		struct xdp_mmap_offsets_v1 off_v1;
		bool flags_supported = true;/*出参内容中是否包含flags*/
		void *to_copy;

		if (len < sizeof(off_v1))
			/*出参长度过小*/
			return -EINVAL;
		else if (len < sizeof(off))
			/*出参长度采用的为v1版本，不包含flags*/
			flags_supported = false;

		if (flags_supported) {
			/* xdp_ring_offset is identical to xdp_ring_offset_v1
			 * except for the flags field added to the end.
			 */
		    //各ring结构体成员在内存中位置偏移量，例如生产者，消费者，描述符的offset
			//由于rx,tx为xdp_rxtx_ring类型，fr,cr为xdp_umem_ring类型，故填充函数不同
			xsk_enter_rxtx_offsets((struct xdp_ring_offset_v1 *)
					       &off.rx);
			xsk_enter_rxtx_offsets((struct xdp_ring_offset_v1 *)
					       &off.tx);
			xsk_enter_umem_offsets((struct xdp_ring_offset_v1 *)
					       &off.fr);
			xsk_enter_umem_offsets((struct xdp_ring_offset_v1 *)
					       &off.cr);

			//填充各ring结构体flags成员在内存中位置的偏移量
			off.rx.flags = offsetof(struct xdp_rxtx_ring,
						ptrs.flags);
			off.tx.flags = offsetof(struct xdp_rxtx_ring,
						ptrs.flags);
			off.fr.flags = offsetof(struct xdp_umem_ring,
						ptrs.flags);
			off.cr.flags = offsetof(struct xdp_umem_ring,
						ptrs.flags);

			len = sizeof(off);
			to_copy = &off;
		} else {
		    //各ring 生产者，消费者，描述符的offset（rx,tx,fill ring,completion ring)
			xsk_enter_rxtx_offsets(&off_v1.rx);
			xsk_enter_rxtx_offsets(&off_v1.tx);
			xsk_enter_umem_offsets(&off_v1.fr);
			xsk_enter_umem_offsets(&off_v1.cr);

			len = sizeof(off_v1);
			to_copy = &off_v1;
		}

		/*将填充结果返回给用户态*/
		if (copy_to_user(optval, to_copy, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;

		return 0;
	}
	case XDP_OPTIONS:
	{
		struct xdp_options opts = {};

		if (len < sizeof(opts))
			return -EINVAL;

		mutex_lock(&xs->mutex);
		if (xs->zc)
			opts.flags |= XDP_OPTIONS_ZEROCOPY;
		mutex_unlock(&xs->mutex);

		len = sizeof(opts);
		if (copy_to_user(optval, &opts, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;

		return 0;
	}
	default:
		break;
	}

	return -EOPNOTSUPP;
}

//映射xdp socket的fill队列，complete队列
static int xsk_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct *vma)
{
	loff_t offset = (loff_t)vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	struct xdp_sock *xs = xdp_sk(sock->sk);
	int state = READ_ONCE(xs->state);
	struct xsk_queue *q = NULL;

	if (state != XSK_READY && state != XSK_BOUND)
		return -EBUSY;

	//通过mmap的offset来区分当前是在映射哪个队列（rx,tx,fq,cq)
	if (offset == XDP_PGOFF_RX_RING) {
		q = READ_ONCE(xs->rx);
	} else if (offset == XDP_PGOFF_TX_RING) {
		q = READ_ONCE(xs->tx);
	} else {
		/* Matches the smp_wmb() in XDP_UMEM_REG */
		smp_rmb();
		if (offset == XDP_UMEM_PGOFF_FILL_RING)
			q = state == XSK_READY ? READ_ONCE(xs->fq_tmp) :
						 READ_ONCE(xs->pool->fq);
		else if (offset == XDP_UMEM_PGOFF_COMPLETION_RING)
			q = state == XSK_READY ? READ_ONCE(xs->cq_tmp) :
						 READ_ONCE(xs->pool->cq);
	}

	if (!q)
		/*提供的offset有误，导致没有查找到对应的ring*/
		return -EINVAL;

	/* Matches the smp_wmb() in xsk_init_queue */
	smp_rmb();
	if (size > q->ring_vmalloc_size)
		/*要求映射的内存超过实际申请的内存长度，报错*/
		return -EINVAL;

	/*完成对应ring的内存映射*/
	return remap_vmalloc_range(vma, q->ring, 0);
}

static int xsk_notifier(struct notifier_block *this,
			unsigned long msg, void *ptr)
{
	/*取产生事件的netdev*/
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	/*取此netdev对应的net ns*/
	struct net *net = dev_net(dev);
	struct sock *sk;

	switch (msg) {
	case NETDEV_UNREGISTER:
		/*设备解注册时，如果存在与此设备关联的xdp socket,则将此socket置为dead状态*/
		mutex_lock(&net->xdp.lock);
		sk_for_each(sk, &net->xdp.list) {
			struct xdp_sock *xs = xdp_sk(sk);

			mutex_lock(&xs->mutex);
			if (xs->dev == dev) {
				sk->sk_err = ENETDOWN;
				if (!sock_flag(sk, SOCK_DEAD))
					sk_error_report(sk);

				xsk_unbind_dev(xs);

				/* Clear device references. */
				xp_clear_dev(xs->pool);
			}
			mutex_unlock(&xs->mutex);
		}
		mutex_unlock(&net->xdp.lock);
		break;
	}
	return NOTIFY_DONE;
}

static struct proto xsk_proto = {
	.name =		"XDP",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct xdp_sock),
};

//AF_XDP负责proto的操作ops
static const struct proto_ops xsk_proto_ops = {
	.family		= PF_XDP,
	.owner		= THIS_MODULE,
	.release	= xsk_release,
	/*实现接口队列与af_xdp socket绑定*/
	.bind		= xsk_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	/*读写事件检测*/
	.poll		= xsk_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	/*mr注册，ring创建等*/
	.setsockopt	= xsk_setsockopt,
	.getsockopt	= xsk_getsockopt,
	/*通过write/send接口向外发送报文*/
	.sendmsg	= xsk_sendmsg,
	/*通过read,recv接口收取报文*/
	.recvmsg	= xsk_recvmsg,
	//实现4种ring的内存映射（用于用户态ring轮询）
	.mmap		= xsk_mmap,
};

static void xsk_destruct(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);

	if (!sock_flag(sk, SOCK_DEAD))
		return;

	if (!xp_put_pool(xs->pool))
		xdp_put_umem(xs->umem, !xs->pool);
}

//负责xdp socket创建
static int xsk_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct xdp_sock *xs;
	struct sock *sk;

	if (!ns_capable(net->user_ns, CAP_NET_RAW))
		return -EPERM;

	//当前仅支持type为raw的情况
	if (sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	/*当前仅支持protocol为0的情况*/
	if (protocol)
		return -EPROTONOSUPPORT;

	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_XDP, GFP_KERNEL, &xsk_proto, kern);
	if (!sk)
		return -ENOBUFS;

	sock->ops = &xsk_proto_ops;/*指定socket对应的ops*/

	sock_init_data(sock, sk);

	sk->sk_family = PF_XDP;

	sk->sk_destruct = xsk_destruct;

	sock_set_flag(sk, SOCK_RCU_FREE);

	//初始化af_xdp socket
	xs = xdp_sk(sk);
	xs->state = XSK_READY;
	mutex_init(&xs->mutex);
	spin_lock_init(&xs->rx_lock);

	INIT_LIST_HEAD(&xs->map_list);
	spin_lock_init(&xs->map_list_lock);

	mutex_lock(&net->xdp.lock);
	/*将此socket挂接在net->xdp.list链表上*/
	sk_add_node_rcu(sk, &net->xdp.list);
	mutex_unlock(&net->xdp.lock);

	sock_prot_inuse_add(net, &xsk_proto, 1);

	return 0;
}

/*创建af_xdp对应的socket*/
static const struct net_proto_family xsk_family_ops = {
	.family = PF_XDP,
	.create = xsk_create,
	.owner	= THIS_MODULE,
};

static struct notifier_block xsk_netdev_notifier = {
	.notifier_call	= xsk_notifier,
};

static int __net_init xsk_net_init(struct net *net)
{
	mutex_init(&net->xdp.lock);
	INIT_HLIST_HEAD(&net->xdp.list);
	return 0;
}

static void __net_exit xsk_net_exit(struct net *net)
{
	/*此net ns退出时，xpd list必定为空*/
	WARN_ON_ONCE(!hlist_empty(&net->xdp.list));
}

static struct pernet_operations xsk_net_ops = {
	.init = xsk_net_init,
	.exit = xsk_net_exit,
};

static int __init xsk_init(void)
{
	int err, cpu;

	err = proto_register(&xsk_proto, 0 /* no slab */);
	if (err)
		goto out;

	//注册AF_XDP协议族
	err = sock_register(&xsk_family_ops);
	if (err)
		goto out_proto;

	err = register_pernet_subsys(&xsk_net_ops);
	if (err)
		goto out_sk;

	/*注册设备notifier，用于底层设备移除时，关闭xdp socket*/
	err = register_netdevice_notifier(&xsk_netdev_notifier);
	if (err)
		goto out_pernet;

	/*初始化xskmap_flush_list链表*/
	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&per_cpu(xskmap_flush_list, cpu));
	return 0;

out_pernet:
	unregister_pernet_subsys(&xsk_net_ops);
out_sk:
	sock_unregister(PF_XDP);
out_proto:
	proto_unregister(&xsk_proto);
out:
	return err;
}

fs_initcall(xsk_init);
