// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * virtio-net server in host kernel.
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>

#include <linux/net.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/if_macvlan.h>
#include <linux/if_tap.h>
#include <linux/if_vlan.h>
#include <linux/skb_array.h>
#include <linux/skbuff.h>

#include <net/sock.h>
#include <net/xdp.h>

#include "vhost.h"

/*默认当前不开启0copy*/
static int experimental_zcopytx = 0;
module_param(experimental_zcopytx, int, 0444);
MODULE_PARM_DESC(experimental_zcopytx, "Enable Zero Copy TX;"
		                       " 1 -Enable; 0 - Disable");

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_NET_WEIGHT 0x80000

/* Max number of packets transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others with small
 * pkts.
 */
#define VHOST_NET_PKT_WEIGHT 256

/* MAX number of TX used buffers for outstanding zerocopy */
#define VHOST_MAX_PEND 128
#define VHOST_GOODCOPY_LEN 256

/*
 * For transmit, used buffer len is unused; we override it to track buffer
 * status internally; used for zerocopy tx only.
 */
/* Lower device DMA failed */
#define VHOST_DMA_FAILED_LEN	((__force __virtio32)3)
/* Lower device DMA done */
#define VHOST_DMA_DONE_LEN	((__force __virtio32)2)
/* Lower device DMA in progress */
#define VHOST_DMA_IN_PROGRESS	((__force __virtio32)1)
/* Buffer unused */
#define VHOST_DMA_CLEAR_LEN	((__force __virtio32)0)

#define VHOST_DMA_IS_DONE(len) ((__force u32)(len) >= (__force u32)VHOST_DMA_DONE_LEN)

enum {
	VHOST_NET_FEATURES = VHOST_FEATURES |
			 (1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |
			 (1ULL << VIRTIO_NET_F_MRG_RXBUF) |
			 (1ULL << VIRTIO_F_ACCESS_PLATFORM) |
			 (1ULL << VIRTIO_F_RING_RESET)
};

enum {
	VHOST_NET_BACKEND_FEATURES = (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2)
};

enum {
	VHOST_NET_VQ_RX = 0,
	VHOST_NET_VQ_TX = 1,
	VHOST_NET_VQ_MAX = 2,
};

struct vhost_net_ubuf_ref {
	/* refcount follows semantics similar to kref:
	 *  0: object is released
	 *  1: no outstanding ubufs
	 * >1: outstanding ubufs
	 */
	atomic_t refcount;
	wait_queue_head_t wait;
	struct vhost_virtqueue *vq;
};

#define VHOST_NET_BATCH 64
struct vhost_net_buf {
	void **queue;/*用于存放元素*/
	int tail;/*队列尾指针*/
	int head;/*队列头指针*/
};

struct vhost_net_virtqueue {
	struct vhost_virtqueue vq;
	/*协商出来的vhost头部长度*/
	size_t vhost_hlen;
	/*协商出来的socket消息头部长度*/
	size_t sock_hlen;
	/* vhost zerocopy support fields below: */
	/* last used idx for outstanding DMA zerocopy buffers */
	int upend_idx;
	/* For TX, first used idx for DMA done zerocopy buffers
	 * For RX, number of batched heads
	 */
	int done_idx;/*索引，负责vq->heads的填充*/
	/* Number of XDP frames batched */
	int batched_xdp;
	/* an array of userspace buffers info */
	struct ubuf_info_msgzc *ubuf_info;
	/* Reference counting for outstanding ubufs.
	 * Protected by vq mutex. Writers must also take device mutex. */
	struct vhost_net_ubuf_ref *ubufs;
	struct ptr_ring *rx_ring;
	/*收队列buffer,用于按batch自rx_ring中获取报文*/
	struct vhost_net_buf rxq;
	/* Batched XDP buffs */
	struct xdp_buff *xdp;
};

struct vhost_net {
    /*vhost设备*/
	struct vhost_dev dev;
	//设备收发队列
	struct vhost_net_virtqueue vqs[VHOST_NET_VQ_MAX];
	/*rx,tx两个队列分别对应的一个vhost_poll*/
	struct vhost_poll poll[VHOST_NET_VQ_MAX];
	/* Number of TX recently submitted.
	 * Protected by tx vq lock. */
	unsigned tx_packets;
	/* Number of times zerocopy TX recently failed.
	 * Protected by tx vq lock. */
	unsigned tx_zcopy_err;
	/* Flush in progress. Protected by tx vq lock. */
	bool tx_flush;
	/* Private page frag */
	struct page_frag page_frag;
	/* Refcount bias of page frag */
	int refcnt_bias;
};

static unsigned vhost_net_zcopy_mask __read_mostly;

static void *vhost_net_buf_get_ptr(struct vhost_net_buf *rxq)
{
    /*如果有数据，则返回head指向的元素，否则返回NULL*/
	if (rxq->tail != rxq->head)
		return rxq->queue[rxq->head];
	else
		return NULL;
}

static int vhost_net_buf_get_size(struct vhost_net_buf *rxq)
{
	return rxq->tail - rxq->head;
}

static int vhost_net_buf_is_empty(struct vhost_net_buf *rxq)
{
    /*检查vhost net buffer是否为空*/
	return rxq->tail == rxq->head;
}

/*获取一个buffer指针，并将head读头前移一格*/
static void *vhost_net_buf_consume(struct vhost_net_buf *rxq)
{
	void *ret = vhost_net_buf_get_ptr(rxq);
	++rxq->head;
	return ret;
}

static int vhost_net_buf_produce(struct vhost_net_virtqueue *nvq)
{
	struct vhost_net_buf *rxq = &nvq->rxq;

	rxq->head = 0;
	/*自rx_ring中最多出VHOST_NET_BATCH个元素，并将其填充到rxq->queue中*/
	rxq->tail = ptr_ring_consume_batched(nvq->rx_ring, rxq->queue,
					      VHOST_NET_BATCH);
	return rxq->tail;/*返回消费指针位置*/
}

static void vhost_net_buf_unproduce(struct vhost_net_virtqueue *nvq)
{
	struct vhost_net_buf *rxq = &nvq->rxq;

	if (nvq->rx_ring && !vhost_net_buf_is_empty(rxq)) {
		ptr_ring_unconsume(nvq->rx_ring, rxq->queue + rxq->head,
				   vhost_net_buf_get_size(rxq)/*rx队列元素数目*/,
				   tun_ptr_free/*释放rxq中的元素*/);
		rxq->head = rxq->tail = 0;
	}
}

static int vhost_net_buf_peek_len(void *ptr)
{
	if (tun_is_xdp_frame(ptr)) {
	    /*取xdp报文长度*/
		struct xdp_frame *xdpf = tun_ptr_to_xdp(ptr);

		return xdpf->len;
	}

	/*按skb考虑其对应长度*/
	return __skb_array_len_with_tag(ptr);
}

/*peer待处理报文的长度*/
static int vhost_net_buf_peek(struct vhost_net_virtqueue *nvq)
{
	struct vhost_net_buf *rxq = &nvq->rxq;

	if (!vhost_net_buf_is_empty(rxq))
	    /*rxq队列不为空，去out*/
		goto out;

	/*尝试从nvq中出一个batch到rxq,如果nvq中无内容，则退出*/
	if (!vhost_net_buf_produce(nvq))
		return 0;

out:
	return vhost_net_buf_peek_len(vhost_net_buf_get_ptr(rxq));
}

static void vhost_net_buf_init(struct vhost_net_buf *rxq)
{
	rxq->head = rxq->tail = 0;
}

/*为vq队列开启零copy*/
static void vhost_net_enable_zcopy(int vq)
{
	vhost_net_zcopy_mask |= 0x1 << vq;
}

static struct vhost_net_ubuf_ref *
vhost_net_ubuf_alloc(struct vhost_virtqueue *vq, bool zcopy)
{
	struct vhost_net_ubuf_ref *ubufs;
	/* No zero copy backend? Nothing to count. */
	if (!zcopy)
	    /*没有开启零copy，则不处理*/
		return NULL;
	ubufs = kmalloc(sizeof(*ubufs), GFP_KERNEL);
	if (!ubufs)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ubufs->refcount, 1);
	init_waitqueue_head(&ubufs->wait);
	ubufs->vq = vq;
	return ubufs;
}

static int vhost_net_ubuf_put(struct vhost_net_ubuf_ref *ubufs)
{
	int r = atomic_sub_return(1, &ubufs->refcount);
	if (unlikely(!r))
		wake_up(&ubufs->wait);
	return r;
}

static void vhost_net_ubuf_put_and_wait(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put(ubufs);
	wait_event(ubufs->wait, !atomic_read(&ubufs->refcount));
}

static void vhost_net_ubuf_put_wait_and_free(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put_and_wait(ubufs);
	kfree(ubufs);
}

static void vhost_net_clear_ubuf_info(struct vhost_net *n)
{
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		kfree(n->vqs[i].ubuf_info);
		n->vqs[i].ubuf_info = NULL;
	}
}

static int vhost_net_set_ubuf_info(struct vhost_net *n)
{
	bool zcopy;
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		zcopy = vhost_net_zcopy_mask & (0x1 << i);
		if (!zcopy)
		    /*如果此队列未开启zcopy,则跳过*/
			continue;
		//申请ubuf_info空间
		n->vqs[i].ubuf_info =
			kmalloc_array(UIO_MAXIOV,
				      sizeof(*n->vqs[i].ubuf_info),
				      GFP_KERNEL);
		if  (!n->vqs[i].ubuf_info)
			goto err;
	}
	return 0;

err:
	vhost_net_clear_ubuf_info(n);
	return -ENOMEM;
}

static void vhost_net_vq_reset(struct vhost_net *n)
{
	int i;

	vhost_net_clear_ubuf_info(n);

	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].done_idx = 0;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].ubufs = NULL;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
		vhost_net_buf_init(&n->vqs[i].rxq);
	}

}

static void vhost_net_tx_packet(struct vhost_net *net)
{
	++net->tx_packets;
	if (net->tx_packets < 1024)
		return;
	net->tx_packets = 0;
	net->tx_zcopy_err = 0;
}

static void vhost_net_tx_err(struct vhost_net *net)
{
	++net->tx_zcopy_err;
}

static bool vhost_net_tx_select_zcopy(struct vhost_net *net)
{
	/* TX flush waits for outstanding DMAs to be done.
	 * Don't start new DMAs.
	 */
	return !net->tx_flush &&
		net->tx_packets / 64 >= net->tx_zcopy_err;
}

static bool vhost_sock_zcopy(struct socket *sock)
{
    /*socket必须与vhost-net同时开启zcopy*/
	return unlikely(experimental_zcopytx) &&
		sock_flag(sock->sk, SOCK_ZEROCOPY);
}

static bool vhost_sock_xdp(struct socket *sock)
{
	return sock_flag(sock->sk, SOCK_XDP);
}

/* In case of DMA done not in order in lower device driver for some reason.
 * upend_idx is used to track end of used idx, done_idx is used to track head
 * of used idx. Once lower device DMA done contiguously, we will signal KVM
 * guest used idx.
 */
static void vhost_zerocopy_signal_used(struct vhost_net *net,
				       struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	int i, add;
	int j = 0;

	for (i = nvq->done_idx; i != nvq->upend_idx; i = (i + 1) % UIO_MAXIOV) {
		if (vq->heads[i].len == VHOST_DMA_FAILED_LEN)
			vhost_net_tx_err(net);
		if (VHOST_DMA_IS_DONE(vq->heads[i].len)) {
			vq->heads[i].len = VHOST_DMA_CLEAR_LEN;
			++j;
		} else
			break;
	}
	while (j) {
		add = min(UIO_MAXIOV - nvq->done_idx, j);
		vhost_add_used_and_signal_n(vq->dev, vq,
					    &vq->heads[nvq->done_idx], add);
		nvq->done_idx = (nvq->done_idx + add) % UIO_MAXIOV;
		j -= add;
	}
}

static void vhost_zerocopy_callback(struct sk_buff *skb,
				    struct ubuf_info *ubuf_base, bool success)
{
	struct ubuf_info_msgzc *ubuf = uarg_to_msgzc(ubuf_base);
	struct vhost_net_ubuf_ref *ubufs = ubuf->ctx;
	struct vhost_virtqueue *vq = ubufs->vq;
	int cnt;

	rcu_read_lock_bh();

	/* set len to mark this desc buffers done DMA */
	vq->heads[ubuf->desc].len = success ?
		VHOST_DMA_DONE_LEN : VHOST_DMA_FAILED_LEN;
	cnt = vhost_net_ubuf_put(ubufs);

	/*
	 * Trigger polling thread if guest stopped submitting new buffers:
	 * in this case, the refcount after decrement will eventually reach 1.
	 * We also trigger polling periodically after each 16 packets
	 * (the value 16 here is more or less arbitrary, it's tuned to trigger
	 * less than 10% of times).
	 */
	if (cnt <= 1 || !(cnt % 16))
		vhost_poll_queue(&vq->poll);

	rcu_read_unlock_bh();
}

static inline unsigned long busy_clock(void)
{
	return local_clock() >> 10;
}

static bool vhost_can_busy_poll(unsigned long endtime)
{
	return likely(!need_resched() && !time_after(busy_clock(), endtime) &&
		      !signal_pending(current));
}

static void vhost_net_disable_vq(struct vhost_net *n,
				 struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	if (!vhost_vq_get_backend(vq))
	    /*如果此vq没有后端，则直接返回*/
		return;
	/*将poll自等待队列中移除*/
	vhost_poll_stop(poll);
}

static int vhost_net_enable_vq(struct vhost_net *n,
				struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	struct socket *sock;

	sock = vhost_vq_get_backend(vq);
	if (!sock)
	    /*此vq后端socket不存在*/
		return 0;

	/*等待sock->file可处理*/
	return vhost_poll_start(poll, sock->file);
}

static void vhost_net_signal_used(struct vhost_net_virtqueue *nvq)
{
	struct vhost_virtqueue *vq = &nvq->vq;
	struct vhost_dev *dev = vq->dev;

	if (!nvq->done_idx)
		/*已置为0,不再通知*/
		return;

	vhost_add_used_and_signal_n(dev, vq, vq->heads, nvq->done_idx);
	nvq->done_idx = 0;
}

static void vhost_tx_batch(struct vhost_net *net,
			   struct vhost_net_virtqueue *nvq,
			   struct socket *sock,
			   struct msghdr *msghdr)
{
	struct tun_msg_ctl ctl = {
		.type = TUN_MSG_PTR,
		.num = nvq->batched_xdp,
		.ptr = nvq->xdp,
	};
	int i, err;

	if (nvq->batched_xdp == 0)
		goto signal_used;

	msghdr->msg_control = &ctl;
	msghdr->msg_controllen = sizeof(ctl);
	err = sock->ops->sendmsg(sock, msghdr, 0);
	if (unlikely(err < 0)) {
		vq_err(&nvq->vq, "Fail to batch sending packets\n");

		/* free pages owned by XDP; since this is an unlikely error path,
		 * keep it simple and avoid more complex bulk update for the
		 * used pages
		 */
		for (i = 0; i < nvq->batched_xdp; ++i)
			put_page(virt_to_head_page(nvq->xdp[i].data));
		nvq->batched_xdp = 0;
		nvq->done_idx = 0;
		return;
	}

signal_used:
	vhost_net_signal_used(nvq);
	nvq->batched_xdp = 0;
}

static int sock_has_rx_data(struct socket *sock)
{
    /*检查sock是否有数据待处理*/
	if (unlikely(!sock))
		return 0;

	if (sock->ops->peek_len)
	    /*如果有peek_len，则通过peek_len检查*/
		return sock->ops->peek_len(sock);

	return skb_queue_empty(&sock->sk->sk_receive_queue);
}

static void vhost_net_busy_poll_try_queue(struct vhost_net *net,
					  struct vhost_virtqueue *vq)
{
	if (!vhost_vq_avail_empty(&net->dev, vq)) {
	    /*poll work入队，交付vhost kernel thread运行*/
		vhost_poll_queue(&vq->poll);
	} else if (unlikely(vhost_enable_notify(&net->dev, vq))) {
		vhost_disable_notify(&net->dev, vq);
		vhost_poll_queue(&vq->poll);
	}
}

static void vhost_net_busy_poll(struct vhost_net *net,
				struct vhost_virtqueue *rvq,
				struct vhost_virtqueue *tvq,
				bool *busyloop_intr,
				bool poll_rx)
{
	unsigned long busyloop_timeout;
	unsigned long endtime;
	struct socket *sock;
	struct vhost_virtqueue *vq = poll_rx ? tvq : rvq;

	/* Try to hold the vq mutex of the paired virtqueue. We can't
	 * use mutex_lock() here since we could not guarantee a
	 * consistenet lock ordering.
	 */
	if (!mutex_trylock(&vq->mutex))
		return;

	vhost_disable_notify(&net->dev, vq);
	/*取后端socket*/
	sock = vhost_vq_get_backend(rvq);

	busyloop_timeout = poll_rx ? rvq->busyloop_timeout:
				     tvq->busyloop_timeout;

	preempt_disable();
	endtime = busy_clock() + busyloop_timeout;

	while (vhost_can_busy_poll(endtime)) {
		if (vhost_vq_has_work(vq)) {
			/*vhost kernel thread 已经有工作了*/
			*busyloop_intr = true;
			break;
		}

		if ((sock_has_rx_data(sock) &&
		     !vhost_vq_avail_empty(&net->dev, rvq)) ||
		    !vhost_vq_avail_empty(&net->dev, tvq))
		    /*socket有数据*/
			break;

		cpu_relax();
	}

	preempt_enable();

	if (poll_rx || sock_has_rx_data(sock))
		vhost_net_busy_poll_try_queue(net, vq);
	else if (!poll_rx) /* On tx here, sock has no rx data. */
		vhost_enable_notify(&net->dev, rvq);

	mutex_unlock(&vq->mutex);
}

/*返回<0,出错；>0本次处理的首个标述符索引；>=vq->num,队列为空，没有取得*/
static int vhost_net_tx_get_vq_desc(struct vhost_net *net,
				    struct vhost_net_virtqueue *tnvq/*tx对应的vq*/,
				    unsigned int *out_num/*出参，可读数据片数目*/, unsigned int *in_num/*出参，可写数据片数目*/,
				    struct msghdr *msghdr, bool *busyloop_intr)
{
	struct vhost_net_virtqueue *rnvq = &net->vqs[VHOST_NET_VQ_RX];/*取rx对应的vq*/
	struct vhost_virtqueue *rvq = &rnvq->vq;
	struct vhost_virtqueue *tvq = &tnvq->vq;

	//读buffer地址到tvq->iov
	int r = vhost_get_vq_desc(tvq, tvq->iov, ARRAY_SIZE(tvq->iov),
				  out_num, in_num, NULL, NULL);

	if (r == tvq->num && tvq->busyloop_timeout) {
		/* Flush batched packets first */
		if (!vhost_sock_zcopy(vhost_vq_get_backend(tvq)))
			vhost_tx_batch(net, tnvq,
				       vhost_vq_get_backend(tvq),
				       msghdr);

		vhost_net_busy_poll(net, rvq, tvq, busyloop_intr, false);

		r = vhost_get_vq_desc(tvq, tvq->iov, ARRAY_SIZE(tvq->iov),
				      out_num, in_num, NULL, NULL);
	}

	return r;
}

static bool vhost_exceeds_maxpend(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;

	return (nvq->upend_idx + UIO_MAXIOV - nvq->done_idx) % UIO_MAXIOV >
	       min_t(unsigned int, VHOST_MAX_PEND, vq->num >> 2);
}

static size_t init_iov_iter(struct vhost_virtqueue *vq, struct iov_iter *iter,
			    size_t hdr_size, int out)
{
	/* Skip header. TODO: support TSO. */
	size_t len = iov_length(vq->iov, out);

	iov_iter_init(iter, ITER_SOURCE, vq->iov, out, len);
	iov_iter_advance(iter, hdr_size);

	return iov_iter_count(iter);
}

static int get_tx_bufs(struct vhost_net *net,
		       struct vhost_net_virtqueue *nvq,
		       struct msghdr *msg,
		       unsigned int *out/*出参，可读数据片数目*/, unsigned int *in/*出参，可写数据片数目*/,
		       size_t *len, bool *busyloop_intr)
{
	struct vhost_virtqueue *vq = &nvq->vq;
	int ret;

	//取tx可用描述符指明的buffer
	ret = vhost_net_tx_get_vq_desc(net, nvq, out, in, msg, busyloop_intr);

	//提取失败或者无可用描述符，直接返回
	if (ret < 0 || ret == vq->num)
		return ret;

	if (*in) {
	    /*当前为读取报文并发送给tap口，故in需要为0*/
		vq_err(vq, "Unexpected descriptor format for TX: out %d, int %d\n",
			*out, *in);
		return -EFAULT;
	}

	/* Sanity check */
	//将描述符指定的buffer赋给msg->msg_iter
	*len = init_iov_iter(vq, &msg->msg_iter, nvq->vhost_hlen, *out);
	if (*len == 0) {
		vq_err(vq, "Unexpected header len for TX: %zd expected %zd\n",
			*len, nvq->vhost_hlen);
		return -EFAULT;
	}

	return ret;
}

static bool tx_can_batch(struct vhost_virtqueue *vq, size_t total_len)
{
	return total_len < VHOST_NET_WEIGHT &&
	       !vhost_vq_avail_empty(vq->dev, vq);
}

static bool vhost_net_page_frag_refill(struct vhost_net *net, unsigned int sz,
				       struct page_frag *pfrag, gfp_t gfp)
{
	if (pfrag->page) {
		if (pfrag->offset + sz <= pfrag->size)
			return true;
		__page_frag_cache_drain(pfrag->page, net->refcnt_bias);
	}

	pfrag->offset = 0;
	net->refcnt_bias = 0;
	if (SKB_FRAG_PAGE_ORDER) {
		/* Avoid direct reclaim but allow kswapd to wake */
		pfrag->page = alloc_pages((gfp & ~__GFP_DIRECT_RECLAIM) |
					  __GFP_COMP | __GFP_NOWARN |
					  __GFP_NORETRY,
					  SKB_FRAG_PAGE_ORDER);
		if (likely(pfrag->page)) {
			pfrag->size = PAGE_SIZE << SKB_FRAG_PAGE_ORDER;
			goto done;
		}
	}
	pfrag->page = alloc_page(gfp);
	if (likely(pfrag->page)) {
		pfrag->size = PAGE_SIZE;
		goto done;
	}
	return false;

done:
	net->refcnt_bias = USHRT_MAX;
	page_ref_add(pfrag->page, USHRT_MAX - 1);
	return true;
}

#define VHOST_NET_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

static int vhost_net_build_xdp(struct vhost_net_virtqueue *nvq,
			       struct iov_iter *from)
{
	struct vhost_virtqueue *vq = &nvq->vq;
	struct vhost_net *net = container_of(vq->dev, struct vhost_net,
					     dev);
	struct socket *sock = vhost_vq_get_backend(vq);
	struct page_frag *alloc_frag = &net->page_frag;
	struct virtio_net_hdr *gso;
	struct xdp_buff *xdp = &nvq->xdp[nvq->batched_xdp];
	struct tun_xdp_hdr *hdr;
	size_t len = iov_iter_count(from);
	int headroom = vhost_sock_xdp(sock) ? XDP_PACKET_HEADROOM : 0;
	int buflen = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	int pad = SKB_DATA_ALIGN(VHOST_NET_RX_PAD + headroom + nvq->sock_hlen);
	int sock_hlen = nvq->sock_hlen;
	void *buf;
	int copied;

	if (unlikely(len < nvq->sock_hlen))
		return -EFAULT;

	if (SKB_DATA_ALIGN(len + pad) +
	    SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) > PAGE_SIZE)
		return -ENOSPC;

	buflen += SKB_DATA_ALIGN(len + pad);
	alloc_frag->offset = ALIGN((u64)alloc_frag->offset, SMP_CACHE_BYTES);
	if (unlikely(!vhost_net_page_frag_refill(net, buflen,
						 alloc_frag, GFP_KERNEL)))
		return -ENOMEM;

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	copied = copy_page_from_iter(alloc_frag->page,
				     alloc_frag->offset +
				     offsetof(struct tun_xdp_hdr, gso),
				     sock_hlen, from);
	if (copied != sock_hlen)
		return -EFAULT;

	hdr = buf;
	gso = &hdr->gso;

	if ((gso->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
	    vhost16_to_cpu(vq, gso->csum_start) +
	    vhost16_to_cpu(vq, gso->csum_offset) + 2 >
	    vhost16_to_cpu(vq, gso->hdr_len)) {
		gso->hdr_len = cpu_to_vhost16(vq,
			       vhost16_to_cpu(vq, gso->csum_start) +
			       vhost16_to_cpu(vq, gso->csum_offset) + 2);

		if (vhost16_to_cpu(vq, gso->hdr_len) > len)
			return -EINVAL;
	}

	len -= sock_hlen;
	copied = copy_page_from_iter(alloc_frag->page,
				     alloc_frag->offset + pad,
				     len, from);
	if (copied != len)
		return -EFAULT;

	xdp_init_buff(xdp, buflen, NULL);
	xdp_prepare_buff(xdp, buf, pad, len, true);
	hdr->buflen = buflen;

	--net->refcnt_bias;
	alloc_frag->offset += buflen;

	++nvq->batched_xdp;

	return 0;
}

//处理发送队列的报文，将其扔给后端socket
static void handle_tx_copy(struct vhost_net *net, struct socket *sock)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned out, in;
	int head;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	size_t len, total_len = 0;
	int err;
	int sent_pkts = 0;
	bool sock_can_batch = (sock->sk->sk_sndbuf == INT_MAX);

	do {
		bool busyloop_intr = false;

		if (nvq->done_idx == VHOST_NET_BATCH)
			vhost_tx_batch(net, nvq, sock, &msg);

		//获取描述符索引及其指明的buffer,并将内容填充到msg中
		head = get_tx_bufs(net, nvq, &msg, &out, &in, &len/*出参，buffer长度*/,
				   &busyloop_intr);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			/*获取时出错*/
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			/*没有数据*/
			if (unlikely(busyloop_intr)) {
				vhost_poll_queue(&vq->poll);
			} else if (unlikely(vhost_enable_notify(&net->dev,
								vq))) {
				vhost_disable_notify(&net->dev, vq);
				continue;
			}
			break;
		}

		total_len += len;

		/* For simplicity, TX batching is only enabled if
		 * sndbuf is unlimited.
		 */
		if (sock_can_batch) {
			err = vhost_net_build_xdp(nvq, &msg.msg_iter);
			if (!err) {
				goto done;
			} else if (unlikely(err != -ENOSPC)) {
				vhost_tx_batch(net, nvq, sock, &msg);
				vhost_discard_vq_desc(vq, 1);
				vhost_net_enable_vq(net, vq);
				break;
			}

			/* We can't build XDP buff, go for single
			 * packet path but let's flush batched
			 * packets.
			 */
			vhost_tx_batch(net, nvq, sock, &msg);
			msg.msg_control = NULL;
		} else {
			if (tx_can_batch(vq, total_len))
				msg.msg_flags |= MSG_MORE;
			else
				msg.msg_flags &= ~MSG_MORE;
		}

		/*向sock中发送msg指定的报文内容*/
		err = sock->ops->sendmsg(sock, &msg, len);
		if (unlikely(err < 0)) {
			if (err == -EAGAIN || err == -ENOMEM || err == -ENOBUFS) {
			    /*向对方发送失败，回退描述符，后续重试*/
				vhost_discard_vq_desc(vq, 1);
				vhost_net_enable_vq(net, vq);
				break;
			}
			pr_debug("Fail to send packet: err %d", err);
		} else if (unlikely(err != len))
			/*发送的内容被截短*/
			pr_debug("Truncated TX packet: len %d != %zd\n",
				 err, len);
done:
        /*发送完成，填充vq->heads*/
		vq->heads[nvq->done_idx].id = cpu_to_vhost32(vq, head);
		vq->heads[nvq->done_idx].len = 0;
		++nvq->done_idx;
	} while (likely(!vhost_exceeds_weight(vq, ++sent_pkts, total_len)));

	vhost_tx_batch(net, nvq, sock, &msg);
}

static void handle_tx_zerocopy(struct vhost_net *net, struct socket *sock)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned out, in;
	int head;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	struct tun_msg_ctl ctl;
	size_t len, total_len = 0;
	int err;
	struct vhost_net_ubuf_ref *ubufs;
	struct ubuf_info_msgzc *ubuf;
	bool zcopy_used;
	int sent_pkts = 0;

	do {
		bool busyloop_intr;

		/* Release DMAs done buffers first */
		vhost_zerocopy_signal_used(net, vq);

		busyloop_intr = false;
		head = get_tx_bufs(net, nvq, &msg, &out, &in, &len,
				   &busyloop_intr);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(busyloop_intr)) {
				vhost_poll_queue(&vq->poll);
			} else if (unlikely(vhost_enable_notify(&net->dev, vq))) {
				vhost_disable_notify(&net->dev, vq);
				continue;
			}
			break;
		}

		zcopy_used = len >= VHOST_GOODCOPY_LEN
			     && !vhost_exceeds_maxpend(net)
			     && vhost_net_tx_select_zcopy(net);

		/* use msg_control to pass vhost zerocopy ubuf info to skb */
		if (zcopy_used) {
			ubuf = nvq->ubuf_info + nvq->upend_idx;
			vq->heads[nvq->upend_idx].id = cpu_to_vhost32(vq, head);
			vq->heads[nvq->upend_idx].len = VHOST_DMA_IN_PROGRESS;
			ubuf->ctx = nvq->ubufs;
			ubuf->desc = nvq->upend_idx;
			ubuf->ubuf.callback = vhost_zerocopy_callback;
			ubuf->ubuf.flags = SKBFL_ZEROCOPY_FRAG;
			refcount_set(&ubuf->ubuf.refcnt, 1);
			msg.msg_control = &ctl;
			ctl.type = TUN_MSG_UBUF;
			ctl.ptr = &ubuf->ubuf;
			msg.msg_controllen = sizeof(ctl);
			ubufs = nvq->ubufs;
			atomic_inc(&ubufs->refcount);
			nvq->upend_idx = (nvq->upend_idx + 1) % UIO_MAXIOV;
		} else {
			msg.msg_control = NULL;
			ubufs = NULL;
		}
		total_len += len;
		if (tx_can_batch(vq, total_len) &&
		    likely(!vhost_exceeds_maxpend(net))) {
			msg.msg_flags |= MSG_MORE;
		} else {
			msg.msg_flags &= ~MSG_MORE;
		}

		err = sock->ops->sendmsg(sock, &msg, len);
		if (unlikely(err < 0)) {
			bool retry = err == -EAGAIN || err == -ENOMEM || err == -ENOBUFS;

			if (zcopy_used) {
				if (vq->heads[ubuf->desc].len == VHOST_DMA_IN_PROGRESS)
					vhost_net_ubuf_put(ubufs);
				if (retry)
					nvq->upend_idx = ((unsigned)nvq->upend_idx - 1)
						% UIO_MAXIOV;
				else
					vq->heads[ubuf->desc].len = VHOST_DMA_DONE_LEN;
			}
			if (retry) {
				vhost_discard_vq_desc(vq, 1);
				vhost_net_enable_vq(net, vq);
				break;
			}
			pr_debug("Fail to send packet: err %d", err);
		} else if (unlikely(err != len))
			pr_debug("Truncated TX packet: "
				 " len %d != %zd\n", err, len);
		if (!zcopy_used)
			vhost_add_used_and_signal(&net->dev, vq, head, 0);
		else
			vhost_zerocopy_signal_used(net, vq);
		vhost_net_tx_packet(net);
	} while (likely(!vhost_exceeds_weight(vq, ++sent_pkts, total_len)));
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
//自vq的tx队列拿到报文，将这些报文通过sendmsg发送给后端socket
static void handle_tx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;
	struct socket *sock;

	//取后端对应的socket
	mutex_lock_nested(&vq->mutex, VHOST_NET_VQ_TX);
	sock = vhost_vq_get_backend(vq);
	if (!sock)
		goto out;

	/*预取meta的iotlb映射信息，如预取失败，则等待guest回复miss*/
	if (!vq_meta_prefetch(vq))
		goto out;

	vhost_disable_notify(&net->dev, vq);
	vhost_net_disable_vq(net, vq);

	if (vhost_sock_zcopy(sock))
		//处理tx队列的报文(非copy版本) ，将其传给sock
		handle_tx_zerocopy(net, sock);
	else
	    //处理tx队列的报文(copy版本) ，将其传给sock
		handle_tx_copy(net, sock);

out:
	mutex_unlock(&vq->mutex);
}

static int peek_head_len(struct vhost_net_virtqueue *rvq, struct sock *sk)
{
	struct sk_buff *head;
	int len = 0;
	unsigned long flags;

	if (rvq->rx_ring)
	    /*采用rx_ring方式时，peek首包文长度*/
		return vhost_net_buf_peek(rvq);

	spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
	/*peer socket的receive queue上的首个报文*/
	head = skb_peek(&sk->sk_receive_queue);
	if (likely(head)) {
	    /*receive_queue上有内容，取报文长度*/
		len = head->len;
		if (skb_vlan_tag_present(head))
		    /*如果我们的报文上有tag,则加上tag头*/
			len += VLAN_HLEN;
	}

	spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);
	/*返回peek的长度*/
	return len;
}

static int vhost_net_rx_peek_head_len(struct vhost_net *net, struct sock *sk,
				      bool *busyloop_intr)
{
	struct vhost_net_virtqueue *rnvq = &net->vqs[VHOST_NET_VQ_RX];
	struct vhost_net_virtqueue *tnvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *rvq = &rnvq->vq;
	struct vhost_virtqueue *tvq = &tnvq->vq;
	/*peek一下rx队列上首个报文的长度*/
	int len = peek_head_len(rnvq, sk);

	if (!len && rvq->busyloop_timeout) {
	    /*rx队列上没有报文，且用户指定了busyloop的超时时间*/
		/* Flush batched heads first */
		vhost_net_signal_used(rnvq);
		/* Both tx vq and rx socket were polled here */
		vhost_net_busy_poll(net, rvq, tvq, busyloop_intr, true);

		len = peek_head_len(rnvq, sk);
	}

	return len;
}

/* This is a multi-buffer version of vhost_get_desc, that works if
 *	vq has read descriptors only.
 * @vq		- the relevant virtqueue
 * @datalen	- data length we'll be reading
 * @iovcount	- returned count of io vectors we fill
 * @log		- vhost log
 * @log_num	- log offset
 * @quota       - headcount quota, 1 for big buffer
 *	returns number of buffer heads allocated, negative on error
 */
static int get_rx_bufs(struct vhost_virtqueue *vq,
		       struct vring_used_elem *heads/*出参，需占用描述符及其能提供的buffer尺寸*/,
		       int datalen/*预期要获得的buffer总大小*/,
		       unsigned *iovcount/*出参，vq->iov被占用总数目*/,
		       struct vhost_log *log,
		       unsigned *log_num,
		       unsigned int quota/*容许占用的描述符数目上限*/)
{
	unsigned int out, in;
	/*当前vq->iov已占用segment大小*/
	int seg = 0;
	int headcount = 0;
	unsigned d;
	int r, nlogs = 0;
	/* len is always initialized before use since we are always called with
	 * datalen > 0.
	 */
	u32 len;

	while (datalen > 0 && headcount < quota) {
		if (unlikely(seg >= UIO_MAXIOV)) {
		    //数据片段过多超过极限，报错
			r = -ENOBUFS;
			goto err;
		}

		//取可用描述符索引
		r = vhost_get_vq_desc(vq, vq->iov + seg/*iov起始位置*/,
				      ARRAY_SIZE(vq->iov) - seg/*可用iov数目*/, &out,
				      &in, log, log_num);
		if (unlikely(r < 0))
			goto err;

		d = r;
		if (d == vq->num) {
		    /*返回值为队列大小，指无可用描述符，退出*/
			r = 0;
			goto err;
		}
		if (unlikely(out || in <= 0)) {
		    /*当前在处理报文发送，故需要可读buffer数目为0*/
			vq_err(vq, "unexpected descriptor format for RX: "
				"out %d, in %d\n", out, in);
			r = -EINVAL;
			goto err;
		}
		if (unlikely(log)) {
			nlogs += *log_num;
			log += *log_num;
		}
		heads[headcount].id = cpu_to_vhost32(vq, d);
		//当前已占用描述符可提供的buffer大小
		len = iov_length(vq->iov + seg, in);
		heads[headcount].len = cpu_to_vhost32(vq, len);
		datalen -= len;//剩余待需要buffer大小
		++headcount;//已占用描述符数目
		seg += in;/*当前已占用iov 数据片总数目*/
	}
	heads[headcount - 1].len = cpu_to_vhost32(vq, len + datalen);
	*iovcount = seg;
	if (unlikely(log))
		*log_num = nlogs;

	/* Detect overrun */
	if (unlikely(datalen > 0)) {
	    /*内容过大，超过quota*/
		r = UIO_MAXIOV + 1;
		goto err;
	}
	return headcount;
err:
	vhost_discard_vq_desc(vq, headcount);
	return r;
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
//从vq中拿到报文，然后将其写入到后端socket中（例如tun口）
static void handle_rx(struct vhost_net *net)
{
    /*取vhost-net RX队列*/
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
	/*取rx对应的vq*/
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned in, log;
	struct vhost_log *vq_log;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL, /* FIXME: get and handle RX aux data. */
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,/*指明非阻塞*/
	};
	struct virtio_net_hdr hdr = {
		.flags = 0,
		.gso_type = VIRTIO_NET_HDR_GSO_NONE
	};
	size_t total_len = 0;
	int err, mergeable;
	s16 headcount;
	size_t vhost_hlen, sock_hlen;
	size_t vhost_len, sock_len;
	bool busyloop_intr = false;
	struct socket *sock;
	struct iov_iter fixup;
	__virtio16 num_buffers;
	int recv_pkts = 0;

	/*锁住此队列*/
	mutex_lock_nested(&vq->mutex, VHOST_NET_VQ_RX);

	//取vq对应的后端socket
	sock = vhost_vq_get_backend(vq);
	if (!sock)
		goto out;

	/*预取meta的iotlb映射信息，如预取失败，则等待guest回复miss*/
	if (!vq_meta_prefetch(vq))
		goto out;

	/*禁止通知*/
	vhost_disable_notify(&net->dev, vq);
	vhost_net_disable_vq(net, vq);

	vhost_hlen = nvq->vhost_hlen;
	sock_hlen = nvq->sock_hlen;

	vq_log = unlikely(vhost_has_feature(vq, VHOST_F_LOG_ALL)) ?
		vq->log : NULL;
	/*检查vq是否开启了merge rxbuf功能*/
	mergeable = vhost_has_feature(vq, VIRTIO_NET_F_MRG_RXBUF);

	do {
	    //通过peek首先确定要接收的pkt长度
		sock_len = vhost_net_rx_peek_head_len(net, sock->sk,
						      &busyloop_intr);
		if (!sock_len)
		    /*无数据，跳出*/
			break;

		//需要读取的buffer总长为vhost_len,获取足够描述符，以便可以存入它
		sock_len += sock_hlen;/*socket负载长度（含socket header）*/
		vhost_len = sock_len + vhost_hlen;/*vhost负载长度（含vhost header)*/

		//获取足够容纳报文的描述符
		headcount = get_rx_bufs(vq, vq->heads + nvq->done_idx,
					vhost_len/*vhost负载长度*/, &in, vq_log, &log,
					likely(mergeable) ? UIO_MAXIOV : 1);
		/* On error, stop handling until the next kick. */
		if (unlikely(headcount < 0))
		    /*获取描述符失败，退出*/
			goto out;
		/* OK, now we need to know about added descriptors. */
		if (!headcount) {
		    /*有报文，但未获取到足够的可用描述符,加入poll队列等待，开启通知*/
			if (unlikely(busyloop_intr)) {
				vhost_poll_queue(&vq->poll);/*尝试下次继续收取*/
			} else if (unlikely(vhost_enable_notify(&net->dev, vq))) {
				/* They have slipped one in as we were
				 * doing that: check again. */
				vhost_disable_notify(&net->dev, vq);
				continue;
			}
			/* Nothing new?  Wait for eventfd to tell us
			 * they refilled. */
			goto out;
		}

		/*获取到足够的描述符*/
		busyloop_intr = false;
		if (nvq->rx_ring)
			msg.msg_control = vhost_net_buf_consume(&nvq->rxq);
		/* On overrun, truncate and discard */
		if (unlikely(headcount > UIO_MAXIOV)) {
		    /*遇到过大报，描述符数量超过配额，截短收包后丢弃*/
			iov_iter_init(&msg.msg_iter, ITER_DEST, vq->iov, 1, 1);
			err = sock->ops->recvmsg(sock, &msg,
						 1, MSG_DONTWAIT | MSG_TRUNC);
			pr_debug("Discarded rx packet: len %zd\n", sock_len);
			continue;
		}
		/* We don't need to be notified again. */
		/*设置可供写入的iov*/
		iov_iter_init(&msg.msg_iter, ITER_DEST, vq->iov, in, vhost_len);
		fixup = msg.msg_iter;
		if (unlikely((vhost_hlen))) {
			/* We will supply the header ourselves
			 * TODO: support TSO.
			 */
			iov_iter_advance(&msg.msg_iter, vhost_hlen);
		}

		/*可写的buffer已被记录在msg.msg_iter中，自sock中拿到报文，并将其写入到msg.msg_iter中
		 * 例如:tun_recvmsg
		 **/
		err = sock->ops->recvmsg(sock, &msg/*出参,存放读取到的内容*/,
					 sock_len, MSG_DONTWAIT | MSG_TRUNC);
		/* Userspace might have consumed the packet meanwhile:
		 * it's not supposed to do this usually, but might be hard
		 * to prevent. Discard data we got (if any) and keep going. */
		if (unlikely(err != sock_len)) {
		    //报文长度有误，归还申请的描述符
			pr_debug("Discarded rx packet: "
				 " len %d, expected %zd\n", err, sock_len);
			vhost_discard_vq_desc(vq, headcount);
			continue;
		}

		/*自tap,tun口完成了报文收取*/
		/* Supply virtio_net_hdr if VHOST_NET_F_VIRTIO_NET_HDR */
		if (unlikely(vhost_hlen)) {
		    /*如果支持vhost header,则取出hdr*/
			if (copy_to_iter(&hdr, sizeof(hdr),
					 &fixup) != sizeof(hdr)) {
				vq_err(vq, "Unable to write vnet_hdr "
				       "at addr %p\n", vq->iov->iov_base);
				goto out;
			}
		} else {
			/* Header came from socket; we'll need to patch
			 * ->num_buffers over if VIRTIO_NET_F_MRG_RXBUF
			 */
			iov_iter_advance(&fixup, sizeof(hdr));
		}
		/* TODO: Should check and handle checksum. */

		num_buffers = cpu_to_vhost16(vq, headcount);
		if (likely(mergeable) &&
		    copy_to_iter(&num_buffers, sizeof num_buffers,
				 &fixup) != sizeof num_buffers) {
			vq_err(vq, "Failed num_buffers write");
			vhost_discard_vq_desc(vq, headcount);
			goto out;
		}
		nvq->done_idx += headcount;
		//如果用量超过阀值，则通知对端
		if (nvq->done_idx > VHOST_NET_BATCH)
			vhost_net_signal_used(nvq);
		if (unlikely(vq_log))
			vhost_log_write(vq, vq_log, log, vhost_len,
					vq->iov, in);
		total_len += vhost_len;
	} while (likely(!vhost_exceeds_weight(vq, ++recv_pkts/*已收的报文增加*/, total_len/*已收到报文字节数*/)));

	if (unlikely(busyloop_intr))
		/*跳过wait,直接加入poll,计划再执行*/
		vhost_poll_queue(&vq->poll);
	else if (!sock_len)
		/*当前数据了，wait等待事件再发生*/
		vhost_net_enable_vq(net, vq);
out:
    //通知对端有报文
	vhost_net_signal_used(nvq);
	mutex_unlock(&vq->mutex);
}

/*处理指定设备的tx*/
static void handle_tx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_net *net = container_of(vq->dev, struct vhost_net, dev);

	handle_tx(net);
}

/*处理指定设备的rx*/
static void handle_rx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_net *net = container_of(vq->dev, struct vhost_net, dev);

	handle_rx(net);
}

/*vhost tx队列处理入口，报文将被发送给后端socket*/
static void handle_tx_net(struct vhost_work *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_TX].work);
	/*针对vhost_net进行发包处理*/
	handle_tx(net);
}

/*vhost rx队列处理入口，报文将被送给vm*/
static void handle_rx_net(struct vhost_work *work)
{
    /*通过work获得其对应的vhost_net结构*/
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_RX].work);
	/*针对vhost_net进行收包处理*/
	handle_rx(net);
}

//处理vhost-net字符设备打开
static int vhost_net_open(struct inode *inode, struct file *f)
{
	struct vhost_net *n;
	struct vhost_dev *dev;
	struct vhost_virtqueue **vqs;
	void **queue;
	struct xdp_buff *xdp;
	int i;

	/*申请vhost_net*/
	n = kvmalloc(sizeof *n, GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!n)
		return -ENOMEM;

	//申请一对儿vq指针
	vqs = kmalloc_array(VHOST_NET_VQ_MAX, sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kvfree(n);
		return -ENOMEM;
	}

	/*初始化rx队列buffer*/
	queue = kmalloc_array(VHOST_NET_BATCH, sizeof(void *),
			      GFP_KERNEL);
	if (!queue) {
		kfree(vqs);
		kvfree(n);
		return -ENOMEM;
	}

	/*设置vhost net设备的rx队列*/
	n->vqs[VHOST_NET_VQ_RX].rxq.queue = queue;

	/*初始化xdp发队列buffer*/
	xdp = kmalloc_array(VHOST_NET_BATCH, sizeof(*xdp), GFP_KERNEL);
	if (!xdp) {
		kfree(vqs);
		kvfree(n);
		kfree(queue);
		return -ENOMEM;
	}
	n->vqs[VHOST_NET_VQ_TX].xdp = xdp;

	dev = &n->dev;
	/*rx,tx分别指向vhost-net设备的vq*/
	vqs[VHOST_NET_VQ_TX] = &n->vqs[VHOST_NET_VQ_TX].vq;
	vqs[VHOST_NET_VQ_RX] = &n->vqs[VHOST_NET_VQ_RX].vq;

	/*设置rx,tx队列的收发处理work*/
	n->vqs[VHOST_NET_VQ_TX].vq.handle_kick = handle_tx_kick;
	n->vqs[VHOST_NET_VQ_RX].vq.handle_kick = handle_rx_kick;

	/*初始化rx,tx对应的vq*/
	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].ubufs = NULL;
		n->vqs[i].ubuf_info = NULL;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].done_idx = 0;
		n->vqs[i].batched_xdp = 0;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
		n->vqs[i].rx_ring = NULL;
		vhost_net_buf_init(&n->vqs[i].rxq);/*初始化rxq，指向空*/
	}

	/*vqs指向n->vqs，已完成初始化,这里初始化virtio-net设备*/
	vhost_dev_init(dev, vqs, VHOST_NET_VQ_MAX/*队列数目*/,
		       UIO_MAXIOV + VHOST_NET_BATCH/*？？？？*/,
		       VHOST_NET_PKT_WEIGHT/*一次最多收的报文数*/, VHOST_NET_WEIGHT/*一轮最多收的字节数*/, true,
		       NULL);

	/*设置n->poll的回调函数，这些函数最终会被vhost-xx线程执行*/
	vhost_poll_init(n->poll + VHOST_NET_VQ_TX, handle_tx_net/*tx处理*/, EPOLLOUT, dev,
			vqs[VHOST_NET_VQ_TX]);
	vhost_poll_init(n->poll + VHOST_NET_VQ_RX, handle_rx_net/*rx处理*/, EPOLLIN, dev,
			vqs[VHOST_NET_VQ_RX]);

	f->private_data = n;
	n->page_frag.page = NULL;
	n->refcnt_bias = 0;

	return 0;
}

/*取出并返回后端对应的sock,并更新设备的sock为NULL，*/
static struct socket *vhost_net_stop_vq(struct vhost_net *n,
					struct vhost_virtqueue *vq)
{
	struct socket *sock;
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);

	mutex_lock(&vq->mutex);
	/*vq的后端为socket,取得它的引用*/
	sock = vhost_vq_get_backend(vq);
	vhost_net_disable_vq(n, vq);
	/*将vq的后端socket置为NULL*/
	vhost_vq_set_backend(vq, NULL);
	vhost_net_buf_unproduce(nvq);
	nvq->rx_ring = NULL;
	mutex_unlock(&vq->mutex);
	/*返回vq后端对应的socket*/
	return sock;
}

/*停止rx,tx队列，并返回rx,tx对应的后端socket*/
static void vhost_net_stop(struct vhost_net *n, struct socket **tx_sock/*出参，tx对应的socket*/,
			   struct socket **rx_sock/*出参，rx对应的socket*/)
{
	*tx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_TX].vq);
	*rx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_RX].vq);
}

static void vhost_net_flush(struct vhost_net *n)
{
	vhost_dev_flush(&n->dev);
	if (n->vqs[VHOST_NET_VQ_TX].ubufs) {
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		n->tx_flush = true;
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		/* Wait for all lower device DMAs done. */
		vhost_net_ubuf_put_and_wait(n->vqs[VHOST_NET_VQ_TX].ubufs);
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		n->tx_flush = false;
		atomic_set(&n->vqs[VHOST_NET_VQ_TX].ubufs->refcount, 1);
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
	}
}

static int vhost_net_release(struct inode *inode, struct file *f)
{
    /*获得file对应的私有数据vhost-net设备*/
	struct vhost_net *n = f->private_data;
	struct socket *tx_sock;
	struct socket *rx_sock;

	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_stop(&n->dev);
	vhost_dev_cleanup(&n->dev);
	vhost_net_vq_reset(n);
	/*减少tx socket,rx socket的引用计数/关闭此socket*/
	if (tx_sock)
		sockfd_put(tx_sock);
	if (rx_sock)
		sockfd_put(rx_sock);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_net_flush(n);
	kfree(n->vqs[VHOST_NET_VQ_RX].rxq.queue);
	kfree(n->vqs[VHOST_NET_VQ_TX].xdp);
	kfree(n->dev.vqs);
	if (n->page_frag.page)
		__page_frag_cache_drain(n->page_frag.page, n->refcnt_bias);
	/*释放vhost-net设备*/
	kvfree(n);
	return 0;
}

static struct socket *get_raw_socket(int fd)
{
	int r;
	struct socket *sock = sockfd_lookup(fd, &r);

	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	/* Parameter checking */
	if (sock->sk->sk_type != SOCK_RAW) {
		r = -ESOCKTNOSUPPORT;
		goto err;
	}

	if (sock->sk->sk_family != AF_PACKET) {
		/*必须为af_packet类型的raw socket*/
		r = -EPFNOSUPPORT;
		goto err;
	}
	return sock;
err:
	sockfd_put(sock);
	return ERR_PTR(r);
}

static struct ptr_ring *get_tap_ptr_ring(struct file *file)
{
	struct ptr_ring *ring;
	ring = tun_get_tx_ring(file);
	if (!IS_ERR(ring))
		goto out;
	ring = tap_get_ptr_ring(file);
	if (!IS_ERR(ring))
		goto out;
	ring = NULL;
out:
	return ring;
}

static struct socket *get_tap_socket(int fd)
{
	struct file *file = fget(fd);
	struct socket *sock;

	if (!file)
		return ERR_PTR(-EBADF);
	/*如果为tap接口，取此tun设备对应的socket*/
	sock = tun_get_socket(file);
	if (!IS_ERR(sock))
		return sock;

	/*如果为tap接口，取此tap设备对应的socket*/
	sock = tap_get_socket(file);
	if (IS_ERR(sock))
		fput(file);
	return sock;
}

//获取fd对应的socket(当前仅支持raw(AF_PACKET),tun两种socket)
static struct socket *get_socket(int fd)
{
	struct socket *sock;

	/* special case to disable backend */
	if (fd == -1)
		return NULL;
	/*检查是否为raw socket*/
	sock = get_raw_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	/*检查是否为tap设备对应的socket*/
	sock = get_tap_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	return ERR_PTR(-ENOTSOCK);
}

/*更新vhost_net设备指定队列的后端设备*/
static long vhost_net_set_backend(struct vhost_net *n, unsigned index/*队列号*/, int fd/*队列对应的fd*/)
{
	struct socket *sock, *oldsock;
	struct vhost_virtqueue *vq;
	struct vhost_net_virtqueue *nvq;
	struct vhost_net_ubuf_ref *ubufs, *oldubufs = NULL;
	int r;

	mutex_lock(&n->dev.mutex);
	//当前进程必须为vhost设备的owner
	r = vhost_dev_check_owner(&n->dev);
	if (r)
		goto err;

	/*设置的队列编号不得大于VHOST_NET_VQ_MAX*/
	if (index >= VHOST_NET_VQ_MAX) {
		r = -ENOBUFS;
		goto err;
	}

	//取收/发队列对应的vq
	vq = &n->vqs[index].vq;/*取此index对应的vhost_vq*/
	nvq = &n->vqs[index];/*取此index对应的vhost_net_vq*/
	mutex_lock(&vq->mutex);

	if (fd == -1)
		vhost_clear_msg(&n->dev);

	/* Verify that ring has been setup correctly. */
	if (!vhost_vq_access_ok(vq)) {
		r = -EFAULT;
		goto err_vq;
	}

	//取此fd对应的socket（当前仅raw-socket,tap-socket）
	sock = get_socket(fd);
	if (IS_ERR(sock)) {
	    /*fd不是一个socket,报错*/
		r = PTR_ERR(sock);
		goto err_vq;
	}

	/* start polling new socket */
	oldsock = vhost_vq_get_backend(vq);/*取vq旧的后端socket*/
	if (sock != oldsock) {
	    /*如果前后两次回调提供的后端socket不一致，则执行更新*/
		ubufs = vhost_net_ubuf_alloc(vq,
					     sock && vhost_sock_zcopy(sock));
		if (IS_ERR(ubufs)) {
			r = PTR_ERR(ubufs);
			goto err_ubufs;
		}

		/*将poll自等待队列中移除*/
		vhost_net_disable_vq(n, vq);
		/*设置vq的后端socket*/
		vhost_vq_set_backend(vq, sock);
		vhost_net_buf_unproduce(nvq);
		//重新初始化vq
		r = vhost_vq_init_access(vq);
		if (r)
			goto err_used;
		//开启对新队列的poll
		r = vhost_net_enable_vq(n, vq);
		if (r)
			goto err_used;
		if (index == VHOST_NET_VQ_RX) {
			if (sock)
				nvq->rx_ring = get_tap_ptr_ring(sock->file);
			else
				nvq->rx_ring = NULL;
		}

		oldubufs = nvq->ubufs;
		nvq->ubufs = ubufs;

		n->tx_packets = 0;
		n->tx_zcopy_err = 0;
		n->tx_flush = false;
	}

	mutex_unlock(&vq->mutex);

	if (oldubufs) {
	    /*释放旧的buffer*/
		vhost_net_ubuf_put_wait_and_free(oldubufs);
		mutex_lock(&vq->mutex);
		vhost_zerocopy_signal_used(n, vq);
		mutex_unlock(&vq->mutex);
	}

	if (oldsock) {
		/*释放旧的sock*/
		vhost_dev_flush(&n->dev);
		sockfd_put(oldsock);
	}

	mutex_unlock(&n->dev.mutex);
	return 0;

err_used:
	vhost_vq_set_backend(vq, oldsock);/*还原旧的socket*/
	vhost_net_enable_vq(n, vq);
	if (ubufs)
		vhost_net_ubuf_put_wait_and_free(ubufs);
err_ubufs:
	if (sock)
		sockfd_put(sock);
err_vq:
	mutex_unlock(&vq->mutex);
err:
	mutex_unlock(&n->dev.mutex);
	return r;
}

static long vhost_net_reset_owner(struct vhost_net *n)
{
	struct socket *tx_sock = NULL;
	struct socket *rx_sock = NULL;
	long err;
	struct vhost_iotlb *umem;

	mutex_lock(&n->dev.mutex);
	/*必须由owner发起reset*/
	err = vhost_dev_check_owner(&n->dev);
	if (err)
		goto done;

	/*申请iotlb*/
	umem = vhost_dev_reset_owner_prepare();
	if (!umem) {
		err = -ENOMEM;
		goto done;
	}
	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_stop(&n->dev);
	vhost_dev_reset_owner(&n->dev, umem);
	vhost_net_vq_reset(n);
done:
	mutex_unlock(&n->dev.mutex);
	if (tx_sock)
		sockfd_put(tx_sock);
	if (rx_sock)
		sockfd_put(rx_sock);
	return err;
}

static int vhost_net_set_features(struct vhost_net *n, u64 features)
{
	size_t vhost_hlen, sock_hlen, hdr_len;
	int i;

	//如果开启了mrg_rxbuf或者version_1,则vhost header长度为mrg_rxbuf,否则为net_hdr
	hdr_len = (features & ((1ULL << VIRTIO_NET_F_MRG_RXBUF) |
			       (1ULL << VIRTIO_F_VERSION_1))) ?
			sizeof(struct virtio_net_hdr_mrg_rxbuf) :
			sizeof(struct virtio_net_hdr);
	if (features & (1 << VHOST_NET_F_VIRTIO_NET_HDR)) {
		/* vhost provides vnet_hdr */
		vhost_hlen = hdr_len;
		sock_hlen = 0;
	} else {
		/* socket provides vnet_hdr */
		vhost_hlen = 0;
		sock_hlen = hdr_len;
	}
	mutex_lock(&n->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&n->dev))
		goto out_unlock;

	//初始化iotlb
	if ((features & (1ULL << VIRTIO_F_ACCESS_PLATFORM))) {
		if (vhost_init_device_iotlb(&n->dev))
			goto out_unlock;
	}

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		mutex_lock(&n->vqs[i].vq.mutex);
		n->vqs[i].vq.acked_features = features;
		n->vqs[i].vhost_hlen = vhost_hlen;
		n->vqs[i].sock_hlen = sock_hlen;
		mutex_unlock(&n->vqs[i].vq.mutex);
	}
	mutex_unlock(&n->dev.mutex);
	return 0;

out_unlock:
	mutex_unlock(&n->dev.mutex);
	return -EFAULT;
}

//为vhost-dev设置owner
static long vhost_net_set_owner(struct vhost_net *n)
{
	int r;

	mutex_lock(&n->dev.mutex);
	if (vhost_dev_has_owner(&n->dev)) {
	    //已有owner,退出
		r = -EBUSY;
		goto out;
	}

	//初始化ubuf_info空间
	r = vhost_net_set_ubuf_info(n);
	if (r)
		goto out;

	//确定vhost-dev的owner，创建相应内核线程
	r = vhost_dev_set_owner(&n->dev);
	if (r)
		vhost_net_clear_ubuf_info(n);
	vhost_net_flush(n);
out:
	mutex_unlock(&n->dev.mutex);
	return r;
}

//处理vhost-net设备的ioctl
static long vhost_net_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
    /*取此文件对应的vhost_net结构体*/
	struct vhost_net *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	struct vhost_vring_file backend;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_NET_SET_BACKEND:
	    /*用于：设置收/发队列的后端socket*/
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;
		return vhost_net_set_backend(n, backend.index, backend.fd);
	case VHOST_GET_FEATURES:
	    /*返回vhost-net支持的features*/
		features = VHOST_NET_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
	    /*设置vhost-net需要支持的features*/
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		/*新设置的features必须是支持的子集*/
		if (features & ~VHOST_NET_FEATURES)
			return -EOPNOTSUPP;
		return vhost_net_set_features(n, features);
	case VHOST_GET_BACKEND_FEATURES:
	    /*返回backed支持的功能*/
		features = VHOST_NET_BACKEND_FEATURES;
		if (copy_to_user(featurep, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_BACKEND_FEATURES:
	    /*设置backed需要支持的功能*/
		if (copy_from_user(&features, featurep, sizeof(features)))
			return -EFAULT;
		if (features & ~VHOST_NET_BACKEND_FEATURES)
			return -EOPNOTSUPP;
		vhost_set_backend_features(&n->dev, features);
		return 0;
	case VHOST_RESET_OWNER:
	    /*重置此设备的owner*/
		return vhost_net_reset_owner(n);
	case VHOST_SET_OWNER:
	    /*为vhost-net设置owner,创建vhost work线程,处理work*/
		return vhost_net_set_owner(n);
	default:
		mutex_lock(&n->dev.mutex);
		/*尝试vhost设备的ioctl*/
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
		    /*尝试vhost设备对应vring的ioctl*/
			r = vhost_vring_ioctl(&n->dev, ioctl, argp);
		else
			vhost_net_flush(n);
		mutex_unlock(&n->dev.mutex);
		return r;
	}
}

/*向用户态返回自身的iotlb miss消息*/
static ssize_t vhost_net_chr_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	/*获得此文件对应的私有数据vhost-net结构*/
	struct vhost_net *n = file->private_data;
	/*获得vhost设备*/
	struct vhost_dev *dev = &n->dev;
	/*检查此文件是否非阻塞*/
	int noblock = file->f_flags & O_NONBLOCK;

	/*以noblock规定的方式读取vhost设备，将内容写入到to*/
	return vhost_chr_read_iter(dev, to, noblock);
}

/*vhost_dev设备的iotlb消息处理*/
static ssize_t vhost_net_chr_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	/*获得此文件对应的私有数据vhost-net结构*/
	struct vhost_net *n = file->private_data;
	/*获得vhost设备*/
	struct vhost_dev *dev = &n->dev;

	/*接收用户态写入的消息，并进行响应*/
	return vhost_chr_write_iter(dev, from);
}

static __poll_t vhost_net_chr_poll(struct file *file, poll_table *wait)
{
    /*取此文件对应的vhost_net结构*/
	struct vhost_net *n = file->private_data;
	/*获得vhost_dev设备*/
	struct vhost_dev *dev = &n->dev;

	return vhost_chr_poll(file, dev, wait);
}

/*vhost-net字符设备操作集
 * read_iter,write_iter,poll分别对应iotlb消息处理的”用户态读取“，”用户态写入“
 * 以下”用户态检测是否可读取“
 * open负责vhost_dev设备的创建
 * unlocked_ioctl负责vhost_dev设备的配置
 */
static const struct file_operations vhost_net_fops = {
	.owner          = THIS_MODULE,
	/*关闭vhost-net设备*/
	.release        = vhost_net_release,
	/*自dev->read_list上获取iotlb消息，并填充到to中，同时将此消息移至dev->pending_list*/
	.read_iter      = vhost_net_chr_read_iter,
	/*响应用户态传入的iotlb更新/无效消息*/
	.write_iter     = vhost_net_chr_write_iter,
	.poll           = vhost_net_chr_poll,
	.unlocked_ioctl = vhost_net_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	/*vhost-net字符设备open函数，创建vhost-net设备，并将其设置为file的私有数据*/
	.open           = vhost_net_open,
	.llseek		= noop_llseek,
};

/*vhost-net设备支持的字符设备 /dev/vhost-net */
static struct miscdevice vhost_net_misc = {
	.minor = VHOST_NET_MINOR,
	.name = "vhost-net",
	.fops = &vhost_net_fops,
};

static int __init vhost_net_init(void)
{
	if (experimental_zcopytx)
		vhost_net_enable_zcopy(VHOST_NET_VQ_TX);

	/*vhost-net字符设备注册*/
	return misc_register(&vhost_net_misc);
}
module_init(vhost_net_init);

static void __exit vhost_net_exit(void)
{
	misc_deregister(&vhost_net_misc);
}
module_exit(vhost_net_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("Host kernel accelerator for virtio net");
MODULE_ALIAS_MISCDEV(VHOST_NET_MINOR);
MODULE_ALIAS("devname:vhost-net");
