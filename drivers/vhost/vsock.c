// SPDX-License-Identifier: GPL-2.0-only
/*
 * vhost transport for vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 */
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <net/sock.h>
#include <linux/virtio_vsock.h>
#include <linux/vhost.h>
#include <linux/hashtable.h>

#include <net/af_vsock.h>
#include "vhost.h"

#define VHOST_VSOCK_DEFAULT_HOST_CID	2
/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_VSOCK_WEIGHT 0x80000
/* Max number of packets transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others with
 * small pkts.
 */
#define VHOST_VSOCK_PKT_WEIGHT 256

enum {
    //指明vhost当前支持的功能
	VHOST_VSOCK_FEATURES = VHOST_FEATURES |
			       (1ULL << VIRTIO_F_ACCESS_PLATFORM) |
			       (1ULL << VIRTIO_VSOCK_F_SEQPACKET)
};

enum {
	VHOST_VSOCK_BACKEND_FEATURES = (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2)
};

/* Used to track all the vhost_vsock instances on the system. */
static DEFINE_MUTEX(vhost_vsock_mutex);
static DEFINE_READ_MOSTLY_HASHTABLE(vhost_vsock_hash, 8);

struct vhost_vsock {
	struct vhost_dev dev;
	struct vhost_virtqueue vqs[2];/*收发包队列*/

	/* Link to global vhost_vsock_hash, writes use vhost_vsock_mutex */
	struct hlist_node hash;

	struct vhost_work send_pkt_work;/*vsock的发包函数*/
	/*待发送的报文*/
	struct sk_buff_head send_pkt_queue; /* host->guest pending packets */

	atomic_t queued_replies;

	u32 guest_cid;/*用户态提供的cid，0表示还没有cid。通过VHOST_VSOCK_SET_GUEST_CID设置*/
	bool seqpacket_allow;
};

//返回local cid
static u32 vhost_transport_get_local_cid(void)
{
	return VHOST_VSOCK_DEFAULT_HOST_CID;
}

/* Callers that dereference the return value must hold vhost_vsock_mutex or the
 * RCU read lock.
 */
static struct vhost_vsock *vhost_vsock_get(u32 guest_cid)
{
	struct vhost_vsock *vsock;

	//在hashtable中查找guest_cid相等的vsock
	hash_for_each_possible_rcu(vhost_vsock_hash/*hash表*/, vsock, hash, guest_cid) {
		u32 other_cid = vsock->guest_cid;

		/* Skip instances that have no CID yet */
		if (other_cid == 0)
		    /*跳过没有cid的*/
			continue;

		if (other_cid == guest_cid)
			return vsock;

	}

	return NULL;
}

//向guest发送报文（报文来源于vsock->send_pkt_list）
static void
vhost_transport_do_send_pkt(struct vhost_vsock *vsock,
			    struct vhost_virtqueue *vq)
{
	struct vhost_virtqueue *tx_vq = &vsock->vqs[VSOCK_VQ_TX];
	int pkts = 0, total_len = 0;
	bool added = false;
	bool restart_tx = false;

	mutex_lock(&vq->mutex);

	if (!vhost_vq_get_backend(vq))
		goto out;

	if (!vq_meta_prefetch(vq))
		goto out;

	/* Avoid further vmexits, we're already processing the virtqueue */
	vhost_disable_notify(&vsock->dev, vq);

	do {
		struct virtio_vsock_hdr *hdr;
		size_t iov_len, payload_len;
		struct iov_iter iov_iter;
		u32 flags_to_restore = 0;
		struct sk_buff *skb;
		unsigned out, in;
		size_t nbytes;
		u32 offset;
		int head;

		//如果vsock没有报文，则跳出
		skb = virtio_vsock_skb_dequeue(&vsock->send_pkt_queue);

		if (!skb) {
			vhost_enable_notify(&vsock->dev, vq);
			break;
		}

		/*取一个可用的描述符*/
		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);
		if (head < 0) {
		    	/*获取数据片信息时出错，将报文加入send_pkt_list上，并退出*/
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue, skb);
			break;
		}

		if (head == vq->num) {
		    	/*当前avali表为空，将报文加入send_pkt_list上，通知对端加快处理?*/
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue, skb);
			/* We cannot finish yet if more buffers snuck in while
			 * re-enabling notify.
			 */
			if (unlikely(vhost_enable_notify(&vsock->dev, vq))) {
				vhost_disable_notify(&vsock->dev, vq);
				continue;
			}
			break;
		}

		//当前是在处理报文发送，故此队列上应没有报文进来，不能有读到的数据
		if (out) {
			kfree_skb(skb);
			vq_err(vq, "Expected 0 output buffers, got %u\n", out);
			break;
		}

		//获取可write的数据片总长度
		iov_len = iov_length(&vq->iov[out], in);
		if (iov_len < sizeof(*hdr)) {
		    	//报文长度一定大于pkt->hdr
			kfree_skb(skb);
			vq_err(vq, "Buffer len [%zu] too small\n", iov_len);
			break;
		}

		iov_iter_init(&iov_iter, ITER_DEST, &vq->iov[out], in, iov_len);
		offset = VIRTIO_VSOCK_SKB_CB(skb)->offset;
		payload_len = skb->len - offset;/*要发送的数据包大小*/
		hdr = virtio_vsock_hdr(skb);

		/* If the packet is greater than the space available in the
		 * buffer, we split it using multiple buffers.
		 */
		if (payload_len > iov_len - sizeof(*hdr)) {
		    	/*报文内容过大，需要拆分成多个buffer进行发送，payload_len变更为当前可发送的最大长度*/
			payload_len = iov_len - sizeof(*hdr);

			/* As we are copying pieces of large packet's buffer to
			 * small rx buffers, headers of packets in rx queue are
			 * created dynamically and are initialized with header
			 * of current packet(except length). But in case of
			 * SOCK_SEQPACKET, we also must clear message delimeter
			 * bit (VIRTIO_VSOCK_SEQ_EOM) and MSG_EOR bit
			 * (VIRTIO_VSOCK_SEQ_EOR) if set. Otherwise,
			 * there will be sequence of packets with these
			 * bits set. After initialized header will be copied to
			 * rx buffer, these required bits will be restored.
			 */
			if (le32_to_cpu(hdr->flags) & VIRTIO_VSOCK_SEQ_EOM) {
				hdr->flags &= ~cpu_to_le32(VIRTIO_VSOCK_SEQ_EOM);
				flags_to_restore |= VIRTIO_VSOCK_SEQ_EOM;

				if (le32_to_cpu(hdr->flags) & VIRTIO_VSOCK_SEQ_EOR) {
					hdr->flags &= ~cpu_to_le32(VIRTIO_VSOCK_SEQ_EOR);
					flags_to_restore |= VIRTIO_VSOCK_SEQ_EOR;
				}
			}
		}

		/* Set the correct length in the header */
		hdr->len = cpu_to_le32(payload_len);

		//将pkt->hdr写入到iov_iter中
		nbytes = copy_to_iter(hdr, sizeof(*hdr), &iov_iter);
		if (nbytes != sizeof(*hdr)) {
			kfree_skb(skb);
			vq_err(vq, "Faulted on copying pkt hdr\n");
			break;
		}

		//将pkt payload (本次可发送payload_len)复制到iov_iter中
		if (skb_copy_datagram_iter(skb,
					   offset,
					   &iov_iter,
					   payload_len)) {
		    	//没有写入预期的大小，报错
			kfree_skb(skb);
			vq_err(vq, "Faulted on copying pkt buf\n");
			break;
		}

		/* Deliver to monitoring devices all packets that we
		 * will transmit.
		 */
		//如有必要，为其它monitor复制一份pkt
		virtio_transport_deliver_tap_pkt(skb);

		//head指向的描述符，被使用了sizeof(pkt->hdr)+payload_len长度,在used表中指明
		vhost_add_used(vq, head, sizeof(*hdr) + payload_len);
		added = true;

		VIRTIO_VSOCK_SKB_CB(skb)->offset += payload_len;
		//更新pkt数据起始位置（原来的数据已填充进iov)
		total_len += payload_len;

		/* If we didn't send all the payload we can requeue the packet
		 * to send it with the next available buffer.
		 */
		if (VIRTIO_VSOCK_SKB_CB(skb)->offset < skb->len) {
			hdr->flags |= cpu_to_le32(flags_to_restore);

		    	//报文并没有发送完全，将其加回到vsock->send_pkt_list中
			/* We are queueing the same skb to handle
			 * the remaining bytes, and we want to deliver it
			 * to monitoring devices in the next iteration.
			 */
			virtio_vsock_skb_clear_tap_delivered(skb);
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue, skb);
		} else {
			if (virtio_vsock_skb_reply(skb)) {
				int val;

				val = atomic_dec_return(&vsock->queued_replies);

				/* Do we have resources to resume tx
				 * processing?
				 */
				if (val + 1 == tx_vq->num)
					restart_tx = true;
			}

			//报文已被发送完全，释放
			virtio_transport_consume_skb_sent(skb, true);
		}
	} while(likely(!vhost_exceeds_weight(vq, ++pkts, total_len)));

	//我们向对端发送了报文，故通过eventfd通知guest,我们发送了报文
	if (added)
		vhost_signal(&vsock->dev, vq);

out:
	mutex_unlock(&vq->mutex);

	if (restart_tx)
		vhost_poll_queue(&tx_vq->poll);
}

/*执行传输层的报文发送工作*/
static void vhost_transport_send_pkt_work(struct vhost_work *work)
{
	struct vhost_virtqueue *vq;
	struct vhost_vsock *vsock;

	//取得其对应的socket
	vsock = container_of(work, struct vhost_vsock, send_pkt_work);
	vq = &vsock->vqs[VSOCK_VQ_RX];

	vhost_transport_do_send_pkt(vsock, vq);
}

//向pkt->hdr.dst_cid发送此报文
static int
vhost_transport_send_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr = virtio_vsock_hdr(skb);
	struct vhost_vsock *vsock;
	int len = skb->len;

	rcu_read_lock();

	/* Find the vhost_vsock according to guest context id  */
	//确定此报文对应的vsock
	vsock = vhost_vsock_get(le64_to_cpu(hdr->dst_cid));
	if (!vsock) {
		rcu_read_unlock();
		kfree_skb(skb);
		return -ENODEV;
	}

	if (virtio_vsock_skb_reply(skb))
		atomic_inc(&vsock->queued_replies);

	//向sock添加要发送的packet
	virtio_vsock_skb_queue_tail(&vsock->send_pkt_queue, skb);
	//为vhost dev添加发送报文的work
	vhost_vq_work_queue(&vsock->vqs[VSOCK_VQ_RX], &vsock->send_pkt_work);

	rcu_read_unlock();
	return len;
}

static int
vhost_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct vhost_vsock *vsock;
	int cnt = 0;
	int ret = -ENODEV;

	rcu_read_lock();

	/* Find the vhost_vsock according to guest context id  */
	vsock = vhost_vsock_get(vsk->remote_addr.svm_cid);
	if (!vsock)
		goto out;

	//移除掉vsocket对应的待发送报文
	cnt = virtio_transport_purge_skbs(vsk, &vsock->send_pkt_queue);

	if (cnt) {
		struct vhost_virtqueue *tx_vq = &vsock->vqs[VSOCK_VQ_TX];
		int new_cnt;

		new_cnt = atomic_sub_return(cnt, &vsock->queued_replies);
		if (new_cnt + cnt >= tx_vq->num && new_cnt < tx_vq->num)
			vhost_poll_queue(&tx_vq->poll);
	}

	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

//针对vq->iov中保存的报文信息，构造virtio_vsock_pkt
static struct sk_buff *
vhost_vsock_alloc_skb(struct vhost_virtqueue *vq,
		      unsigned int out, unsigned int in)
{
	struct virtio_vsock_hdr *hdr;
	struct iov_iter iov_iter;
	struct sk_buff *skb;
	size_t payload_len;
	size_t nbytes;
	size_t len;

	if (in != 0) {
	    /*in必须为0*/
		vq_err(vq, "Expected 0 input buffers, got %u\n", in);
		return NULL;
	}

	len = iov_length(vq->iov, out);

	/* len contains both payload and hdr */
	/*申请packet*/
	skb = virtio_vsock_alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return NULL;

	iov_iter_init(&iov_iter, ITER_SOURCE, vq->iov, out, len);

	/*将iov_iter中的内容pkt头部信息复制到pkt->hdr中*/
	hdr = virtio_vsock_hdr(skb);
	nbytes = copy_from_iter(hdr, sizeof(*hdr), &iov_iter);
	if (nbytes != sizeof(*hdr)) {
		/*内容不足pkt头部，报错返回NULL*/
		vq_err(vq, "Expected %zu bytes for pkt->hdr, got %zu bytes\n",
		       sizeof(*hdr), nbytes);
		kfree_skb(skb);
		return NULL;
	}

	payload_len = le32_to_cpu(hdr->len);

	/* No payload */
	if (!payload_len)
		return skb;

	/* The pkt is too big or the length in the header is invalid */
	if (payload_len > VIRTIO_VSOCK_MAX_PKT_BUF_SIZE ||
	    payload_len + sizeof(*hdr) > len) {
		kfree_skb(skb);
		return NULL;
	}

	virtio_vsock_skb_rx_put(skb);

	//自iov_iter中复制报文信息
	nbytes = copy_from_iter(skb->data, payload_len, &iov_iter);
	if (nbytes != payload_len) {
	    	/*报文信息长度不足，报错*/
		vq_err(vq, "Expected %zu byte payload, got %zu bytes\n",
		       payload_len, nbytes);
		kfree_skb(skb);
		return NULL;
	}

	//返回收到的报文
	return skb;
}

/* Is there space left for replies to rx packets? */
static bool vhost_vsock_more_replies(struct vhost_vsock *vsock)
{
	struct vhost_virtqueue *vq = &vsock->vqs[VSOCK_VQ_TX];
	int val;

	smp_rmb(); /* paired with atomic_inc() and atomic_dec_return() */
	val = atomic_read(&vsock->queued_replies);

	return val < vq->num;
}

static bool vhost_transport_msgzerocopy_allow(void)
{
	return true;
}

static bool vhost_transport_seqpacket_allow(u32 remote_cid);

static struct virtio_transport vhost_transport = {
	.transport = {
		.module                   = THIS_MODULE,

		.get_local_cid            = vhost_transport_get_local_cid,

		.init                     = virtio_transport_do_socket_init,
		.destruct                 = virtio_transport_destruct,
		.release                  = virtio_transport_release,
		.connect                  = virtio_transport_connect,
		.shutdown                 = virtio_transport_shutdown,
		.cancel_pkt               = vhost_transport_cancel_pkt,

		.dgram_enqueue            = virtio_transport_dgram_enqueue,
		.dgram_dequeue            = virtio_transport_dgram_dequeue,
		.dgram_bind               = virtio_transport_dgram_bind,
		.dgram_allow              = virtio_transport_dgram_allow,

		.stream_enqueue           = virtio_transport_stream_enqueue,
		.stream_dequeue           = virtio_transport_stream_dequeue,
		.stream_has_data          = virtio_transport_stream_has_data,
		.stream_has_space         = virtio_transport_stream_has_space,
		.stream_rcvhiwat          = virtio_transport_stream_rcvhiwat,
		.stream_is_active         = virtio_transport_stream_is_active,
		.stream_allow             = virtio_transport_stream_allow,

		.seqpacket_dequeue        = virtio_transport_seqpacket_dequeue,
		.seqpacket_enqueue        = virtio_transport_seqpacket_enqueue,
		.seqpacket_allow          = vhost_transport_seqpacket_allow,
		.seqpacket_has_data       = virtio_transport_seqpacket_has_data,

		.msgzerocopy_allow        = vhost_transport_msgzerocopy_allow,

		.notify_poll_in           = virtio_transport_notify_poll_in,
		.notify_poll_out          = virtio_transport_notify_poll_out,
		.notify_recv_init         = virtio_transport_notify_recv_init,
		.notify_recv_pre_block    = virtio_transport_notify_recv_pre_block,
		.notify_recv_pre_dequeue  = virtio_transport_notify_recv_pre_dequeue,
		.notify_recv_post_dequeue = virtio_transport_notify_recv_post_dequeue,
		.notify_send_init         = virtio_transport_notify_send_init,
		.notify_send_pre_block    = virtio_transport_notify_send_pre_block,
		.notify_send_pre_enqueue  = virtio_transport_notify_send_pre_enqueue,
		.notify_send_post_enqueue = virtio_transport_notify_send_post_enqueue,
		.notify_buffer_size       = virtio_transport_notify_buffer_size,
		.notify_set_rcvlowat      = virtio_transport_notify_set_rcvlowat,

		.unsent_bytes             = virtio_transport_unsent_bytes,

		.read_skb = virtio_transport_read_skb,
	},

	//向pkt->hdr.dst_cid发送报文
	.send_pkt = vhost_transport_send_pkt,
};

static bool vhost_transport_seqpacket_allow(u32 remote_cid)
{
	struct vhost_vsock *vsock;
	bool seqpacket_allow = false;

	rcu_read_lock();
	vsock = vhost_vsock_get(remote_cid);

	if (vsock)
		seqpacket_allow = vsock->seqpacket_allow;

	rcu_read_unlock();

	return seqpacket_allow;
}

//自vq中收取pkt并处理
static void vhost_vsock_handle_tx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_vsock *vsock = container_of(vq->dev, struct vhost_vsock,
						 dev);
	int head, pkts = 0, total_len = 0;
	unsigned int out, in;
	struct sk_buff *skb;
	bool added = false;

	mutex_lock(&vq->mutex);

	if (!vhost_vq_get_backend(vq))
		goto out;

	if (!vq_meta_prefetch(vq))
		goto out;

	//先临时关闭通知
	vhost_disable_notify(&vsock->dev, vq);
	do {
		struct virtio_vsock_hdr *hdr;

		if (!vhost_vsock_more_replies(vsock)) {
			/* Stop tx until the device processes already
			 * pending replies.  Leave tx virtqueue
			 * callbacks disabled.
			 */
			goto no_more_replies;
		}

		/*取可用描述符head及其指明的报文内容*/
		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
					 &out, &in, NULL, NULL);
		if (head < 0)
			break;

		if (head == vq->num) {
		    /*无可用描述符*/
			if (unlikely(vhost_enable_notify(&vsock->dev, vq))) {
				vhost_disable_notify(&vsock->dev, vq);
				continue;
			}
			break;
		}

		//用vq->iov中保存的报文信息，构造pkt
		skb = vhost_vsock_alloc_skb(vq, out, in);
		if (!skb) {
			vq_err(vq, "Faulted on pkt\n");
			continue;
		}

		total_len += sizeof(*hdr) + skb->len;

		/* Deliver to monitoring devices all received packets */
		//给monitor设备给一份
		virtio_transport_deliver_tap_pkt(skb);

		hdr = virtio_vsock_hdr(skb);

		/* Only accept correctly addressed packets */
		/*报文必须是由guest_cid到host local cid的，否则被丢弃*/
		if (le64_to_cpu(hdr->src_cid) == vsock->guest_cid &&
		    le64_to_cpu(hdr->dst_cid) ==
		    vhost_transport_get_local_cid())
			virtio_transport_recv_pkt(&vhost_transport, skb);
		else
			kfree_skb(skb);

		vhost_add_used(vq, head, 0);
		added = true;
	} while(likely(!vhost_exceeds_weight(vq, ++pkts, total_len)));

no_more_replies:
	if (added)
		vhost_signal(&vsock->dev, vq);

out:
	mutex_unlock(&vq->mutex);
}

static void vhost_vsock_handle_rx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						poll.work);
	struct vhost_vsock *vsock = container_of(vq->dev, struct vhost_vsock,
						 dev);

	vhost_transport_do_send_pkt(vsock, vq);
}

static int vhost_vsock_start(struct vhost_vsock *vsock)
{
	struct vhost_virtqueue *vq;
	size_t i;
	int ret;

	mutex_lock(&vsock->dev.mutex);

	//确认start是由owner发起的
	ret = vhost_dev_check_owner(&vsock->dev);
	if (ret)
		goto err;

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		vq = &vsock->vqs[i];

		mutex_lock(&vq->mutex);

		//确认vq访问ok
		if (!vhost_vq_access_ok(vq)) {
			ret = -EFAULT;
			goto err_vq;
		}

		if (!vhost_vq_get_backend(vq)) {
		    /*如果vq没有后端，则指明vsock为其后端*/
			vhost_vq_set_backend(vq, vsock);
			ret = vhost_vq_init_access(vq);
			if (ret)
				goto err_vq;
		}

		mutex_unlock(&vq->mutex);
	}

	/* Some packets may have been queued before the device was started,
	 * let's kick the send worker to send them.
	 */
	vhost_vq_work_queue(&vsock->vqs[VSOCK_VQ_RX], &vsock->send_pkt_work);

	mutex_unlock(&vsock->dev.mutex);
	return 0;

err_vq:
	vhost_vq_set_backend(vq, NULL);
	mutex_unlock(&vq->mutex);

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		vq = &vsock->vqs[i];

		mutex_lock(&vq->mutex);
		vhost_vq_set_backend(vq, NULL);
		mutex_unlock(&vq->mutex);
	}
err:
	mutex_unlock(&vsock->dev.mutex);
	return ret;
}

static int vhost_vsock_stop(struct vhost_vsock *vsock, bool check_owner)
{
	size_t i;
	int ret = 0;

	mutex_lock(&vsock->dev.mutex);

	if (check_owner) {
		ret = vhost_dev_check_owner(&vsock->dev);
		if (ret)
			goto err;
	}

	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		struct vhost_virtqueue *vq = &vsock->vqs[i];

		mutex_lock(&vq->mutex);
		vhost_vq_set_backend(vq, NULL);
		mutex_unlock(&vq->mutex);
	}

err:
	mutex_unlock(&vsock->dev.mutex);
	return ret;
}

static void vhost_vsock_free(struct vhost_vsock *vsock)
{
	kvfree(vsock);
}

/*创建vsock,并初始化*/
static int vhost_vsock_dev_open(struct inode *inode, struct file *file)
{
	struct vhost_virtqueue **vqs;
	struct vhost_vsock *vsock;
	int ret;

	/* This struct is large and allocation could fail, fall back to vmalloc
	 * if there is no other way.
	 */
	//创建vsock
	vsock = kvmalloc(sizeof(*vsock), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!vsock)
		return -ENOMEM;

	//创建多个vqs指针
	vqs = kmalloc_array(ARRAY_SIZE(vsock->vqs), sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		ret = -ENOMEM;
		goto out;
	}

	//此vsock还没有关联的guest_cid
	vsock->guest_cid = 0; /* no CID assigned yet */
	vsock->seqpacket_allow = false;

	atomic_set(&vsock->queued_replies, 0);

	//初始化设置vsock->vqs
	vqs[VSOCK_VQ_TX] = &vsock->vqs[VSOCK_VQ_TX];
	vqs[VSOCK_VQ_RX] = &vsock->vqs[VSOCK_VQ_RX];
	/*指明rx,tx对应的kick回调*/
	vsock->vqs[VSOCK_VQ_TX].handle_kick = vhost_vsock_handle_tx_kick;
	vsock->vqs[VSOCK_VQ_RX].handle_kick = vhost_vsock_handle_rx_kick;

	//初始化vsock对应的设备
	vhost_dev_init(&vsock->dev, vqs, ARRAY_SIZE(vsock->vqs),
		       UIO_MAXIOV, VHOST_VSOCK_PKT_WEIGHT,
		       VHOST_VSOCK_WEIGHT, true, NULL/*指定消息处理为空*/);

	/*将vsock指定为私有数据*/
	file->private_data = vsock;
	skb_queue_head_init(&vsock->send_pkt_queue);
	/*指明此work未在排队，并指定work的工作函数*/
	vhost_work_init(&vsock->send_pkt_work, vhost_transport_send_pkt_work);
	return 0;

out:
	vhost_vsock_free(vsock);
	return ret;
}

static void vhost_vsock_flush(struct vhost_vsock *vsock)
{
	vhost_dev_flush(&vsock->dev);
}

static void vhost_vsock_reset_orphans(struct sock *sk)
{
	struct vsock_sock *vsk = vsock_sk(sk);

	/* vmci_transport.c doesn't take sk_lock here either.  At least we're
	 * under vsock_table_lock so the sock cannot disappear while we're
	 * executing.
	 */

	/* If the peer is still valid, no need to reset connection */
	if (vhost_vsock_get(vsk->remote_addr.svm_cid))
		return;

	/* If the close timeout is pending, let it expire.  This avoids races
	 * with the timeout callback.
	 */
	if (vsk->close_work_scheduled)
		return;

	sock_set_flag(sk, SOCK_DONE);
	vsk->peer_shutdown = SHUTDOWN_MASK;
	sk->sk_state = SS_UNCONNECTED;
	sk->sk_err = ECONNRESET;
	sk_error_report(sk);
}

static int vhost_vsock_dev_release(struct inode *inode, struct file *file)
{
	struct vhost_vsock *vsock = file->private_data;

	mutex_lock(&vhost_vsock_mutex);
	if (vsock->guest_cid)
		hash_del_rcu(&vsock->hash);
	mutex_unlock(&vhost_vsock_mutex);

	/* Wait for other CPUs to finish using vsock */
	synchronize_rcu();

	/* Iterating over all connections for all CIDs to find orphans is
	 * inefficient.  Room for improvement here. */
	vsock_for_each_connected_socket(&vhost_transport.transport,
					vhost_vsock_reset_orphans);

	/* Don't check the owner, because we are in the release path, so we
	 * need to stop the vsock device in any case.
	 * vhost_vsock_stop() can not fail in this case, so we don't need to
	 * check the return code.
	 */
	vhost_vsock_stop(vsock, false);
	vhost_vsock_flush(vsock);
	vhost_dev_stop(&vsock->dev);

	//移除掉此vsocket上待发送的报文
	virtio_vsock_skb_queue_purge(&vsock->send_pkt_queue);

	vhost_dev_cleanup(&vsock->dev);
	kfree(vsock->dev.vqs);
	vhost_vsock_free(vsock);
	return 0;
}

//为vsock关联相应的cid
static int vhost_vsock_set_cid(struct vhost_vsock *vsock, u64 guest_cid)
{
	struct vhost_vsock *other;

	/* Refuse reserved CIDs */
	//不能使用预留的cids
	if (guest_cid <= VMADDR_CID_HOST ||
	    guest_cid == U32_MAX)
		return -EINVAL;

	/* 64-bit CIDs are not yet supported */
	//当前不支持cids超过u32最大值
	if (guest_cid > U32_MAX)
		return -EINVAL;

	/* Refuse if CID is assigned to the guest->host transport (i.e. nested
	 * VM), to make the loopback work.
	 */
	if (vsock_find_cid(guest_cid))
	    //给定的cid已存在，报错
		return -EADDRINUSE;

	/* Refuse if CID is already in use */
	mutex_lock(&vhost_vsock_mutex);
	/*检查guest_cid是否已被使用*/
	other = vhost_vsock_get(guest_cid);
	if (other && other != vsock) {
		mutex_unlock(&vhost_vsock_mutex);
		return -EADDRINUSE;
	}

	/*之前已有guest_cid,则先自hash表中移除*/
	if (vsock->guest_cid)
		hash_del_rcu(&vsock->hash);

	//再赋值，并加入hash表
	vsock->guest_cid = guest_cid;
	hash_add_rcu(vhost_vsock_hash, &vsock->hash, vsock->guest_cid);
	mutex_unlock(&vhost_vsock_mutex);

	return 0;
}

static int vhost_vsock_set_features(struct vhost_vsock *vsock, u64 features)
{
	struct vhost_virtqueue *vq;
	int i;

	//需要开启的功能不能超过可支持的功能集合
	if (features & ~VHOST_VSOCK_FEATURES)
		return -EOPNOTSUPP;

	mutex_lock(&vsock->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vsock->dev)) {
	    /*开启log_all时，vhost_log_access_ok必须为true*/
		goto err;
	}

	if ((features & (1ULL << VIRTIO_F_ACCESS_PLATFORM))) {
		if (vhost_init_device_iotlb(&vsock->dev))
			goto err;
	}

	vsock->seqpacket_allow = features & (1ULL << VIRTIO_VSOCK_F_SEQPACKET);

	//为每个vq设置要开启的功能
	for (i = 0; i < ARRAY_SIZE(vsock->vqs); i++) {
		vq = &vsock->vqs[i];
		mutex_lock(&vq->mutex);
		vq->acked_features = features;
		mutex_unlock(&vq->mutex);
	}
	mutex_unlock(&vsock->dev.mutex);
	return 0;

err:
	mutex_unlock(&vsock->dev.mutex);
	return -EFAULT;
}

//vhost vsocket设备ioctl处理
static long vhost_vsock_dev_ioctl(struct file *f, unsigned int ioctl,
				  unsigned long arg)
{
	struct vhost_vsock *vsock = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 guest_cid;
	u64 features;
	int start;
	int r;

	switch (ioctl) {
	case VHOST_VSOCK_SET_GUEST_CID:
	    //为vsocket设置cid
		if (copy_from_user(&guest_cid, argp, sizeof(guest_cid)))
			return -EFAULT;
		return vhost_vsock_set_cid(vsock, guest_cid);
	case VHOST_VSOCK_SET_RUNNING:
	    //使vsocket开始工作/停止工作
		if (copy_from_user(&start, argp, sizeof(start)))
			return -EFAULT;
		if (start/*参数为真，则启动*/)
			return vhost_vsock_start(vsock);
		else
			return vhost_vsock_stop(vsock, true);
	case VHOST_GET_FEATURES:
	    /*返回设备当前可支持的功能*/
		features = VHOST_VSOCK_FEATURES;
		if (copy_to_user(argp, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
	    /*设置设备可开启的功能*/
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		return vhost_vsock_set_features(vsock, features);
	case VHOST_GET_BACKEND_FEATURES:
		features = VHOST_VSOCK_BACKEND_FEATURES;
		if (copy_to_user(argp, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_BACKEND_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		if (features & ~VHOST_VSOCK_BACKEND_FEATURES)
			return -EOPNOTSUPP;
		vhost_set_backend_features(&vsock->dev, features);
		return 0;
	default:
		mutex_lock(&vsock->dev.mutex);
		/*其它vhost设备的ioctl处理 */
		r = vhost_dev_ioctl(&vsock->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vsock->dev, ioctl, argp);
		else
			vhost_vsock_flush(vsock);
		mutex_unlock(&vsock->dev.mutex);
		return r;
	}
}

static ssize_t vhost_vsock_chr_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_dev *dev = &vsock->dev;
	int noblock = file->f_flags & O_NONBLOCK;

	return vhost_chr_read_iter(dev, to, noblock);
}

static ssize_t vhost_vsock_chr_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_dev *dev = &vsock->dev;

	return vhost_chr_write_iter(dev, from);
}

static __poll_t vhost_vsock_chr_poll(struct file *file, poll_table *wait)
{
	struct vhost_vsock *vsock = file->private_data;
	struct vhost_dev *dev = &vsock->dev;

	return vhost_chr_poll(file, dev, wait);
}

static const struct file_operations vhost_vsock_fops = {
	.owner          = THIS_MODULE,
	.open           = vhost_vsock_dev_open,
	.release        = vhost_vsock_dev_release,
	.llseek		= noop_llseek,
	.unlocked_ioctl = vhost_vsock_dev_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.read_iter      = vhost_vsock_chr_read_iter,
	.write_iter     = vhost_vsock_chr_write_iter,
	.poll           = vhost_vsock_chr_poll,
};

/*vhost-vsock字符设备*/
static struct miscdevice vhost_vsock_misc = {
	.minor = VHOST_VSOCK_MINOR,
	.name = "vhost-vsock",
	.fops = &vhost_vsock_fops,
};

static int __init vhost_vsock_init(void)
{
	int ret;

	//注册host to guest传输方式
	ret = vsock_core_register(&vhost_transport.transport,
				  VSOCK_TRANSPORT_F_H2G);
	if (ret < 0)
		return ret;
	//注册misc设备
	ret = misc_register(&vhost_vsock_misc);
	if (ret) {
		vsock_core_unregister(&vhost_transport.transport);
		return ret;
	}

	return 0;
};

static void __exit vhost_vsock_exit(void)
{
	misc_deregister(&vhost_vsock_misc);
	vsock_core_unregister(&vhost_transport.transport);
};

module_init(vhost_vsock_init);
module_exit(vhost_vsock_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("vhost transport for vsock ");
MODULE_ALIAS_MISCDEV(VHOST_VSOCK_MINOR);
MODULE_ALIAS("devname:vhost-vsock");
