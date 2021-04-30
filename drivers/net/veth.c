// SPDX-License-Identifier: GPL-2.0-only
/*
 *  drivers/net/veth.c
 *
 *  Copyright (C) 2007 OpenVZ http://openvz.org, SWsoft Inc
 *
 * Author: Pavel Emelianov <xemul@openvz.org>
 * Ethtool interface from: Eric W. Biederman <ebiederm@xmission.com>
 *
 */

#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/xdp.h>
#include <linux/veth.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf_trace.h>
#include <linux/net_tstamp.h>

#define DRV_NAME	"veth"
#define DRV_VERSION	"1.0"

#define VETH_XDP_FLAG		BIT(0)
#define VETH_RING_SIZE		256
#define VETH_XDP_HEADROOM	(XDP_PACKET_HEADROOM + NET_IP_ALIGN)

#define VETH_XDP_TX_BULK_SIZE	16
#define VETH_XDP_BATCH		16

struct veth_stats {
	u64	rx_drops;/*rx方向丢包数*/
	/* xdp */
	u64	xdp_packets;
	u64	xdp_bytes;//xdp报文数
	u64	xdp_redirect;/*redirect的报文数*/
	u64	xdp_drops;/*xdp丢包数量*/
	u64	xdp_tx;/*送tx方向的报文数*/
	u64	xdp_tx_err;
	u64	peer_tq_xdp_xmit;
	u64	peer_tq_xdp_xmit_err;
};

struct veth_rq_stats {
	struct veth_stats	vs;/*记录此队列状态*/
	struct u64_stats_sync	syncp;
};

struct veth_rq {
	struct napi_struct	xdp_napi;/*用于napi轮循*/
	struct net_device	*dev;/*此队列所属的dev*/
	struct bpf_prog __rcu	*xdp_prog;/*指向本队列对应的xdp程序*/
	struct xdp_mem_info	xdp_mem;/*指向xdp_prog中的mem*/
	struct veth_rq_stats	stats;
	bool			rx_notify_masked;
	struct ptr_ring		xdp_ring;/*负责入队xdp报文*/
	struct xdp_rxq_info	xdp_rxq;
};

struct veth_priv {
	struct net_device __rcu	*peer;/*对端设备*/
	atomic64_t		dropped;
	struct bpf_prog		*_xdp_prog;/*指向被设置的xdp程序*/
	struct veth_rq		*rq;/*多个收队列*/
	unsigned int		requested_headroom;
};

struct veth_xdp_tx_bq {
    //缓存xdp_frame
	struct xdp_frame *q[VETH_XDP_TX_BULK_SIZE];
	//当前缓存的xdp_frame大小
	unsigned int count;
};

/*
 * ethtool interface
 */

struct veth_q_stat_desc {
	char	desc[ETH_GSTRING_LEN];
	size_t	offset;
};

#define VETH_RQ_STAT(m)	offsetof(struct veth_stats, m)

static const struct veth_q_stat_desc veth_rq_stats_desc[] = {
	{ "xdp_packets",	VETH_RQ_STAT(xdp_packets) },
	{ "xdp_bytes",		VETH_RQ_STAT(xdp_bytes) },
	{ "drops",		VETH_RQ_STAT(rx_drops) },
	{ "xdp_redirect",	VETH_RQ_STAT(xdp_redirect) },
	{ "xdp_drops",		VETH_RQ_STAT(xdp_drops) },
	{ "xdp_tx",		VETH_RQ_STAT(xdp_tx) },
	{ "xdp_tx_errors",	VETH_RQ_STAT(xdp_tx_err) },
};

#define VETH_RQ_STATS_LEN	ARRAY_SIZE(veth_rq_stats_desc)

static const struct veth_q_stat_desc veth_tq_stats_desc[] = {
	{ "xdp_xmit",		VETH_RQ_STAT(peer_tq_xdp_xmit) },
	{ "xdp_xmit_errors",	VETH_RQ_STAT(peer_tq_xdp_xmit_err) },
};

#define VETH_TQ_STATS_LEN	ARRAY_SIZE(veth_tq_stats_desc)

static struct {
	const char string[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{ "peer_ifindex" },
};

static int veth_get_link_ksettings(struct net_device *dev,
				   struct ethtool_link_ksettings *cmd)
{
	cmd->base.speed		= SPEED_10000;
	cmd->base.duplex	= DUPLEX_FULL;
	cmd->base.port		= PORT_TP;
	cmd->base.autoneg	= AUTONEG_DISABLE;
	return 0;
}

static void veth_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static void veth_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	char *p = (char *)buf;
	int i, j;

	switch(stringset) {
	case ETH_SS_STATS:
		memcpy(p, &ethtool_stats_keys, sizeof(ethtool_stats_keys));
		p += sizeof(ethtool_stats_keys);
		for (i = 0; i < dev->real_num_rx_queues; i++) {
			for (j = 0; j < VETH_RQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN,
					 "rx_queue_%u_%.18s",
					 i, veth_rq_stats_desc[j].desc);
				p += ETH_GSTRING_LEN;
			}
		}
		for (i = 0; i < dev->real_num_tx_queues; i++) {
			for (j = 0; j < VETH_TQ_STATS_LEN; j++) {
				snprintf(p, ETH_GSTRING_LEN,
					 "tx_queue_%u_%.18s",
					 i, veth_tq_stats_desc[j].desc);
				p += ETH_GSTRING_LEN;
			}
		}
		break;
	}
}

static int veth_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stats_keys) +
		       VETH_RQ_STATS_LEN * dev->real_num_rx_queues +
		       VETH_TQ_STATS_LEN * dev->real_num_tx_queues;
	default:
		return -EOPNOTSUPP;
	}
}

static void veth_get_ethtool_stats(struct net_device *dev,
		struct ethtool_stats *stats, u64 *data)
{
	struct veth_priv *rcv_priv, *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);
	int i, j, idx;

	data[0] = peer ? peer->ifindex : 0;
	idx = 1;
	for (i = 0; i < dev->real_num_rx_queues; i++) {
		const struct veth_rq_stats *rq_stats = &priv->rq[i].stats;
		const void *stats_base = (void *)&rq_stats->vs;
		unsigned int start;
		size_t offset;

		do {
			start = u64_stats_fetch_begin_irq(&rq_stats->syncp);
			for (j = 0; j < VETH_RQ_STATS_LEN; j++) {
				offset = veth_rq_stats_desc[j].offset;
				data[idx + j] = *(u64 *)(stats_base + offset);
			}
		} while (u64_stats_fetch_retry_irq(&rq_stats->syncp, start));
		idx += VETH_RQ_STATS_LEN;
	}

	if (!peer)
		return;

	rcv_priv = netdev_priv(peer);
	for (i = 0; i < peer->real_num_rx_queues; i++) {
		const struct veth_rq_stats *rq_stats = &rcv_priv->rq[i].stats;
		const void *base = (void *)&rq_stats->vs;
		unsigned int start, tx_idx = idx;
		size_t offset;

		tx_idx += (i % dev->real_num_tx_queues) * VETH_TQ_STATS_LEN;
		do {
			start = u64_stats_fetch_begin_irq(&rq_stats->syncp);
			for (j = 0; j < VETH_TQ_STATS_LEN; j++) {
				offset = veth_tq_stats_desc[j].offset;
				data[tx_idx + j] += *(u64 *)(base + offset);
			}
		} while (u64_stats_fetch_retry_irq(&rq_stats->syncp, start));
	}
}

static const struct ethtool_ops veth_ethtool_ops = {
	.get_drvinfo		= veth_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_strings		= veth_get_strings,
	.get_sset_count		= veth_get_sset_count,
	.get_ethtool_stats	= veth_get_ethtool_stats,
	.get_link_ksettings	= veth_get_link_ksettings,
	.get_ts_info		= ethtool_op_get_ts_info,
};

/* general routines */

static bool veth_is_xdp_frame(void *ptr)
{
    /*检查是否为xdp frame*/
	return (unsigned long)ptr & VETH_XDP_FLAG;
}

/*针对xdp frame,获取其对应的xdp_frame地址*/
static struct xdp_frame *veth_ptr_to_xdp(void *ptr)
{
	return (void *)((unsigned long)ptr & ~VETH_XDP_FLAG);
}

static void *veth_xdp_to_ptr(struct xdp_frame *xdp)
{
	return (void *)((unsigned long)xdp | VETH_XDP_FLAG);
}

static void veth_ptr_free(void *ptr)
{
	if (veth_is_xdp_frame(ptr))
		xdp_return_frame(veth_ptr_to_xdp(ptr));
	else
		kfree_skb(ptr);
}

static void __veth_xdp_flush(struct veth_rq *rq)
{
	/* Write ptr_ring before reading rx_notify_masked */
	smp_mb();
	if (!rq->rx_notify_masked) {
		rq->rx_notify_masked = true;
		napi_schedule(&rq->xdp_napi);
	}
}

//支持xdp的rx方式（将报文直接投递到rq的xdp_ring，napi会poll其中的报文并处理）
static int veth_xdp_rx(struct veth_rq *rq, struct sk_buff *skb)
{
	if (unlikely(ptr_ring_produce(&rq->xdp_ring, skb))) {
		dev_kfree_skb_any(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}

static int veth_forward_skb(struct net_device *dev, struct sk_buff *skb,
			    struct veth_rq *rq, bool xdp)
{
	return __dev_forward_skb(dev, skb) ?: xdp ?
		veth_xdp_rx(rq, skb) :
		netif_rx(skb);
}

//veth接口发包函数
static netdev_tx_t veth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct veth_priv *rcv_priv, *priv = netdev_priv(dev);
	struct veth_rq *rq = NULL;
	struct net_device *rcv;
	int length = skb->len;
	bool rcv_xdp = false;
	int rxq;

	rcu_read_lock();
	rcv = rcu_dereference(priv->peer);
	if (unlikely(!rcv)) {
		kfree_skb(skb);
		goto drop;
	}

	rcv_priv = netdev_priv(rcv);
	rxq = skb_get_queue_mapping(skb);
	if (rxq < rcv->real_num_rx_queues) {
		rq = &rcv_priv->rq[rxq];
		/*如果此队列上有xdp程序，则需要采用xdp方式收包*/
		rcv_xdp = rcu_access_pointer(rq->xdp_prog);
		skb_record_rx_queue(skb, rxq);
	}

	skb_tx_timestamp(skb);
	//切换设备，完成peer收包
	if (likely(veth_forward_skb(rcv, skb, rq, rcv_xdp) == NET_RX_SUCCESS)) {
		if (!rcv_xdp)
			dev_lstats_add(dev, length);
	} else {
drop:
		atomic64_inc(&priv->dropped);
	}

	if (rcv_xdp)
		__veth_xdp_flush(rq);

	rcu_read_unlock();

	return NETDEV_TX_OK;
}

static u64 veth_stats_tx(struct net_device *dev, u64 *packets, u64 *bytes)
{
	struct veth_priv *priv = netdev_priv(dev);

	dev_lstats_read(dev, packets, bytes);
	return atomic64_read(&priv->dropped);
}

static void veth_stats_rx(struct veth_stats *result, struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int i;

	result->peer_tq_xdp_xmit_err = 0;
	result->xdp_packets = 0;
	result->xdp_tx_err = 0;
	result->xdp_bytes = 0;
	result->rx_drops = 0;
	for (i = 0; i < dev->num_rx_queues; i++) {
		u64 packets, bytes, drops, xdp_tx_err, peer_tq_xdp_xmit_err;
		struct veth_rq_stats *stats = &priv->rq[i].stats;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			peer_tq_xdp_xmit_err = stats->vs.peer_tq_xdp_xmit_err;
			xdp_tx_err = stats->vs.xdp_tx_err;
			packets = stats->vs.xdp_packets;
			bytes = stats->vs.xdp_bytes;
			drops = stats->vs.rx_drops;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));
		result->peer_tq_xdp_xmit_err += peer_tq_xdp_xmit_err;
		result->xdp_tx_err += xdp_tx_err;
		result->xdp_packets += packets;
		result->xdp_bytes += bytes;
		result->rx_drops += drops;
	}
}

static void veth_get_stats64(struct net_device *dev,
			     struct rtnl_link_stats64 *tot)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	struct veth_stats rx;
	u64 packets, bytes;

	tot->tx_dropped = veth_stats_tx(dev, &packets, &bytes);
	tot->tx_bytes = bytes;
	tot->tx_packets = packets;

	veth_stats_rx(&rx, dev);
	tot->tx_dropped += rx.xdp_tx_err;
	tot->rx_dropped = rx.rx_drops + rx.peer_tq_xdp_xmit_err;
	tot->rx_bytes = rx.xdp_bytes;
	tot->rx_packets = rx.xdp_packets;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (peer) {
		veth_stats_tx(peer, &packets, &bytes);
		tot->rx_bytes += bytes;
		tot->rx_packets += packets;

		veth_stats_rx(&rx, peer);
		tot->tx_dropped += rx.peer_tq_xdp_xmit_err;
		tot->rx_dropped += rx.xdp_tx_err;
		tot->tx_bytes += rx.xdp_bytes;
		tot->tx_packets += rx.xdp_packets;
	}
	rcu_read_unlock();
}

/* fake multicast ability */
static void veth_set_multicast_list(struct net_device *dev)
{
}

/*通过buffer构造skb*/
static struct sk_buff *veth_build_skb(void *head/*buffer地始地址*/, int headroom/*headroom长度*/, int len/*报文长度*/,
				      int buflen/*buffer长度*/)
{
	struct sk_buff *skb;

	//通过head生成skb
	skb = build_skb(head, buflen);
	if (!skb)
		return NULL;

	//跳过headroom长度
	skb_reserve(skb, headroom);
	skb_put(skb, len);

	return skb;
}

static int veth_select_rxq(struct net_device *dev)
{
	return smp_processor_id() % dev->real_num_rx_queues;
}

static struct net_device *veth_peer_dev(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);

	/* Callers must be under RCU read side. */
	return rcu_dereference(priv->peer);
}

//将xdp_frame发送到对端设备
static int veth_xdp_xmit(struct net_device *dev, int n/*要发送的报文数目*/,
			 struct xdp_frame **frames/*待发送报文数组*/,
			 u32 flags, bool ndo_xmit)
{
	struct veth_priv *rcv_priv, *priv = netdev_priv(dev);
	int i, ret = -ENXIO, drops = 0;
	struct net_device *rcv;
	unsigned int max_len;
	struct veth_rq *rq;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	rcu_read_lock();
	/*取对端设备*/
	rcv = rcu_dereference(priv->peer);
	if (unlikely(!rcv))
		goto out;

	/*选择收包队列*/
	rcv_priv = netdev_priv(rcv);
	rq = &rcv_priv->rq[veth_select_rxq(rcv)];
	/* Non-NULL xdp_prog ensures that xdp_ring is initialized on receive
	 * side. This means an XDP program is loaded on the peer and the peer
	 * device is up.
	 */
	if (!rcu_access_pointer(rq->xdp_prog))
	    /*此队列没有prog,退出*/
		goto out;

	max_len = rcv->mtu + rcv->hard_header_len + VLAN_HLEN;

	//加生产者锁，遍历每个frames,将其打上xdp_frame标记，并入队列xdp_ring中
	spin_lock(&rq->xdp_ring.producer_lock);
	for (i = 0; i < n; i++) {
		struct xdp_frame *frame = frames[i];
		void *ptr = veth_xdp_to_ptr(frame);

		//如果报文长度超限，或者ring存入失败，则丢包
		if (unlikely(frame->len > max_len ||
			     __ptr_ring_produce(&rq->xdp_ring, ptr))) {
			xdp_return_frame_rx_napi(frame);
			drops++;
		}
	}
	spin_unlock(&rq->xdp_ring.producer_lock);

	//如有必要，使设备可被调度，使其收包
	if (flags & XDP_XMIT_FLUSH)
		__veth_xdp_flush(rq);

	/*记录成功发送的数目*/
	ret = n - drops;
	if (ndo_xmit) {
		u64_stats_update_begin(&rq->stats.syncp);
		rq->stats.vs.peer_tq_xdp_xmit += n - drops;
		rq->stats.vs.peer_tq_xdp_xmit_err += drops;
		u64_stats_update_end(&rq->stats.syncp);
	}

out:
	rcu_read_unlock();

	return ret;
}

//veth xdp报文发送回调函数
static int veth_ndo_xdp_xmit(struct net_device *dev, int n,
			     struct xdp_frame **frames, u32 flags)
{
	int err;

	err = veth_xdp_xmit(dev, n, frames, flags, true);
	if (err < 0) {
		struct veth_priv *priv = netdev_priv(dev);

		atomic64_add(n, &priv->dropped);
	}

	return err;
}

static void veth_xdp_flush_bq(struct veth_rq *rq, struct veth_xdp_tx_bq *bq)
{
	int sent, i, err = 0;

	/*将bq上缓存的报文，自rq->dev设备发送出去*/
	sent = veth_xdp_xmit(rq->dev, bq->count, bq->q, 0, false);
	if (sent < 0) {
		err = sent;
		sent = 0;
		for (i = 0; i < bq->count; i++)
			xdp_return_frame(bq->q[i]);
	}
	trace_xdp_bulk_tx(rq->dev, sent, bq->count - sent, err);

	u64_stats_update_begin(&rq->stats.syncp);
	rq->stats.vs.xdp_tx += sent;
	rq->stats.vs.xdp_tx_err += bq->count - sent;
	u64_stats_update_end(&rq->stats.syncp);

	bq->count = 0;
}

static void veth_xdp_flush(struct veth_rq *rq, struct veth_xdp_tx_bq *bq)
{
	struct veth_priv *rcv_priv, *priv = netdev_priv(rq->dev);
	struct net_device *rcv;
	struct veth_rq *rcv_rq;

	rcu_read_lock();
	veth_xdp_flush_bq(rq, bq);
	rcv = rcu_dereference(priv->peer);
	if (unlikely(!rcv))
		goto out;

	rcv_priv = netdev_priv(rcv);
	rcv_rq = &rcv_priv->rq[veth_select_rxq(rcv)];
	/* xdp_ring is initialized on receive side? */
	if (unlikely(!rcu_access_pointer(rcv_rq->xdp_prog)))
		goto out;

	__veth_xdp_flush(rcv_rq);
out:
	rcu_read_unlock();
}

//将xdp buffer转为xdp_frame,并将其挂接在bq->q中
static int veth_xdp_tx(struct veth_rq *rq, struct xdp_buff *xdp,
		       struct veth_xdp_tx_bq *bq)
{
    //将xdp_buff转换为xdp_frame
	struct xdp_frame *frame = xdp_convert_buff_to_frame(xdp);

	if (unlikely(!frame))
		return -EOVERFLOW;

	/*bq中存储了一批报文，但已满，将其刷出*/
	if (unlikely(bq->count == VETH_XDP_TX_BULK_SIZE))
		veth_xdp_flush_bq(rq, bq);

	/*将frame缓存在bq->q上*/
	bq->q[bq->count++] = frame;

	return 0;
}

/*veth xdp收到一个xdp_frame,进行处理，返回对应的skb*/
static struct xdp_frame *veth_xdp_rcv_one(struct veth_rq *rq,
					  struct xdp_frame *frame,
					  struct veth_xdp_tx_bq *bq,
					  struct veth_stats *stats)
{
	struct xdp_frame orig_frame;
	struct bpf_prog *xdp_prog;

	rcu_read_lock();
	/*取rx队列上的xdp程序*/
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (likely(xdp_prog)) {
		struct xdp_buff xdp;
		u32 act;

		//将xdp frame转为xdp buffer
		xdp_convert_frame_to_buff(frame, &xdp);
		xdp.rxq = &rq->xdp_rxq;

		//运行xdp_prog->bpf_func,取其返回值
		act = bpf_prog_run_xdp(xdp_prog, &xdp);

		switch (act) {
		case XDP_PASS:
		    	/*报文需要上送协议栈*/
			if (xdp_update_frame_from_buff(&xdp, frame))
				goto err_xdp;
			break;
		case XDP_TX:
		    //收到报文需要走tx方向，这里将报文挂在bq队列上，等待发送。
			orig_frame = *frame;
			xdp.rxq->mem = frame->mem;
			if (unlikely(veth_xdp_tx(rq, &xdp, bq) < 0)) {
				trace_xdp_exception(rq->dev, xdp_prog, act);
				frame = &orig_frame;
				stats->rx_drops++;
				goto err_xdp;
			}
			stats->xdp_tx++;
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
		    //完成报文重定向
			orig_frame = *frame;
			xdp.rxq->mem = frame->mem;
			if (xdp_do_redirect(rq->dev, &xdp, xdp_prog)) {
				frame = &orig_frame;
				stats->rx_drops++;
				goto err_xdp;
			}
			stats->xdp_redirect++;
			rcu_read_unlock();
			goto xdp_xmit;
		default:
		    /*不支持的返回值*/
			bpf_warn_invalid_xdp_action(act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(rq->dev, xdp_prog, act);
			fallthrough;
		case XDP_DROP:
		    /*要求丢包，执行丢包统计*/
			stats->xdp_drops++;
			goto err_xdp;
		}
	}
	rcu_read_unlock();

	return frame;
err_xdp:
	rcu_read_unlock();
	xdp_return_frame(frame);
xdp_xmit:
	return NULL;
}

/* frames array contains VETH_XDP_BATCH at most */
static void veth_xdp_rcv_bulk_skb(struct veth_rq *rq, void **frames,
				  int n_xdpf, struct veth_xdp_tx_bq *bq,
				  struct veth_stats *stats)
{
	void *skbs[VETH_XDP_BATCH];
	int i;

	if (xdp_alloc_skb_bulk(skbs, n_xdpf,
			       GFP_ATOMIC | __GFP_ZERO) < 0) {
		for (i = 0; i < n_xdpf; i++)
			xdp_return_frame(frames[i]);
		stats->rx_drops += n_xdpf;

		return;
	}

	for (i = 0; i < n_xdpf; i++) {
		struct sk_buff *skb = skbs[i];

		skb = __xdp_build_skb_from_frame(frames[i], skb,
						 rq->dev);
		if (!skb) {
			xdp_return_frame(frames[i]);
			stats->rx_drops++;
			continue;
		}
		napi_gro_receive(&rq->xdp_napi, skb);
	}
}

/*veth xdp收到一个skb报文*/
static struct sk_buff *veth_xdp_rcv_skb(struct veth_rq *rq,
					struct sk_buff *skb,
					struct veth_xdp_tx_bq *bq,
					struct veth_stats *stats)
{
	u32 pktlen, headroom, act, metalen, frame_sz;
	void *orig_data, *orig_data_end;
	struct bpf_prog *xdp_prog;
	int mac_len, delta, off;
	struct xdp_buff xdp;

	skb_orphan(skb);

	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (unlikely(!xdp_prog)) {
	    /*没有xdp程序，直接退出*/
		rcu_read_unlock();
		goto out;
	}

	/*当前解析位置为ip头部，获得mac头部长度*/
	mac_len = skb->data - skb_mac_header(skb);
	/*获得报文总长度*/
	pktlen = skb->len + mac_len;
	/*获得headroom可用长度*/
	headroom = skb_headroom(skb) - mac_len;

	if (skb_shared(skb) || skb_head_is_locked(skb) ||
	    skb_is_nonlinear(skb) || headroom < XDP_PACKET_HEADROOM) {
	    /*headroom不足xdp要求的headroom空间，或者与其它share skb,skb非线性*/
		struct sk_buff *nskb;
		int size, head_off;
		void *head, *start;
		struct page *page;

		/*获得适合此skb的内存大小*/
		size = SKB_DATA_ALIGN(VETH_XDP_HEADROOM + pktlen) +
		       SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		if (size > PAGE_SIZE)
			goto drop;

		/*申请一个内存页*/
		page = alloc_page(GFP_ATOMIC | __GFP_NOWARN);
		if (!page)
			goto drop;

		head = page_address(page);
		start = head + VETH_XDP_HEADROOM;//可存放skb数据的起始位置

		//自mac层起始位置开始，copy报文到申请的页中
		if (skb_copy_bits(skb, -mac_len, start, pktlen)) {
			page_frag_free(head);
			goto drop;
		}

		/*构造新生成的skb*/
		nskb = veth_build_skb(head, VETH_XDP_HEADROOM + mac_len,
				      skb->len, PAGE_SIZE);
		if (!nskb) {
			page_frag_free(head);
			goto drop;
		}

		skb_copy_header(nskb, skb);
		head_off = skb_headroom(nskb) - skb_headroom(skb);
		skb_headers_offset_update(nskb, head_off);
		/*不再引用此skb*/
		consume_skb(skb);
		/*使用新申请的skb*/
		skb = nskb;
	}

	/* SKB "head" area always have tailroom for skb_shared_info */
	frame_sz = skb_end_pointer(skb) - skb->head;
	frame_sz += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	xdp_init_buff(&xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(&xdp, skb->head, skb->mac_header, pktlen, true);

	/*记录报文原始的起始位置及终止位置*/
	orig_data = xdp.data;
	orig_data_end = xdp.data_end;

	//执行此接收队列对应的bpf程序
	act = bpf_prog_run_xdp(xdp_prog, &xdp);

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
	    //将此报文自收接口扔回
		get_page(virt_to_page(xdp.data));
		consume_skb(skb);
		xdp.rxq->mem = rq->xdp_mem;
		if (unlikely(veth_xdp_tx(rq, &xdp, bq) < 0)) {
			trace_xdp_exception(rq->dev, xdp_prog, act);
			stats->rx_drops++;
			goto err_xdp;
		}
		stats->xdp_tx++;
		rcu_read_unlock();
		goto xdp_xmit;
	case XDP_REDIRECT:
	    /*报文redirect*/
		get_page(virt_to_page(xdp.data));
		consume_skb(skb);
		xdp.rxq->mem = rq->xdp_mem;
		if (xdp_do_redirect(rq->dev, &xdp, xdp_prog)) {
			stats->rx_drops++;
			goto err_xdp;
		}
		stats->xdp_redirect++;
		rcu_read_unlock();
		goto xdp_xmit;
	default:
	    //其它无效返回值，丢包
		bpf_warn_invalid_xdp_action(act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(rq->dev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		stats->xdp_drops++;
		goto xdp_drop;
	}
	rcu_read_unlock();

	/* check if bpf_xdp_adjust_head was used */
	/*报文起始位置变换delta*/
	delta = orig_data - xdp.data;
	off = mac_len + delta;
	//更新报文数据的起始位置
	if (off > 0)
		__skb_push(skb, off);
	else if (off < 0)
		__skb_pull(skb, -off);

	/*更新到mac头偏移量长度*/
	skb->mac_header -= delta;

	/* check if bpf_xdp_adjust_tail was used */
	/*更新报文终止位置*/
	off = xdp.data_end - orig_data_end;
	if (off != 0)
		__skb_put(skb, off); /* positive on grow, negative on shrink */
	/*防止报文更改，重新解析报文协议*/
	skb->protocol = eth_type_trans(skb, rq->dev);

	/*更新报文metadata长度*/
	metalen = xdp.data - xdp.data_meta;
	if (metalen)
		skb_metadata_set(skb, metalen);
out:
	return skb;
drop:
	stats->rx_drops++;
xdp_drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return NULL;
err_xdp:
	rcu_read_unlock();
	page_frag_free(xdp.data);
xdp_xmit:
	return NULL;
}

//自xdp_ring中收取报文，并针对单个报文执行xdp程序
static int veth_xdp_rcv(struct veth_rq *rq, int budget,
			struct veth_xdp_tx_bq *bq,
			struct veth_stats *stats)
{
	int i, done = 0, n_xdpf = 0;
	void *xdpf[VETH_XDP_BATCH];

	for (i = 0; i < budget; i++) {
	    /*自xdp ring中出队一个报文*/
		void *ptr = __ptr_ring_consume(&rq->xdp_ring);

		if (!ptr)
		    /*队列已为空*/
			break;

		if (veth_is_xdp_frame(ptr)) {
			/* ndo_xdp_xmit */
		    	//ring中出的是xdp格式报文
			struct xdp_frame *frame = veth_ptr_to_xdp(ptr);

			stats->xdp_bytes += frame->len;
			/*veth xdp收到一个xdp frame*/
			frame = veth_xdp_rcv_one(rq, frame, bq, stats);
			if (frame) {
				/* XDP_PASS */
				xdpf[n_xdpf++] = frame;
				if (n_xdpf == VETH_XDP_BATCH) {
					veth_xdp_rcv_bulk_skb(rq, xdpf, n_xdpf,
							      bq, stats);
					n_xdpf = 0;
				}
			}
		} else {
			/* ndo_start_xmit */
		    	//ring中出的是普通skb报文
			struct sk_buff *skb = ptr;

			stats->xdp_bytes += skb->len;
			/*veth xdp收到一个skb*/
			skb = veth_xdp_rcv_skb(rq, skb, bq, stats);
			if (skb)
				napi_gro_receive(&rq->xdp_napi, skb);
		}
		done++;
	}

	if (n_xdpf)
		veth_xdp_rcv_bulk_skb(rq, xdpf, n_xdpf, bq, stats);

	u64_stats_update_begin(&rq->stats.syncp);
	rq->stats.vs.xdp_redirect += stats->xdp_redirect;
	rq->stats.vs.xdp_bytes += stats->xdp_bytes;
	rq->stats.vs.xdp_drops += stats->xdp_drops;
	rq->stats.vs.rx_drops += stats->rx_drops;
	rq->stats.vs.xdp_packets += done;
	u64_stats_update_end(&rq->stats.syncp);

	return done;
}

//负责xdp ring队列收包
static int veth_poll(struct napi_struct *napi, int budget)
{
    /*通过napi取得对应的veth_rq*/
	struct veth_rq *rq =
		container_of(napi, struct veth_rq, xdp_napi);
	/*记录veth_xdp_rcv时，报文统计信息*/
	struct veth_stats stats = {};
	/*在此队列上记录，需要执行tx发送的skb*/
	struct veth_xdp_tx_bq bq;
	int done;

	bq.count = 0;

	xdp_set_return_frame_no_direct();
	/*自rq中收取报文*/
	done = veth_xdp_rcv(rq, budget, &bq, &stats);

	if (done < budget && napi_complete_done(napi, done)) {
		/* Write rx_notify_masked before reading ptr_ring */
		smp_store_mb(rq->rx_notify_masked, false);
		if (unlikely(!__ptr_ring_empty(&rq->xdp_ring))) {
		    /*xdp_ring不为空，仍需要继续调度*/
			rq->rx_notify_masked = true;
			napi_schedule(&rq->xdp_napi);
		}
	}

	/*有xdp_tx报文，将这些报文发出*/
	if (stats.xdp_tx > 0)
		veth_xdp_flush(rq, &bq);
	/*有xddp redirect类型报文，将这些报文发出*/
	if (stats.xdp_redirect > 0)
		xdp_do_flush();
	xdp_clear_return_frame_no_direct();

	return done;
}

//为每个rq创建xdp_ring并将其加入到napi中
static int veth_napi_add(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int err, i;

	//为每个rq创建xdp_ring
	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		err = ptr_ring_init(&rq->xdp_ring, VETH_RING_SIZE, GFP_KERNEL);
		if (err)
			goto err_xdp_ring;
	}

	//将每个队列加入到napi中
	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		napi_enable(&rq->xdp_napi);
	}

	return 0;
err_xdp_ring:
	for (i--; i >= 0; i--)
		ptr_ring_cleanup(&priv->rq[i].xdp_ring, veth_ptr_free);

	return err;
}

static void veth_napi_del(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		napi_disable(&rq->xdp_napi);
		__netif_napi_del(&rq->xdp_napi);
	}
	synchronize_net();

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		rq->rx_notify_masked = false;
		ptr_ring_cleanup(&rq->xdp_ring, veth_ptr_free);
	}
}

//veth设备开启xdp
static int veth_enable_xdp(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int err, i;

	if (!xdp_rxq_info_is_reg(&priv->rq[0].xdp_rxq)) {
	    /*rq上没有xdp_rxq,则进入，并遍历每个rx队列*/
		for (i = 0; i < dev->real_num_rx_queues; i++) {
			struct veth_rq *rq = &priv->rq[i];

			/*初始化此队列对应的xdp_rxq*/
			netif_napi_add(dev, &rq->xdp_napi, veth_poll, NAPI_POLL_WEIGHT);
			err = xdp_rxq_info_reg(&rq->xdp_rxq, dev, i, rq->xdp_napi.napi_id);
			if (err < 0)
				goto err_rxq_reg;

			/*设置xdp_rxq的memory type*/
			err = xdp_rxq_info_reg_mem_model(&rq->xdp_rxq,
							 MEM_TYPE_PAGE_SHARED,
							 NULL);
			if (err < 0)
				goto err_reg_mem;

			/* Save original mem info as it can be overwritten */
			rq->xdp_mem = rq->xdp_rxq.mem;
		}

		err = veth_napi_add(dev);
		if (err)
			goto err_rxq_reg;
	}

	/*为每个rq队列设置xdp_prog*/
	for (i = 0; i < dev->real_num_rx_queues; i++)
		rcu_assign_pointer(priv->rq[i].xdp_prog, priv->_xdp_prog);

	return 0;
err_reg_mem:
	xdp_rxq_info_unreg(&priv->rq[i].xdp_rxq);
err_rxq_reg:
	for (i--; i >= 0; i--) {
		struct veth_rq *rq = &priv->rq[i];

		xdp_rxq_info_unreg(&rq->xdp_rxq);
		netif_napi_del(&rq->xdp_napi);
	}

	return err;
}

//禁止掉veth上的xdp功能
static void veth_disable_xdp(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < dev->real_num_rx_queues; i++)
		rcu_assign_pointer(priv->rq[i].xdp_prog, NULL);
	veth_napi_del(dev);
	for (i = 0; i < dev->real_num_rx_queues; i++) {
		struct veth_rq *rq = &priv->rq[i];

		rq->xdp_rxq.mem = rq->xdp_mem;
		xdp_rxq_info_unreg(&rq->xdp_rxq);
	}
}

static int veth_open(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);
	int err;

	if (!peer)
		return -ENOTCONN;

	/*veth有xdp_pro,开启xdp*/
	if (priv->_xdp_prog) {
		err = veth_enable_xdp(dev);
		if (err)
			return err;
	}

	if (peer->flags & IFF_UP) {
		netif_carrier_on(dev);
		netif_carrier_on(peer);
	}

	return 0;
}

static int veth_close(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	netif_carrier_off(dev);
	if (peer)
		netif_carrier_off(peer);

	if (priv->_xdp_prog)
		veth_disable_xdp(dev);

	return 0;
}

static int is_valid_veth_mtu(int mtu)
{
	return mtu >= ETH_MIN_MTU && mtu <= ETH_MAX_MTU;
}

/*为veth申请rx队列*/
static int veth_alloc_queues(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	int i;

	/*申请num_rx_queues个队列*/
	priv->rq = kcalloc(dev->num_rx_queues, sizeof(*priv->rq), GFP_KERNEL);
	if (!priv->rq)
		return -ENOMEM;

	for (i = 0; i < dev->num_rx_queues; i++) {
		priv->rq[i].dev = dev;
		u64_stats_init(&priv->rq[i].stats.syncp);
	}

	return 0;
}

static void veth_free_queues(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);

	kfree(priv->rq);
}

/*初始化rx队列，申请link统计*/
static int veth_dev_init(struct net_device *dev)
{
	int err;

	dev->lstats = netdev_alloc_pcpu_stats(struct pcpu_lstats);
	if (!dev->lstats)
		return -ENOMEM;

	err = veth_alloc_queues(dev);
	if (err) {
		free_percpu(dev->lstats);
		return err;
	}

	return 0;
}

static void veth_dev_free(struct net_device *dev)
{
	veth_free_queues(dev);
	free_percpu(dev->lstats);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void veth_poll_controller(struct net_device *dev)
{
	/* veth only receives frames when its peer sends one
	 * Since it has nothing to do with disabling irqs, we are guaranteed
	 * never to have pending data when we poll for it so
	 * there is nothing to do here.
	 *
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
}
#endif	/* CONFIG_NET_POLL_CONTROLLER */

static int veth_get_iflink(const struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer;
	int iflink;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	iflink = peer ? peer->ifindex : 0;
	rcu_read_unlock();

	return iflink;
}

static netdev_features_t veth_fix_features(struct net_device *dev,
					   netdev_features_t features)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer;

	peer = rtnl_dereference(priv->peer);
	if (peer) {
		struct veth_priv *peer_priv = netdev_priv(peer);

		if (peer_priv->_xdp_prog)
			features &= ~NETIF_F_GSO_SOFTWARE;
	}

	return features;
}

static void veth_set_rx_headroom(struct net_device *dev, int new_hr)
{
	struct veth_priv *peer_priv, *priv = netdev_priv(dev);
	struct net_device *peer;

	if (new_hr < 0)
		new_hr = 0;

	rcu_read_lock();
	peer = rcu_dereference(priv->peer);
	if (unlikely(!peer))
		goto out;

	peer_priv = netdev_priv(peer);
	priv->requested_headroom = new_hr;
	new_hr = max(priv->requested_headroom, peer_priv->requested_headroom);
	dev->needed_headroom = new_hr;
	peer->needed_headroom = new_hr;

out:
	rcu_read_unlock();
}

static int veth_xdp_set(struct net_device *dev, struct bpf_prog *prog,
			struct netlink_ext_ack *extack)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct bpf_prog *old_prog;/*之前设置的旧bpf程序*/
	struct net_device *peer;
	unsigned int max_mtu;
	int err;

	old_prog = priv->_xdp_prog;
	priv->_xdp_prog = prog;//设置当前需生效的bpf程序
	peer = rtnl_dereference(priv->peer);

	if (prog) {
		if (!peer) {
		    /*对端不存在，不能设置bpf程序，报错*/
			NL_SET_ERR_MSG_MOD(extack, "Cannot set XDP when peer is detached");
			err = -ENOTCONN;
			goto err;
		}

		max_mtu = PAGE_SIZE - VETH_XDP_HEADROOM -
			  peer->hard_header_len -
			  SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		if (peer->mtu > max_mtu) {
		    //对端mtu不得大于bpf程序支持的最大mtu
			NL_SET_ERR_MSG_MOD(extack, "Peer MTU is too large to set XDP");
			err = -ERANGE;
			goto err;
		}

		//两端生效队列数必须一致
		if (dev->real_num_rx_queues < peer->real_num_tx_queues) {
			NL_SET_ERR_MSG_MOD(extack, "XDP expects number of rx queues not less than peer tx queues");
			err = -ENOSPC;
			goto err;
		}

		if (dev->flags & IFF_UP) {
		    //设备接口已up,则使能XDP
			err = veth_enable_xdp(dev);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Setup for XDP failed");
				goto err;
			}
		}

		//首次设置，则关闭对端的gso功能，更新max_mtu
		if (!old_prog) {
			peer->hw_features &= ~NETIF_F_GSO_SOFTWARE;
			peer->max_mtu = max_mtu;
		}
	}

	if (old_prog) {
		if (!prog) {
		    /*原来有prog,现在没有了，需要禁用xdp程序*/
			if (dev->flags & IFF_UP)
				veth_disable_xdp(dev);

			//还原gso功能，更新max_mtu
			if (peer) {
				peer->hw_features |= NETIF_F_GSO_SOFTWARE;
				peer->max_mtu = ETH_MAX_MTU;
			}
		}
		bpf_prog_put(old_prog);
	}

	//如果首次，或者原来有现在被移除，则更新peer的功能（前面修改了）
	if ((!!old_prog ^ !!prog) && peer)
		netdev_update_features(peer);

	return 0;
err:
	priv->_xdp_prog = old_prog;

	return err;
}

//veth对xdp的处理
static int veth_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	switch (xdp->command) {
	case XDP_SETUP_PROG:
	    //设置xdp程序
		return veth_xdp_set(dev, xdp->prog, xdp->extack);
	default:
		return -EINVAL;
	}
}

static const struct net_device_ops veth_netdev_ops = {
	.ndo_init            = veth_dev_init,
	.ndo_open            = veth_open,
	.ndo_stop            = veth_close,
	//veth发送
	.ndo_start_xmit      = veth_xmit,
	.ndo_get_stats64     = veth_get_stats64,
	.ndo_set_rx_mode     = veth_set_multicast_list,
	.ndo_set_mac_address = eth_mac_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= veth_poll_controller,
#endif
	.ndo_get_iflink		= veth_get_iflink,
	.ndo_fix_features	= veth_fix_features,
	.ndo_features_check	= passthru_features_check,
	.ndo_set_rx_headroom	= veth_set_rx_headroom,
	.ndo_bpf		= veth_xdp,
	.ndo_xdp_xmit		= veth_ndo_xdp_xmit,
	.ndo_get_peer_dev	= veth_peer_dev,
};

#define VETH_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM | \
		       NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_HIGHDMA | \
		       NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL | \
		       NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX | \
		       NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_STAG_RX )

static void veth_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->priv_flags |= IFF_PHONY_HEADROOM;

	dev->netdev_ops = &veth_netdev_ops;
	dev->ethtool_ops = &veth_ethtool_ops;
	dev->features |= NETIF_F_LLTX;
	dev->features |= VETH_FEATURES;
	dev->vlan_features = dev->features &
			     ~(NETIF_F_HW_VLAN_CTAG_TX |
			       NETIF_F_HW_VLAN_STAG_TX |
			       NETIF_F_HW_VLAN_CTAG_RX |
			       NETIF_F_HW_VLAN_STAG_RX);
	dev->needs_free_netdev = true;
	dev->priv_destructor = veth_dev_free;
	dev->max_mtu = ETH_MAX_MTU;

	dev->hw_features = VETH_FEATURES;
	dev->hw_enc_features = VETH_FEATURES;
	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
}

/*
 * netlink interface
 */

static int veth_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
	    /*地址长度校验*/
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU]) {
	    /*mtu校验*/
		if (!is_valid_veth_mtu(nla_get_u32(tb[IFLA_MTU])))
			return -EINVAL;
	}
	return 0;
}

static struct rtnl_link_ops veth_link_ops;

/*veth接口新建*/
static int veth_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	int err;
	struct net_device *peer;
	struct veth_priv *priv;
	char ifname[IFNAMSIZ];
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp;
	unsigned char name_assign_type;
	struct ifinfomsg *ifmp;
	struct net *net;

	/*
	 * create and register peer first
	 */
	if (data != NULL && data[VETH_INFO_PEER] != NULL) {
	    /*解析对端*/
		struct nlattr *nla_peer;

		nla_peer = data[VETH_INFO_PEER];
		/*指向对端配置*/
		ifmp = nla_data(nla_peer);
		err = rtnl_nla_parse_ifla(peer_tb,
					  nla_data(nla_peer) + sizeof(struct ifinfomsg),
					  nla_len(nla_peer) - sizeof(struct ifinfomsg),
					  NULL);
		if (err < 0)
			return err;

		err = veth_validate(peer_tb, NULL, extack);
		if (err < 0)
			return err;

		tbp = peer_tb;
	} else {
		ifmp = NULL;
		tbp = tb;
	}

	if (ifmp && tbp[IFLA_IFNAME]) {
	    	/*获取对端接口名称*/
		nla_strscpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	} else {
	    /*使用动态的接口名称*/
		snprintf(ifname, IFNAMSIZ, DRV_NAME "%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	/*创建对端link*/
	peer = rtnl_create_link(net, ifname, name_assign_type,
				&veth_link_ops, tbp, extack);
	if (IS_ERR(peer)) {
		put_net(net);
		return PTR_ERR(peer);
	}

	/*为peer生成mac地址*/
	if (!ifmp || !tbp[IFLA_ADDRESS])
		eth_hw_addr_random(peer);

	/*设置peer的ifindex*/
	if (ifmp && (dev->ifindex != 0))
		peer->ifindex = ifmp->ifi_index;

	peer->gso_max_size = dev->gso_max_size;
	peer->gso_max_segs = dev->gso_max_segs;

	/*注册peer设备*/
	err = register_netdevice(peer);
	put_net(net);
	net = NULL;
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	/*按flags配置peer*/
	err = rtnl_configure_link(peer, ifmp);
	if (err < 0)
		goto err_configure_peer;

	/*
	 * register dev last
	 *
	 * note, that since we've registered new device the dev's name
	 * should be re-allocated
	 */

	/*为本端生成随机mac*/
	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	/*设置本端名称*/
	if (tb[IFLA_IFNAME])
		nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	/*注册本端设备*/
	err = register_netdevice(dev);
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);

	/*
	 * tie the deviced together
	 */

	/*对端互指*/
	priv = netdev_priv(dev);
	rcu_assign_pointer(priv->peer, peer);

	priv = netdev_priv(peer);
	rcu_assign_pointer(priv->peer, dev);

	return 0;

err_register_dev:
	/* nothing to do */
err_configure_peer:
	unregister_netdevice(peer);
	return err;

err_register_peer:
	free_netdev(peer);
	return err;
}

/*veth链路删除回调*/
static void veth_dellink(struct net_device *dev, struct list_head *head)
{
	struct veth_priv *priv;
	struct net_device *peer;

	priv = netdev_priv(dev);
	peer = rtnl_dereference(priv->peer);

	/* Note : dellink() is called from default_device_exit_batch(),
	 * before a rcu_synchronize() point. The devices are guaranteed
	 * not being freed before one RCU grace period.
	 */
	RCU_INIT_POINTER(priv->peer, NULL);
	unregister_netdevice_queue(dev, head);

	if (peer) {
		priv = netdev_priv(peer);
		RCU_INIT_POINTER(priv->peer, NULL);
		unregister_netdevice_queue(peer, head);
	}
}

static const struct nla_policy veth_policy[VETH_INFO_MAX + 1] = {
	[VETH_INFO_PEER]	= { .len = sizeof(struct ifinfomsg) },
};

/*获取设备所属的net namespace*/
static struct net *veth_get_link_net(const struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	return peer ? dev_net(peer) : dev_net(dev);
}

//veth link 操作集
static struct rtnl_link_ops veth_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct veth_priv),
	.setup		= veth_setup,
	.validate	= veth_validate,
	//新建veth link
	.newlink	= veth_newlink,
	//删除veth link
	.dellink	= veth_dellink,
	.policy		= veth_policy,
	.maxtype	= VETH_INFO_MAX,
	.get_link_net	= veth_get_link_net,
};

/*
 * init/fini
 */

static __init int veth_init(void)
{
	return rtnl_link_register(&veth_link_ops);
}

static __exit void veth_exit(void)
{
	rtnl_link_unregister(&veth_link_ops);
}

module_init(veth_init);
module_exit(veth_exit);

MODULE_DESCRIPTION("Virtual Ethernet Tunnel");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
