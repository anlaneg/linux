// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_fifo.c	The simplest FIFO queue.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

/* 1 band FIFO pseudo-"scheduler" */

static int bfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free)
{
	if (likely(sch->qstats.backlog + qdisc_pkt_len(skb) <= sch->limit))
		return qdisc_enqueue_tail(skb, sch);

	return qdisc_drop(skb, sch, to_free);
}

//packet 方式的fifo入队
static int pfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free)
{
	if (likely(sch->q.qlen < sch->limit))
		return qdisc_enqueue_tail(skb, sch);

	//存入队列中的报文长度超限时，报文将被丢弃
	return qdisc_drop(skb, sch, to_free);
}

//packet方式的fifo，将报文入队列结尾
static int pfifo_tail_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			      struct sk_buff **to_free)
{
	unsigned int prev_backlog;

	if (likely(sch->q.qlen < sch->limit))
	    //直接存入
		return qdisc_enqueue_tail(skb, sch);

	//报文不可存放，自sch队首出一个报文，并将skb加入到sch队列的结尾
	prev_backlog = sch->qstats.backlog;
	/* queue full, remove one skb to fulfill the limit */
	__qdisc_queue_drop_head(sch, &sch->q, to_free);
	qdisc_qstats_drop(sch);
	qdisc_enqueue_tail(skb, sch);

	qdisc_tree_reduce_backlog(sch, 0, prev_backlog - sch->qstats.backlog);
	return NET_XMIT_CN;
}

static void fifo_offload_init(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct tc_fifo_qopt_offload qopt;

	if (!tc_can_offload(dev) || !dev->netdev_ops->ndo_setup_tc)
		return;

	qopt.command = TC_FIFO_REPLACE;
	qopt.handle = sch->handle;
	qopt.parent = sch->parent;
	dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_QDISC_FIFO, &qopt);
}

static void fifo_offload_destroy(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct tc_fifo_qopt_offload qopt;

	if (!tc_can_offload(dev) || !dev->netdev_ops->ndo_setup_tc)
		return;

	qopt.command = TC_FIFO_DESTROY;
	qopt.handle = sch->handle;
	qopt.parent = sch->parent;
	dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_QDISC_FIFO, &qopt);
}

static int fifo_offload_dump(struct Qdisc *sch)
{
	struct tc_fifo_qopt_offload qopt;

	qopt.command = TC_FIFO_STATS;
	qopt.handle = sch->handle;
	qopt.parent = sch->parent;
	qopt.stats.bstats = &sch->bstats;
	qopt.stats.qstats = &sch->qstats;

	return qdisc_offload_dump_helper(sch, TC_SETUP_QDISC_FIFO, &qopt);
}

//fifo队列初始化(fifo)
static int __fifo_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	bool bypass;
	bool is_bfifo = sch->ops == &bfifo_qdisc_ops;

	if (opt == NULL) {
	    /*未指定opt,默认使用tx队列长度为limit*/
		u32 limit = qdisc_dev(sch)->tx_queue_len;

		if (is_bfifo)
		    /*以字节方式计算时，乘以（mtu+硬件头长度）*/
			limit *= psched_mtu(qdisc_dev(sch));

		sch->limit = limit;
	} else {
	    /*使用指定的limit*/
		struct tc_fifo_qopt *ctl = nla_data(opt);

		if (nla_len(opt) < sizeof(*ctl))
			return -EINVAL;

		sch->limit = ctl->limit;
	}

	//limit大于 1时，定为bypass
	if (is_bfifo)
		bypass = sch->limit >= psched_mtu(qdisc_dev(sch));
	else
		bypass = sch->limit >= 1;

	if (bypass)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;

	return 0;
}

static int fifo_init(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	int err;

	err = __fifo_init(sch, opt, extack);
	if (err)
		return err;

	fifo_offload_init(sch);
	return 0;
}

static int fifo_hd_init(struct Qdisc *sch, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	return __fifo_init(sch, opt, extack);
}

static void fifo_destroy(struct Qdisc *sch)
{
	fifo_offload_destroy(sch);
}

//返回当前队列对应的limit配置
static int __fifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tc_fifo_qopt opt = { .limit = sch->limit };

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	return -1;
}

static int fifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	int err;

	err = fifo_offload_dump(sch);
	if (err)
		return err;

	return __fifo_dump(sch, skb);
}

static int fifo_hd_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return __fifo_dump(sch, skb);
}

//按packet方式先进先出（超限后丢入队元素）
struct Qdisc_ops pfifo_qdisc_ops __read_mostly = {
	.id		=	"pfifo",
	.priv_size	=	0,
	.enqueue	=	pfifo_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.init		=	fifo_init,
	.destroy	=	fifo_destroy,
	.reset		=	qdisc_reset_queue,
	.change		=	fifo_init,
	.dump		=	fifo_dump,
	.owner		=	THIS_MODULE,
};
EXPORT_SYMBOL(pfifo_qdisc_ops);

//按byte计算先进先出（超限后丢入队元素）
struct Qdisc_ops bfifo_qdisc_ops __read_mostly = {
	.id		=	"bfifo",
	.priv_size	=	0,
	.enqueue	=	bfifo_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.init		=	fifo_init,
	.destroy	=	fifo_destroy,
	.reset		=	qdisc_reset_queue,
	.change		=	fifo_init,
	.dump		=	fifo_dump,
	.owner		=	THIS_MODULE,
};
EXPORT_SYMBOL(bfifo_qdisc_ops);


//按packet方式先进先出，超限后丢弃队首元素
struct Qdisc_ops pfifo_head_drop_qdisc_ops __read_mostly = {
	.id		=	"pfifo_head_drop",
	.priv_size	=	0,
	//先进先出入队
	.enqueue	=	pfifo_tail_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.init		=	fifo_hd_init,
	.reset		=	qdisc_reset_queue,
	//执行fifo配置变更
	.change		=	fifo_hd_init,
	.dump		=	fifo_hd_dump,
	.owner		=	THIS_MODULE,
};

/* Pass size change message down to embedded FIFO */
int fifo_set_limit(struct Qdisc *q, unsigned int limit)
{
	struct nlattr *nla;
	int ret = -ENOMEM;

	/* Hack to avoid sending change message to non-FIFO */
	//确保为[pb]fifo*类型的队列
	if (strncmp(q->ops->id + 1, "fifo", 4) != 0)
		return 0;

	if (!q->ops->change)
		return 0;

	//构造limit对应的netlink消息，进行limit变更
	nla = kmalloc(nla_attr_size(sizeof(struct tc_fifo_qopt)), GFP_KERNEL);
	if (nla) {
		nla->nla_type = RTM_NEWQDISC;
		nla->nla_len = nla_attr_size(sizeof(struct tc_fifo_qopt));
		((struct tc_fifo_qopt *)nla_data(nla))->limit = limit;

		ret = q->ops->change(q, nla, NULL);
		kfree(nla);
	}
	return ret;
}
EXPORT_SYMBOL(fifo_set_limit);

//创建fifo队列，并配置limit
struct Qdisc *fifo_create_dflt(struct Qdisc *sch, struct Qdisc_ops *ops,
			       unsigned int limit,
			       struct netlink_ext_ack *extack)
{
	struct Qdisc *q;
	int err = -ENOMEM;

	q = qdisc_create_dflt(sch->dev_queue, ops, TC_H_MAKE(sch->handle, 1),
			      extack);
	if (q) {
	    //为队列配置limit
		err = fifo_set_limit(q, limit);
		if (err < 0) {
			qdisc_put(q);
			q = NULL;
		}
	}

	return q ? : ERR_PTR(err);
}
EXPORT_SYMBOL(fifo_create_dflt);
