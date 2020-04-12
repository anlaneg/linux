// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_blackhole.c	Black hole queue
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 *
 * Note: Quantum tunneling is not supported.
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

//进入blackhole的所有报文将均被free
static int blackhole_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	qdisc_drop(skb, sch, to_free);
	return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
}

//自blackhole中不能出队任何报文
static struct sk_buff *blackhole_dequeue(struct Qdisc *sch)
{
	return NULL;
}

static struct Qdisc_ops blackhole_qdisc_ops __read_mostly = {
	.id		= "blackhole",
	.priv_size	= 0,
	.enqueue	= blackhole_enqueue,
	.dequeue	= blackhole_dequeue,
	.peek		= blackhole_dequeue,
	.owner		= THIS_MODULE,
};

static int __init blackhole_init(void)
{
	return register_qdisc(&blackhole_qdisc_ops);
}
device_initcall(blackhole_init)
