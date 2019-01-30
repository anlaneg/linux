/* xfrm4_protocol.c - Generic xfrm protocol multiplexer.
 *
 * Copyright (C) 2013 secunet Security Networks AG
 *
 * Author:
 * Steffen Klassert <steffen.klassert@secunet.com>
 *
 * Based on:
 * net/ipv4/tunnel4.c
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/xfrm.h>

static struct xfrm4_protocol __rcu *esp4_handlers __read_mostly;
static struct xfrm4_protocol __rcu *ah4_handlers __read_mostly;
static struct xfrm4_protocol __rcu *ipcomp4_handlers __read_mostly;
static DEFINE_MUTEX(xfrm4_protocol_mutex);

//查询esp,ah,comp的报文处理链
static inline struct xfrm4_protocol __rcu **proto_handlers(u8 protocol)
{
	switch (protocol) {
	case IPPROTO_ESP:
		return &esp4_handlers;
	case IPPROTO_AH:
		return &ah4_handlers;
	case IPPROTO_COMP:
		return &ipcomp4_handlers;
	}

	return NULL;
}

#define for_each_protocol_rcu(head, handler)		\
	for (handler = rcu_dereference(head);		\
	     handler != NULL;				\
	     handler = rcu_dereference(handler->next))	\

//xfm4 协议收包回调
int xfrm4_rcv_cb(struct sk_buff *skb, u8 protocol, int err)
{
	int ret;
	struct xfrm4_protocol *handler;
	//找对应协议的cb链，并逐个执行
	struct xfrm4_protocol __rcu **head = proto_handlers(protocol);

	if (!head)
		return 0;

	for_each_protocol_rcu(*head, handler)
		if ((ret = handler->cb_handler(skb, err)) <= 0)
			return ret;

	return 0;
}
EXPORT_SYMBOL(xfrm4_rcv_cb);

int xfrm4_rcv_encap(struct sk_buff *skb, int nexthdr, __be32 spi,
		    int encap_type)
{
	int ret;
	struct xfrm4_protocol *handler;
	struct xfrm4_protocol __rcu **head = proto_handlers(nexthdr);

	XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4 = NULL;
	XFRM_SPI_SKB_CB(skb)->family = AF_INET;
	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct iphdr, daddr);

	if (!head)
		goto out;

	//遍历*head链表上的每个handler,执行input_handler回调
	for_each_protocol_rcu(*head, handler)
		if ((ret = handler->input_handler(skb, nexthdr, spi, encap_type)) != -EINVAL)
			return ret;

out:
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL(xfrm4_rcv_encap);

static int xfrm4_esp_rcv(struct sk_buff *skb)
{
	int ret;
	struct xfrm4_protocol *handler;

	XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4 = NULL;

	for_each_protocol_rcu(esp4_handlers, handler)
		if ((ret = handler->handler(skb)) != -EINVAL)
			return ret;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	kfree_skb(skb);
	return 0;
}

static int xfrm4_esp_err(struct sk_buff *skb, u32 info)
{
	struct xfrm4_protocol *handler;

	for_each_protocol_rcu(esp4_handlers, handler)
		if (!handler->err_handler(skb, info))
			return 0;

	return -ENOENT;
}

//kernel在ip_local_deliver_finish处检查发现ip->protocol为ah协议时，此函数将被调用
static int xfrm4_ah_rcv(struct sk_buff *skb)
{
	int ret;
	struct xfrm4_protocol *handler;

	XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4 = NULL;

	//遍历指定ah4 handler的handler函数，完成报文处理
	for_each_protocol_rcu(ah4_handlers, handler)
		if ((ret = handler->handler(skb)) != -EINVAL)
			return ret;

	//报文无效，发送目的不可达icmp报文
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	kfree_skb(skb);
	return 0;
}

static int xfrm4_ah_err(struct sk_buff *skb, u32 info)
{
	struct xfrm4_protocol *handler;

	for_each_protocol_rcu(ah4_handlers, handler)
		if (!handler->err_handler(skb, info))
			return 0;

	return -ENOENT;
}

static int xfrm4_ipcomp_rcv(struct sk_buff *skb)
{
	int ret;
	struct xfrm4_protocol *handler;

	XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4 = NULL;

	for_each_protocol_rcu(ipcomp4_handlers, handler)
		if ((ret = handler->handler(skb)) != -EINVAL)
			return ret;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	kfree_skb(skb);
	return 0;
}

static int xfrm4_ipcomp_err(struct sk_buff *skb, u32 info)
{
	struct xfrm4_protocol *handler;

	for_each_protocol_rcu(ipcomp4_handlers, handler)
		if (!handler->err_handler(skb, info))
			return 0;

	return -ENOENT;
}

static const struct net_protocol esp4_protocol = {
	.handler	=	xfrm4_esp_rcv,
	.err_handler	=	xfrm4_esp_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

//ah报文入口
static const struct net_protocol ah4_protocol = {
	.handler	=	xfrm4_ah_rcv,
	.err_handler	=	xfrm4_ah_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

static const struct net_protocol ipcomp4_protocol = {
	.handler	=	xfrm4_ipcomp_rcv,
	.err_handler	=	xfrm4_ipcomp_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

static const struct xfrm_input_afinfo xfrm4_input_afinfo = {
	.family		=	AF_INET,
	.callback	=	xfrm4_rcv_cb,//ipv4收取入
};

//依据不同的protocol返回，esp,ah,comp协议的协议栈入理入口
static inline const struct net_protocol *netproto(unsigned char protocol)
{
	switch (protocol) {
	case IPPROTO_ESP:
		return &esp4_protocol;
	case IPPROTO_AH:
		return &ah4_protocol;
	case IPPROTO_COMP:
		return &ipcomp4_protocol;
	}

	return NULL;
}

//按优先级将handler插入到合适的proto_handlers中
int xfrm4_protocol_register(struct xfrm4_protocol *handler,
			    unsigned char protocol)
{
	struct xfrm4_protocol __rcu **pprev;
	struct xfrm4_protocol *t;
	bool add_netproto = false;
	int ret = -EEXIST;
	int priority = handler->priority;

	//xfrm如果不支持此协议，返回失败
	if (!proto_handlers(protocol) || !netproto(protocol))
		return -EINVAL;

	mutex_lock(&xfrm4_protocol_mutex);

	//如果此协议未注册，则要求将报文rcv函数注册inet协议报文处理
	if (!rcu_dereference_protected(*proto_handlers(protocol),
				       lockdep_is_held(&xfrm4_protocol_mutex)))
		add_netproto = true;

	//注册handler
	for (pprev = proto_handlers(protocol);
	     (t = rcu_dereference_protected(*pprev,
			lockdep_is_held(&xfrm4_protocol_mutex))) != NULL;
	     pprev = &t->next) {
		if (t->priority < priority)
			break;
		if (t->priority == priority)
			goto err;
	}

	handler->next = *pprev;
	rcu_assign_pointer(*pprev, handler);

	ret = 0;

err:
	mutex_unlock(&xfrm4_protocol_mutex);

	//需要添加到协议栈，则注册到４层协议栈中
	if (add_netproto) {
		if (inet_add_protocol(netproto(protocol), protocol)) {
			pr_err("%s: can't add protocol\n", __func__);
			ret = -EAGAIN;
		}
	}

	return ret;
}
EXPORT_SYMBOL(xfrm4_protocol_register);

int xfrm4_protocol_deregister(struct xfrm4_protocol *handler,
			      unsigned char protocol)
{
	struct xfrm4_protocol __rcu **pprev;
	struct xfrm4_protocol *t;
	int ret = -ENOENT;

	if (!proto_handlers(protocol) || !netproto(protocol))
		return -EINVAL;

	mutex_lock(&xfrm4_protocol_mutex);

	for (pprev = proto_handlers(protocol);
	     (t = rcu_dereference_protected(*pprev,
			lockdep_is_held(&xfrm4_protocol_mutex))) != NULL;
	     pprev = &t->next) {
		if (t == handler) {
			*pprev = handler->next;
			ret = 0;
			break;
		}
	}

	if (!rcu_dereference_protected(*proto_handlers(protocol),
				       lockdep_is_held(&xfrm4_protocol_mutex))) {
		if (inet_del_protocol(netproto(protocol), protocol) < 0) {
			pr_err("%s: can't remove protocol\n", __func__);
			ret = -EAGAIN;
		}
	}

	mutex_unlock(&xfrm4_protocol_mutex);

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(xfrm4_protocol_deregister);

void __init xfrm4_protocol_init(void)
{
	xfrm_input_register_afinfo(&xfrm4_input_afinfo);
}
EXPORT_SYMBOL(xfrm4_protocol_init);
