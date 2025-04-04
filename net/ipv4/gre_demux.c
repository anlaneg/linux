// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	GRE over IPv4 demultiplexer driver
 *
 *	Authors: Dmitry Kozlov (xeb@mail.ru)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/if.h>
#include <linux/icmp.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_tunnel.h>
#include <linux/spinlock.h>
#include <net/protocol.h>
#include <net/gre.h>
#include <net/erspan.h>

#include <net/icmp.h>
#include <net/route.h>
#include <net/xfrm.h>

//注册不同gre协议处理函数
static const struct gre_protocol __rcu *gre_proto[GREPROTO_MAX] __read_mostly;

//注册指定版本的gre协议处理
int gre_add_protocol(const struct gre_protocol *proto, u8 version)
{
	if (version >= GREPROTO_MAX)
		return -EINVAL;

	return (cmpxchg((const struct gre_protocol **)&gre_proto[version], NULL, proto) == NULL) ?
		0 : -EBUSY;
}
EXPORT_SYMBOL_GPL(gre_add_protocol);

//删除指定版本的gre协议处理
int gre_del_protocol(const struct gre_protocol *proto, u8 version)
{
	int ret;

	if (version >= GREPROTO_MAX)
		return -EINVAL;

	ret = (cmpxchg((const struct gre_protocol **)&gre_proto[version], proto, NULL) == proto) ?
		0 : -EBUSY;

	if (ret)
		return ret;

	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL_GPL(gre_del_protocol);

/* Fills in tpi and returns header length to be pulled.
 * Note that caller must use pskb_may_pull() before pulling GRE header.
 */
int gre_parse_header(struct sk_buff *skb, struct tnl_ptk_info *tpi,
		     bool *csum_err, __be16 proto, int nhs)
{
	const struct gre_base_hdr *greh;
	__be32 *options;
	int hdr_len;

	if (unlikely(!pskb_may_pull(skb, nhs + sizeof(struct gre_base_hdr))))
		return -EINVAL;

	//取gre协议头（nhs到头部的偏移量）
	greh = (struct gre_base_hdr *)(skb->data + nhs);
	//如果版本不为０，或者含路由标记则无法解析
	if (unlikely(greh->flags & (GRE_VERSION | GRE_ROUTING)))
		return -EINVAL;

	//依据gre协议头的flags字段，决定gre头部的长度
	tpi->flags = gre_flags_to_tnl_flags(greh->flags);
	hdr_len = gre_calc_hlen(tpi->flags);

	//要求整个gre均在平坦内存中
	if (!pskb_may_pull(skb, nhs + hdr_len))
		return -EINVAL;

	//记录封装协议
	greh = (struct gre_base_hdr *)(skb->data + nhs);
	tpi->proto = greh->protocol;

	//指向选项
	options = (__be32 *)(greh + 1);
	if (greh->flags & GRE_CSUM) {
		//有checksum标记，校验gre checksum
		if (!skb_checksum_simple_validate(skb)) {
			skb_checksum_try_convert(skb, IPPROTO_GRE,
						 null_compute_pseudo);
		} else if (csum_err) {
			*csum_err = true;
			return -EINVAL;
		}

		options++;
	}

	//有key标记，提取key
	if (greh->flags & GRE_KEY) {
		tpi->key = *options;
		options++;
	} else {
		tpi->key = 0;
	}

	//有seq标记，提取seq
	if (unlikely(greh->flags & GRE_SEQ)) {
		tpi->seq = *options;
		options++;
	} else {
		tpi->seq = 0;
	}
	/* WCCP version 1 and 2 protocol decoding.
	 * - Change protocol to IPv4/IPv6
	 * - When dealing with WCCPv2, Skip extra 4 bytes in GRE header
	 */
	if (greh->flags == 0 && tpi->proto == htons(ETH_P_WCCP)) {
		u8 _val, *val;

		val = skb_header_pointer(skb, nhs + hdr_len,
					 sizeof(_val), &_val);
		if (!val)
			return -EINVAL;
		tpi->proto = proto;
		if ((*val & 0xF0) != 0x40)
			hdr_len += 4;
	}
	//指明头部长度
	tpi->hdr_len = hdr_len;

	/* ERSPAN ver 1 and 2 protocol sets GRE key field
	 * to 0 and sets the configured key in the
	 * inner erspan header field
	 */
	if ((greh->protocol == htons(ETH_P_ERSPAN) && hdr_len != 4) ||
	    greh->protocol == htons(ETH_P_ERSPAN2)) {
		struct erspan_base_hdr *ershdr;

		if (!pskb_may_pull(skb, nhs + hdr_len + sizeof(*ershdr)))
			return -EINVAL;

		ershdr = (struct erspan_base_hdr *)(skb->data + nhs + hdr_len);
		tpi->key = cpu_to_be32(get_session_id(ershdr));
	}

	return hdr_len;
}
EXPORT_SYMBOL(gre_parse_header);

//如果ip的上层协议为gre，则此函数将被调用，用于解析处理gre报文
//此函数会根据gre协议的版本号，调用对应版本的gre处理函数
static int gre_rcv(struct sk_buff *skb)
{
	const struct gre_protocol *proto;
	u8 ver;
	int ret;

	if (!pskb_may_pull(skb, 12))
		goto drop;

	//取gre协议版本号
	ver = skb->data[1]&0x7f;
	if (ver >= GREPROTO_MAX)
		goto drop;//遇到不支持的gre版本，丢包

	//取解析ver版本的gre处理函数
	rcu_read_lock();
	proto = rcu_dereference(gre_proto[ver]);//取对应版本的gre处理函数

	//没有此版本gre协议的处理函数，丢包
	if (!proto || !proto->handler)
		goto drop_unlock;

	//gre报文处理
	ret = proto->handler(skb);
	rcu_read_unlock();
	return ret;

drop_unlock:
	rcu_read_unlock();
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

//依据不同版本的gre，处理相应的gre_err
static int gre_err(struct sk_buff *skb, u32 info)
{
	const struct gre_protocol *proto;
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	u8 ver = skb->data[(iph->ihl<<2) + 1]&0x7f;
	int err = 0;

	if (ver >= GREPROTO_MAX)
		return -EINVAL;

	rcu_read_lock();
	proto = rcu_dereference(gre_proto[ver]);
	if (proto && proto->err_handler)
		proto->err_handler(skb, info);
	else
		err = -EPROTONOSUPPORT;
	rcu_read_unlock();

	return err;
}

//gre协议处理
static const struct net_protocol net_gre_protocol = {
	.handler     = gre_rcv,
	.err_handler = gre_err,
};

static int __init gre_init(void)
{
	pr_info("GRE over IPv4 demultiplexor driver\n");

	//为ip层注册gre协议的处理回调，收到gre协议报文后gre_rcv将被调用
	if (inet_add_protocol(&net_gre_protocol, IPPROTO_GRE) < 0) {
		pr_err("can't add protocol\n");
		return -EAGAIN;
	}
	return 0;
}

static void __exit gre_exit(void)
{
	inet_del_protocol(&net_gre_protocol, IPPROTO_GRE);
}

module_init(gre_init);
module_exit(gre_exit);

MODULE_DESCRIPTION("GRE over IPv4 demultiplexer driver");
MODULE_AUTHOR("D. Kozlov (xeb@mail.ru)");
MODULE_LICENSE("GPL");
