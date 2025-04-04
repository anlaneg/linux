// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015 Pablo Neira Ayuso <pablo@netfilter.org>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_offload.h>
#include <net/netfilter/nf_dup_netdev.h>

#define NF_RECURSION_LIMIT	2

static DEFINE_PER_CPU(u8, nf_dup_skb_recursion);

//将skb自dev口发出
static void nf_do_netdev_egress(struct sk_buff *skb, struct net_device *dev,
				enum nf_dev_hooks hook)
{
	if (__this_cpu_read(nf_dup_skb_recursion) > NF_RECURSION_LIMIT)
		goto err;

	if (hook == NF_NETDEV_INGRESS && skb_mac_header_was_set(skb)) {
		if (skb_cow_head(skb, skb->mac_len))
			goto err;

		skb_push(skb, skb->mac_len);
	}

	skb->dev = dev;
	skb_clear_tstamp(skb);
	__this_cpu_inc(nf_dup_skb_recursion);
	dev_queue_xmit(skb);
	__this_cpu_dec(nf_dup_skb_recursion);
	return;
err:
	kfree_skb(skb);
}

//将报文自oif口发出
void nf_fwd_netdev_egress(const struct nft_pktinfo *pkt, int oif)
{
	struct net_device *dev;

	//取oif对应的dev
	dev = dev_get_by_index_rcu(nft_net(pkt), oif);
	if (!dev) {
		kfree_skb(pkt->skb);
		return;
	}

	nf_do_netdev_egress(pkt->skb, dev, nft_hook(pkt));
}
EXPORT_SYMBOL_GPL(nf_fwd_netdev_egress);

//制作一份副本，自oif口扔出
void nf_dup_netdev_egress(const struct nft_pktinfo *pkt, int oif)
{
	struct net_device *dev;
	struct sk_buff *skb;

	//找出oif对应的net_device
	dev = dev_get_by_index_rcu(nft_net(pkt), oif);
	if (dev == NULL)
		return;

	//复制一份报文，将其自dev口扔出
	skb = skb_clone(pkt->skb, GFP_ATOMIC);
	if (skb)
		nf_do_netdev_egress(skb, dev, nft_hook(pkt));
}
EXPORT_SYMBOL_GPL(nf_dup_netdev_egress);

int nft_fwd_dup_netdev_offload(struct nft_offload_ctx *ctx,
			       struct nft_flow_rule *flow,
			       enum flow_action_id id, int oif)
{
	struct flow_action_entry *entry;
	struct net_device *dev;

	/* nft_flow_rule_destroy() releases the reference on this device. */
	dev = dev_get_by_index(ctx->net, oif);
	if (!dev)
		return -EOPNOTSUPP;

	entry = &flow->rule->action.entries[ctx->num_actions++];
	entry->id = id;
	entry->dev = dev;

	return 0;
}
EXPORT_SYMBOL_GPL(nft_fwd_dup_netdev_offload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pablo Neira Ayuso <pablo@netfilter.org>");
MODULE_DESCRIPTION("Netfilter packet duplication support");
