// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
#include <net/netfilter/nf_queue.h>
#endif
#include <linux/neighbour.h>
#include <net/arp.h>
#include <net/dsa.h>
#include <linux/export.h>
#include <linux/rculist.h>
#include "br_private.h"
#include "br_private_tunnel.h"

static int
br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	br_drop_fake_rtable(skb);
	return netif_receive_skb(skb);
}

//二层转三层处理
static int br_pass_frame_up(struct sk_buff *skb)
{
	struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(brdev);
	struct net_bridge_vlan_group *vg;

	dev_sw_netstats_rx_add(brdev, skb->len);

	vg = br_vlan_group_rcu(br);

	/* Reset the offload_fwd_mark because there could be a stacked
	 * bridge above, and it should not think this bridge it doing
	 * that bridge's work forwarding out its ports.
	 */
	br_switchdev_frame_unmark(skb);

	/* Bridge is just like any other port.  Make sure the
	 * packet is allowed except in promisc mode when someone
	 * may be running packet capture.
	 */
	if (!(brdev->flags & IFF_PROMISC) &&
	    !br_allowed_egress(vg, skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	indev = skb->dev;
	//更新入接口为桥上连口，准备送三层
	skb->dev = brdev;
	skb = br_handle_vlan(br, NULL, vg, skb);
	if (!skb)
		return NET_RX_DROP;
	/* update the multicast stats if the packet is IGMP/MLD */
	br_multicast_count(br, NULL, skb, br_multicast_igmp_type(skb),
			   BR_MCAST_DIR_TX);

	//送本机处理
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
		       dev_net(indev), NULL, skb, indev, NULL,
		       br_netif_receive_skb);
}

/* note: already called with rcu_read_lock */
//pre routing钩子点执行完成后，此函数将被执行
int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	enum br_pkt_type pkt_type = BR_PKT_UNICAST;
	struct net_bridge_fdb_entry *dst = NULL;
	struct net_bridge_mcast_port *pmctx;
	struct net_bridge_mdb_entry *mdst;
	bool local_rcv, mcast_hit = false;
	struct net_bridge_mcast *brmctx;
	struct net_bridge_vlan *vlan;
	struct net_bridge *br;
	u16 vid = 0;
	u8 state;

	//接口处于disable状态，丢包
	if (!p)
		goto drop;

	br = p->br;

	if (br_mst_is_enabled(br)) {
		state = BR_STATE_FORWARDING;
	} else {
		if (p->state == BR_STATE_DISABLED)
			goto drop;

		state = p->state;
	}

	brmctx = &p->br->multicast_ctx;
	pmctx = &p->multicast_ctx;
	if (!br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid/*出参，取vlan*/,
				&state, &vlan))
		goto out;

	if (p->flags & BR_PORT_LOCKED) {
	    /*利用smac,查询fdb表*/
		struct net_bridge_fdb_entry *fdb_src =
			br_fdb_find_rcu(br, eth_hdr(skb)->h_source, vid);

		if (!fdb_src) {
			/* FDB miss. Create locked FDB entry if MAB is enabled
			 * and drop the packet.
			 */
			if (p->flags & BR_PORT_MAB)
				br_fdb_update(br, p, eth_hdr(skb)->h_source,
					      vid, BIT(BR_FDB_LOCKED));
		    	/*没有查询到fdb表项，表项有local标记，表项的dst与入接口不相等，丢包*/
			goto drop;
		} else if (READ_ONCE(fdb_src->dst) != p ||
			   test_bit(BR_FDB_LOCAL, &fdb_src->flags)) {
			/* FDB mismatch. Drop the packet without roaming. */
			goto drop;
		} else if (test_bit(BR_FDB_LOCKED, &fdb_src->flags)) {
			/* FDB match, but entry is locked. Refresh it and drop
			 * the packet.
			 */
			br_fdb_update(br, p, eth_hdr(skb)->h_source, vid,
				      BIT(BR_FDB_LOCKED));
			goto drop;
		}
	}

	nbp_switchdev_frame_mark(p, skb);

	/* insert into forwarding database after filtering to avoid spoofing */
	if (p->flags & BR_LEARNING)
		//fdb学习
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, 0);

	/*此设备是否开启混杂*/
	local_rcv = !!(br->dev->flags & IFF_PROMISC);
	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest)) {
		//广播报文，组播报文标记处理
		/* by definition the broadcast is also a multicast address */
		if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)) {
			pkt_type = BR_PKT_BROADCAST;
			local_rcv = true;
		} else {
			pkt_type = BR_PKT_MULTICAST;
			//igmp snooping表项学习，pim snooping,mld表项学习
			//如果非ipv4的igmp,非ipv6的mld协议，则会返回0，而不合法igmp,mld会在此丢包
			if (br_multicast_rcv(&brmctx, &pmctx, vlan, skb, vid))
				goto drop;
		}
	}

	if (state == BR_STATE_LEARNING)
	    //当前不转发报文，但学习fdb
		goto drop;

	BR_INPUT_SKB_CB(skb)->brdev = br->dev;
	BR_INPUT_SKB_CB(skb)->src_port_isolated = !!(p->flags & BR_ISOLATED);

	if (IS_ENABLED(CONFIG_INET) &&
	    (skb->protocol == htons(ETH_P_ARP) ||
	     skb->protocol == htons(ETH_P_RARP))) {
		//arp抑制处理
		br_do_proxy_suppress_arp(skb, br, vid, p);
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   skb->protocol == htons(ETH_P_IPV6) &&
		   br_opt_get(br, BROPT_NEIGH_SUPPRESS_ENABLED) &&
		   pskb_may_pull(skb, sizeof(struct ipv6hdr) +
				 sizeof(struct nd_msg)) &&
		   ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {

		    //ipv6 nd抑制处理
			struct nd_msg *msg, _msg;
			msg = br_is_nd_neigh_msg(skb, &_msg);
			if (msg)
				br_do_suppress_nd(skb, br, vid, p, msg);
	}

	switch (pkt_type) {
	case BR_PKT_MULTICAST:
		//组播表查询,执行组播转发
		mdst = br_mdb_get(brmctx, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(brmctx, eth_hdr(skb), mdst)) {
			if ((mdst && mdst->host_joined) ||
			    br_multicast_is_router(brmctx, skb)) {
				local_rcv = true;
				br->dev->stats.multicast++;
			}
			mcast_hit = true;//组播命中
		} else {
			local_rcv = true;
			br->dev->stats.multicast++;
		}
		break;
	case BR_PKT_UNICAST:
		//给定vlan,目的mac查fdb表
		dst = br_fdb_find_rcu(br, eth_hdr(skb)->h_dest, vid);
		break;
	default:
		break;
	}

	if (dst) {
		unsigned long now = jiffies;

		if (test_bit(BR_FDB_LOCAL, &dst->flags))
			//dst为local口，送三层处理
			return br_pass_frame_up(skb);

		//fdb时间刷新
		if (now != dst->used)
			dst->used = now;
		//执行单播报文转发
		br_forward(dst->dst, skb, local_rcv, false);
	} else {
		//未查询到出接口且非组播报文，执行flood
		if (!mcast_hit)
			br_flood(br, skb, pkt_type, local_rcv, false);
		else
			//组播命中，按mdst中对应的一组出接口进行flood
			br_multicast_flood(mdst, skb, brmctx, local_rcv, false);
	}

	if (local_rcv)
	    /*送local*/
		return br_pass_frame_up(skb);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}
EXPORT_SYMBOL_GPL(br_handle_frame_finish);

//bridge执行local报文处理
static void __br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	u16 vid = 0;

	/* check if vlan is allowed, to avoid spoofing */
	if ((p->flags & BR_LEARNING) &&
	    nbp_state_should_learn(p) &&
	    !br_opt_get(p->br, BROPT_NO_LL_LEARN) &&
	    br_should_learn(p, skb, &vid))
		//执行fdb更新
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source, vid, 0);
}

/* note: already called with rcu_read_lock */
static int br_handle_local_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	__br_handle_local_finish(skb);

	/* return 1 to signal the okfn() was called so it's ok to use the skb */
	return 1;
}

static int nf_hook_bridge_pre(struct sk_buff *skb, struct sk_buff **pskb)
{
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
	struct nf_hook_entries *e = NULL;
	struct nf_hook_state state;
	unsigned int verdict, i;
	struct net *net;
	int ret;

	net = dev_net(skb->dev);
#ifdef HAVE_JUMP_LABEL
	if (!static_key_false(&nf_hooks_needed[NFPROTO_BRIDGE][NF_BR_PRE_ROUTING]))
		goto frame_finish;
#endif

	//解发bridge的PRE_ROUTING钩子
	e = rcu_dereference(net->nf.hooks_bridge[NF_BR_PRE_ROUTING]);
	if (!e)
		goto frame_finish;

	/*1.1 初始化state*/
	nf_hook_state_init(&state, NF_BR_PRE_ROUTING,
			   NFPROTO_BRIDGE, skb->dev, NULL, NULL,
			   net, br_handle_frame_finish);

	/*1.2 逐个触发hook*/
	for (i = 0; i < e->num_hook_entries; i++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[i], skb, &state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			if (BR_INPUT_SKB_CB(skb)->br_netfilter_broute) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			break;
		case NF_DROP:
		    /*丢包处理*/
			kfree_skb(skb);
			return RX_HANDLER_CONSUMED;
		case NF_QUEUE:
		    /*入队处理*/
			ret = nf_queue(skb, &state, i, verdict);
			if (ret == 1)
				continue;
			return RX_HANDLER_CONSUMED;
		default: /* STOLEN */
			return RX_HANDLER_CONSUMED;
		}
	}
frame_finish:
    /*执行转发*/
	net = dev_net(skb->dev);
	br_handle_frame_finish(net, NULL, skb);
#else
	br_handle_frame_finish(dev_net(skb->dev), NULL, skb);
#endif
	return RX_HANDLER_CONSUMED;
}

/* Return 0 if the frame was not processed otherwise 1
 * note: already called with rcu_read_lock
 */
static int br_process_frame_type(struct net_bridge_port *p,
				 struct sk_buff *skb)
{
	struct br_frame_type *tmp;

	/*如果协议匹配，则此协议交由tmp对应的frame_handler进行处理，桥不再处理*/
	hlist_for_each_entry_rcu(tmp, &p->br->frame_type_list, list)
		if (unlikely(tmp->type == skb->protocol))
			return tmp->frame_handler(p, skb);

	return 0;
}

/*
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock
 */
//桥接口收到报文时此接口将被调用（此接口被置为bridge的rx_handler回调）
static rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;//指向目的mac

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;//桥放通此报文，使之不被桥可见

	//进行源mac校验，srcmac必须为单播mac,且全0mac是无效的
	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;//clone失败，报文已释放

	memset(skb->cb, 0, sizeof(struct br_input_skb_cb));

	p = br_port_get_rcu(skb->dev);
	if (p->flags & BR_VLAN_TUNNEL)
	    /*实现与tunnel到vlan的映射*/
		br_handle_ingress_vlan_tunnel(skb, p, nbp_vlan_group_rcu(p));

	//如果是local链路以太地址（二层协议），则处理
	if (unlikely(is_link_local_ether_addr(dest))) {
		u16 fwd_mask = p->br->group_fwd_mask_required;

		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		fwd_mask |= p->group_fwd_mask;
		switch (dest[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP ||
			    fwd_mask & (1u << dest[5]))
				goto forward;//转发此报文
			*pskb = skb;
			//将报文送给local执行fdb更新，并发通stp协议报文
			__br_handle_local_finish(skb);
			return RX_HANDLER_PASS;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		case 0x0E:	/* 802.1AB LLDP */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
			*pskb = skb;
			//放通lldp协议报文
			__br_handle_local_finish(skb);
			return RX_HANDLER_PASS;

		default:
			/* Allow selective forwarding for most other protocols */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
		}

		/* The else clause should be hit when nf_hook():
		 *   - returns < 0 (drop/error)
		 *   - returns = 0 (stolen/nf_queue)
		 * Thus return 1 from the okfn() to signal the skb is ok to pass
		 */
		//bridge的local in hook点触发
		//二层link local报文进来,设备直接处理
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
			    dev_net(skb->dev), NULL, skb, skb->dev, NULL,
			    br_handle_local_finish) == 1) {
			return RX_HANDLER_PASS;
		} else {
			return RX_HANDLER_CONSUMED;
		}
	}

	/*检查此skb是否为预定的需特别处理的帧类型*/
	if (unlikely(br_process_frame_type(p, skb)))
		return RX_HANDLER_PASS;

forward:
	if (br_mst_is_enabled(p->br))
		goto defer_stp_filtering;

	switch (p->state) {
	//按端口状态，处理流量
	case BR_STATE_FORWARDING:
	case BR_STATE_LEARNING:
defer_stp_filtering:
		if (ether_addr_equal(p->br->dev->dev_addr, dest))
		    //目的地址与br上连口mac一致，送3层
			skb->pkt_type = PACKET_HOST;

		//触发bridge路由前hook点
		return nf_hook_bridge_pre(skb, pskb);
	default:
		//端口处于其它状态，丢包
drop:
		kfree_skb(skb);
	}
	return RX_HANDLER_CONSUMED;
}

/* This function has no purpose other than to appease the br_port_get_rcu/rtnl
 * helpers which identify bridged ports according to the rx_handler installed
 * on them (so there _needs_ to be a bridge rx_handler even if we don't need it
 * to do anything useful). This bridge won't support traffic to/from the stack,
 * but only hardware bridging. So return RX_HANDLER_PASS so we don't steal
 * frames from the ETH_P_XDSA packet_type handler.
 */
static rx_handler_result_t br_handle_frame_dummy(struct sk_buff **pskb)
{
	return RX_HANDLER_PASS;
}

rx_handler_func_t *br_get_rx_handler(const struct net_device *dev)
{
	if (netdev_uses_dsa(dev))
		return br_handle_frame_dummy;

	return br_handle_frame;
}

/*注册br要收取的不同type的帧*/
void br_add_frame(struct net_bridge *br, struct br_frame_type *ft)
{
	hlist_add_head_rcu(&ft->list, &br->frame_type_list);
}

/*移除br要收取的帧类型*/
void br_del_frame(struct net_bridge *br, struct br_frame_type *ft)
{
	struct br_frame_type *tmp;

	hlist_for_each_entry(tmp, &br->frame_type_list, list)
		if (ft == tmp) {
			hlist_del_rcu(&ft->list);
			return;
		}
}
