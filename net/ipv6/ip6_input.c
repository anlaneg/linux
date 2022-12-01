// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	IPv6 input
 *	Linux INET6 implementation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Ian P. Morris		<I.P.Morris@soton.ac.uk>
 *
 *	Based in linux/net/ipv4/ip_input.c
 */
/* Changes
 *
 *	Mitsuru KANDA @USAGI and
 *	YOSHIFUJI Hideaki @USAGI: Remove ipv6_parse_exthdrs().
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/icmpv6.h>
#include <linux/mroute6.h>
#include <linux/slab.h>
#include <linux/indirect_call_wrapper.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include <net/sock.h>
#include <net/snmp.h>
#include <net/udp.h>

#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/rawv6.h>
#include <net/ndisc.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/xfrm.h>
#include <net/inet_ecn.h>
#include <net/dst_metadata.h>

INDIRECT_CALLABLE_DECLARE(void tcp_v6_early_demux(struct sk_buff *));
static void ip6_rcv_finish_core(struct net *net, struct sock *sk,
				struct sk_buff *skb)
{
	void (*edemux)(struct sk_buff *skb);

	/*通过est socket反向确定sbk->dst,尝试跳过ip6_route_input*/
	if (net->ipv4.sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) {
		const struct inet6_protocol *ipprot;

		ipprot = rcu_dereference(inet6_protos[ipv6_hdr(skb)->nexthdr]);
		if (ipprot && (edemux = READ_ONCE(ipprot->early_demux)))
			INDIRECT_CALL_2(edemux, tcp_v6_early_demux,
					udp_v6_early_demux, skb);
	}

	/*执行ipv6路由查询*/
	if (!skb_valid_dst(skb))
		ip6_route_input(skb);
}

int ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip6_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;
	ip6_rcv_finish_core(net, sk, skb);

	/*按路由进行input投递*/
	return dst_input(skb);
}

static void ip6_sublist_rcv_finish(struct list_head *head)
{
	struct sk_buff *skb, *next;

	list_for_each_entry_safe(skb, next, head, list) {
		skb_list_del_init(skb);
		dst_input(skb);
	}
}

static bool ip6_can_use_hint(const struct sk_buff *skb,
			     const struct sk_buff *hint)
{
	return hint && !skb_dst(skb) &&
	       ipv6_addr_equal(&ipv6_hdr(hint)->daddr, &ipv6_hdr(skb)->daddr);
}

static struct sk_buff *ip6_extract_route_hint(const struct net *net,
					      struct sk_buff *skb)
{
	if (fib6_routes_require_src(net) || fib6_has_custom_rules(net))
		return NULL;

	return skb;
}

static void ip6_list_rcv_finish(struct net *net, struct sock *sk,
				struct list_head *head)
{
	struct sk_buff *skb, *next, *hint = NULL;
	struct dst_entry *curr_dst = NULL;
	struct list_head sublist;

	INIT_LIST_HEAD(&sublist);
	list_for_each_entry_safe(skb, next, head, list) {
		struct dst_entry *dst;

		skb_list_del_init(skb);
		/* if ingress device is enslaved to an L3 master device pass the
		 * skb to its handler for processing
		 */
		skb = l3mdev_ip6_rcv(skb);
		if (!skb)
			continue;

		if (ip6_can_use_hint(skb, hint))
			skb_dst_copy(skb, hint);
		else
			ip6_rcv_finish_core(net, sk, skb);
		dst = skb_dst(skb);
		if (curr_dst != dst) {
			hint = ip6_extract_route_hint(net, skb);

			/* dispatch old sublist */
			if (!list_empty(&sublist))
				ip6_sublist_rcv_finish(&sublist);
			/* start new sublist */
			INIT_LIST_HEAD(&sublist);
			curr_dst = dst;
		}
		list_add_tail(&skb->list, &sublist);
	}
	/* dispatch final sublist */
	ip6_sublist_rcv_finish(&sublist);
}

//ipv6报文收取
static struct sk_buff *ip6_rcv_core(struct sk_buff *skb, struct net_device *dev,
				    struct net *net)
{
	const struct ipv6hdr *hdr;
	u32 pkt_len;
	struct inet6_dev *idev;

	//丢掉二层送其它主机的报文
	if (skb->pkt_type == PACKET_OTHERHOST) {
		kfree_skb(skb);
		return NULL;
	}

	rcu_read_lock();

	//取此net_device对应的inet6_dev
	idev = __in6_dev_get(skb->dev);

	//ipv6 in报文计数
	__IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_IN, skb->len);

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL ||
	    !idev/*设备无inet6_dev，丢包*/ || unlikely(idev->cnf.disable_ipv6)) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	//清空控制块
	memset(IP6CB(skb), 0, sizeof(struct inet6_skb_parm));

	/*
	 * Store incoming device index. When the packet will
	 * be queued, we cannot refer to skb->dev anymore.
	 *
	 * BTW, when we send a packet for our own local address on a
	 * non-loopback interface (e.g. ethX), it is being delivered
	 * via the loopback interface (lo) here; skb->dev = loopback_dev.
	 * It, however, should be considered as if it is being
	 * arrived via the sending interface (ethX), because of the
	 * nature of scoping architecture. --yoshfuji
	 */
	IP6CB(skb)->iif = skb_valid_dst(skb) ? ip6_dst_idev(skb_dst(skb))->dev->ifindex : dev->ifindex;

	//skb必须有完整的ipv6hdr
	if (unlikely(!pskb_may_pull(skb, sizeof(*hdr))))
		goto err;

	hdr = ipv6_hdr(skb);

	//版本必须为6
	if (hdr->version != 6)
		goto err;

	/*按ecn标记进行计数统计0，1，2，3*/
	__IP6_ADD_STATS(net, idev,
			IPSTATS_MIB_NOECTPKTS +
				(ipv6_get_dsfield(hdr) & INET_ECN_MASK),
			max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));
	/*
	 * RFC4291 2.5.3
	 * The loopback address must not be used as the source address in IPv6
	 * packets that are sent outside of a single node. [..]
	 * A packet received on an interface with a destination address
	 * of loopback must be dropped.
	 */
	if ((ipv6_addr_loopback(&hdr->saddr) ||
	     ipv6_addr_loopback(&hdr->daddr)) &&
	    !(dev->flags & IFF_LOOPBACK) &&
	    !netif_is_l3_master(dev))
	    /*在非loopback口上收到loopback地址，丢包*/
		goto err;

	/* RFC4291 Errata ID: 3480
	 * Interface-Local scope spans only a single interface on a
	 * node and is useful only for loopback transmission of
	 * multicast.  Packets with interface-local scope received
	 * from another node must be discarded.
	 */
	if (!(skb->pkt_type == PACKET_LOOPBACK ||
	      dev->flags & IFF_LOOPBACK) &&
	    ipv6_addr_is_multicast(&hdr->daddr) &&
	    IPV6_ADDR_MC_SCOPE(&hdr->daddr) == 1)
		goto err;

	/* If enabled, drop unicast packets that were encapsulated in link-layer
	 * multicast or broadcast to protected against the so-called "hole-196"
	 * attack in 802.11 wireless.
	 */
	if (!ipv6_addr_is_multicast(&hdr->daddr) &&
	    (skb->pkt_type == PACKET_BROADCAST ||
	     skb->pkt_type == PACKET_MULTICAST) &&
	    idev->cnf.drop_unicast_in_l2_multicast)
	    /*mac层是组播，但目的ip不是组播，丢包*/
		goto err;

	/* RFC4291 2.7
	 * Nodes must not originate a packet to a multicast address whose scope
	 * field contains the reserved value 0; if such a packet is received, it
	 * must be silently dropped.
	 */
	if (ipv6_addr_is_multicast(&hdr->daddr) &&
	    IPV6_ADDR_MC_SCOPE(&hdr->daddr) == 0)
		goto err;

	/*
	 * RFC4291 2.7
	 * Multicast addresses must not be used as source addresses in IPv6
	 * packets or appear in any Routing header.
	 */
	if (ipv6_addr_is_multicast(&hdr->saddr))
	    //源地址不得为组播地址
		goto err;

	/*更新l4层头offset*/
	skb->transport_header = skb->network_header + sizeof(*hdr);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	/*ipv6层payload长度*/
	pkt_len = ntohs(hdr->payload_len);

	/* pkt_len may be zero if Jumbo payload option is present */
	if (pkt_len || hdr->nexthdr != NEXTHDR_HOP) {
		if (pkt_len + sizeof(struct ipv6hdr) > skb->len) {
		    /*指定的payload len大于buffer len，丢弃*/
			__IP6_INC_STATS(net,
					idev, IPSTATS_MIB_INTRUNCATEDPKTS);
			goto drop;
		}

		/*packet_len与buffer_len相比，当buffer len更大时，将被截短*/
		if (pskb_trim_rcsum(skb, pkt_len + sizeof(struct ipv6hdr))) {
		    /*不能截短，则丢包*/
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			goto drop;
		}
		hdr = ipv6_hdr(skb);
	}

	/*刚才没有处理nexthdr_hop情况，这里处理,解析ipv6选项*/
	if (hdr->nexthdr == NEXTHDR_HOP) {
		if (ipv6_parse_hopopts(skb) < 0) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			rcu_read_unlock();
			return NULL;
		}
	}

	rcu_read_unlock();

	/* Must drop socket now because of tproxy. */
	if (!skb_sk_is_prefetched(skb))
		skb_orphan(skb);

	return skb;
err:
	__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return NULL;
}

//实现ipv6报文收取
int ipv6_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct net *net = dev_net(skb->dev);

	skb = ip6_rcv_core(skb, dev, net);
	if (skb == NULL)
		return NET_RX_DROP;
	//走pre routing钩子点
	return NF_HOOK(NFPROTO_IPV6, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip6_rcv_finish);
}

static void ip6_sublist_rcv(struct list_head *head, struct net_device *dev,
			    struct net *net)
{
	NF_HOOK_LIST(NFPROTO_IPV6, NF_INET_PRE_ROUTING, net, NULL,
		     head, dev, NULL, ip6_rcv_finish);
	ip6_list_rcv_finish(net, NULL, head);
}

/* Receive a list of IPv6 packets */
void ipv6_list_rcv(struct list_head *head, struct packet_type *pt,
		   struct net_device *orig_dev)
{
	struct net_device *curr_dev = NULL;
	struct net *curr_net = NULL;
	struct sk_buff *skb, *next;
	struct list_head sublist;

	INIT_LIST_HEAD(&sublist);
	list_for_each_entry_safe(skb, next, head, list) {
		struct net_device *dev = skb->dev;
		struct net *net = dev_net(dev);

		skb_list_del_init(skb);
		skb = ip6_rcv_core(skb, dev, net);
		if (skb == NULL)
			continue;

		if (curr_dev != dev || curr_net != net) {
			/* dispatch old sublist */
			if (!list_empty(&sublist))
				ip6_sublist_rcv(&sublist, curr_dev, curr_net);
			/* start new sublist */
			INIT_LIST_HEAD(&sublist);
			curr_dev = dev;
			curr_net = net;
		}
		list_add_tail(&skb->list, &sublist);
	}
	/* dispatch final sublist */
	if (!list_empty(&sublist))
		ip6_sublist_rcv(&sublist, curr_dev, curr_net);
}

INDIRECT_CALLABLE_DECLARE(int tcp_v6_rcv(struct sk_buff *));

/*
 *	Deliver the packet to the host
 */
void ip6_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int nexthdr,
			      bool have_final)
{
	const struct inet6_protocol *ipprot;
	struct inet6_dev *idev;
	unsigned int nhoff;
	bool raw;

	/*
	 *	Parse extension headers
	 */

resubmit:
	idev = ip6_dst_idev(skb_dst(skb));
	/*取next_header字段对应的偏移量*/
	nhoff = IP6CB(skb)->nhoff;
	if (!have_final) {
		if (!pskb_pull(skb, skb_transport_offset(skb)))
			goto discard;
		/*取下一层的nexthdr*/
		nexthdr = skb_network_header(skb)[nhoff];
	}

resubmit_final:
    /*通过nexthdr查是否有对应的raw socket*/
	raw = raw6_local_deliver(skb, nexthdr);
	/*通过nexthdr取4层协议对应的ipprot对象*/
	ipprot = rcu_dereference(inet6_protos[nexthdr]);
	if (ipprot) {
		int ret;

		if (have_final) {
			if (!(ipprot->flags & INET6_PROTO_FINAL)) {
				/* Once we've seen a final protocol don't
				 * allow encapsulation on any non-final
				 * ones. This allows foo in UDP encapsulation
				 * to work.
				 */
				goto discard;
			}
		} else if (ipprot->flags & INET6_PROTO_FINAL) {
		    /*ipprot有final标记*/
			const struct ipv6hdr *hdr;
			int sdif = inet6_sdif(skb);
			struct net_device *dev;

			/* Only do this once for first final protocol */
			have_final = true;

			/* Free reference early: we don't need it any more,
			   and it may hold ip_conntrack module loaded
			   indefinitely. */
			nf_reset_ct(skb);

			skb_postpull_rcsum(skb, skb_network_header(skb),
					   skb_network_header_len(skb));
			hdr = ipv6_hdr(skb);

			/* skb->dev passed may be master dev for vrfs. */
			if (sdif) {
				dev = dev_get_by_index_rcu(net, sdif);
				if (!dev)
					goto discard;
			} else {
				dev = skb->dev;
			}

			/*目的地址是组播地址时，如果校验组播组及组播源是确认为不接收，且不是mld报文，则丢包*/
			if (ipv6_addr_is_multicast(&hdr->daddr) &&
			    !ipv6_chk_mcast_addr(dev, &hdr->daddr,
						 &hdr->saddr) &&
			    !ipv6_is_mld(skb, nexthdr, skb_network_header_len(skb)))
				goto discard;
		}

		/*如果未注明no policy标记，则执行xfrm6的policy检查*/
		if (!(ipprot->flags & INET6_PROTO_NOPOLICY) &&
		    !xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto discard;

		//由l4协议处理报文，例如送udp/tcp协议
		ret = INDIRECT_CALL_2(ipprot->handler, tcp_v6_rcv, udpv6_rcv,
				      skb);
		if (ret > 0) {
		    /*返回值大于0，表示本次已处理，没有消耗报文，重查下一层*/
			if (ipprot->flags & INET6_PROTO_FINAL) {
				/* Not an extension header, most likely UDP
				 * encapsulation. Use return value as nexthdr
				 * protocol not nhoff (which presumably is
				 * not set by handler).
				 */
				nexthdr = ret;
				goto resubmit_final;/*返回值，指定了nexthdr,执行l4协议查询*/
			} else {
			    /*未达到final,执行重查，例如分片重组*/
				goto resubmit;
			}
		} else if (ret == 0) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDELIVERS);
		}
	} else {
	    /*没有找到此协议对应的报文，丢弃*/
		if (!raw) {
			if (xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				__IP6_INC_STATS(net, idev,
						IPSTATS_MIB_INUNKNOWNPROTOS);
				icmpv6_send(skb, ICMPV6_PARAMPROB,
					    ICMPV6_UNK_NEXTHDR, nhoff);
			}
			kfree_skb(skb);
		} else {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDELIVERS);
			consume_skb(skb);
		}
	}
	return;

discard:
	__IP6_INC_STATS(net, idev, IPSTATS_MIB_INDISCARDS);
	kfree_skb(skb);
}

static int ip6_input_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_clear_delivery_time(skb);
	rcu_read_lock();
	/*local in报文投递*/
	ip6_protocol_deliver_rcu(net, skb, 0, false);
	rcu_read_unlock();

	return 0;
}

/*路由确定此ipv6报文送主机，此函数走local_in钩子点*/
int ip6_input(struct sk_buff *skb)
{
    /*ipv6走local in流程*/
	return NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_IN,
		       dev_net(skb->dev), NULL, skb, skb->dev, NULL,
		       ip6_input_finish);
}
EXPORT_SYMBOL_GPL(ip6_input);

/*ipv6 组播输入*/
int ip6_mc_input(struct sk_buff *skb)
{
	int sdif = inet6_sdif(skb);
	const struct ipv6hdr *hdr;
	struct net_device *dev;
	bool deliver;

	__IP6_UPD_PO_STATS(dev_net(skb_dst(skb)->dev),
			 __in6_dev_get_safely(skb->dev), IPSTATS_MIB_INMCAST,
			 skb->len);

	/* skb->dev passed may be master dev for vrfs. */
	if (sdif) {
		rcu_read_lock();
		dev = dev_get_by_index_rcu(dev_net(skb->dev), sdif);
		if (!dev) {
			rcu_read_unlock();
			kfree_skb(skb);
			return -ENODEV;
		}
	} else {
		dev = skb->dev;
	}

	hdr = ipv6_hdr(skb);
	deliver = ipv6_chk_mcast_addr(dev, &hdr->daddr, NULL);
	if (sdif)
		rcu_read_unlock();

#ifdef CONFIG_IPV6_MROUTE
	/*
	 *      IPv6 multicast router mode is now supported ;)
	 */
	if (atomic_read(&dev_net(skb->dev)->ipv6.devconf_all->mc_forwarding) &&
	    !(ipv6_addr_type(&hdr->daddr) &
	      (IPV6_ADDR_LOOPBACK|IPV6_ADDR_LINKLOCAL)) &&
	    likely(!(IP6CB(skb)->flags & IP6SKB_FORWARDED))) {
		/*
		 * Okay, we try to forward - split and duplicate
		 * packets.
		 */
		struct sk_buff *skb2;
		struct inet6_skb_parm *opt = IP6CB(skb);

		/* Check for MLD */
		if (unlikely(opt->flags & IP6SKB_ROUTERALERT)) {
			/* Check if this is a mld message */
			u8 nexthdr = hdr->nexthdr;
			__be16 frag_off;
			int offset;

			/* Check if the value of Router Alert
			 * is for MLD (0x0000).
			 */
			if (opt->ra == htons(IPV6_OPT_ROUTERALERT_MLD)) {
				deliver = false;

				if (!ipv6_ext_hdr(nexthdr)) {
					/* BUG */
					goto out;
				}
				offset = ipv6_skip_exthdr(skb, sizeof(*hdr),
							  &nexthdr, &frag_off);
				if (offset < 0)
					goto out;

				if (ipv6_is_mld(skb, nexthdr, offset))
					deliver = true;

				goto out;
			}
			/* unknown RA - process it normally */
		}

		if (deliver)
			skb2 = skb_clone(skb, GFP_ATOMIC);
		else {
			skb2 = skb;
			skb = NULL;
		}

		if (skb2) {
			ip6_mr_input(skb2);
		}
	}
out:
#endif
	if (likely(deliver))
		ip6_input(skb);
	else {
		/* discard */
		kfree_skb(skb);
	}

	return 0;
}
