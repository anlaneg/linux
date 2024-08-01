// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2014 Mahesh Bandewar <maheshb@google.com>
 */

#include "ipvlan.h"

static u32 ipvlan_jhash_secret __read_mostly;

void ipvlan_init_secret(void)
{
	/*生成一个混淆hashcode*/
	net_get_random_once(&ipvlan_jhash_secret, sizeof(ipvlan_jhash_secret));
}

void ipvlan_count_rx(const struct ipvl_dev *ipvlan,
			    unsigned int len, bool success, bool mcast)
{
	if (likely(success)) {
		struct ipvl_pcpu_stats *pcptr;

		pcptr = this_cpu_ptr(ipvlan->pcpu_stats);
		u64_stats_update_begin(&pcptr->syncp);
		u64_stats_inc(&pcptr->rx_pkts);
		u64_stats_add(&pcptr->rx_bytes, len);
		if (mcast)
			u64_stats_inc(&pcptr->rx_mcast);
		u64_stats_update_end(&pcptr->syncp);
	} else {
		this_cpu_inc(ipvlan->pcpu_stats->rx_errs);
	}
}
EXPORT_SYMBOL_GPL(ipvlan_count_rx);

#if IS_ENABLED(CONFIG_IPV6)
static u8 ipvlan_get_v6_hash(const void *iaddr)
{
	const struct in6_addr *ip6_addr = iaddr;

	return __ipv6_addr_jhash(ip6_addr, ipvlan_jhash_secret) &
	       IPVLAN_HASH_MASK;
}
#else
static u8 ipvlan_get_v6_hash(const void *iaddr)
{
	return 0;
}
#endif

static u8 ipvlan_get_v4_hash(const void *iaddr)
{
	const struct in_addr *ip4_addr = iaddr;

	return jhash_1word(ip4_addr->s_addr, ipvlan_jhash_secret) &
	       IPVLAN_HASH_MASK;
}

/*检查ip地址是否相等*/
static bool addr_equal(bool is_v6, struct ipvl_addr *addr, const void *iaddr)
{
	if (!is_v6 && addr->atype == IPVL_IPV4) {
		struct in_addr *i4addr = (struct in_addr *)iaddr;

		return addr->ip4addr.s_addr == i4addr->s_addr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (is_v6 && addr->atype == IPVL_IPV6) {
		struct in6_addr *i6addr = (struct in6_addr *)iaddr;

		return ipv6_addr_equal(&addr->ip6addr, i6addr);
#endif
	}

	return false;
}

static struct ipvl_addr *ipvlan_ht_addr_lookup(const struct ipvl_port *port,
					       const void *iaddr, bool is_v6)
{
	struct ipvl_addr *addr;
	u8 hash;

	/*取hash*/
	hash = is_v6 ? ipvlan_get_v6_hash(iaddr) :
	       ipvlan_get_v4_hash(iaddr);
	/*在list上遍历，查找是否有对应的ipvl_addr*/
	hlist_for_each_entry_rcu(addr, &port->hlhead[hash], hlnode)
		if (addr_equal(is_v6, addr, iaddr))
			return addr;
	return NULL;
}

/*为此ipvlan增加ipvl_addr（加入后可处理报文）*/
void ipvlan_ht_addr_add(struct ipvl_dev *ipvlan, struct ipvl_addr *addr)
{
	struct ipvl_port *port = ipvlan->port;
	u8 hash;

	hash = (addr->atype == IPVL_IPV6) ?
	       ipvlan_get_v6_hash(&addr->ip6addr) :
	       ipvlan_get_v4_hash(&addr->ip4addr);
	if (hlist_unhashed(&addr->hlnode))
		hlist_add_head_rcu(&addr->hlnode, &port->hlhead[hash]);
}

/*移除ipvlan上的ipvl_addr*/
void ipvlan_ht_addr_del(struct ipvl_addr *addr)
{
	hlist_del_init_rcu(&addr->hlnode);
}

/*检查ipvlan上是否有包含此addr*/
struct ipvl_addr *ipvlan_find_addr(const struct ipvl_dev *ipvlan,
				   const void *iaddr, bool is_v6)
{
	struct ipvl_addr *addr, *ret = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(addr, &ipvlan->addrs, anode) {
		if (addr_equal(is_v6, addr, iaddr)) {
			ret = addr;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

bool ipvlan_addr_busy(struct ipvl_port *port, void *iaddr, bool is_v6)
{
	struct ipvl_dev *ipvlan;
	bool ret = false;

	rcu_read_lock();
	list_for_each_entry_rcu(ipvlan, &port->ipvlans, pnode) {
		if (ipvlan_find_addr(ipvlan, iaddr, is_v6)) {
			ret = true;/*标记地址已存在*/
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

//分析报文找出三层协议头，并返回，例如：arp头，ip头（用type返回对应的协议）
void *ipvlan_get_L3_hdr(struct ipvl_port *port, struct sk_buff *skb, int *type/*协议类型*/)
{
	void *lyr3h = NULL;

	switch (skb->protocol) {
	case htons(ETH_P_ARP): {
		/*arp协议，取arp header*/
		struct arphdr *arph;

		if (unlikely(!pskb_may_pull(skb, arp_hdr_len(port->dev))))
			return NULL;

		arph = arp_hdr(skb);
		*type = IPVL_ARP;
		lyr3h = arph;
		break;
	}
	case htons(ETH_P_IP): {
		u32 pktlen;
		struct iphdr *ip4h;

		if (unlikely(!pskb_may_pull(skb, sizeof(*ip4h))))
			return NULL;

		ip4h = ip_hdr(skb);
		pktlen = skb_ip_totlen(skb);
		if (ip4h->ihl < 5 || ip4h->version != 4)
			return NULL;
		if (skb->len < pktlen || pktlen < (ip4h->ihl * 4))
			return NULL;

		*type = IPVL_IPV4;
		lyr3h = ip4h;
		break;
	}
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6): {
		struct ipv6hdr *ip6h;

		if (unlikely(!pskb_may_pull(skb, sizeof(*ip6h))))
			return NULL;

		ip6h = ipv6_hdr(skb);
		if (ip6h->version != 6)
			return NULL;

		*type = IPVL_IPV6;
		lyr3h = ip6h;
		/* Only Neighbour Solicitation pkts need different treatment */
		if (ipv6_addr_any(&ip6h->saddr) &&
		    ip6h->nexthdr == NEXTHDR_ICMP) {
			struct icmp6hdr	*icmph;

			if (unlikely(!pskb_may_pull(skb, sizeof(*ip6h) + sizeof(*icmph))))
				return NULL;

			ip6h = ipv6_hdr(skb);
			icmph = (struct icmp6hdr *)(ip6h + 1);

			if (icmph->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION) {
				/* Need to access the ipv6 address in body */
				if (unlikely(!pskb_may_pull(skb, sizeof(*ip6h) + sizeof(*icmph)
						+ sizeof(struct in6_addr))))
					return NULL;

				ip6h = ipv6_hdr(skb);
				icmph = (struct icmp6hdr *)(ip6h + 1);
			}

			*type = IPVL_ICMPV6;
			lyr3h = icmph;
		}
		break;
	}
#endif
	default:
		return NULL;
	}

	return lyr3h;
}

unsigned int ipvlan_mac_hash(const unsigned char *addr)
{
	u32 hash = jhash_1word(__get_unaligned_cpu32(addr+2),
			       ipvlan_jhash_secret);

	return hash & IPVLAN_MAC_FILTER_MASK;
}

/*ipvlan的二层组播广播报文处理*/
void ipvlan_process_multicast(struct work_struct *work)
{
	struct ipvl_port *port = container_of(work, struct ipvl_port, wq);
	struct ethhdr *ethh;
	struct ipvl_dev *ipvlan;
	struct sk_buff *skb, *nskb;
	struct sk_buff_head list;
	unsigned int len;
	unsigned int mac_hash;
	int ret;
	u8 pkt_type;
	bool tx_pkt;

	__skb_queue_head_init(&list);

	spin_lock_bh(&port->backlog.lock);
	/*取backlog下所有skb*/
	skb_queue_splice_tail_init(&port->backlog, &list);
	spin_unlock_bh(&port->backlog.lock);

	/*对list上所有报文进行遍历*/
	while ((skb = __skb_dequeue(&list)) != NULL) {
		struct net_device *dev = skb->dev;
		bool consumed = false;

		ethh = eth_hdr(skb);
		tx_pkt = IPVL_SKB_CB(skb)->tx_pkt;
		mac_hash = ipvlan_mac_hash(ethh->h_dest);

		/*匹配为广播地址或者组播地址*/
		if (ether_addr_equal(ethh->h_dest, port->dev->broadcast))
			pkt_type = PACKET_BROADCAST;
		else
			pkt_type = PACKET_MULTICAST;

		rcu_read_lock();
		list_for_each_entry_rcu(ipvlan, &port->ipvlans, pnode) {
			if (tx_pkt && (ipvlan->dev == skb->dev))
				/*tx方向报文，且报文源方向即为此设备，跳过*/
				continue;
			if (!test_bit(mac_hash, ipvlan->mac_filters))
				/*此设备不关注此组播，跳过*/
				continue;
			if (!(ipvlan->dev->flags & IFF_UP))
				/*设备没有up,跳过*/
				continue;
			ret = NET_RX_DROP;
			len = skb->len + ETH_HLEN;
			/*复制一份，准备投递*/
			nskb = skb_clone(skb, GFP_ATOMIC);
			local_bh_disable();
			if (nskb) {
				consumed = true;
				nskb->pkt_type = pkt_type;
				nskb->dev = ipvlan->dev;/*设置投递目的设备*/
				if (tx_pkt)
					/*向投递目标设备forward一份*/
					ret = dev_forward_skb(ipvlan->dev, nskb);
				else
					/*报文报文，指明目的设备收到一份*/
					ret = netif_rx(nskb);
			}
			/*增加统计计数*/
			ipvlan_count_rx(ipvlan, len, ret == NET_RX_SUCCESS, true);
			local_bh_enable();
		}
		rcu_read_unlock();

		/*以上是向ipvlan的同级设备每人送了一份，这里向upper设备送一份（这次不用copy)*/
		if (tx_pkt) {
			/* If the packet originated here, send it out. */
			skb->dev = port->dev;
			skb->pkt_type = pkt_type;
			dev_queue_xmit(skb);
		} else {
			if (consumed)
				consume_skb(skb);
			else
				kfree_skb(skb);
		}
		dev_put(dev);
		cond_resched();
	}
}

static void ipvlan_skb_crossing_ns(struct sk_buff *skb, struct net_device *dev)
{
	bool xnet = true;

	if (dev)
		xnet = !net_eq(dev_net(skb->dev), dev_net(dev));

	skb_scrub_packet(skb, xnet);
	if (dev)
		skb->dev = dev;
}

/*ipvlan接收报文，报文送ipvlan接口（走rx流程）*/
static int ipvlan_rcv_frame(struct ipvl_addr *addr, struct sk_buff **pskb,
			    bool local)
{
	struct ipvl_dev *ipvlan = addr->master;
	struct net_device *dev = ipvlan->dev;
	unsigned int len;
	rx_handler_result_t ret = RX_HANDLER_CONSUMED;
	bool success = false;
	struct sk_buff *skb = *pskb;

	len = skb->len + ETH_HLEN;
	/* Only packets exchanged between two local slaves need to have
	 * device-up check as well as skb-share check.
	 */
	if (local) {
		if (unlikely(!(dev->flags & IFF_UP))) {
			kfree_skb(skb);
			goto out;
		}

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			goto out;

		*pskb = skb;
	}

	if (local) {
		skb->pkt_type = PACKET_HOST;
		if (dev_forward_skb(ipvlan->dev, skb) == NET_RX_SUCCESS)
			success = true;
	} else {
		skb->dev = dev;
		ret = RX_HANDLER_ANOTHER;
		success = true;
	}

out:
	ipvlan_count_rx(ipvlan, len, success, false);
	return ret;
}

//检查接口上是否存在与lyr3h指出的地址相同的地址
struct ipvl_addr *ipvlan_addr_lookup(struct ipvl_port *port, void *lyr3h/*三层协议头*/,
				     int addr_type/*三层协议类型*/, bool use_dest/*是否使用目的地址*/)
{
	struct ipvl_addr *addr = NULL;

	switch (addr_type) {
#if IS_ENABLED(CONFIG_IPV6)
	case IPVL_IPV6: {
		struct ipv6hdr *ip6h;
		struct in6_addr *i6addr;

		ip6h = (struct ipv6hdr *)lyr3h;
		i6addr = use_dest ? &ip6h->daddr : &ip6h->saddr;
		addr = ipvlan_ht_addr_lookup(port, i6addr, true);
		break;
	}
	case IPVL_ICMPV6: {
		struct nd_msg *ndmh;
		struct in6_addr *i6addr;

		/* Make sure that the NeighborSolicitation ICMPv6 packets
		 * are handled to avoid DAD issue.
		 */
		ndmh = (struct nd_msg *)lyr3h;
		if (ndmh->icmph.icmp6_type == NDISC_NEIGHBOUR_SOLICITATION) {
			i6addr = &ndmh->target;
			addr = ipvlan_ht_addr_lookup(port, i6addr, true);
		}
		break;
	}
#endif
	case IPVL_IPV4: {
		struct iphdr *ip4h;
		__be32 *i4addr;

		ip4h = (struct iphdr *)lyr3h;
		i4addr = use_dest ? &ip4h->daddr : &ip4h->saddr;
		//查找接口上是否有与此i4addr相同的ipv4地址,如果有则返回，如果无，返回NULL
		addr = ipvlan_ht_addr_lookup(port, i4addr, false);
		break;
	}
	case IPVL_ARP: {
		struct arphdr *arph;
		unsigned char *arp_ptr;
		__be32 dip;

		arph = (struct arphdr *)lyr3h;
		arp_ptr = (unsigned char *)(arph + 1);
		if (use_dest)
			arp_ptr += (2 * port->dev->addr_len) + 4;
		else
			arp_ptr += port->dev->addr_len;

		memcpy(&dip, arp_ptr, 4);
		addr = ipvlan_ht_addr_lookup(port, &dip, false);
		break;
	}
	}

	return addr;
}

static noinline_for_stack int ipvlan_process_v4_outbound(struct sk_buff *skb)
{
	const struct iphdr *ip4h = ip_hdr(skb);
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	struct rtable *rt;
	int err, ret = NET_XMIT_DROP;
	struct flowi4 fl4 = {
		.flowi4_oif = dev->ifindex,
		.flowi4_tos = RT_TOS(ip4h->tos),
		.flowi4_flags = FLOWI_FLAG_ANYSRC,
		.flowi4_mark = skb->mark,
		.daddr = ip4h->daddr,
		.saddr = ip4h->saddr,
	};

	rt = ip_route_output_flow(net, &fl4, NULL);
	if (IS_ERR(rt))
		goto err;

	//只支持本机，网关，直连三种方式
	if (rt->rt_type != RTN_UNICAST && rt->rt_type != RTN_LOCAL) {
		ip_rt_put(rt);
		goto err;
	}
	skb_dst_set(skb, &rt->dst);

	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

	//走local向外发包流程
	err = ip_local_out(net, skb->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		DEV_STATS_INC(dev, tx_errors);
	else
		ret = NET_XMIT_SUCCESS;
	goto out;
err:
	DEV_STATS_INC(dev, tx_errors);
	kfree_skb(skb);
out:
	return ret;
}

#if IS_ENABLED(CONFIG_IPV6)

static noinline_for_stack int
ipvlan_route_v6_outbound(struct net_device *dev, struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct flowi6 fl6 = {
		.flowi6_oif = dev->ifindex,
		.daddr = ip6h->daddr,
		.saddr = ip6h->saddr,
		.flowi6_flags = FLOWI_FLAG_ANYSRC,
		.flowlabel = ip6_flowinfo(ip6h),
		.flowi6_mark = skb->mark,
		.flowi6_proto = ip6h->nexthdr,
	};
	struct dst_entry *dst;
	int err;

	dst = ip6_route_output(dev_net(dev), NULL, &fl6);
	err = dst->error;
	if (err) {
		dst_release(dst);
		return err;
	}
	skb_dst_set(skb, dst);
	return 0;
}

static int ipvlan_process_v6_outbound(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	int err, ret = NET_XMIT_DROP;

	err = ipvlan_route_v6_outbound(dev, skb);
	if (unlikely(err)) {
		DEV_STATS_INC(dev, tx_errors);
		kfree_skb(skb);
		return err;
	}

	memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));

	err = ip6_local_out(dev_net(dev), skb->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		DEV_STATS_INC(dev, tx_errors);
	else
		ret = NET_XMIT_SUCCESS;
	return ret;
}
#else
static int ipvlan_process_v6_outbound(struct sk_buff *skb)
{
	return NET_XMIT_DROP;
}
#endif

static int ipvlan_process_outbound(struct sk_buff *skb)
{
	int ret = NET_XMIT_DROP;

	/* The ipvlan is a pseudo-L2 device, so the packets that we receive
	 * will have L2; which need to discarded and processed further
	 * in the net-ns of the main-device.
	 */
	if (skb_mac_header_was_set(skb)) {
		/* In this mode we dont care about
		 * multicast and broadcast traffic */
		struct ethhdr *ethh = eth_hdr(skb);

		if (is_multicast_ether_addr(ethh->h_dest)) {
			pr_debug_ratelimited(
				"Dropped {multi|broad}cast of type=[%x]\n",
				ntohs(skb->protocol));
			kfree_skb(skb);
			goto out;
		}

		skb_pull(skb, sizeof(*ethh));
		skb->mac_header = (typeof(skb->mac_header))~0U;
		skb_reset_network_header(skb);
	}

	if (skb->protocol == htons(ETH_P_IPV6))
		ret = ipvlan_process_v6_outbound(skb);
	else if (skb->protocol == htons(ETH_P_IP))
		//对外发送ipv4报文
		ret = ipvlan_process_v4_outbound(skb);
	else {
		pr_warn_ratelimited("Dropped outbound packet type=%x\n",
				    ntohs(skb->protocol));
		kfree_skb(skb);
	}
out:
	return ret;
}

static void ipvlan_multicast_enqueue(struct ipvl_port *port,
				     struct sk_buff *skb, bool tx_pkt/*标记这个报文是否为tx方向*/)
{
    //收到pause帧，丢弃此报文
	if (skb->protocol == htons(ETH_P_PAUSE)) {
		kfree_skb(skb);
		return;
	}

	/* Record that the deferred packet is from TX or RX path. By
	 * looking at mac-addresses on packet will lead to erronus decisions.
	 * (This would be true for a loopback-mode on master device or a
	 * hair-pin mode of the switch.)
	 */
	IPVL_SKB_CB(skb)->tx_pkt = tx_pkt;/*标识这个报文是tx方向*/

	spin_lock(&port->backlog.lock);
	if (skb_queue_len(&port->backlog) < IPVLAN_QBACKLOG_LIMIT) {
		dev_hold(skb->dev);
		/*容量未超限，报文添加进backlog*/
		__skb_queue_tail(&port->backlog, skb);
		spin_unlock(&port->backlog.lock);
		/*指示wq需要调度*/
		schedule_work(&port->wq);
	} else {
		spin_unlock(&port->backlog.lock);
		/*容量超限，报文需要丢弃，增加统计计数*/
		dev_core_stats_rx_dropped_inc(skb->dev);
		kfree_skb(skb);
	}
}

static int ipvlan_xmit_mode_l3(struct sk_buff *skb, struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	void *lyr3h;
	struct ipvl_addr *addr;
	int addr_type;

	//解析报文，返回协议头
	lyr3h = ipvlan_get_L3_hdr(ipvlan->port, skb, &addr_type);
	if (!lyr3h)
		goto out;

	if (!ipvlan_is_vepa(ipvlan->port)) {
		addr = ipvlan_addr_lookup(ipvlan->port, lyr3h, addr_type, true);
		if (addr) {
			if (ipvlan_is_private(ipvlan->port)) {
				consume_skb(skb);
				return NET_XMIT_DROP;
			}
			ipvlan_rcv_frame(addr, &skb, true);
			return NET_XMIT_SUCCESS;
		}
	}
out:
	//将报文归属于ipvlan->phy_dev
	ipvlan_skb_crossing_ns(skb, ipvlan->phy_dev);
	return ipvlan_process_outbound(skb);
}

//ipvlan 二层发包
static int ipvlan_xmit_mode_l2(struct sk_buff *skb, struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ethhdr *eth = skb_eth_hdr(skb);
	struct ipvl_addr *addr;
	void *lyr3h;
	int addr_type;

	if (!ipvlan_is_vepa(ipvlan->port) &&
	    ether_addr_equal(eth->h_dest, eth->h_source)) {
		lyr3h = ipvlan_get_L3_hdr(ipvlan->port, skb, &addr_type);
		if (lyr3h) {
			/*提取协议三层头*/
			addr = ipvlan_addr_lookup(ipvlan->port, lyr3h, addr_type, true);
			if (addr) {
				if (ipvlan_is_private(ipvlan->port)) {
					consume_skb(skb);
					return NET_XMIT_DROP;
				}
				/*报文的目的指向此物理口上当前或别一个ipvlan，走报文接收流程*/
				ipvlan_rcv_frame(addr, &skb, true);
				return NET_XMIT_SUCCESS;
			}
		}
		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			return NET_XMIT_DROP;

		/* Packet definitely does not belong to any of the
		 * virtual devices, but the dest is local. So forward
		 * the skb for the main-dev. At the RX side we just return
		 * RX_PASS for it to be processed further on the stack.
		 */
		dev_forward_skb(ipvlan->phy_dev, skb);
		return NET_XMIT_SUCCESS;

	} else if (is_multicast_ether_addr(eth->h_dest)) {
		/*遇到组播或广播报文，入队进行组播广播处理*/
		skb_reset_mac_header(skb);
		ipvlan_skb_crossing_ns(skb, NULL);
		ipvlan_multicast_enqueue(ipvlan->port, skb, true);
		return NET_XMIT_SUCCESS;
	}

	skb->dev = ipvlan->phy_dev;
	return dev_queue_xmit(skb);
}

int ipvlan_queue_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ipvl_port *port = ipvlan_port_get_rcu_bh(ipvlan->phy_dev);

	if (!port)
		goto out;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct ethhdr))))
		goto out;

	switch(port->mode) {
	case IPVLAN_MODE_L2:
		return ipvlan_xmit_mode_l2(skb, dev);
	case IPVLAN_MODE_L3:
#ifdef CONFIG_IPVLAN_L3S
	case IPVLAN_MODE_L3S:
#endif
		return ipvlan_xmit_mode_l3(skb, dev);
	}

	/* Should not reach here */
	WARN_ONCE(true, "%s called for mode = [%x]\n", __func__, port->mode);
out:
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

static bool ipvlan_external_frame(struct sk_buff *skb, struct ipvl_port *port)
{
	struct ethhdr *eth = eth_hdr(skb);
	struct ipvl_addr *addr;
	void *lyr3h;
	int addr_type;

	if (ether_addr_equal(eth->h_source, skb->dev->dev_addr)) {
		/*收到了一个组播报文，源MAc是自已的（可以是本设备上其它ipvlan发送出来的，送了我们一份）*/
		lyr3h = ipvlan_get_L3_hdr(port, skb, &addr_type);
		if (!lyr3h)
			return true;

		addr = ipvlan_addr_lookup(port, lyr3h, addr_type, false/*查源地址*/);
		if (addr)
			/*这个报文的源地址是我们，返回false*/
			return false;
	}

	return true;
}

static rx_handler_result_t ipvlan_handle_mode_l3(struct sk_buff **pskb,
						 struct ipvl_port *port)
{
	void *lyr3h;
	int addr_type;
	struct ipvl_addr *addr;
	struct sk_buff *skb = *pskb;
	rx_handler_result_t ret = RX_HANDLER_PASS;

	lyr3h = ipvlan_get_L3_hdr(port, skb, &addr_type);
	if (!lyr3h)
		goto out;

	addr = ipvlan_addr_lookup(port, lyr3h, addr_type, true/*查目的ip*/);
	if (addr)
		/*这个报文我们可以接收，收取报文*/
		ret = ipvlan_rcv_frame(addr, pskb, false);

out:
	return ret;
}

static rx_handler_result_t ipvlan_handle_mode_l2(struct sk_buff **pskb,
						 struct ipvl_port *port)
{
	struct sk_buff *skb = *pskb;
	struct ethhdr *eth = eth_hdr(skb);
	rx_handler_result_t ret = RX_HANDLER_PASS;

	if (is_multicast_ether_addr(eth->h_dest)) {
		/*遇到组播，广播报文,检查这个报文是否为外部过来的报文*/
		if (ipvlan_external_frame(skb, port)) {
			struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);

			/* External frames are queued for device local
			 * distribution, but a copy is given to master
			 * straight away to avoid sending duplicates later
			 * when work-queue processes this frame. This is
			 * achieved by returning RX_HANDLER_PASS.
			 */
			if (nskb) {
				/*复制一份入队（由wq复制给其它ipvlan接口）*/
				ipvlan_skb_crossing_ns(nskb, NULL);
				ipvlan_multicast_enqueue(port, nskb, false);
			}
		}
	} else {
		/* Perform like l3 mode for non-multicast packet */
		ret = ipvlan_handle_mode_l3(pskb, port);/*处理单播报文*/
	}

	return ret;
}

/*ipvlan报文处理入口*/
rx_handler_result_t ipvlan_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct ipvl_port *port = ipvlan_port_get_rcu(skb->dev);/*取此dev关联的ipvl_port*/

	if (!port)
		/*无ipvl_port，跳出*/
		return RX_HANDLER_PASS;

	switch (port->mode) {
	case IPVLAN_MODE_L2:
		/*如果是l2模式，看mac(处理广播，组播），单播按ip投递*/
		return ipvlan_handle_mode_l2(pskb, port);
	case IPVLAN_MODE_L3:
		/*如果是l3模式，只按ip投递，不看组播*/
		return ipvlan_handle_mode_l3(pskb, port);
#ifdef CONFIG_IPVLAN_L3S
	case IPVLAN_MODE_L3S:
		/*针对l3s设备，通过标记此回调，指明了回调，但直接放通（仅标识这是一个ipvlan port)*/
		return RX_HANDLER_PASS;
#endif
	}

	/* Should not reach here */
	WARN_ONCE(true, "%s called for mode = [%x]\n", __func__, port->mode);
	kfree_skb(skb);
	return RX_HANDLER_CONSUMED;
}
