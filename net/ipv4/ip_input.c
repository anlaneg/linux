// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/indirect_call_wrapper.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <net/dst_metadata.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);

	for (ra = rcu_dereference(net->ipv4.ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex)) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(net, skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

INDIRECT_CALLABLE_DECLARE(int udp_rcv(struct sk_buff *));
INDIRECT_CALLABLE_DECLARE(int tcp_v4_rcv(struct sk_buff *));

//处理要送往本机的ip报文
void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
	const struct net_protocol *ipprot;
	int raw, ret;

resubmit:
	//检查是否需要给相关的raw socket传递此报文的副本
	raw = raw_local_deliver(skb, protocol);

	//按ip->protocol查找协议处理函数(例如：tcp_protocol，udp_protocol，igmp_protocol）
	ipprot = rcu_dereference(inet_protos[protocol]);
	if (ipprot) {
		if (!ipprot->no_policy) {
			//协议no_policy标记为0，执行xfrm4_policy_check，检查不通过，则丢包
			if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				kfree_skb_reason(skb,
						 SKB_DROP_REASON_XFRM_POLICY);
				return;
			}
			/*准备送协议栈，可能被缓存，清除ct引用*/
			nf_reset_ct(skb);
		}

		//协议报文处理(交给ip上层协议进行处理）
		ret = INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv,
				      skb);
		if (ret < 0) {
			//如果handle返回负数，则取abs后会得到新的protocol，并重新处理。
			protocol = -ret;
			goto resubmit;
		}
		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	} else {
		//协议栈上没有protocol对应的处理模块
		if (!raw) {
			if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
				//响应icmp协议不可达
				icmp_send(skb, ICMP_DEST_UNREACH,
					  ICMP_PROT_UNREACH, 0);
			}
			//释放报文
			kfree_skb_reason(skb, SKB_DROP_REASON_IP_NOPROTO);
		} else {
			//有raw socket收取此报文，上面已复制交付，这里释放原件
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
			consume_skb(skb);
		}
	}
}

static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_clear_delivery_time(skb);
	//使data跳过ip头部，指向传输层
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
//本地报文处理（送高层协议去处理）
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	//分片组装
	struct net *net = dev_net(skb->dev);

	if (ip_is_fragment(ip_hdr(skb))) {
		//分片报文，处理分片重组
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	//往本地协议栈钩子点（local_in)
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
EXPORT_SYMBOL(ip_local_deliver);

//ip层选项处理
static inline bool ip_rcv_options(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_options *opt;
	const struct iphdr *iph;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	//设置Ip层选项总长度，含补齐
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb, dev))
			goto drop;
	}

	return false;
drop:
	return true;
}

static bool ip_can_use_hint(const struct sk_buff *skb, const struct iphdr *iph,
			    const struct sk_buff *hint)
{
	return hint && !skb_dst(skb) && ip_hdr(hint)->daddr == iph->daddr &&
	       ip_hdr(hint)->tos == iph->tos;
}

int tcp_v4_early_demux(struct sk_buff *skb);
int udp_v4_early_demux(struct sk_buff *skb);
//准备进行路由处理
static int ip_rcv_finish_core(struct net *net, struct sock *sk,
			      struct sk_buff *skb, struct net_device *dev,
			      const struct sk_buff *hint)
{
	const struct iphdr *iph = ip_hdr(skb);
	int err, drop_reason;
	struct rtable *rt;

	drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

	if (ip_can_use_hint(skb, iph, hint)) {
		err = ip_route_use_hint(skb, iph->daddr, iph->saddr, iph->tos,
					dev, hint);
		if (unlikely(err))
			goto drop_error;
	}

	//默认情况下sysctl_ip_early_demux为１
	//执行上层协议的early_demux回调（udp,tcp主要是提前查询对应的socket)
	if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) &&
	    !skb_dst(skb) &&
	    !skb->sk &&
	    !ip_is_fragment(iph)) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux)) {
				tcp_v4_early_demux(skb);

				/* must reload iph, skb->head might have changed */
				iph = ip_hdr(skb);
			}
			break;
		case IPPROTO_UDP:
			if (READ_ONCE(net->ipv4.sysctl_udp_early_demux)) {
				err = udp_v4_early_demux(skb);
				if (unlikely(err))
					goto drop_error;

				/* must reload iph, skb->head might have changed */
				iph = ip_hdr(skb);
			}
			break;
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_valid_dst(skb)) {
		/*此分支情况下仅在skb没有dst下进入*/
		//传入目的地址，源地址，tos,报文入口设备,查询路由
		//单播时:skb->dst.input=ip_forword将被设置
		//组播时:skb->dst.input=ip_mr_input将被设置
		//路由未命中时：skb->dst.input=ip_error将被设置
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					   iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	} else {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev && IN_DEV_ORCONF(in_dev, NOPOLICY))
			IPCB(skb)->flags |= IPSKB_NOPOLICY;
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	//ip有选项，处理ip选项
	if (iph->ihl > 5 && ip_rcv_options(skb, dev))
		goto drop;

	//取路由查询结果
	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		//组播转发
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST) {
		//广播转发
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	} else if (skb->pkt_type == PACKET_BROADCAST ||
		   skb->pkt_type == PACKET_MULTICAST) {
		//二层采用的是广播或者组播mac
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		/* RFC 1122 3.3.6:
		 *
		 *   When a host sends a datagram to a link-layer broadcast
		 *   address, the IP destination address MUST be a legal IP
		 *   broadcast or IP multicast address.
		 *   当一个主机采用链路层广播地址发送一个报文，ip目的地址必须是一个合法的广播或者组播ip
		 *
		 *   A host SHOULD silently discard a datagram that is received
		 *   via a link-layer broadcast (see Section 2.4) but does not
		 *   specify an IP multicast or broadcast destination address.
		 *   主机应安静的丢弃，链路层广播，但ip目的地址不是广播或者组播的报文。
		 *
		 * This doesn't explicitly say L2 *broadcast*, but broadcast is
		 * in a way a form of multicast and the most common use case for
		 * this is 802.11 protecting against cross-station spoofing (the
		 * so-called "hole-196" attack) so do it for both.
		 */
		if (in_dev &&
		    IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST)) {
			//如果接口配直了丢弃，则丢弃，否则忽略
			drop_reason = SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST;
			goto drop;
		}
	}

	return NET_RX_SUCCESS;
drop:
	kfree_skb_reason(skb, drop_reason);
	return NET_RX_DROP;

drop_error:
	if (err == -EXDEV) {
		drop_reason = SKB_DROP_REASON_IP_RPFILTER;
		__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
	}
	goto drop;
}

static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	int ret;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	//如果入接口设备是从属于l3 master device的,则更换设备
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
	if (ret != NET_RX_DROP)
		//单播在查到路由后且非本机时，在此处走ip_forward
		//单播在查到路由后且为本机时，在此处走ip_local_deliver
		//组播在查到路由后，在此处走ip_mr_input
		//路由未命中时，在此处走ip_error
		ret = dst_input(skb);
	return ret;
}

/*
 * 	Main IP Receive routine.
 */
//ip报文接收入口(主要做了ip头部合法性校验）
static struct sk_buff *ip_rcv_core(struct sk_buff *skb, struct net *net)
{
	const struct iphdr *iph;
	int drop_reason;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST) {
		dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
		//现在我们在处理三层，故如果mac不是我们的,则不处理,直接丢
		drop_reason = SKB_DROP_REASON_OTHERHOST;
		goto drop;
	}

	//统计入口包数，入口字节数
	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
	//报文长度检查
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */
	//ip头部长度至少20字节，此函数仅处理ipv4
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	__IP_ADD_STATS(net,
		       IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
		       max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	//通过ip总头长度，再检查一遍
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = ip_hdr(skb);

	//ip头部校验
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	//ip层总长度
	len = iph_totlen(skb, iph);
	if (skb->len < len) {
		drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
		//待分析的报文长度小于len,报文格式有误
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		//total length比ip头部长度还要小，报文格式有误
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	//如果报文中填充的total_len小于packet buffer len,
	//会将buffer截断使之与total_len一致，继续向上送。
	if (pskb_trim_rcsum(skb, len)) {
	    /*不能截断，丢包*/
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	//设置传输层偏移量
	iph = ip_hdr(skb);
	skb->transport_header = skb->network_header + iph->ihl*4;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	if (!skb_sk_is_prefetched(skb))
		skb_orphan(skb);

	return skb;
csum_error:
	drop_reason = SKB_DROP_REASON_IP_CSUM;
	__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
		drop_reason = SKB_DROP_REASON_IP_INHDR;
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb_reason(skb, drop_reason);
out:
	return NULL;
}

/*
 * IP receive entry point
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);

	skb = ip_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	//触发PRE_ROUTING钩子点
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}

static void ip_sublist_rcv_finish(struct list_head *head)
{
	struct sk_buff *skb, *next;

	list_for_each_entry_safe(skb, next, head, list) {
		skb_list_del_init(skb);
		dst_input(skb);
	}
}

static struct sk_buff *ip_extract_route_hint(const struct net *net,
					     struct sk_buff *skb, int rt_type)
{
	if (fib4_has_custom_rules(net) || rt_type == RTN_BROADCAST ||
	    IPCB(skb)->flags & IPSKB_MULTIPATH)
		return NULL;

	return skb;
}

static void ip_list_rcv_finish(struct net *net, struct sock *sk,
			       struct list_head *head)
{
	struct sk_buff *skb, *next, *hint = NULL;
	struct dst_entry *curr_dst = NULL;
	struct list_head sublist;

	INIT_LIST_HEAD(&sublist);
	list_for_each_entry_safe(skb, next, head, list) {
		struct net_device *dev = skb->dev;
		struct dst_entry *dst;

		skb_list_del_init(skb);
		/* if ingress device is enslaved to an L3 master device pass the
		 * skb to its handler for processing
		 */
		skb = l3mdev_ip_rcv(skb);
		if (!skb)
			continue;
		if (ip_rcv_finish_core(net, sk, skb, dev, hint) == NET_RX_DROP)
			continue;

		dst = skb_dst(skb);
		if (curr_dst != dst) {
			hint = ip_extract_route_hint(net, skb,
					       ((struct rtable *)dst)->rt_type);

			/* dispatch old sublist */
			if (!list_empty(&sublist))
				ip_sublist_rcv_finish(&sublist);
			/* start new sublist */
			INIT_LIST_HEAD(&sublist);
			curr_dst = dst;
		}
		list_add_tail(&skb->list, &sublist);
	}
	/* dispatch final sublist */
	ip_sublist_rcv_finish(&sublist);
}

static void ip_sublist_rcv(struct list_head *head, struct net_device *dev,
			   struct net *net)
{
	NF_HOOK_LIST(NFPROTO_IPV4, NF_INET_PRE_ROUTING, net, NULL,
		     head, dev, NULL, ip_rcv_finish);
	ip_list_rcv_finish(net, NULL, head);
}

/* Receive a list of IP packets */
//收取到一组ip报文
void ip_list_rcv(struct list_head *head, struct packet_type *pt,
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
		skb = ip_rcv_core(skb, net);
		if (skb == NULL)
			continue;

		if (curr_dev != dev || curr_net != net) {
			/* dispatch old sublist */
			if (!list_empty(&sublist))
				ip_sublist_rcv(&sublist, curr_dev, curr_net);
			/* start new sublist */
			INIT_LIST_HEAD(&sublist);
			curr_dev = dev;
			curr_net = net;
		}
		list_add_tail(&skb->list, &sublist);
	}
	/* dispatch final sublist */
	if (!list_empty(&sublist))
		ip_sublist_rcv(&sublist, curr_dev, curr_net);
}
