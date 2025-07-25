// SPDX-License-Identifier: GPL-2.0
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP to API glue.
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip.c for history.
 *		Martin Mares	:	TOS setting fixed.
 *		Alan Cox	:	Fixed a couple of oopses in Martin's
 *					TOS tweaks.
 *		Mike McLagan	:	Routing by source
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp_states.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/netfilter.h>
#include <linux/route.h>
#include <linux/mroute.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/compat.h>
#include <net/checksum.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/transp_v6.h>
#endif
#include <net/ip_fib.h>

#include <linux/errqueue.h>
#include <linux/uaccess.h>

/*
 *	SOL_IP control messages.
 */

static void ip_cmsg_recv_pktinfo(struct msghdr *msg, struct sk_buff *skb)
{
	struct in_pktinfo info = *PKTINFO_SKB_CB(skb);

	info.ipi_addr.s_addr = ip_hdr(skb)->daddr;

	put_cmsg(msg, SOL_IP, IP_PKTINFO, sizeof(info), &info);
}

static void ip_cmsg_recv_ttl(struct msghdr *msg, struct sk_buff *skb)
{
	int ttl = ip_hdr(skb)->ttl;
	put_cmsg(msg, SOL_IP, IP_TTL, sizeof(int), &ttl);
}

static void ip_cmsg_recv_tos(struct msghdr *msg, struct sk_buff *skb)
{
	put_cmsg(msg, SOL_IP, IP_TOS, 1, &ip_hdr(skb)->tos);
}

static void ip_cmsg_recv_opts(struct msghdr *msg, struct sk_buff *skb)
{
	if (IPCB(skb)->opt.optlen == 0)
		return;

	put_cmsg(msg, SOL_IP, IP_RECVOPTS, IPCB(skb)->opt.optlen,
		 ip_hdr(skb) + 1);
}


static void ip_cmsg_recv_retopts(struct net *net, struct msghdr *msg,
				 struct sk_buff *skb)
{
	unsigned char optbuf[sizeof(struct ip_options) + 40];
	struct ip_options *opt = (struct ip_options *)optbuf;

	if (IPCB(skb)->opt.optlen == 0)
		return;

	if (ip_options_echo(net, opt, skb)) {
		msg->msg_flags |= MSG_CTRUNC;
		return;
	}
	ip_options_undo(opt);

	put_cmsg(msg, SOL_IP, IP_RETOPTS, opt->optlen, opt->__data);
}

static void ip_cmsg_recv_fragsize(struct msghdr *msg, struct sk_buff *skb)
{
	int val;

	if (IPCB(skb)->frag_max_size == 0)
		return;

	val = IPCB(skb)->frag_max_size;
	put_cmsg(msg, SOL_IP, IP_RECVFRAGSIZE, sizeof(val), &val);
}

static void ip_cmsg_recv_checksum(struct msghdr *msg, struct sk_buff *skb,
				  int tlen, int offset)
{
	__wsum csum = skb->csum;

	if (skb->ip_summed != CHECKSUM_COMPLETE)
		return;

	if (offset != 0) {
		int tend_off = skb_transport_offset(skb) + tlen;
		csum = csum_sub(csum, skb_checksum(skb, tend_off, offset, 0));
	}

	put_cmsg(msg, SOL_IP, IP_CHECKSUM, sizeof(__wsum), &csum);
}

static void ip_cmsg_recv_security(struct msghdr *msg, struct sk_buff *skb)
{
	char *secdata;
	u32 seclen, secid;
	int err;

	err = security_socket_getpeersec_dgram(NULL, skb, &secid);
	if (err)
		return;

	err = security_secid_to_secctx(secid, &secdata, &seclen);
	if (err)
		return;

	put_cmsg(msg, SOL_IP, SCM_SECURITY, seclen, secdata);
	security_release_secctx(secdata, seclen);
}

static void ip_cmsg_recv_dstaddr(struct msghdr *msg, struct sk_buff *skb)
{
	__be16 _ports[2], *ports;
	struct sockaddr_in sin;

	/* All current transport protocols have the port numbers in the
	 * first four bytes of the transport header and this function is
	 * written with this assumption in mind.
	 */
	ports = skb_header_pointer(skb, skb_transport_offset(skb),
				   sizeof(_ports), &_ports);
	if (!ports)
		return;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip_hdr(skb)->daddr;
	sin.sin_port = ports[1];
	memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

	put_cmsg(msg, SOL_IP, IP_ORIGDSTADDR, sizeof(sin), &sin);
}

void ip_cmsg_recv_offset(struct msghdr *msg, struct sock *sk,
			 struct sk_buff *skb, int tlen, int offset)
{
	unsigned long flags = inet_cmsg_flags(inet_sk(sk));

	if (!flags)
		return;

	/* Ordered by supposed usage frequency */
	if (flags & IP_CMSG_PKTINFO) {
	    /*按flags填充pktinfo*/
		ip_cmsg_recv_pktinfo(msg, skb);

		flags &= ~IP_CMSG_PKTINFO;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_TTL) {
	    /*按flags要求，填充ttl*/
		ip_cmsg_recv_ttl(msg, skb);

		flags &= ~IP_CMSG_TTL;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_TOS) {
	    /*按flag要求，填充tos*/
		ip_cmsg_recv_tos(msg, skb);

		flags &= ~IP_CMSG_TOS;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_RECVOPTS) {
	    /*按flag要求，填充Opts*/
		ip_cmsg_recv_opts(msg, skb);

		flags &= ~IP_CMSG_RECVOPTS;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_RETOPTS) {
		ip_cmsg_recv_retopts(sock_net(sk), msg, skb);

		flags &= ~IP_CMSG_RETOPTS;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_PASSSEC) {
		ip_cmsg_recv_security(msg, skb);

		flags &= ~IP_CMSG_PASSSEC;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_ORIGDSTADDR) {
		ip_cmsg_recv_dstaddr(msg, skb);

		flags &= ~IP_CMSG_ORIGDSTADDR;
		if (!flags)
			return;
	}

	if (flags & IP_CMSG_CHECKSUM)
		ip_cmsg_recv_checksum(msg, skb, tlen, offset);

	if (flags & IP_CMSG_RECVFRAGSIZE)
		ip_cmsg_recv_fragsize(msg, skb);
}
EXPORT_SYMBOL(ip_cmsg_recv_offset);

int ip_cmsg_send(struct sock *sk, struct msghdr *msg, struct ipcm_cookie *ipc,
		 bool allow_ipv6)
{
	int err, val;
	struct cmsghdr *cmsg;
	struct net *net = sock_net(sk);

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;
#if IS_ENABLED(CONFIG_IPV6)
		if (allow_ipv6 &&
		    cmsg->cmsg_level == SOL_IPV6 &&
		    cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *src_info;

			if (cmsg->cmsg_len < CMSG_LEN(sizeof(*src_info)))
				return -EINVAL;
			src_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			if (!ipv6_addr_v4mapped(&src_info->ipi6_addr))
				return -EINVAL;
			if (src_info->ipi6_ifindex)
				ipc->oif = src_info->ipi6_ifindex;
			ipc->addr = src_info->ipi6_addr.s6_addr32[3];
			continue;
		}
#endif
		if (cmsg->cmsg_level == SOL_SOCKET) {
			err = __sock_cmsg_send(sk, cmsg, &ipc->sockc);
			if (err)
				return err;
			continue;
		}

		if (cmsg->cmsg_level != SOL_IP)
			continue;
		switch (cmsg->cmsg_type) {
		case IP_RETOPTS:
			err = cmsg->cmsg_len - sizeof(struct cmsghdr);

			/* Our caller is responsible for freeing ipc->opt */
			err = ip_options_get(net, &ipc->opt,
					     KERNEL_SOCKPTR(CMSG_DATA(cmsg)),
					     err < 40 ? err : 40);
			if (err)
				return err;
			break;
		case IP_PKTINFO:
		{
			struct in_pktinfo *info;
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct in_pktinfo)))
				return -EINVAL;
			info = (struct in_pktinfo *)CMSG_DATA(cmsg);
			if (info->ipi_ifindex)
				ipc->oif = info->ipi_ifindex;
			ipc->addr = info->ipi_spec_dst.s_addr;
			break;
		}
		case IP_TTL:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
				return -EINVAL;
			val = *(int *)CMSG_DATA(cmsg);
			if (val < 1 || val > 255)
				return -EINVAL;
			ipc->ttl = val;
			break;
		case IP_TOS:
			if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)))
				val = *(int *)CMSG_DATA(cmsg);
			else if (cmsg->cmsg_len == CMSG_LEN(sizeof(u8)))
				val = *(u8 *)CMSG_DATA(cmsg);
			else
				return -EINVAL;
			if (val < 0 || val > 255)
				return -EINVAL;
			ipc->tos = val;
			ipc->priority = rt_tos2priority(ipc->tos);
			break;
		case IP_PROTOCOL:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
				return -EINVAL;
			val = *(int *)CMSG_DATA(cmsg);
			if (val < 1 || val > 255)
				return -EINVAL;
			ipc->protocol = val;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void ip_ra_destroy_rcu(struct rcu_head *head)
{
	struct ip_ra_chain *ra = container_of(head, struct ip_ra_chain, rcu);

	sock_put(ra->saved_sk);
	kfree(ra);
}

int ip_ra_control(struct sock *sk, unsigned char on,
		  void (*destructor)(struct sock *))
{
	struct ip_ra_chain *ra, *new_ra;
	struct ip_ra_chain __rcu **rap;
	struct net *net = sock_net(sk);

	if (sk->sk_type != SOCK_RAW || inet_sk(sk)->inet_num == IPPROTO_RAW)
		return -EINVAL;

	new_ra = on ? kmalloc(sizeof(*new_ra), GFP_KERNEL) : NULL;
	if (on && !new_ra)
		return -ENOMEM;

	mutex_lock(&net->ipv4.ra_mutex);
	for (rap = &net->ipv4.ra_chain;
	     (ra = rcu_dereference_protected(*rap,
			lockdep_is_held(&net->ipv4.ra_mutex))) != NULL;
	     rap = &ra->next) {
		if (ra->sk == sk) {
			if (on) {
				mutex_unlock(&net->ipv4.ra_mutex);
				kfree(new_ra);
				return -EADDRINUSE;
			}
			/* dont let ip_call_ra_chain() use sk again */
			ra->sk = NULL;
			RCU_INIT_POINTER(*rap, ra->next);
			mutex_unlock(&net->ipv4.ra_mutex);

			if (ra->destructor)
				ra->destructor(sk);
			/*
			 * Delay sock_put(sk) and kfree(ra) after one rcu grace
			 * period. This guarantee ip_call_ra_chain() dont need
			 * to mess with socket refcounts.
			 */
			ra->saved_sk = sk;
			call_rcu(&ra->rcu, ip_ra_destroy_rcu);
			return 0;
		}
	}
	if (!new_ra) {
		mutex_unlock(&net->ipv4.ra_mutex);
		return -ENOBUFS;
	}
	new_ra->sk = sk;
	new_ra->destructor = destructor;

	RCU_INIT_POINTER(new_ra->next, ra);
	rcu_assign_pointer(*rap, new_ra);
	sock_hold(sk);
	mutex_unlock(&net->ipv4.ra_mutex);

	return 0;
}

static void ipv4_icmp_error_rfc4884(const struct sk_buff *skb,
				    struct sock_ee_data_rfc4884 *out)
{
	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		ip_icmp_error_rfc4884(skb, out, sizeof(struct icmphdr),
				      icmp_hdr(skb)->un.reserved[1] * 4);
	}
}

void ip_icmp_error(struct sock *sk, struct sk_buff *skb, int err,
		   __be16 port, u32 info, u8 *payload)
{
	struct sock_exterr_skb *serr;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		return;

	serr = SKB_EXT_ERR(skb);
	serr->ee.ee_errno = err;
	serr->ee.ee_origin = SO_EE_ORIGIN_ICMP;
	serr->ee.ee_type = icmp_hdr(skb)->type;
	serr->ee.ee_code = icmp_hdr(skb)->code;
	serr->ee.ee_pad = 0;
	serr->ee.ee_info = info;
	serr->ee.ee_data = 0;
	serr->addr_offset = (u8 *)&(((struct iphdr *)(icmp_hdr(skb) + 1))->daddr) -
				   skb_network_header(skb);
	serr->port = port;

	if (skb_pull(skb, payload - skb->data)) {
		if (inet_test_bit(RECVERR_RFC4884, sk))
			ipv4_icmp_error_rfc4884(skb, &serr->ee.ee_rfc4884);

		skb_reset_transport_header(skb);
		if (sock_queue_err_skb(sk, skb) == 0)
			return;
	}
	kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(ip_icmp_error);

void ip_local_error(struct sock *sk, int err, __be32 daddr, __be16 port, u32 info)
{
	struct sock_exterr_skb *serr;
	struct iphdr *iph;
	struct sk_buff *skb;

	if (!inet_test_bit(RECVERR, sk))
		return;

	skb = alloc_skb(sizeof(struct iphdr), GFP_ATOMIC);
	if (!skb)
		return;

	skb_put(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->daddr = daddr;

	serr = SKB_EXT_ERR(skb);
	serr->ee.ee_errno = err;
	serr->ee.ee_origin = SO_EE_ORIGIN_LOCAL;
	serr->ee.ee_type = 0;
	serr->ee.ee_code = 0;
	serr->ee.ee_pad = 0;
	serr->ee.ee_info = info;
	serr->ee.ee_data = 0;
	serr->addr_offset = (u8 *)&iph->daddr - skb_network_header(skb);
	serr->port = port;

	__skb_pull(skb, skb_tail_pointer(skb) - skb->data);
	skb_reset_transport_header(skb);

	if (sock_queue_err_skb(sk, skb))
		kfree_skb(skb);
}

/* For some errors we have valid addr_offset even with zero payload and
 * zero port. Also, addr_offset should be supported if port is set.
 */
static inline bool ipv4_datagram_support_addr(struct sock_exterr_skb *serr)
{
	return serr->ee.ee_origin == SO_EE_ORIGIN_ICMP ||
	       serr->ee.ee_origin == SO_EE_ORIGIN_LOCAL || serr->port;
}

/* IPv4 supports cmsg on all imcp errors and some timestamps
 *
 * Timestamp code paths do not initialize the fields expected by cmsg:
 * the PKTINFO fields in skb->cb[]. Fill those in here.
 */
static bool ipv4_datagram_support_cmsg(const struct sock *sk,
				       struct sk_buff *skb,
				       int ee_origin)
{
	struct in_pktinfo *info;

	if (ee_origin == SO_EE_ORIGIN_ICMP)
		return true;

	if (ee_origin == SO_EE_ORIGIN_LOCAL)
		return false;

	/* Support IP_PKTINFO on tstamp packets if requested, to correlate
	 * timestamp with egress dev. Not possible for packets without iif
	 * or without payload (SOF_TIMESTAMPING_OPT_TSONLY).
	 */
	info = PKTINFO_SKB_CB(skb);
	if (!(READ_ONCE(sk->sk_tsflags) & SOF_TIMESTAMPING_OPT_CMSG) ||
	    !info->ipi_ifindex)
		return false;

	info->ipi_spec_dst.s_addr = ip_hdr(skb)->saddr;
	return true;
}

/*
 *	Handle MSG_ERRQUEUE
 */
int ip_recv_error(struct sock *sk, struct msghdr *msg, int len, int *addr_len)
{
	struct sock_exterr_skb *serr;
	struct sk_buff *skb;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);
	struct {
		struct sock_extended_err ee;
		struct sockaddr_in	 offender;
	} errhdr;
	int err;
	int copied;

	err = -EAGAIN;
	skb = sock_dequeue_err_skb(sk);
	if (!skb)
		goto out;

	copied = skb->len;
	if (copied > len) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}
	err = skb_copy_datagram_msg(skb, 0, msg, copied);
	if (unlikely(err)) {
		kfree_skb(skb);
		return err;
	}
	sock_recv_timestamp(msg, sk, skb);

	serr = SKB_EXT_ERR(skb);

	if (sin && ipv4_datagram_support_addr(serr)) {
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = *(__be32 *)(skb_network_header(skb) +
						   serr->addr_offset);
		sin->sin_port = serr->port;
		memset(&sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);
	}

	memcpy(&errhdr.ee, &serr->ee, sizeof(struct sock_extended_err));
	sin = &errhdr.offender;
	memset(sin, 0, sizeof(*sin));

	if (ipv4_datagram_support_cmsg(sk, skb, serr->ee.ee_origin)) {
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		if (inet_cmsg_flags(inet_sk(sk)))
			ip_cmsg_recv(msg, skb);
	}

	put_cmsg(msg, SOL_IP, IP_RECVERR, sizeof(errhdr), &errhdr);

	/* Now we could try to dump offended packet options */

	msg->msg_flags |= MSG_ERRQUEUE;
	err = copied;

	consume_skb(skb);
out:
	return err;
}

void __ip_sock_set_tos(struct sock *sk, int val)
{
	u8 old_tos = inet_sk(sk)->tos;

	if (sk->sk_type == SOCK_STREAM) {
		val &= ~INET_ECN_MASK;
		val |= old_tos & INET_ECN_MASK;
	}
	if (old_tos != val) {
		WRITE_ONCE(inet_sk(sk)->tos, val);
		WRITE_ONCE(sk->sk_priority, rt_tos2priority(val));
		sk_dst_reset(sk);
	}
}

void ip_sock_set_tos(struct sock *sk, int val)
{
	sockopt_lock_sock(sk);
	__ip_sock_set_tos(sk, val);
	sockopt_release_sock(sk);
}
EXPORT_SYMBOL(ip_sock_set_tos);

void ip_sock_set_freebind(struct sock *sk)
{
	inet_set_bit(FREEBIND, sk);
}
EXPORT_SYMBOL(ip_sock_set_freebind);

void ip_sock_set_recverr(struct sock *sk)
{
	inet_set_bit(RECVERR, sk);
}
EXPORT_SYMBOL(ip_sock_set_recverr);

int ip_sock_set_mtu_discover(struct sock *sk, int val)
{
	if (val < IP_PMTUDISC_DONT || val > IP_PMTUDISC_OMIT)
		return -EINVAL;
	WRITE_ONCE(inet_sk(sk)->pmtudisc, val);
	return 0;
}
EXPORT_SYMBOL(ip_sock_set_mtu_discover);

void ip_sock_set_pktinfo(struct sock *sk)
{
	inet_set_bit(PKTINFO, sk);
}
EXPORT_SYMBOL(ip_sock_set_pktinfo);

/*
 *	Socket option code for IP. This is the end of the line after any
 *	TCP,UDP etc options on an IP socket.
 */
static bool setsockopt_needs_rtnl(int optname)
{
	switch (optname) {
	case IP_ADD_MEMBERSHIP:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case IP_BLOCK_SOURCE:
	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	case IP_MSFILTER:
	case IP_UNBLOCK_SOURCE:
	case MCAST_BLOCK_SOURCE:
	case MCAST_MSFILTER:
	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
	case MCAST_UNBLOCK_SOURCE:
		return true;
	}
	return false;
}

static int set_mcast_msfilter(struct sock *sk, int ifindex,
			      int numsrc, int fmode,
			      struct sockaddr_storage *group,
			      struct sockaddr_storage *list)
{
	struct ip_msfilter *msf;
	struct sockaddr_in *psin;
	int err, i;

	msf = kmalloc(IP_MSFILTER_SIZE(numsrc), GFP_KERNEL);
	if (!msf)
		return -ENOBUFS;

	psin = (struct sockaddr_in *)group;
	if (psin->sin_family != AF_INET)
		goto Eaddrnotavail;
	msf->imsf_multiaddr = psin->sin_addr.s_addr;
	msf->imsf_interface = 0;
	msf->imsf_fmode = fmode;
	msf->imsf_numsrc = numsrc;
	for (i = 0; i < numsrc; ++i) {
		psin = (struct sockaddr_in *)&list[i];

		if (psin->sin_family != AF_INET)
			goto Eaddrnotavail;
		msf->imsf_slist_flex[i] = psin->sin_addr.s_addr;
	}
	err = ip_mc_msfilter(sk, msf, ifindex);
	kfree(msf);
	return err;

Eaddrnotavail:
	kfree(msf);
	return -EADDRNOTAVAIL;
}

static int copy_group_source_from_sockptr(struct group_source_req *greqs,
		sockptr_t optval, int optlen)
{
	if (in_compat_syscall()) {
		struct compat_group_source_req gr32;

		if (optlen != sizeof(gr32))
			return -EINVAL;
		if (copy_from_sockptr(&gr32, optval, sizeof(gr32)))
			return -EFAULT;
		greqs->gsr_interface = gr32.gsr_interface;
		greqs->gsr_group = gr32.gsr_group;
		greqs->gsr_source = gr32.gsr_source;
	} else {
		if (optlen != sizeof(*greqs))
			return -EINVAL;
		if (copy_from_sockptr(greqs, optval, sizeof(*greqs)))
			return -EFAULT;
	}

	return 0;
}

static int do_mcast_group_source(struct sock *sk, int optname,
		sockptr_t optval, int optlen)
{
	struct group_source_req greqs;
	struct ip_mreq_source mreqs;
	struct sockaddr_in *psin;
	int omode, add, err;

	err = copy_group_source_from_sockptr(&greqs, optval, optlen);
	if (err)
		return err;

	if (greqs.gsr_group.ss_family != AF_INET ||
	    greqs.gsr_source.ss_family != AF_INET)
		return -EADDRNOTAVAIL;

	psin = (struct sockaddr_in *)&greqs.gsr_group;
	mreqs.imr_multiaddr = psin->sin_addr.s_addr;
	psin = (struct sockaddr_in *)&greqs.gsr_source;
	mreqs.imr_sourceaddr = psin->sin_addr.s_addr;
	mreqs.imr_interface = 0; /* use index for mc_source */

	if (optname == MCAST_BLOCK_SOURCE) {
		omode = MCAST_EXCLUDE;
		add = 1;
	} else if (optname == MCAST_UNBLOCK_SOURCE) {
		omode = MCAST_EXCLUDE;
		add = 0;
	} else if (optname == MCAST_JOIN_SOURCE_GROUP) {
		struct ip_mreqn mreq;

		psin = (struct sockaddr_in *)&greqs.gsr_group;
		mreq.imr_multiaddr = psin->sin_addr;
		mreq.imr_address.s_addr = 0;
		mreq.imr_ifindex = greqs.gsr_interface;
		err = ip_mc_join_group_ssm(sk, &mreq, MCAST_INCLUDE);
		if (err && err != -EADDRINUSE)
			return err;
		greqs.gsr_interface = mreq.imr_ifindex;
		omode = MCAST_INCLUDE;
		add = 1;
	} else /* MCAST_LEAVE_SOURCE_GROUP */ {
		omode = MCAST_INCLUDE;
		add = 0;
	}
	return ip_mc_source(add, omode, sk, &mreqs, greqs.gsr_interface);
}

static int ip_set_mcast_msfilter(struct sock *sk, sockptr_t optval, int optlen)
{
	struct group_filter *gsf = NULL;
	int err;

	if (optlen < GROUP_FILTER_SIZE(0))
		return -EINVAL;
	if (optlen > READ_ONCE(sock_net(sk)->core.sysctl_optmem_max))
		return -ENOBUFS;

	gsf = memdup_sockptr(optval, optlen);
	if (IS_ERR(gsf))
		return PTR_ERR(gsf);

	/* numsrc >= (4G-140)/128 overflow in 32 bits */
	err = -ENOBUFS;
	if (gsf->gf_numsrc >= 0x1ffffff ||
	    gsf->gf_numsrc > READ_ONCE(sock_net(sk)->ipv4.sysctl_igmp_max_msf))
		goto out_free_gsf;

	err = -EINVAL;
	if (GROUP_FILTER_SIZE(gsf->gf_numsrc) > optlen)
		goto out_free_gsf;

	err = set_mcast_msfilter(sk, gsf->gf_interface, gsf->gf_numsrc,
				 gsf->gf_fmode, &gsf->gf_group,
				 gsf->gf_slist_flex);
out_free_gsf:
	kfree(gsf);
	return err;
}

static int compat_ip_set_mcast_msfilter(struct sock *sk, sockptr_t optval,
		int optlen)
{
	const int size0 = offsetof(struct compat_group_filter, gf_slist_flex);
	struct compat_group_filter *gf32;
	unsigned int n;
	void *p;
	int err;

	if (optlen < size0)
		return -EINVAL;
	if (optlen > READ_ONCE(sock_net(sk)->core.sysctl_optmem_max) - 4)
		return -ENOBUFS;

	p = kmalloc(optlen + 4, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	gf32 = p + 4; /* we want ->gf_group and ->gf_slist_flex aligned */

	err = -EFAULT;
	if (copy_from_sockptr(gf32, optval, optlen))
		goto out_free_gsf;

	/* numsrc >= (4G-140)/128 overflow in 32 bits */
	n = gf32->gf_numsrc;
	err = -ENOBUFS;
	if (n >= 0x1ffffff)
		goto out_free_gsf;

	err = -EINVAL;
	if (offsetof(struct compat_group_filter, gf_slist_flex[n]) > optlen)
		goto out_free_gsf;

	/* numsrc >= (4G-140)/128 overflow in 32 bits */
	err = -ENOBUFS;
	if (n > READ_ONCE(sock_net(sk)->ipv4.sysctl_igmp_max_msf))
		goto out_free_gsf;
	err = set_mcast_msfilter(sk, gf32->gf_interface, n, gf32->gf_fmode,
				 &gf32->gf_group, gf32->gf_slist_flex);
out_free_gsf:
	kfree(p);
	return err;
}

static int ip_mcast_join_leave(struct sock *sk, int optname,
		sockptr_t optval, int optlen)
{
	struct ip_mreqn mreq = { };
	struct sockaddr_in *psin;
	struct group_req greq;

	if (optlen < sizeof(struct group_req))
		return -EINVAL;
	if (copy_from_sockptr(&greq, optval, sizeof(greq)))
		return -EFAULT;

	psin = (struct sockaddr_in *)&greq.gr_group;
	if (psin->sin_family != AF_INET)
		return -EINVAL;
	mreq.imr_multiaddr = psin->sin_addr;
	mreq.imr_ifindex = greq.gr_interface;
	if (optname == MCAST_JOIN_GROUP)
		return ip_mc_join_group(sk, &mreq);
	return ip_mc_leave_group(sk, &mreq);
}

static int compat_ip_mcast_join_leave(struct sock *sk, int optname,
		sockptr_t optval, int optlen)
{
	struct compat_group_req greq;
	struct ip_mreqn mreq = { };
	struct sockaddr_in *psin;

	if (optlen < sizeof(struct compat_group_req))
		return -EINVAL;
	if (copy_from_sockptr(&greq, optval, sizeof(greq)))
		return -EFAULT;

	psin = (struct sockaddr_in *)&greq.gr_group;
	if (psin->sin_family != AF_INET)
		return -EINVAL;
	mreq.imr_multiaddr = psin->sin_addr;
	mreq.imr_ifindex = greq.gr_interface;

	if (optname == MCAST_JOIN_GROUP)
		return ip_mc_join_group(sk, &mreq);
	return ip_mc_leave_group(sk, &mreq);
}

DEFINE_STATIC_KEY_FALSE(ip4_min_ttl);

int do_ip_setsockopt(struct sock *sk, int level, int optname,
		     sockptr_t optval, unsigned int optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	int val = 0, err;
	bool needs_rtnl = setsockopt_needs_rtnl(optname);

	switch (optname) {
	case IP_PKTINFO:
	case IP_RECVTTL:
	case IP_RECVOPTS:
	case IP_RECVTOS:
	case IP_RETOPTS:
	case IP_TOS:
	case IP_TTL:
	case IP_HDRINCL:
	case IP_MTU_DISCOVER:
	case IP_RECVERR:
	case IP_ROUTER_ALERT:
	case IP_FREEBIND:
	case IP_PASSSEC:
	case IP_TRANSPARENT:
	case IP_MINTTL:
	case IP_NODEFRAG:
	case IP_BIND_ADDRESS_NO_PORT:
	case IP_UNICAST_IF:
	case IP_MULTICAST_TTL:
	case IP_MULTICAST_ALL:
	case IP_MULTICAST_LOOP:
	case IP_RECVORIGDSTADDR:
	case IP_CHECKSUM:
	case IP_RECVFRAGSIZE:
	case IP_RECVERR_RFC4884:
	case IP_LOCAL_PORT_RANGE:
		if (optlen >= sizeof(int)) {
			if (copy_from_sockptr(&val, optval, sizeof(val)))
				return -EFAULT;
		} else if (optlen >= sizeof(char)) {
			unsigned char ucval;

			if (copy_from_sockptr(&ucval, optval, sizeof(ucval)))
				return -EFAULT;
			val = (int) ucval;
		}
	}

	/* If optlen==0, it is equivalent to val == 0 */

	if (optname == IP_ROUTER_ALERT)
		return ip_ra_control(sk, val ? 1 : 0, NULL);
	if (ip_mroute_opt(optname))
		return ip_mroute_setsockopt(sk, optname, optval, optlen);

	/* Handle options that can be set without locking the socket. */
	switch (optname) {
	case IP_PKTINFO:
		inet_assign_bit(PKTINFO, sk, val);
		return 0;
	case IP_RECVTTL:
		inet_assign_bit(TTL, sk, val);
		return 0;
	case IP_RECVTOS:
		inet_assign_bit(TOS, sk, val);
		return 0;
	case IP_RECVOPTS:
		inet_assign_bit(RECVOPTS, sk, val);
		return 0;
	case IP_RETOPTS:
		inet_assign_bit(RETOPTS, sk, val);
		return 0;
	case IP_PASSSEC:
		inet_assign_bit(PASSSEC, sk, val);
		return 0;
	case IP_RECVORIGDSTADDR:
		inet_assign_bit(ORIGDSTADDR, sk, val);
		return 0;
	case IP_RECVFRAGSIZE:
		if (sk->sk_type != SOCK_RAW && sk->sk_type != SOCK_DGRAM)
			return -EINVAL;
		inet_assign_bit(RECVFRAGSIZE, sk, val);
		return 0;
	case IP_RECVERR:
		inet_assign_bit(RECVERR, sk, val);
		if (!val)
			skb_errqueue_purge(&sk->sk_error_queue);
		return 0;
	case IP_RECVERR_RFC4884:
		if (val < 0 || val > 1)
			return -EINVAL;
		inet_assign_bit(RECVERR_RFC4884, sk, val);
		return 0;
	case IP_FREEBIND:
		if (optlen < 1)
			return -EINVAL;
		inet_assign_bit(FREEBIND, sk, val);
		return 0;
	case IP_HDRINCL:
		if (sk->sk_type != SOCK_RAW)
			return -ENOPROTOOPT;
		inet_assign_bit(HDRINCL, sk, val);
		return 0;
	case IP_MULTICAST_LOOP:
		if (optlen < 1)
			return -EINVAL;
		inet_assign_bit(MC_LOOP, sk, val);
		return 0;
	case IP_MULTICAST_ALL:
		if (optlen < 1)
			return -EINVAL;
		if (val != 0 && val != 1)
			return -EINVAL;
		inet_assign_bit(MC_ALL, sk, val);
		return 0;
	case IP_TRANSPARENT:
		if (!!val && !sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_RAW) &&
		    !sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		if (optlen < 1)
			return -EINVAL;
		inet_assign_bit(TRANSPARENT, sk, val);
		return 0;
	case IP_NODEFRAG:
		if (sk->sk_type != SOCK_RAW)
			return -ENOPROTOOPT;
		inet_assign_bit(NODEFRAG, sk, val);
		return 0;
	case IP_BIND_ADDRESS_NO_PORT:
		inet_assign_bit(BIND_ADDRESS_NO_PORT, sk, val);
		return 0;
	case IP_TTL:
		if (optlen < 1)
			return -EINVAL;
		if (val != -1 && (val < 1 || val > 255))
			return -EINVAL;
		WRITE_ONCE(inet->uc_ttl, val);
		return 0;
	case IP_MINTTL:
		if (optlen < 1)
			return -EINVAL;
		if (val < 0 || val > 255)
			return -EINVAL;

		if (val)
			static_branch_enable(&ip4_min_ttl);

		WRITE_ONCE(inet->min_ttl, val);
		return 0;
	case IP_MULTICAST_TTL:
		if (sk->sk_type == SOCK_STREAM)
			/*必须不为stream*/
			return -EINVAL;
		if (optlen < 1)
			/*选项长度过小*/
			return -EINVAL;
		if (val == -1)
			val = 1;
		/*指定的ttl不符合要求*/
		if (val < 0 || val > 255)
			return -EINVAL;
		/*开启ipv4 min ttl检查*/
		WRITE_ONCE(inet->mc_ttl, val);
		return 0;
	case IP_MTU_DISCOVER:
		return ip_sock_set_mtu_discover(sk, val);
	case IP_TOS:	/* This sets both TOS and Precedence */
		ip_sock_set_tos(sk, val);
		return 0;
	case IP_LOCAL_PORT_RANGE:
	{
		u16 lo = val;
		u16 hi = val >> 16;

		if (optlen != sizeof(u32))
			return -EINVAL;
		if (lo != 0 && hi != 0 && lo > hi)
			return -EINVAL;

		WRITE_ONCE(inet->local_port_range, val);
		return 0;
	}
	}

	err = 0;
	if (needs_rtnl)
		rtnl_lock();
	sockopt_lock_sock(sk);

	switch (optname) {
	case IP_OPTIONS:
	{
		struct ip_options_rcu *old, *opt = NULL;

		if (optlen > 40)
			goto e_inval;
		err = ip_options_get(sock_net(sk), &opt, optval, optlen);
		if (err)
			break;
		old = rcu_dereference_protected(inet->inet_opt,
						lockdep_sock_is_held(sk));
		if (inet_test_bit(IS_ICSK, sk)) {
			struct inet_connection_sock *icsk = inet_csk(sk);
#if IS_ENABLED(CONFIG_IPV6)
			if (sk->sk_family == PF_INET ||
			    (!((1 << sk->sk_state) &
			       (TCPF_LISTEN | TCPF_CLOSE)) &&
			     inet->inet_daddr != LOOPBACK4_IPV6)) {
#endif
				if (old)
					icsk->icsk_ext_hdr_len -= old->opt.optlen;
				if (opt)
					icsk->icsk_ext_hdr_len += opt->opt.optlen;
				icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
#if IS_ENABLED(CONFIG_IPV6)
			}
#endif
		}
		rcu_assign_pointer(inet->inet_opt, opt);
		if (old)
			kfree_rcu(old, rcu);
		break;
	}
	case IP_CHECKSUM:
		if (val) {
			if (!(inet_test_bit(CHECKSUM, sk))) {
				inet_inc_convert_csum(sk);
				inet_set_bit(CHECKSUM, sk);
			}
		} else {
			if (inet_test_bit(CHECKSUM, sk)) {
				inet_dec_convert_csum(sk);
				inet_clear_bit(CHECKSUM, sk);
			}
		}
		break;
	case IP_UNICAST_IF:
	{
		struct net_device *dev = NULL;
		int ifindex;
		int midx;

		if (optlen != sizeof(int))
			goto e_inval;

		ifindex = (__force int)ntohl((__force __be32)val);
		if (ifindex == 0) {
			WRITE_ONCE(inet->uc_index, 0);
			err = 0;
			break;
		}

		dev = dev_get_by_index(sock_net(sk), ifindex);
		err = -EADDRNOTAVAIL;
		if (!dev)
			break;

		midx = l3mdev_master_ifindex(dev);
		dev_put(dev);

		err = -EINVAL;
		if (sk->sk_bound_dev_if && midx != sk->sk_bound_dev_if)
			break;

		WRITE_ONCE(inet->uc_index, ifindex);
		err = 0;
		break;
	}
	case IP_MULTICAST_IF:
	{
		struct ip_mreqn mreq;
		struct net_device *dev = NULL;
		int midx;

		if (sk->sk_type == SOCK_STREAM)
			goto e_inval;/*不得设置stream*/
		/*
		 *	Check the arguments are allowable
		 */

		if (optlen < sizeof(struct in_addr))
			goto e_inval;/*选项参数长度不正确*/

		/*复制参数*/
		err = -EFAULT;
		if (optlen >= sizeof(struct ip_mreqn)) {
			if (copy_from_sockptr(&mreq, optval, sizeof(mreq)))
				break;
		} else {
			memset(&mreq, 0, sizeof(mreq));
			if (optlen >= sizeof(struct ip_mreq)) {
				if (copy_from_sockptr(&mreq, optval,
						      sizeof(struct ip_mreq)))
					break;
			} else if (optlen >= sizeof(struct in_addr)) {
				if (copy_from_sockptr(&mreq.imr_address, optval,
						      sizeof(struct in_addr)))
					break;
			}
		}

		if (!mreq.imr_ifindex) {
			if (mreq.imr_address.s_addr == htonl(INADDR_ANY)) {
				/*未指明源地址,出接口设置为无效值*/
				WRITE_ONCE(inet->mc_index, 0);
				WRITE_ONCE(inet->mc_addr, 0);
				err = 0;
				break;
			}
			/*通过地址查找对应的inet4_dev*/
			dev = ip_dev_find(sock_net(sk), mreq.imr_address.s_addr);
			if (dev)
				mreq.imr_ifindex = dev->ifindex;
		} else
			dev = dev_get_by_index(sock_net(sk), mreq.imr_ifindex);


		err = -EADDRNOTAVAIL;
		if (!dev)
			break;

		midx = l3mdev_master_ifindex(dev);

		dev_put(dev);

		err = -EINVAL;
		if (sk->sk_bound_dev_if &&
		    mreq.imr_ifindex != sk->sk_bound_dev_if &&
		    midx != sk->sk_bound_dev_if)
			break;

		/*填充组播出接口，组播报文采用的源ip*/
		WRITE_ONCE(inet->mc_index, mreq.imr_ifindex);
		WRITE_ONCE(inet->mc_addr, mreq.imr_address.s_addr);
		err = 0;
		break;
	}

	/*加入/离开组播组*/
	case IP_ADD_MEMBERSHIP:
	case IP_DROP_MEMBERSHIP:
	{
		struct ip_mreqn mreq;

		err = -EPROTO;
		if (inet_test_bit(IS_ICSK, sk))
			break;

		if (optlen < sizeof(struct ip_mreq))
			goto e_inval;
		err = -EFAULT;
		if (optlen >= sizeof(struct ip_mreqn)) {
			/*长度过大，截短复制*/
			if (copy_from_sockptr(&mreq, optval, sizeof(mreq)))
				break;
		} else {
			/*长度过小，清空后复制*/
			memset(&mreq, 0, sizeof(mreq));
			if (copy_from_sockptr(&mreq, optval,
					      sizeof(struct ip_mreq)))
				break;
		}

		if (optname == IP_ADD_MEMBERSHIP)
			/*加入组播组*/
			err = ip_mc_join_group(sk, &mreq);
		else
			/*离开组播组*/
			err = ip_mc_leave_group(sk, &mreq);
		break;
	}
	case IP_MSFILTER:
	{
		struct ip_msfilter *msf;

		if (optlen < IP_MSFILTER_SIZE(0))
			goto e_inval;
		if (optlen > READ_ONCE(net->core.sysctl_optmem_max)) {
			err = -ENOBUFS;
			break;
		}
		msf = memdup_sockptr(optval, optlen);
		if (IS_ERR(msf)) {
			err = PTR_ERR(msf);
			break;
		}
		/* numsrc >= (1G-4) overflow in 32 bits */
		if (msf->imsf_numsrc >= 0x3ffffffcU ||
		    msf->imsf_numsrc > READ_ONCE(net->ipv4.sysctl_igmp_max_msf)) {
			kfree(msf);
			err = -ENOBUFS;
			break;
		}
		if (IP_MSFILTER_SIZE(msf->imsf_numsrc) > optlen) {
			kfree(msf);
			err = -EINVAL;
			break;
		}
		err = ip_mc_msfilter(sk, msf, 0);
		kfree(msf);
		break;
	}
	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	{
		struct ip_mreq_source mreqs;
		int omode, add;

		if (optlen != sizeof(struct ip_mreq_source))
			goto e_inval;
		if (copy_from_sockptr(&mreqs, optval, sizeof(mreqs))) {
			err = -EFAULT;
			break;
		}
		if (optname == IP_BLOCK_SOURCE) {
			omode = MCAST_EXCLUDE;
			add = 1;
		} else if (optname == IP_UNBLOCK_SOURCE) {
			omode = MCAST_EXCLUDE;
			add = 0;
		} else if (optname == IP_ADD_SOURCE_MEMBERSHIP) {
			struct ip_mreqn mreq;

			mreq.imr_multiaddr.s_addr = mreqs.imr_multiaddr;
			mreq.imr_address.s_addr = mreqs.imr_interface;
			mreq.imr_ifindex = 0;
			err = ip_mc_join_group_ssm(sk, &mreq, MCAST_INCLUDE);
			if (err && err != -EADDRINUSE)
				break;
			omode = MCAST_INCLUDE;
			add = 1;
		} else /* IP_DROP_SOURCE_MEMBERSHIP */ {
			omode = MCAST_INCLUDE;
			add = 0;
		}
		err = ip_mc_source(add, omode, sk, &mreqs, 0);
		break;
	}
	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
		if (in_compat_syscall())
			err = compat_ip_mcast_join_leave(sk, optname, optval,
							 optlen);
		else
			err = ip_mcast_join_leave(sk, optname, optval, optlen);
		break;
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		err = do_mcast_group_source(sk, optname, optval, optlen);
		break;
	case MCAST_MSFILTER:
		if (in_compat_syscall())
			err = compat_ip_set_mcast_msfilter(sk, optval, optlen);
		else
			err = ip_set_mcast_msfilter(sk, optval, optlen);
		break;
	case IP_IPSEC_POLICY:
	case IP_XFRM_POLICY:
		err = -EPERM;
		if (!sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			break;
		err = xfrm_user_policy(sk, optname, optval, optlen);
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}
	sockopt_release_sock(sk);
	if (needs_rtnl)
		rtnl_unlock();
	return err;

e_inval:
	sockopt_release_sock(sk);
	if (needs_rtnl)
		rtnl_unlock();
	return -EINVAL;
}

/**
 * ipv4_pktinfo_prepare - transfer some info from rtable to skb
 * @sk: socket
 * @skb: buffer
 *
 * To support IP_CMSG_PKTINFO option, we store rt_iif and specific
 * destination in skb->cb[] before dst drop.
 * This way, receiver doesn't make cache line misses to read rtable.
 */
void ipv4_pktinfo_prepare(const struct sock *sk, struct sk_buff *skb)
{
	struct in_pktinfo *pktinfo = PKTINFO_SKB_CB(skb);
	bool prepare = inet_test_bit(PKTINFO, sk) ||
		       ipv6_sk_rxinfo(sk);

	if (prepare && skb_rtable(skb)) {
		/* skb->cb is overloaded: prior to this point it is IP{6}CB
		 * which has interface index (iif) as the first member of the
		 * underlying inet{6}_skb_parm struct. This code then overlays
		 * PKTINFO_SKB_CB and in_pktinfo also has iif as the first
		 * element so the iif is picked up from the prior IPCB. If iif
		 * is the loopback interface, then return the sending interface
		 * (e.g., process binds socket to eth0 for Tx which is
		 * redirected to loopback in the rtable/dst).
		 */
		struct rtable *rt = skb_rtable(skb);
		bool l3slave = ipv4_l3mdev_skb(IPCB(skb)->flags);

		if (pktinfo->ipi_ifindex == LOOPBACK_IFINDEX)
			pktinfo->ipi_ifindex = inet_iif(skb);
		else if (l3slave && rt && rt->rt_iif)
			pktinfo->ipi_ifindex = rt->rt_iif;

		pktinfo->ipi_spec_dst.s_addr = fib_compute_spec_dst(skb);
	} else {
		pktinfo->ipi_ifindex = 0;
		pktinfo->ipi_spec_dst.s_addr = 0;
	}
	skb_dst_drop(skb);
}

int ip_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		unsigned int optlen)
{
	int err;

	if (level != SOL_IP)
		/*此函数只处理ip相关的socket opt*/
		return -ENOPROTOOPT;

	/*处理ip相关的socketopt*/
	err = do_ip_setsockopt(sk, level, optname, optval, optlen);
#ifdef CONFIG_NETFILTER
	/* we need to exclude all possible ENOPROTOOPTs except default case */
	if (err == -ENOPROTOOPT && optname != IP_HDRINCL &&
			optname != IP_IPSEC_POLICY &&
			optname != IP_XFRM_POLICY &&
			!ip_mroute_opt(optname))
		err = nf_setsockopt(sk, PF_INET, optname, optval, optlen);
#endif
	return err;
}
EXPORT_SYMBOL(ip_setsockopt);

/*
 *	Get the options. Note for future reference. The GET of IP options gets
 *	the _received_ ones. The set sets the _sent_ ones.
 */

static bool getsockopt_needs_rtnl(int optname)
{
	switch (optname) {
	case IP_MSFILTER:
	case MCAST_MSFILTER:
		return true;
	}
	return false;
}

static int ip_get_mcast_msfilter(struct sock *sk, sockptr_t optval,
				 sockptr_t optlen, int len)
{
	const int size0 = offsetof(struct group_filter, gf_slist_flex);
	struct group_filter gsf;
	int num, gsf_size;
	int err;

	if (len < size0)
		return -EINVAL;
	if (copy_from_sockptr(&gsf, optval, size0))
		return -EFAULT;

	num = gsf.gf_numsrc;
	err = ip_mc_gsfget(sk, &gsf, optval,
			   offsetof(struct group_filter, gf_slist_flex));
	if (err)
		return err;
	if (gsf.gf_numsrc < num)
		num = gsf.gf_numsrc;
	gsf_size = GROUP_FILTER_SIZE(num);
	if (copy_to_sockptr(optlen, &gsf_size, sizeof(int)) ||
	    copy_to_sockptr(optval, &gsf, size0))
		return -EFAULT;
	return 0;
}

static int compat_ip_get_mcast_msfilter(struct sock *sk, sockptr_t optval,
					sockptr_t optlen, int len)
{
	const int size0 = offsetof(struct compat_group_filter, gf_slist_flex);
	struct compat_group_filter gf32;
	struct group_filter gf;
	int num;
	int err;

	if (len < size0)
		return -EINVAL;
	if (copy_from_sockptr(&gf32, optval, size0))
		return -EFAULT;

	gf.gf_interface = gf32.gf_interface;
	gf.gf_fmode = gf32.gf_fmode;
	num = gf.gf_numsrc = gf32.gf_numsrc;
	gf.gf_group = gf32.gf_group;

	err = ip_mc_gsfget(sk, &gf, optval,
			   offsetof(struct compat_group_filter, gf_slist_flex));
	if (err)
		return err;
	if (gf.gf_numsrc < num)
		num = gf.gf_numsrc;
	len = GROUP_FILTER_SIZE(num) - (sizeof(gf) - sizeof(gf32));
	if (copy_to_sockptr(optlen, &len, sizeof(int)) ||
	    copy_to_sockptr_offset(optval, offsetof(struct compat_group_filter, gf_fmode),
				   &gf.gf_fmode, sizeof(gf.gf_fmode)) ||
	    copy_to_sockptr_offset(optval, offsetof(struct compat_group_filter, gf_numsrc),
				   &gf.gf_numsrc, sizeof(gf.gf_numsrc)))
		return -EFAULT;
	return 0;
}

int do_ip_getsockopt(struct sock *sk, int level, int optname,
		     sockptr_t optval, sockptr_t optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	bool needs_rtnl = getsockopt_needs_rtnl(optname);
	int val, err = 0;
	int len;

	if (level != SOL_IP)
		return -EOPNOTSUPP;

	if (ip_mroute_opt(optname))
		return ip_mroute_getsockopt(sk, optname, optval, optlen);

	if (copy_from_sockptr(&len, optlen, sizeof(int)))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	/* Handle options that can be read without locking the socket. */
	switch (optname) {
	case IP_PKTINFO:
		val = inet_test_bit(PKTINFO, sk);
		goto copyval;
	case IP_RECVTTL:
		val = inet_test_bit(TTL, sk);
		goto copyval;
	case IP_RECVTOS:
		val = inet_test_bit(TOS, sk);
		goto copyval;
	case IP_RECVOPTS:
		val = inet_test_bit(RECVOPTS, sk);
		goto copyval;
	case IP_RETOPTS:
		val = inet_test_bit(RETOPTS, sk);
		goto copyval;
	case IP_PASSSEC:
		val = inet_test_bit(PASSSEC, sk);
		goto copyval;
	case IP_RECVORIGDSTADDR:
		val = inet_test_bit(ORIGDSTADDR, sk);
		goto copyval;
	case IP_CHECKSUM:
		val = inet_test_bit(CHECKSUM, sk);
		goto copyval;
	case IP_RECVFRAGSIZE:
		val = inet_test_bit(RECVFRAGSIZE, sk);
		goto copyval;
	case IP_RECVERR:
		val = inet_test_bit(RECVERR, sk);
		goto copyval;
	case IP_RECVERR_RFC4884:
		val = inet_test_bit(RECVERR_RFC4884, sk);
		goto copyval;
	case IP_FREEBIND:
		val = inet_test_bit(FREEBIND, sk);
		goto copyval;
	case IP_HDRINCL:
		val = inet_test_bit(HDRINCL, sk);
		goto copyval;
	case IP_MULTICAST_LOOP:
		val = inet_test_bit(MC_LOOP, sk);
		goto copyval;
	case IP_MULTICAST_ALL:
		val = inet_test_bit(MC_ALL, sk);
		goto copyval;
	case IP_TRANSPARENT:
		val = inet_test_bit(TRANSPARENT, sk);
		goto copyval;
	case IP_NODEFRAG:
		val = inet_test_bit(NODEFRAG, sk);
		goto copyval;
	case IP_BIND_ADDRESS_NO_PORT:
		val = inet_test_bit(BIND_ADDRESS_NO_PORT, sk);
		goto copyval;
	case IP_TTL:
		val = READ_ONCE(inet->uc_ttl);
		if (val < 0)
			val = READ_ONCE(sock_net(sk)->ipv4.sysctl_ip_default_ttl);
		goto copyval;
	case IP_MINTTL:
		val = READ_ONCE(inet->min_ttl);
		goto copyval;
	case IP_MULTICAST_TTL:
		val = READ_ONCE(inet->mc_ttl);
		goto copyval;
	case IP_MTU_DISCOVER:
		val = READ_ONCE(inet->pmtudisc);
		goto copyval;
	case IP_TOS:
		val = READ_ONCE(inet->tos);
		goto copyval;
	case IP_OPTIONS:
	{
		unsigned char optbuf[sizeof(struct ip_options)+40];
		struct ip_options *opt = (struct ip_options *)optbuf;
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		opt->optlen = 0;
		if (inet_opt)
			memcpy(optbuf, &inet_opt->opt,
			       sizeof(struct ip_options) +
			       inet_opt->opt.optlen);
		rcu_read_unlock();

		if (opt->optlen == 0) {
			len = 0;
			return copy_to_sockptr(optlen, &len, sizeof(int));
		}

		ip_options_undo(opt);

		len = min_t(unsigned int, len, opt->optlen);
		if (copy_to_sockptr(optlen, &len, sizeof(int)))
			return -EFAULT;
		if (copy_to_sockptr(optval, opt->__data, len))
			return -EFAULT;
		return 0;
	}
	case IP_MTU:
	{
		struct dst_entry *dst;
		val = 0;
		dst = sk_dst_get(sk);
		if (dst) {
			val = dst_mtu(dst);
			dst_release(dst);
		}
		if (!val)
			return -ENOTCONN;
		goto copyval;
	}
	case IP_PKTOPTIONS:
	{
		struct msghdr msg;

		if (sk->sk_type != SOCK_STREAM)
			return -ENOPROTOOPT;

		if (optval.is_kernel) {
			msg.msg_control_is_user = false;
			msg.msg_control = optval.kernel;
		} else {
			msg.msg_control_is_user = true;
			msg.msg_control_user = optval.user;
		}
		msg.msg_controllen = len;
		msg.msg_flags = in_compat_syscall() ? MSG_CMSG_COMPAT : 0;

		if (inet_test_bit(PKTINFO, sk)) {
			struct in_pktinfo info;

			info.ipi_addr.s_addr = READ_ONCE(inet->inet_rcv_saddr);
			info.ipi_spec_dst.s_addr = READ_ONCE(inet->inet_rcv_saddr);
			info.ipi_ifindex = READ_ONCE(inet->mc_index);
			put_cmsg(&msg, SOL_IP, IP_PKTINFO, sizeof(info), &info);
		}
		if (inet_test_bit(TTL, sk)) {
			int hlim = READ_ONCE(inet->mc_ttl);

			put_cmsg(&msg, SOL_IP, IP_TTL, sizeof(hlim), &hlim);
		}
		if (inet_test_bit(TOS, sk)) {
			int tos = READ_ONCE(inet->rcv_tos);
			put_cmsg(&msg, SOL_IP, IP_TOS, sizeof(tos), &tos);
		}
		len -= msg.msg_controllen;
		return copy_to_sockptr(optlen, &len, sizeof(int));
	}
	case IP_UNICAST_IF:
		val = (__force int)htonl((__u32) READ_ONCE(inet->uc_index));
		goto copyval;
	case IP_MULTICAST_IF:
	{
		struct in_addr addr;
		len = min_t(unsigned int, len, sizeof(struct in_addr));
		addr.s_addr = READ_ONCE(inet->mc_addr);

		if (copy_to_sockptr(optlen, &len, sizeof(int)))
			return -EFAULT;
		if (copy_to_sockptr(optval, &addr, len))
			return -EFAULT;
		return 0;
	}
	case IP_LOCAL_PORT_RANGE:
		val = READ_ONCE(inet->local_port_range);
		goto copyval;
	}

	if (needs_rtnl)
		rtnl_lock();
	sockopt_lock_sock(sk);

	switch (optname) {
	case IP_MSFILTER:
	{
		struct ip_msfilter msf;

		if (len < IP_MSFILTER_SIZE(0)) {
			err = -EINVAL;
			goto out;
		}
		if (copy_from_sockptr(&msf, optval, IP_MSFILTER_SIZE(0))) {
			err = -EFAULT;
			goto out;
		}
		err = ip_mc_msfget(sk, &msf, optval, optlen);
		goto out;
	}
	case MCAST_MSFILTER:
		if (in_compat_syscall())
			err = compat_ip_get_mcast_msfilter(sk, optval, optlen,
							   len);
		else
			err = ip_get_mcast_msfilter(sk, optval, optlen, len);
		goto out;
	case IP_PROTOCOL:
		val = inet_sk(sk)->inet_num;
		break;
	default:
		sockopt_release_sock(sk);
		return -ENOPROTOOPT;
	}
	sockopt_release_sock(sk);
copyval:
	if (len < sizeof(int) && len > 0 && val >= 0 && val <= 255) {
		unsigned char ucval = (unsigned char)val;
		len = 1;
		if (copy_to_sockptr(optlen, &len, sizeof(int)))
			return -EFAULT;
		if (copy_to_sockptr(optval, &ucval, 1))
			return -EFAULT;
	} else {
		len = min_t(unsigned int, sizeof(int), len);
		if (copy_to_sockptr(optlen, &len, sizeof(int)))
			return -EFAULT;
		if (copy_to_sockptr(optval, &val, len))
			return -EFAULT;
	}
	return 0;

out:
	sockopt_release_sock(sk);
	if (needs_rtnl)
		rtnl_unlock();
	return err;
}

int ip_getsockopt(struct sock *sk, int level,
		  int optname, char __user *optval, int __user *optlen)
{
	int err;

	err = do_ip_getsockopt(sk, level, optname,
			       USER_SOCKPTR(optval), USER_SOCKPTR(optlen));

#ifdef CONFIG_NETFILTER
	/* we need to exclude all possible ENOPROTOOPTs except default case */
	if (err == -ENOPROTOOPT && optname != IP_PKTOPTIONS &&
			!ip_mroute_opt(optname)) {
		int len;

		if (get_user(len, optlen))
			return -EFAULT;

		err = nf_getsockopt(sk, PF_INET, optname, optval, &len);
		if (err >= 0)
			err = put_user(len, optlen);
		return err;
	}
#endif
	return err;
}
EXPORT_SYMBOL(ip_getsockopt);
