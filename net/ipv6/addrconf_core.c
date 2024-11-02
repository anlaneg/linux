// SPDX-License-Identifier: GPL-2.0-only
/*
 * IPv6 library code, needed by static components when full IPv6 support is
 * not configured or static.
 */

#include <linux/export.h>
#include <net/ipv6.h>
#include <net/ipv6_stubs.h>
#include <net/addrconf.h>
#include <net/ip.h>

/* if ipv6 module registers this function is used by xfrm to force all
 * sockets to relookup their nodes - this is fairly expensive, be
 * careful
 */
void (*__fib6_flush_trees)(struct net *);
EXPORT_SYMBOL(__fib6_flush_trees);

#define IPV6_ADDR_SCOPE_TYPE(scope)	((scope) << 16)

static inline unsigned int ipv6_addr_scope2type(unsigned int scope)
{
	switch (scope) {
	case IPV6_ADDR_SCOPE_NODELOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_NODELOCAL) |
			IPV6_ADDR_LOOPBACK);
	case IPV6_ADDR_SCOPE_LINKLOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL) |
			IPV6_ADDR_LINKLOCAL);
	case IPV6_ADDR_SCOPE_SITELOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL) |
			IPV6_ADDR_SITELOCAL);
	}
	return IPV6_ADDR_SCOPE_TYPE(scope);
}

/*取ipv6地址类型*/
int __ipv6_addr_type(const struct in6_addr *addr)
{
	__be32 st;

	st = addr->s6_addr32[0];/*ipv6地址的前4个字节*/

	/* Consider all addresses with the first three bits different of
	   000 and 111 as unicasts.
	 */
	if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
	    (st & htonl(0xE0000000)) != htonl(0xE0000000))
		/*遇到开区间（000，111）间的数值，为单播，global地址*/
		return (IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));

	/*此线后，仅考虑000b,111b两种情况*/
	/*FF00::/8地址范围为组播地址
	 *
	 * */
	if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
		/* multicast */
		/* addr-select 3.1 */
		return (IPV6_ADDR_MULTICAST |
			ipv6_addr_scope2type(IPV6_ADDR_MC_SCOPE(addr)));
	}

	/*FE80::/10地址范围的为linklocal地址，见rfc2373 2.5.8节
	 *
	 * FE::/7中只有FE/8,FF/8两段，FF::/8做为组播，余FE::/8;
	 * FE::/8中共有 FE00::/10, FE40::/10, FE80::/10,FEC0::/10 四段，这里分配FE80::/10*/
	if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
		return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));		/* addr-select 3.1 */

	/*FEC0::/10地址范围为ipv6私有地址(site local)
	 *
	 * FE::/8中再分配FEC0::/10,此时FE::/8中还剩下两段,即“FE00::/10” 与“FE40::/10”
	 * */
	if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
		return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));		/* addr-select 3.1 */

	/*由rfc 4193定义的私有地址 FC::/7,
	 * FD::/8表示locally assigned，FC::/8 may be defined in the future
	 *
	 *  FC::/6中共有以下FD::/8, FE::/7, FC::/8三段，如上已知，FE::/7已分配完。
	 *  这里分配了FD::/8,FC::/8, 到此FC::/6分配完了。
	 * */
	if ((st & htonl(0xFE000000)) == htonl(0xFC000000))
		return (IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));			/* RFC 4193 */

	if ((addr->s6_addr32[0] | addr->s6_addr32[1]) == 0) {
		if (addr->s6_addr32[2] == 0) {
			if (addr->s6_addr32[3] == 0)
				/*::/128,全0地址,见rfc2373 2.5.2节*/
				return IPV6_ADDR_ANY;

			if (addr->s6_addr32[3] == htonl(0x00000001))
				/*::1/128 为loopback地址，见rfc2373 2.5.3节*/
				return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
					IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));	/* addr-select 3.4 */

			/*::/96范围为v4兼容地址，见rfc2373 2.5.4节*/
			return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.3 */
		}

		/*::ffff00000000/96范围的为映射地址，见2.5.4节（第二种map形式）*/
		if (addr->s6_addr32[2] == htonl(0x0000ffff))
			return (IPV6_ADDR_MAPPED |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.3 */
	}

	/*其它地址，包括未分配出来的，均为global地址*/
	return (IPV6_ADDR_UNICAST |
		IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.4 */
}
EXPORT_SYMBOL(__ipv6_addr_type);

static ATOMIC_NOTIFIER_HEAD(inet6addr_chain);
static BLOCKING_NOTIFIER_HEAD(inet6addr_validator_chain);

int register_inet6addr_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&inet6addr_chain, nb);
}
EXPORT_SYMBOL(register_inet6addr_notifier);

int unregister_inet6addr_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&inet6addr_chain, nb);
}
EXPORT_SYMBOL(unregister_inet6addr_notifier);

int inet6addr_notifier_call_chain(unsigned long val, void *v)
{
	return atomic_notifier_call_chain(&inet6addr_chain, val, v);
}
EXPORT_SYMBOL(inet6addr_notifier_call_chain);

int register_inet6addr_validator_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&inet6addr_validator_chain, nb);
}
EXPORT_SYMBOL(register_inet6addr_validator_notifier);

int unregister_inet6addr_validator_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&inet6addr_validator_chain,
						  nb);
}
EXPORT_SYMBOL(unregister_inet6addr_validator_notifier);

int inet6addr_validator_notifier_call_chain(unsigned long val, void *v)
{
	/*触发validator通知链*/
	return blocking_notifier_call_chain(&inet6addr_validator_chain, val, v);
}
EXPORT_SYMBOL(inet6addr_validator_notifier_call_chain);

static struct dst_entry *eafnosupport_ipv6_dst_lookup_flow(struct net *net,
							   const struct sock *sk,
							   struct flowi6 *fl6,
							   const struct in6_addr *final_dst)
{
	return ERR_PTR(-EAFNOSUPPORT);
}

static int eafnosupport_ipv6_route_input(struct sk_buff *skb)
{
	return -EAFNOSUPPORT;
}

static struct fib6_table *eafnosupport_fib6_get_table(struct net *net, u32 id)
{
	return NULL;
}

static int
eafnosupport_fib6_table_lookup(struct net *net, struct fib6_table *table,
			       int oif, struct flowi6 *fl6,
			       struct fib6_result *res, int flags)
{
	return -EAFNOSUPPORT;
}

static int
eafnosupport_fib6_lookup(struct net *net, int oif, struct flowi6 *fl6,
			 struct fib6_result *res, int flags)
{
	return -EAFNOSUPPORT;
}

static void
eafnosupport_fib6_select_path(const struct net *net, struct fib6_result *res,
			      struct flowi6 *fl6, int oif, bool have_oif_match,
			      const struct sk_buff *skb, int strict)
{
}

static u32
eafnosupport_ip6_mtu_from_fib6(const struct fib6_result *res,
			       const struct in6_addr *daddr,
			       const struct in6_addr *saddr)
{
	return 0;
}

static int eafnosupport_fib6_nh_init(struct net *net, struct fib6_nh *fib6_nh,
				     struct fib6_config *cfg, gfp_t gfp_flags,
				     struct netlink_ext_ack *extack)
{
	NL_SET_ERR_MSG(extack, "IPv6 support not enabled in kernel");
	return -EAFNOSUPPORT;
}

static int eafnosupport_ip6_del_rt(struct net *net, struct fib6_info *rt,
				   bool skip_notify)
{
	return -EAFNOSUPPORT;
}

static int eafnosupport_ipv6_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
				      int (*output)(struct net *, struct sock *, struct sk_buff *))
{
	kfree_skb(skb);
	return -EAFNOSUPPORT;
}

static struct net_device *eafnosupport_ipv6_dev_find(struct net *net, const struct in6_addr *addr,
						     struct net_device *dev)
{
	return ERR_PTR(-EAFNOSUPPORT);
}

const struct ipv6_stub *ipv6_stub __read_mostly = &(struct ipv6_stub) {
	.ipv6_dst_lookup_flow = eafnosupport_ipv6_dst_lookup_flow,
	.ipv6_route_input  = eafnosupport_ipv6_route_input,
	.fib6_get_table    = eafnosupport_fib6_get_table,
	.fib6_table_lookup = eafnosupport_fib6_table_lookup,
	.fib6_lookup       = eafnosupport_fib6_lookup,
	.fib6_select_path  = eafnosupport_fib6_select_path,
	.ip6_mtu_from_fib6 = eafnosupport_ip6_mtu_from_fib6,
	.fib6_nh_init	   = eafnosupport_fib6_nh_init,
	.ip6_del_rt	   = eafnosupport_ip6_del_rt,
	.ipv6_fragment	   = eafnosupport_ipv6_fragment,
	.ipv6_dev_find     = eafnosupport_ipv6_dev_find,
};
EXPORT_SYMBOL_GPL(ipv6_stub);

/* IPv6 Wildcard Address and Loopback Address defined by RFC2553 */
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;/*ipv6 loopback地址*/
EXPORT_SYMBOL(in6addr_loopback);
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
EXPORT_SYMBOL(in6addr_any);
const struct in6_addr in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
EXPORT_SYMBOL(in6addr_linklocal_allnodes);
const struct in6_addr in6addr_linklocal_allrouters = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;
EXPORT_SYMBOL(in6addr_linklocal_allrouters);
/*ipv6用来指代interface local“所有节点”的地址*/
const struct in6_addr in6addr_interfacelocal_allnodes = IN6ADDR_INTERFACELOCAL_ALLNODES_INIT;
EXPORT_SYMBOL(in6addr_interfacelocal_allnodes);
const struct in6_addr in6addr_interfacelocal_allrouters = IN6ADDR_INTERFACELOCAL_ALLROUTERS_INIT;
EXPORT_SYMBOL(in6addr_interfacelocal_allrouters);
const struct in6_addr in6addr_sitelocal_allrouters = IN6ADDR_SITELOCAL_ALLROUTERS_INIT;
EXPORT_SYMBOL(in6addr_sitelocal_allrouters);

static void snmp6_free_dev(struct inet6_dev *idev)
{
	kfree(idev->stats.icmpv6msgdev);
	kfree(idev->stats.icmpv6dev);
	free_percpu(idev->stats.ipv6);
}

static void in6_dev_finish_destroy_rcu(struct rcu_head *head)
{
	struct inet6_dev *idev = container_of(head, struct inet6_dev, rcu);

	snmp6_free_dev(idev);
	kfree(idev);
}

/* Nobody refers to this device, we may destroy it. */

void in6_dev_finish_destroy(struct inet6_dev *idev)
{
	struct net_device *dev = idev->dev;

	WARN_ON(!list_empty(&idev->addr_list));
	WARN_ON(rcu_access_pointer(idev->mc_list));
	WARN_ON(timer_pending(&idev->rs_timer));

#ifdef NET_REFCNT_DEBUG
	pr_debug("%s: %s\n", __func__, dev ? dev->name : "NIL");
#endif
	netdev_put(dev, &idev->dev_tracker);
	if (!idev->dead) {
		pr_warn("Freeing alive inet6 device %p\n", idev);
		return;
	}
	call_rcu(&idev->rcu, in6_dev_finish_destroy_rcu);
}
EXPORT_SYMBOL(in6_dev_finish_destroy);
