// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_INET6 protocol dispatch tables.
 *
 * Authors:	Pedro Roque	<roque@di.fc.ul.pt>
 */

/*
 *      Changes:
 *
 *      Vince Laviano (vince@cs.stanford.edu)       16 May 2001
 *      - Removed unused variable 'inet6_protocol_base'
 *      - Modified inet6_del_protocol() to correctly maintain copy bit.
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <net/protocol.h>

#if IS_ENABLED(CONFIG_IPV6)
/*支持的ipv6 l4协议*/
struct inet6_protocol __rcu *inet6_protos[MAX_INET_PROTOS] __read_mostly;
EXPORT_SYMBOL(inet6_protos);

/*向ipv6添加支持的l4协议号*/
int inet6_add_protocol(const struct inet6_protocol *prot, unsigned char protocol)
{
	return !cmpxchg((const struct inet6_protocol **)&inet6_protos[protocol],
			NULL, prot) ? 0 : -1;
}
EXPORT_SYMBOL(inet6_add_protocol);

/*移除ipv6支持的l4协议号*/
int inet6_del_protocol(const struct inet6_protocol *prot, unsigned char protocol)
{
	int ret;

	ret = (cmpxchg((const struct inet6_protocol **)&inet6_protos[protocol],
		       prot, NULL) == prot) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(inet6_del_protocol);
#endif

const struct net_offload __rcu *inet6_offloads[MAX_INET_PROTOS] __read_mostly;
EXPORT_SYMBOL(inet6_offloads);

/*为指定协议添加offload*/
int inet6_add_offload(const struct net_offload *prot, unsigned char protocol)
{
	return !cmpxchg((const struct net_offload **)&inet6_offloads[protocol],
			NULL, prot) ? 0 : -1;
}
EXPORT_SYMBOL(inet6_add_offload);

/*移除指定协议的offload*/
int inet6_del_offload(const struct net_offload *prot, unsigned char protocol)
{
	int ret;

	ret = (cmpxchg((const struct net_offload **)&inet6_offloads[protocol],
		       prot, NULL) == prot) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(inet6_del_offload);
