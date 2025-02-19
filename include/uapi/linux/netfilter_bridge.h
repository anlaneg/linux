/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BRIDGE_NETFILTER_H
#define _UAPI__LINUX_BRIDGE_NETFILTER_H

/* bridge-specific defines for netfilter. 
 */

#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>

#ifndef __KERNEL__
#include <limits.h> /* for INT_MIN, INT_MAX */
#endif

/* Bridge Hooks */
/* After promisc drops, checksum checks. */
#define NF_BR_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_BR_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_BR_FORWARD		2
/* Packets coming from a local process. */
#define NF_BR_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_BR_POST_ROUTING	4
/* Not really a hook, but used for the ebtables broute table */
#define NF_BR_BROUTING		5
#define NF_BR_NUMHOOKS		6

//桥设备的优先级
enum nf_br_hook_priorities {
	NF_BR_PRI_FIRST = INT_MIN,
	NF_BR_PRI_NAT_DST_BRIDGED = -300,//做目的mac变更
	NF_BR_PRI_FILTER_BRIDGED = -200,//forward报文filter处理
	NF_BR_PRI_BRNF = 0,//复用inet的钩子点
	NF_BR_PRI_NAT_DST_OTHER = 100,//对本机出去的报文做dnat(即目的mac变更）
	NF_BR_PRI_FILTER_OTHER = 200,//对本机出去的报文做filter
	NF_BR_PRI_NAT_SRC = 300,//做源mac变更
	NF_BR_PRI_LAST = INT_MAX,
};

#endif /* _UAPI__LINUX_BRIDGE_NETFILTER_H */
