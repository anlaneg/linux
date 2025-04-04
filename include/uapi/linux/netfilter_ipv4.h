/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* IPv4-specific defines for netfilter. 
 * (C)1998 Rusty Russell -- This code is GPL.
 */
#ifndef _UAPI__LINUX_IP_NETFILTER_H
#define _UAPI__LINUX_IP_NETFILTER_H


#include <linux/netfilter.h>

/* only for userspace compatibility */
#ifndef __KERNEL__

#include <limits.h> /* for INT_MIN, INT_MAX */

/* IP Hooks */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5
#endif /* ! __KERNEL__ */

enum nf_ip_hook_priorities {
	NF_IP_PRI_FIRST = INT_MIN,//第一优先级
	NF_IP_PRI_RAW_BEFORE_DEFRAG = -450,//分片重组前
	NF_IP_PRI_CONNTRACK_DEFRAG = -400,//执行分片重组
	NF_IP_PRI_RAW = -300,//执行raw点
	NF_IP_PRI_SELINUX_FIRST = -225,
	//连接跟踪在此点创建(此时创建出来的不考虑nat情况，正反向一致）
	NF_IP_PRI_CONNTRACK = -200,
	//执行mangle点
	NF_IP_PRI_MANGLE = -150,
	//dnat点（这里会因为nat修改连接跟踪）
	NF_IP_PRI_NAT_DST = -100,
	//执行filter
	NF_IP_PRI_FILTER = 0,
	NF_IP_PRI_SECURITY = 50,
	NF_IP_PRI_NAT_SRC = 100,//snat点
	NF_IP_PRI_SELINUX_LAST = 225,
	NF_IP_PRI_CONNTRACK_HELPER = 300,//期待分析
	NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,//连接跟踪confirm点
	NF_IP_PRI_LAST = INT_MAX,
};

/* Arguments for setsockopt SOL_IP: */
/* 2.0 firewalling went from 64 through 71 (and +256, +512, etc). */
/* 2.2 firewalling (+ masq) went from 64 through 76 */
/* 2.4 firewalling went 64 through 67. */
#define SO_ORIGINAL_DST 80


#endif /* _UAPI__LINUX_IP_NETFILTER_H */
