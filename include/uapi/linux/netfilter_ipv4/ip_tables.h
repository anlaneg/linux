/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * 25-Jul-1998 Major changes to allow for ip chain table
 *
 * 3-Jan-2000 Named tables to allow packet selection for different uses.
 */

/*
 * 	Format of an IP firewall descriptor
 *
 * 	src, dst, src_mask, dst_mask are always stored in network byte order.
 * 	flags are stored in host byte order (of course).
 * 	Port numbers are stored in HOST byte order.
 */

#ifndef _UAPI_IPTABLES_H
#define _UAPI_IPTABLES_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>

#include <linux/netfilter/x_tables.h>

#ifndef __KERNEL__
#define IPT_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IPT_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define ipt_match xt_match
#define ipt_target xt_target
#define ipt_table xt_table
#define ipt_get_revision xt_get_revision
#define ipt_entry_match xt_entry_match
#define ipt_entry_target xt_entry_target
#define ipt_standard_target xt_standard_target
#define ipt_error_target xt_error_target
#define ipt_counters xt_counters
#define IPT_CONTINUE XT_CONTINUE
#define IPT_RETURN XT_RETURN

/* This group is older than old (iptables < v1.4.0-rc1~89) */
#include <linux/netfilter/xt_tcpudp.h>
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp
#define IPT_TCP_INV_SRCPT	XT_TCP_INV_SRCPT
#define IPT_TCP_INV_DSTPT	XT_TCP_INV_DSTPT
#define IPT_TCP_INV_FLAGS	XT_TCP_INV_FLAGS
#define IPT_TCP_INV_OPTION	XT_TCP_INV_OPTION
#define IPT_TCP_INV_MASK	XT_TCP_INV_MASK
#define IPT_UDP_INV_SRCPT	XT_UDP_INV_SRCPT
#define IPT_UDP_INV_DSTPT	XT_UDP_INV_DSTPT
#define IPT_UDP_INV_MASK	XT_UDP_INV_MASK

/* The argument to IPT_SO_ADD_COUNTERS. */
#define ipt_counters_info xt_counters_info
/* Standard return verdict, or do jump. */
#define IPT_STANDARD_TARGET XT_STANDARD_TARGET
/* Error verdict. */
#define IPT_ERROR_TARGET XT_ERROR_TARGET

/* fn returns 0 to continue iteration */
#define IPT_MATCH_ITERATE(e, fn, args...) \
	XT_MATCH_ITERATE(struct ipt_entry, e, fn, ## args)

/* fn returns 0 to continue iteration */
#define IPT_ENTRY_ITERATE(entries, size, fn, args...) \
	XT_ENTRY_ITERATE(struct ipt_entry, entries, size, fn, ## args)
#endif

/* Yes, Virginia, you have to zero the padding. */
struct ipt_ip {
	/* Source and destination IP addr */
	//源地址，目的地址
	struct in_addr src, dst;
	//源地址，目的地址掩码
	/* Mask for src and dest IP addr */
	struct in_addr smsk, dmsk;
	//接口名称
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	//接口名称掩码（字符串掩码用于表示，是否比对此字节）
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

	/* Protocol, 0 = ANY */
	__u16 proto;

	/* Flags word */
	__u8 flags;
	/* Inverse flags */
	__u8 invflags;
};

/* Values for "flag" field in struct ipt_ip (general ip structure). */
#define IPT_F_FRAG		0x01	/* Set if rule is a fragment rule */
#define IPT_F_GOTO		0x02	/* Set if jump is a goto */
#define IPT_F_MASK		0x03	/* All possible flag bits mask. */

/* Values for "inv" field in struct ipt_ip. */
#define IPT_INV_VIA_IN		0x01	/* Invert the sense of IN IFACE. */
#define IPT_INV_VIA_OUT		0x02	/* Invert the sense of OUT IFACE */
#define IPT_INV_TOS		0x04	/* Invert the sense of TOS. */
#define IPT_INV_SRCIP		0x08	/* Invert the sense of SRC IP. */
#define IPT_INV_DSTIP		0x10	/* Invert the sense of DST OP. */
#define IPT_INV_FRAG		0x20	/* Invert the sense of FRAG. */
#define IPT_INV_PROTO		XT_INV_PROTO
#define IPT_INV_MASK		0x7F	/* All possible flag bits mask. */

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches */
struct ipt_entry {
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	__u16 target_offset;//用于指出到target的偏移（隐含辅助指出match的总长度）
	/* Size of ipt_entry + matches + target */
	__u16 next_offset;//指出到下一个entry的偏移

	/* Back pointer */
	unsigned int comefrom;

	/* Packet and byte counters. */
	struct xt_counters counters;//记录规则被匹配的字节数及包数

	/* The matches (if any), then the target. */
	//注意match可以是多个，故用了s
	//elems指向所有规则，其格式为matchs + target
	//matchs为xt_entry_match结构，由其内的match_size指定单个的长度
	//matchs的总长度为ipt中的target_offset字段隐含给出
	//target为xt_entry_target结构，由其内的target_size指定其长度
	//每个ipt_entry结构由其内的next_offset指向下一个ipt_entry
	unsigned char elems[];
};

/*
 * New IP firewall options for [gs]etsockopt at the RAW IP level.
 * Unlike BSD Linux inherits IP options so you don't have to use a raw
 * socket for this. Instead we check rights in the calls.
 *
 * ATTENTION: check linux/in.h before adding new number here.
 */
#define IPT_BASE_CTL		64

#define IPT_SO_SET_REPLACE	(IPT_BASE_CTL)
#define IPT_SO_SET_ADD_COUNTERS	(IPT_BASE_CTL + 1)
#define IPT_SO_SET_MAX		IPT_SO_SET_ADD_COUNTERS

#define IPT_SO_GET_INFO			(IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES		(IPT_BASE_CTL + 1)
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#define IPT_SO_GET_MAX			IPT_SO_GET_REVISION_TARGET

/* ICMP matching stuff */
struct ipt_icmp {
	__u8 type;				/* type to match */
	__u8 code[2];				/* range of code */
	__u8 invflags;				/* Inverse flags */
};

/* Values for "inv" field for struct ipt_icmp. */
#define IPT_ICMP_INV	0x01	/* Invert the sense of type/code test */

/* The argument to IPT_SO_GET_INFO */
struct ipt_getinfo {
	/* Which table: caller fills this in. */
	char name[XT_TABLE_MAXNAMELEN];

	/* Kernel fills these in. */
	/* Which hook entry points are valid: bitmask */
	unsigned int valid_hooks;

	/* Hook entry points: one per netfilter hook. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];//各hook点首个规则偏移量

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];//各hook点兜底规则偏移量

	/* Number of entries */
	unsigned int num_entries;

	/* Size of entries. */
	unsigned int size;
};

/* The argument to IPT_SO_SET_REPLACE. */
struct ipt_replace {
	/* Which table. */
	char name[XT_TABLE_MAXNAMELEN];//表名称

	/* Which hook entry points are valid: bitmask.  You can't
           change this. */
	unsigned int valid_hooks;//需要挂接的hook点（掩码形式）

	/* Number of entries */
	unsigned int num_entries;//(hook点数目，entries表数目）

	/* Total size of new entries */
	unsigned int size;//entries指向的内存大小

	/* Hook entry points. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Underflow points. */
	unsigned int underflow[NF_INET_NUMHOOKS];

	/* Information about old entries: */
	/* Number of counters (must be equal to current number of entries). */
	unsigned int num_counters;
	/* The old entries' counters. */
	struct xt_counters __user *counters;

	/* The entries (hang off end: not really an array). */
	struct ipt_entry entries[];
};

/* The argument to IPT_SO_GET_ENTRIES. */
struct ipt_get_entries {
	/* Which table: user fills this in. */
	char name[XT_TABLE_MAXNAMELEN];

	/* User fills this in: total entry size. */
	unsigned int size;

	/* The entries. */
	struct ipt_entry entrytable[];
};

/* Helper functions */
static __inline__ struct xt_entry_target *
ipt_get_target(struct ipt_entry *e)
{
	return (struct xt_entry_target *)((char *)e + e->target_offset);
}

/*
 *	Main firewall chains definitions and global var's definitions.
 */
#endif /* _UAPI_IPTABLES_H */
