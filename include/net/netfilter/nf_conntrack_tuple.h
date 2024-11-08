/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions and Declarations for tuple.
 *
 * 16 Dec 2003: Yasuyuki Kozakai @USAGI <yasuyuki.kozakai@toshiba.co.jp>
 *	- generalize L3 protocol dependent part.
 *
 * Derived from include/linux/netfiter_ipv4/ip_conntrack_tuple.h
 */

#ifndef _NF_CONNTRACK_TUPLE_H
#define _NF_CONNTRACK_TUPLE_H

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/list_nulls.h>

/* A `tuple' is a structure containing the information to uniquely
  identify a connection.  ie. if two packets have the same tuple, they
  are in the same connection; if not, they are not.

  We divide the structure along "manipulatable" and
  "non-manipulatable" lines, for the benefit of the NAT code.
*/

#define NF_CT_TUPLE_L3SIZE	ARRAY_SIZE(((union nf_inet_addr *)NULL)->all)

/* The manipulable part of the tuple. */
struct nf_conntrack_man {
	union nf_inet_addr u3;//3层地址
	union nf_conntrack_man_proto u;//4层端口
	/* Layer 3 protocol */
	u_int16_t l3num;//3层协议号
};

/* This contains the information to distinguish a connection. */
struct nf_conntrack_tuple
 {
    //源地址，源端口及l3协议
	struct nf_conntrack_man src;

	/* These are the parts of the tuple which are fixed. */
	struct {
		union nf_inet_addr u3;
		union {
			/* Add other protocols here. */
			__be16 all;

			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type, code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;

		/* The protocol. */
		u_int8_t protonum;//l4层协议号

		/* The direction must be ignored for the tuplehash */
		struct { } __nfct_hash_offsetend;

		/* The direction (for tuplehash) */
		u_int8_t dir;//元组方向
	} dst;
};

struct nf_conntrack_tuple_mask {
	struct {
		union nf_inet_addr u3;
		union nf_conntrack_man_proto u;
	} src;
};

//dump元组ip
static inline void nf_ct_dump_tuple_ip(const struct nf_conntrack_tuple *t)
{
#ifdef DEBUG
	printk("tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
	       t, t->dst.protonum,
	       &t->src.u3.ip, ntohs(t->src.u.all),
	       &t->dst.u3.ip, ntohs(t->dst.u.all));
#endif
}

static inline void nf_ct_dump_tuple_ipv6(const struct nf_conntrack_tuple *t)
{
#ifdef DEBUG
	printk("tuple %p: %u %pI6 %hu -> %pI6 %hu\n",
	       t, t->dst.protonum,
	       t->src.u3.all, ntohs(t->src.u.all),
	       t->dst.u3.all, ntohs(t->dst.u.all));
#endif
}

//元组信息dump
static inline void nf_ct_dump_tuple(const struct nf_conntrack_tuple *t)
{
	switch (t->src.l3num) {
	case AF_INET:
		nf_ct_dump_tuple_ip(t);
		break;
	case AF_INET6:
		nf_ct_dump_tuple_ipv6(t);
		break;
	}
}

/* If we're the first tuple, it's the original dir. */
//获得flow的方向
#define NF_CT_DIRECTION(h)						\
	((enum ip_conntrack_dir)(h)->tuple.dst.dir)

/* Connections have two entries in the hash table: one for each way */
struct nf_conntrack_tuple_hash {
	struct hlist_nulls_node hnnode;
	struct nf_conntrack_tuple tuple;//流的五元组信息
};

//检查两个tuple src是否相等
static inline bool __nf_ct_tuple_src_equal(const struct nf_conntrack_tuple *t1,
					   const struct nf_conntrack_tuple *t2)
{
	return (nf_inet_addr_cmp(&t1->src.u3, &t2->src.u3) /*端ip比对*/&&
		t1->src.u.all == t2->src.u.all /*源端口比对*/&&
		t1->src.l3num == t2->src.l3num);/*l3协议号必须相同*/
}

//检查两个tuple dst是否相等
static inline bool __nf_ct_tuple_dst_equal(const struct nf_conntrack_tuple *t1,
					   const struct nf_conntrack_tuple *t2)
{
	return (nf_inet_addr_cmp(&t1->dst.u3, &t2->dst.u3) &&
		t1->dst.u.all == t2->dst.u.all &&
		t1->dst.protonum == t2->dst.protonum);/*l4协议号必须相同*/
}

//检查t1,t2两个元组是否相等
static inline bool nf_ct_tuple_equal(const struct nf_conntrack_tuple *t1,
				     const struct nf_conntrack_tuple *t2)
{
	return __nf_ct_tuple_src_equal(t1, t2) &&
	       __nf_ct_tuple_dst_equal(t1, t2);
}

static inline bool
nf_ct_tuple_mask_equal(const struct nf_conntrack_tuple_mask *m1,
		       const struct nf_conntrack_tuple_mask *m2)
{
	return (nf_inet_addr_cmp(&m1->src.u3, &m2->src.u3) &&
		m1->src.u.all == m2->src.u.all);
}

//期待原比较
static inline bool
nf_ct_tuple_src_mask_cmp(const struct nf_conntrack_tuple *t1,
			 const struct nf_conntrack_tuple *t2,
			 const struct nf_conntrack_tuple_mask *mask)
{
	int count;

	//源地址匹配（合上掩码）
	for (count = 0; count < NF_CT_TUPLE_L3SIZE; count++) {
		if ((t1->src.u3.all[count] ^ t2->src.u3.all[count]) &
		    mask->src.u3.all[count])
			return false;
	}

	//端口匹配（合上掩码）
	if ((t1->src.u.all ^ t2->src.u.all) & mask->src.u.all)
		return false;

	//３层协议号，４层协议号匹配
	if (t1->src.l3num != t2->src.l3num ||
	    t1->dst.protonum != t2->dst.protonum)
		return false;

	return true;
}

//实现期待含mask的元组比较(源支持mask)目的完全匹配
static inline bool
nf_ct_tuple_mask_cmp(const struct nf_conntrack_tuple *t,
		     const struct nf_conntrack_tuple *tuple,
		     const struct nf_conntrack_tuple_mask *mask)
{
	return nf_ct_tuple_src_mask_cmp(t, tuple, mask) &&
	       __nf_ct_tuple_dst_equal(t, tuple);
}

#endif /* _NF_CONNTRACK_TUPLE_H */
