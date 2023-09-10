/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 *	Generic internet FLOW.
 *
 */

#ifndef _NET_FLOW_H
#define _NET_FLOW_H

#include <linux/in6.h>
#include <linux/atomic.h>
#include <linux/container_of.h>
#include <linux/uidgid.h>

struct flow_keys;

/*
 * ifindex generation is per-net namespace, and loopback is
 * always the 1st device in ns (see net_dev_init), thus any
 * loopback device should get ifindex 1
 */

#define LOOPBACK_IFINDEX	1

struct flowi_tunnel {
	__be64			tun_id;
};

struct flowi_common {
	int	flowic_oif;//出接口
	int	flowic_iif;//入接口
	int     flowic_l3mdev;
	__u32	flowic_mark;/*skb mark取值*/
	__u8	flowic_tos;//tos取值
	__u8	flowic_scope;
	__u8	flowic_proto;//下层协议号
	__u8	flowic_flags;
#define FLOWI_FLAG_ANYSRC		0x01
#define FLOWI_FLAG_KNOWN_NH		0x02
	__u32	flowic_secid;
	kuid_t  flowic_uid;//用户传入的不透明id
	struct flowi_tunnel flowic_tun_key;/*隧道id*/
	__u32		flowic_multipath_hash;
};

union flowi_uli {
	struct {
		__be16	dport;
		__be16	sport;
	} ports;

	struct {
		__u8	type;
		__u8	code;
	} icmpt;

	__be32		gre_key;

	struct {
		__u8	type;
	} mht;
};

struct flowi4 {
	struct flowi_common	__fl_common;
	//出接口
#define flowi4_oif		__fl_common.flowic_oif
	//入接口
#define flowi4_iif		__fl_common.flowic_iif
#define flowi4_l3mdev		__fl_common.flowic_l3mdev
	//报文命中的mark值
#define flowi4_mark		__fl_common.flowic_mark
	//报文tos
#define flowi4_tos		__fl_common.flowic_tos
	//地址scope
#define flowi4_scope		__fl_common.flowic_scope
	//4层的网络协议号
#define flowi4_proto		__fl_common.flowic_proto
#define flowi4_flags		__fl_common.flowic_flags
#define flowi4_secid		__fl_common.flowic_secid
#define flowi4_tun_key		__fl_common.flowic_tun_key
#define flowi4_uid		__fl_common.flowic_uid
#define flowi4_multipath_hash	__fl_common.flowic_multipath_hash

	/* (saddr,daddr) must be grouped, same order as in IP header */
	__be32			saddr;//源地址
	__be32			daddr;//目的地址

	union flowi_uli		uli;//port信息
//源port
#define fl4_sport		uli.ports.sport
//目的port
#define fl4_dport		uli.ports.dport
//icmp对应type
#define fl4_icmp_type		uli.icmpt.type
//icmp对应code
#define fl4_icmp_code		uli.icmpt.code
#define fl4_mh_type		uli.mht.type
//gre对应的key
#define fl4_gre_key		uli.gre_key
} __attribute__((__aligned__(BITS_PER_LONG/8)));

/*初始化flowi4*/
static inline void flowi4_init_output(struct flowi4 *fl4, int oif/*出接口*/,
				      __u32 mark/*fwmark*/, __u8 tos, __u8 scope/*地址范围*/,
				      __u8 proto, __u8 flags,
				      __be32 daddr, __be32 saddr,
				      __be16 dport, __be16 sport,
				      kuid_t uid)
{
	fl4->flowi4_oif = oif;
	/*入接口默认指定为loopback口*/
	fl4->flowi4_iif = LOOPBACK_IFINDEX;
	fl4->flowi4_l3mdev = 0;
	fl4->flowi4_mark = mark;
	fl4->flowi4_tos = tos;
	fl4->flowi4_scope = scope;
	fl4->flowi4_proto = proto;/*对应的4层协议*/
	fl4->flowi4_flags = flags;
	fl4->flowi4_secid = 0;
	fl4->flowi4_tun_key.tun_id = 0;
	fl4->flowi4_uid = uid;
	fl4->daddr = daddr;/*目的地址*/
	fl4->saddr = saddr;/*源地址*/
	fl4->fl4_dport = dport;/*目的端口*/
	fl4->fl4_sport = sport;/*源端口*/
	fl4->flowi4_multipath_hash = 0;
}

/* Reset some input parameters after previous lookup */
static inline void flowi4_update_output(struct flowi4 *fl4, int oif, __u8 tos,
					__be32 daddr, __be32 saddr)
{
	fl4->flowi4_oif = oif;
	fl4->flowi4_tos = tos;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
}


struct flowi6 {
	struct flowi_common	__fl_common;
#define flowi6_oif		__fl_common.flowic_oif
	/*设备入接口*/
#define flowi6_iif		__fl_common.flowic_iif
#define flowi6_l3mdev		__fl_common.flowic_l3mdev
#define flowi6_mark		__fl_common.flowic_mark
#define flowi6_scope		__fl_common.flowic_scope
#define flowi6_proto		__fl_common.flowic_proto
#define flowi6_flags		__fl_common.flowic_flags
#define flowi6_secid		__fl_common.flowic_secid
#define flowi6_tun_key		__fl_common.flowic_tun_key
#define flowi6_uid		__fl_common.flowic_uid
	struct in6_addr		daddr;//目的地址
	struct in6_addr		saddr;//源地址
	/* Note: flowi6_tos is encoded in flowlabel, too. */
	__be32			flowlabel;/*ipv6头部flowlabel*/
	union flowi_uli		uli;
#define fl6_sport		uli.ports.sport
#define fl6_dport		uli.ports.dport
#define fl6_icmp_type		uli.icmpt.type
#define fl6_icmp_code		uli.icmpt.code
#define fl6_mh_type		uli.mht.type
#define fl6_gre_key		uli.gre_key
	__u32			mp_hash;
} __attribute__((__aligned__(BITS_PER_LONG/8)));

struct flowi {
	union {
		struct flowi_common	__fl_common;
		struct flowi4		ip4;
		struct flowi6		ip6;
	} u;
#define flowi_oif	u.__fl_common.flowic_oif
#define flowi_iif	u.__fl_common.flowic_iif
#define flowi_l3mdev	u.__fl_common.flowic_l3mdev
#define flowi_mark	u.__fl_common.flowic_mark
#define flowi_tos	u.__fl_common.flowic_tos
#define flowi_scope	u.__fl_common.flowic_scope
#define flowi_proto	u.__fl_common.flowic_proto
#define flowi_flags	u.__fl_common.flowic_flags
#define flowi_secid	u.__fl_common.flowic_secid
#define flowi_tun_key	u.__fl_common.flowic_tun_key
#define flowi_uid	u.__fl_common.flowic_uid
} __attribute__((__aligned__(BITS_PER_LONG/8)));

static inline struct flowi *flowi4_to_flowi(struct flowi4 *fl4)
{
	return container_of(fl4, struct flowi, u.ip4);
}

static inline struct flowi_common *flowi4_to_flowi_common(struct flowi4 *fl4)
{
	return &(fl4->__fl_common);
}

static inline struct flowi *flowi6_to_flowi(struct flowi6 *fl6)
{
	return container_of(fl6, struct flowi, u.ip6);
}

static inline struct flowi_common *flowi6_to_flowi_common(struct flowi6 *fl6)
{
	return &(fl6->__fl_common);
}

__u32 __get_hash_from_flowi6(const struct flowi6 *fl6, struct flow_keys *keys);

#endif
