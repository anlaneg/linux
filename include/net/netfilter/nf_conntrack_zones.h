/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_ZONES_H
#define _NF_CONNTRACK_ZONES_H

#include <linux/netfilter/nf_conntrack_zones_common.h>
#include <net/netfilter/nf_conntrack.h>

//取连接所属的zone信息
static inline const struct nf_conntrack_zone *
nf_ct_zone(const struct nf_conn *ct)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
    //使用ct中的zone
	return &ct->zone;
#else
	//使用0号zone
	return &nf_ct_zone_dflt;
#endif
}

static inline const struct nf_conntrack_zone *
nf_ct_zone_init(struct nf_conntrack_zone *zone, u16 id, u8 dir, u8 flags)
{
	zone->id = id;
	zone->flags = flags;
	zone->dir = dir;

	return zone;
}

//获取ct对应的zone
static inline const struct nf_conntrack_zone *
nf_ct_zone_tmpl(const struct nf_conn *tmpl, const struct sk_buff *skb,
		struct nf_conntrack_zone *tmp)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	if (!tmpl)
	    //无模板，直接使用nf_ct_zone_dflt （0号zone)
		return &nf_ct_zone_dflt;

	if (tmpl->zone.flags & NF_CT_FLAG_MARK)
	    //创建zone,并以skb->mark为zone id
		return nf_ct_zone_init(tmp, skb->mark/*采用mark做为zone id*/, tmpl->zone.dir/*使用模板上的zone 方向*/, 0);
#endif
	//使用模板对应的zone
	return nf_ct_zone(tmpl);
}

//设置ct的zone
static inline void nf_ct_zone_add(struct nf_conn *ct,
				  const struct nf_conntrack_zone *zone)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	ct->zone = *zone;
#endif
}

static inline bool nf_ct_zone_matches_dir(const struct nf_conntrack_zone *zone,
					  enum ip_conntrack_dir dir)
{
	return zone->dir & (1 << dir);
}

static inline u16 nf_ct_zone_id(const struct nf_conntrack_zone *zone,
				enum ip_conntrack_dir dir)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	return nf_ct_zone_matches_dir(zone, dir) ?
	       zone->id : NF_CT_DEFAULT_ZONE_ID;
#else
	return NF_CT_DEFAULT_ZONE_ID;
#endif
}

/*检查两者zone id是否匹配*/
static inline bool nf_ct_zone_equal(const struct nf_conn *a,
				    const struct nf_conntrack_zone *b,
				    enum ip_conntrack_dir dir)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
    //检查zone id是否匹配
	return nf_ct_zone_id(nf_ct_zone(a), dir) ==
	       nf_ct_zone_id(b, dir);
#else
	return true;
#endif
}

static inline bool nf_ct_zone_equal_any(const struct nf_conn *a,
					const struct nf_conntrack_zone *b)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	return nf_ct_zone(a)->id == b->id;
#else
	return true;
#endif
}

#endif /* _NF_CONNTRACK_ZONES_H */
