// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* -
 * net/sched/act_ct.c  Connection Tracking action
 *
 * Authors:   Paul Blakey <paulb@mellanox.com>
 *            Yossi Kuperman <yossiku@mellanox.com>
 *            Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/act_api.h>
#include <net/ip.h>
#include <net/ipv6_frag.h>
#include <uapi/linux/tc_act/tc_ct.h>
#include <net/tc_act/tc_ct.h>

#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#include <uapi/linux/netfilter/nf_nat.h>

static struct workqueue_struct *act_ct_wq;
/*每个zone一个hashtable*/
static struct rhashtable zones_ht;
static DEFINE_MUTEX(zones_mutex);

struct tcf_ct_flow_table {
	struct rhash_head node; /* In zones tables */

	struct rcu_work rwork;
	struct nf_flowtable nf_ft;/*flowtable指针*/
	refcount_t ref;
	u16 zone;

	bool dying;
};

static const struct rhashtable_params zones_params = {
	.head_offset = offsetof(struct tcf_ct_flow_table, node),
	.key_offset = offsetof(struct tcf_ct_flow_table, zone),
	.key_len = sizeof_field(struct tcf_ct_flow_table, zone),
	.automatic_shrinking = true,
};

static struct flow_action_entry *
tcf_ct_flow_table_flow_action_get_next(struct flow_action *flow_action)
{
	int i = flow_action->num_entries++;

	return &flow_action->entries[i];
}

static void tcf_ct_add_mangle_action(struct flow_action *action,
				     enum flow_action_mangle_base htype,
				     u32 offset,
				     u32 mask,
				     u32 val)
{
	struct flow_action_entry *entry;

	entry = tcf_ct_flow_table_flow_action_get_next(action);
	entry->id = FLOW_ACTION_MANGLE;
	entry->mangle.htype = htype;
	entry->mangle.mask = ~mask;
	entry->mangle.offset = offset;
	entry->mangle.val = val;
}

/* The following nat helper functions check if the inverted reverse tuple
 * (target) is different then the current dir tuple - meaning nat for ports
 * and/or ip is needed, and add the relevant mangle actions.
 */
static void
tcf_ct_flow_table_add_action_nat_ipv4(const struct nf_conntrack_tuple *tuple,
				      struct nf_conntrack_tuple target,
				      struct flow_action *action)
{
    /*指定ipv4 src/dst地址转换*/
	if (memcmp(&target.src.u3, &tuple->src.u3, sizeof(target.src.u3)))
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_IP4,
					 offsetof(struct iphdr, saddr),
					 0xFFFFFFFF,
					 be32_to_cpu(target.src.u3.ip));
	if (memcmp(&target.dst.u3, &tuple->dst.u3, sizeof(target.dst.u3)))
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_IP4,
					 offsetof(struct iphdr, daddr),
					 0xFFFFFFFF,
					 be32_to_cpu(target.dst.u3.ip));
}

static void
tcf_ct_add_ipv6_addr_mangle_action(struct flow_action *action,
				   union nf_inet_addr *addr,
				   u32 offset)
{
	int i;

	for (i = 0; i < sizeof(struct in6_addr) / sizeof(u32); i++)
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_IP6,
					 i * sizeof(u32) + offset,
					 0xFFFFFFFF, be32_to_cpu(addr->ip6[i]));
}

static void
tcf_ct_flow_table_add_action_nat_ipv6(const struct nf_conntrack_tuple *tuple,
				      struct nf_conntrack_tuple target,
				      struct flow_action *action)
{
	if (memcmp(&target.src.u3, &tuple->src.u3, sizeof(target.src.u3)))
		tcf_ct_add_ipv6_addr_mangle_action(action, &target.src.u3,
						   offsetof(struct ipv6hdr,
							    saddr));
	if (memcmp(&target.dst.u3, &tuple->dst.u3, sizeof(target.dst.u3)))
		tcf_ct_add_ipv6_addr_mangle_action(action, &target.dst.u3,
						   offsetof(struct ipv6hdr,
							    daddr));
}

/*指定tcp src/dst port转换*/
static void
tcf_ct_flow_table_add_action_nat_tcp(const struct nf_conntrack_tuple *tuple,
				     struct nf_conntrack_tuple target,
				     struct flow_action *action)
{
	__be16 target_src = target.src.u.tcp.port;
	__be16 target_dst = target.dst.u.tcp.port;

	if (target_src != tuple->src.u.tcp.port)
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_TCP,
					 offsetof(struct tcphdr, source),
					 0xFFFF, be16_to_cpu(target_src));
	if (target_dst != tuple->dst.u.tcp.port)
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_TCP,
					 offsetof(struct tcphdr, dest),
					 0xFFFF, be16_to_cpu(target_dst));
}

//指定udp src/dst port转换
static void
tcf_ct_flow_table_add_action_nat_udp(const struct nf_conntrack_tuple *tuple,
				     struct nf_conntrack_tuple target,
				     struct flow_action *action)
{
	__be16 target_src = target.src.u.udp.port;
	__be16 target_dst = target.dst.u.udp.port;

	if (target_src != tuple->src.u.udp.port)
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_UDP,
					 offsetof(struct udphdr, source),
					 0xFFFF, be16_to_cpu(target_src));
	if (target_dst != tuple->dst.u.udp.port)
		tcf_ct_add_mangle_action(action, FLOW_ACT_MANGLE_HDR_TYPE_UDP,
					 offsetof(struct udphdr, dest),
					 0xFFFF, be16_to_cpu(target_dst));
}

static void tcf_ct_flow_table_add_action_meta(struct nf_conn *ct,
					      enum ip_conntrack_dir dir,
					      struct flow_action *action)
{
	struct nf_conn_labels *ct_labels;
	struct flow_action_entry *entry;
	enum ip_conntrack_info ctinfo;
	u32 *act_ct_labels;

	entry = tcf_ct_flow_table_flow_action_get_next(action);
	entry->id = FLOW_ACTION_CT_METADATA;
#if IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)
	entry->ct_metadata.mark = ct->mark;
#endif
	ctinfo = dir == IP_CT_DIR_ORIGINAL ? IP_CT_ESTABLISHED :
					     IP_CT_ESTABLISHED_REPLY;
	/* aligns with the CT reference on the SKB nf_ct_set */
	entry->ct_metadata.cookie = (unsigned long)ct | ctinfo;
	entry->ct_metadata.orig_dir = dir == IP_CT_DIR_ORIGINAL;

	/*填充ct的labels*/
	act_ct_labels = entry->ct_metadata.labels;
	ct_labels = nf_ct_labels_find(ct);
	if (ct_labels)
		memcpy(act_ct_labels, ct_labels->bits, NF_CT_LABELS_MAX_SIZE);
	else
		memset(act_ct_labels, 0, NF_CT_LABELS_MAX_SIZE);
}

static int tcf_ct_flow_table_add_action_nat(struct net *net,
					    struct nf_conn *ct,
					    enum ip_conntrack_dir dir,
					    struct flow_action *action)
{
	const struct nf_conntrack_tuple *tuple = &ct->tuplehash[dir].tuple;
	struct nf_conntrack_tuple target;

	if (!(ct->status & IPS_NAT_MASK))
		return 0;

	nf_ct_invert_tuple(&target, &ct->tuplehash[!dir].tuple);

	/*地址转换*/
	switch (tuple->src.l3num) {
	case NFPROTO_IPV4:
		tcf_ct_flow_table_add_action_nat_ipv4(tuple, target,
						      action);
		break;
	case NFPROTO_IPV6:
		tcf_ct_flow_table_add_action_nat_ipv6(tuple, target,
						      action);
		break;
	default:
		return -EOPNOTSUPP;
	}

	/*端口转换*/
	switch (nf_ct_protonum(ct)) {
	case IPPROTO_TCP:
		tcf_ct_flow_table_add_action_nat_tcp(tuple, target, action);
		break;
	case IPPROTO_UDP:
		tcf_ct_flow_table_add_action_nat_udp(tuple, target, action);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

/*转换flow的action*/
static int tcf_ct_flow_table_fill_actions(struct net *net,
					  const struct flow_offload *flow,
					  enum flow_offload_tuple_dir tdir,
					  struct nf_flow_rule *flow_rule)
{
	struct flow_action *action = &flow_rule->rule->action;
	int num_entries = action->num_entries;
	struct nf_conn *ct = flow->ct;
	enum ip_conntrack_dir dir;
	int i, err;

	switch (tdir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		dir = IP_CT_DIR_ORIGINAL;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		dir = IP_CT_DIR_REPLY;
		break;
	default:
		return -EOPNOTSUPP;
	}

	err = tcf_ct_flow_table_add_action_nat(net, ct, dir, action);
	if (err)
		goto err_nat;

	tcf_ct_flow_table_add_action_meta(ct, dir, action);
	return 0;

err_nat:
	/* Clear filled actions */
	for (i = num_entries; i < action->num_entries; i++)
		memset(&action->entries[i], 0, sizeof(action->entries[i]));
	action->num_entries = num_entries;

	return err;
}

/*指定flowtable类型为ct*/
static struct nf_flowtable_type flowtable_ct = {
	.action		= tcf_ct_flow_table_fill_actions,
	.owner		= THIS_MODULE,
};

/*依据params创建ct_ft*/
static int tcf_ct_flow_table_get(struct tcf_ct_params *params)
{
	struct tcf_ct_flow_table *ct_ft;
	int err = -ENOMEM;

	mutex_lock(&zones_mutex);
	/*如果params已存在，则返回*/
	ct_ft = rhashtable_lookup_fast(&zones_ht, &params->zone, zones_params);
	if (ct_ft && refcount_inc_not_zero(&ct_ft->ref))
		goto out_unlock;

	/*申请ct flow table*/
	ct_ft = kzalloc(sizeof(*ct_ft), GFP_KERNEL);
	if (!ct_ft)
		goto err_alloc;
	refcount_set(&ct_ft->ref, 1);

	/*将ct_ft加入到zones_ht中*/
	ct_ft->zone = params->zone;
	err = rhashtable_insert_fast(&zones_ht, &ct_ft->node, zones_params);
	if (err)
		goto err_insert;

	/*设置flowtable的ct type*/
	ct_ft->nf_ft.type = &flowtable_ct;
	ct_ft->nf_ft.flags |= NF_FLOWTABLE_HW_OFFLOAD |
			      NF_FLOWTABLE_COUNTER;
	/*初始化flow table*/
	err = nf_flow_table_init(&ct_ft->nf_ft);
	if (err)
		goto err_init;

	__module_get(THIS_MODULE);
out_unlock:
	params->ct_ft = ct_ft;
	params->nf_ft = &ct_ft->nf_ft;
	mutex_unlock(&zones_mutex);

	return 0;

err_init:
	rhashtable_remove_fast(&zones_ht, &ct_ft->node, zones_params);
err_insert:
	kfree(ct_ft);
err_alloc:
	mutex_unlock(&zones_mutex);
	return err;
}

static void tcf_ct_flow_table_cleanup_work(struct work_struct *work)
{
	struct tcf_ct_flow_table *ct_ft;

	ct_ft = container_of(to_rcu_work(work), struct tcf_ct_flow_table,
			     rwork);
	nf_flow_table_free(&ct_ft->nf_ft);
	kfree(ct_ft);

	module_put(THIS_MODULE);
}

static void tcf_ct_flow_table_put(struct tcf_ct_params *params)
{
	struct tcf_ct_flow_table *ct_ft = params->ct_ft;

	if (refcount_dec_and_test(&params->ct_ft->ref)) {
	    /*将ct_ft节点自zones_ht中移除*/
		rhashtable_remove_fast(&zones_ht, &ct_ft->node, zones_params);
		INIT_RCU_WORK(&ct_ft->rwork, tcf_ct_flow_table_cleanup_work);
		/*将ct_ft加入到act_ct_wq*/
		queue_rcu_work(act_ct_wq, &ct_ft->rwork);
	}
}

/*向flowtable中添加flow_offload_entry，并促使其向驱动进行offload*/
static void tcf_ct_flow_table_add(struct tcf_ct_flow_table *ct_ft,
				  struct nf_conn *ct,
				  bool tcp)
{
	struct flow_offload *entry;
	int err;

	/*ct已卸载跳过*/
	if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status))
		return;

	/*创建并填充ct对应的flow_offload entry*/
	entry = flow_offload_alloc(ct);
	if (!entry) {
		WARN_ON_ONCE(1);
		goto err_alloc;
	}

	/*针对tcp,由于卸载后窗口检查容易出错，故放宽此检查*/
	if (tcp) {
		ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	/*将flow offload entry加入到flow table*/
	err = flow_offload_add(&ct_ft->nf_ft, entry);
	if (err)
		goto err_add;

	return;

err_add:
	flow_offload_free(entry);
err_alloc:
	clear_bit(IPS_OFFLOAD_BIT, &ct->status);
}

static void tcf_ct_flow_table_process_conn(struct tcf_ct_flow_table *ct_ft,
					   struct nf_conn *ct,
					   enum ip_conntrack_info ctinfo)
{
	bool tcp = false;

	//只处理est,est_reply
	if (ctinfo != IP_CT_ESTABLISHED && ctinfo != IP_CT_ESTABLISHED_REPLY)
		return;

	switch (nf_ct_protonum(ct)) {
	case IPPROTO_TCP:
		tcp = true;
		if (ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED)
		    /*tcp状态必须达到estable状态*/
			return;
		break;
	case IPPROTO_UDP:
	    /*udp流量无要求*/
		break;
	default:
		return;
	}

	/*如果ct有helper,且需要seq调整，则不将其加入流表*/
	if (nf_ct_ext_exist(ct, NF_CT_EXT_HELPER) ||
	    ct->status & IPS_SEQ_ADJUST)
		return;

	/*向flowtable中加入此ct,触发卸载*/
	tcf_ct_flow_table_add(ct_ft, ct, tcp);
}

//解析tcp/udp报文，填充tuple
static bool
tcf_ct_flow_table_fill_tuple_ipv4(struct sk_buff *skb,
				  struct flow_offload_tuple *tuple/*出参，待填充的元组信息*/,
				  struct tcphdr **tcph/*出参，如为tcp协议，则返回tcp头指针*/)
{
	struct flow_ports *ports;
	unsigned int thoff;
	struct iphdr *iph;

	/*使ip头可平坦访问*/
	if (!pskb_network_may_pull(skb, sizeof(*iph)))
		return false;

	iph = ip_hdr(skb);
	thoff = iph->ihl * 4;

	/*ip为分片报文或者ip头存在选项，则返回false*/
	if (ip_is_fragment(iph) ||
	    unlikely(thoff != sizeof(struct iphdr)))
		return false;

	/*非tcp,udp协议返回false*/
	if (iph->protocol != IPPROTO_TCP &&
	    iph->protocol != IPPROTO_UDP)
		return false;

	/*ttl过小*/
	if (iph->ttl <= 1)
		return false;

	/*使l4头部可访问*/
	if (!pskb_network_may_pull(skb, iph->protocol == IPPROTO_TCP ?
					thoff + sizeof(struct tcphdr) :
					thoff + sizeof(*ports)))
		return false;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP)
		*tcph = (void *)(skb_network_header(skb) + thoff);

	ports = (struct flow_ports *)(skb_network_header(skb) + thoff);
	tuple->src_v4.s_addr = iph->saddr;
	tuple->dst_v4.s_addr = iph->daddr;
	tuple->src_port = ports->source;
	tuple->dst_port = ports->dest;
	tuple->l3proto = AF_INET;
	tuple->l4proto = iph->protocol;

	return true;
}

//解析ipv6报文，填充tuple
static bool
tcf_ct_flow_table_fill_tuple_ipv6(struct sk_buff *skb,
				  struct flow_offload_tuple *tuple/*出参，待填充tuple*/,
				  struct tcphdr **tcph/*出参，如为tcp协议，则指向tcp头部*/)
{
	struct flow_ports *ports;
	struct ipv6hdr *ip6h;
	unsigned int thoff;

	//获取ipv6头部
	if (!pskb_network_may_pull(skb, sizeof(*ip6h)))
		return false;

	ip6h = ipv6_hdr(skb);

	//只容许下一层为tcp/udp
	if (ip6h->nexthdr != IPPROTO_TCP &&
	    ip6h->nexthdr != IPPROTO_UDP)
		return false;

	if (ip6h->hop_limit <= 1)
		return false;

	thoff = sizeof(*ip6h);
	if (!pskb_network_may_pull(skb, ip6h->nexthdr == IPPROTO_TCP ?
					thoff + sizeof(struct tcphdr) :
					thoff + sizeof(*ports)))
		return false;

	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr == IPPROTO_TCP)
		*tcph = (void *)(skb_network_header(skb) + thoff);

	//填充tuple
	ports = (struct flow_ports *)(skb_network_header(skb) + thoff);
	tuple->src_v6 = ip6h->saddr;
	tuple->dst_v6 = ip6h->daddr;
	tuple->src_port = ports->source;
	tuple->dst_port = ports->dest;
	tuple->l3proto = AF_INET6;
	tuple->l4proto = ip6h->nexthdr;

	return true;
}

static bool tcf_ct_flow_table_lookup(struct tcf_ct_params *p,
				     struct sk_buff *skb,
				     u8 family)
{
	struct nf_flowtable *nf_ft = &p->ct_ft->nf_ft;
	struct flow_offload_tuple_rhash *tuplehash;
	struct flow_offload_tuple tuple = {};
	enum ip_conntrack_info ctinfo;
	struct tcphdr *tcph = NULL;
	struct flow_offload *flow;
	struct nf_conn *ct;
	u8 dir;

	/* Previously seen or loopback */
	ct = nf_ct_get(skb, &ctinfo);
	if ((ct && !nf_ct_is_template(ct)) || ctinfo == IP_CT_UNTRACKED)
		return false;

	//解析报文元组信息;如不支持解析，返回false
	switch (family) {
	case NFPROTO_IPV4:
		if (!tcf_ct_flow_table_fill_tuple_ipv4(skb, &tuple, &tcph))
			return false;
		break;
	case NFPROTO_IPV6:
		if (!tcf_ct_flow_table_fill_tuple_ipv6(skb, &tuple, &tcph))
			return false;
		break;
	default:
		return false;
	}

	/*如不存在tuplehash,返回false*/
	tuplehash = flow_offload_lookup(nf_ft, &tuple);
	if (!tuplehash)
		return false;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
	ct = flow->ct;

	/*tcp报文，且包含fin,rst标记时，将flow标记为teardown状态*/
	if (tcph && (unlikely(tcph->fin || tcph->rst))) {
		flow_offload_teardown(flow);
		return false;
	}

	//flow已存在，如为原方向，则为est;否则反方向，则为est_reply
	ctinfo = dir == FLOW_OFFLOAD_DIR_ORIGINAL ? IP_CT_ESTABLISHED :
						    IP_CT_ESTABLISHED_REPLY;

	/*刷新netfilter表中的flow*/
	flow_offload_refresh(nf_ft, flow);
	nf_conntrack_get(&ct->ct_general);
	/*状态更新*/
	nf_ct_set(skb, ct, ctinfo);
	/*统计更新*/
	if (nf_ft->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(ct, dir, skb->len);

	return true;
}

static int tcf_ct_flow_tables_init(void)
{
	return rhashtable_init(&zones_ht, &zones_params);
}

static void tcf_ct_flow_tables_uninit(void)
{
	rhashtable_destroy(&zones_ht);
}

static struct tc_action_ops act_ct_ops;
static unsigned int ct_net_id;

struct tc_ct_action_net {
	struct tc_action_net tn; /* Must be first */
	bool labels;
};

/* Determine whether skb->_nfct is equal to the result of conntrack lookup. */
//检测当前skb中缓存的ct是否与待查询的ct相同，如果相同返回true,否则返回false
static bool tcf_ct_skb_nfct_cached(struct net *net, struct sk_buff *skb,
				   u16 zone_id, bool force)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	//取skb的链接跟踪
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
	    /*如果没有对应的ct，则直接返回*/
		return false;

	//有ct,且与ct不属于同一个net namespace，返回false
	if (!net_eq(net, read_pnet(&ct->ct_net)))
		return false;

	//zone id不相同
	if (nf_ct_zone(ct)->id != zone_id)
		return false;

	/* Force conntrack entry direction. */
	//当前有ct,但当前报文方向非original,如果给定force,则将其移除
	if (force && CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
	    /*移除ct，且将其置为untracked*/
		if (nf_ct_is_confirmed(ct))
			nf_ct_kill(ct);

		nf_conntrack_put(&ct->ct_general);
		nf_ct_set(skb, NULL, IP_CT_UNTRACKED);

		return false;
	}

	/*可以复用ct*/
	return true;
}

/* Trim the skb to the length specified by the IP/IPv6 header,
 * removing any trailing lower-layer padding. This prepares the skb
 * for higher-layer processing that assumes skb->len excludes padding
 * (such as nf_ip_checksum). The caller needs to pull the skb to the
 * network header, and ensure ip_hdr/ipv6_hdr points to valid data.
 */
static int tcf_ct_skb_network_trim(struct sk_buff *skb, int family)
{
	unsigned int len;
	int err;

	switch (family) {
	case NFPROTO_IPV4:
		len = ntohs(ip_hdr(skb)->tot_len);
		break;
	case NFPROTO_IPV6:
		len = sizeof(struct ipv6hdr)
			+ ntohs(ipv6_hdr(skb)->payload_len);
		break;
	default:
		len = skb->len;
	}

	err = pskb_trim_rcsum(skb, len);

	return err;
}

static u8 tcf_ct_skb_nf_family(struct sk_buff *skb)
{
	u8 family = NFPROTO_UNSPEC;

	switch (skb_protocol(skb, true)) {
	case htons(ETH_P_IP):
		family = NFPROTO_IPV4;
		break;
	case htons(ETH_P_IPV6):
		family = NFPROTO_IPV6;
		break;
	default:
		break;
	}

	return family;
}

//检查skb是否为ipv4分片报文
static int tcf_ct_ipv4_is_fragment(struct sk_buff *skb, bool *frag/*出参，是否为分片报文*/)
{
	unsigned int len;

	len =  skb_network_offset(skb) + sizeof(struct iphdr);
	if (unlikely(skb->len < len))
	    /*ip头部不完整，报错*/
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, len)))
	    /*使ip头部平坦失败*/
		return -ENOMEM;

	*frag = ip_is_fragment(ip_hdr(skb));
	return 0;
}

/*检查skb是否为ipv6分片*/
static int tcf_ct_ipv6_is_fragment(struct sk_buff *skb, bool *frag)
{
	unsigned int flags = 0, len, payload_ofs = 0;
	unsigned short frag_off;
	int nexthdr;

	len =  skb_network_offset(skb) + sizeof(struct ipv6hdr);
	if (unlikely(skb->len < len))
	    /*报文长度不足ipv6*/
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, len)))
	    /*报文长度平坦失败*/
		return -ENOMEM;

	nexthdr = ipv6_find_hdr(skb, &payload_ofs, -1, &frag_off, &flags);
	if (unlikely(nexthdr < 0))
		return -EPROTO;

	*frag = flags & IP6_FH_F_FRAG;
	return 0;
}

/*ct前执行分片重组*/
static int tcf_ct_handle_fragments(struct net *net, struct sk_buff *skb,
				   u8 family, u16 zone, bool *defrag)
{
	enum ip_conntrack_info ctinfo;
	struct qdisc_skb_cb cb;
	struct nf_conn *ct;
	int err = 0;
	bool frag;

	/* Previously seen (loopback)? Ignore. */
	ct = nf_ct_get(skb, &ctinfo);
	if ((ct && !nf_ct_is_template(ct)) || ctinfo == IP_CT_UNTRACKED)
		return 0;

	/*确定当前报文是否为分片报文*/
	if (family == NFPROTO_IPV4)
		err = tcf_ct_ipv4_is_fragment(skb, &frag);
	else
		err = tcf_ct_ipv6_is_fragment(skb, &frag);
	if (err || !frag)
	    /*解析出错或者报文非分片，则返回*/
		return err;

	skb_get(skb);
	cb = *qdisc_skb_cb(skb);

	//处理ipv4/ipv6分片重组
	if (family == NFPROTO_IPV4) {
		enum ip_defrag_users user = IP_DEFRAG_CONNTRACK_IN + zone;

		memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
		local_bh_disable();
		err = ip_defrag(net, skb, user);
		local_bh_enable();
		if (err && err != -EINPROGRESS)
			return err;

		if (!err) {
			*defrag = true;
			cb.mru = IPCB(skb)->frag_max_size;
		}
	} else { /* NFPROTO_IPV6 */
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6)
		enum ip6_defrag_users user = IP6_DEFRAG_CONNTRACK_IN + zone;

		memset(IP6CB(skb), 0, sizeof(struct inet6_skb_parm));
		err = nf_ct_frag6_gather(net, skb, user);
		if (err && err != -EINPROGRESS)
			goto out_free;

		if (!err) {
			*defrag = true;
			cb.mru = IP6CB(skb)->frag_max_size;
		}
#else
		err = -EOPNOTSUPP;
		goto out_free;
#endif
	}

	*qdisc_skb_cb(skb) = cb;
	skb_clear_hash(skb);
	skb->ignore_df = 1;
	return err;

out_free:
	kfree_skb(skb);
	return err;
}

static void tcf_ct_params_free(struct rcu_head *head)
{
	struct tcf_ct_params *params = container_of(head,
						    struct tcf_ct_params, rcu);

	tcf_ct_flow_table_put(params);

	if (params->tmpl)
		nf_conntrack_put(&params->tmpl->ct_general);
	kfree(params);
}

#if IS_ENABLED(CONFIG_NF_NAT)
/* Modelled after nf_nat_ipv[46]_fn().
 * range is only used for new, uninitialized NAT state.
 * Returns either NF_ACCEPT or NF_DROP.
 */
static int ct_nat_execute(struct sk_buff *skb, struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  const struct nf_nat_range2 *range,
			  enum nf_nat_manip_type maniptype)
{
	__be16 proto = skb_protocol(skb, true);
	int hooknum, err = NF_ACCEPT;

	/* See HOOK2MANIP(). */
	//确定在哪个钩子点做
	if (maniptype == NF_NAT_MANIP_SRC)
		hooknum = NF_INET_LOCAL_IN; /* Source NAT */
	else
		hooknum = NF_INET_LOCAL_OUT; /* Destination NAT */

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
	    	//主要是icmp嵌套报文nat转换
		if (proto == htons(ETH_P_IP) &&
		    ip_hdr(skb)->protocol == IPPROTO_ICMP) {
		    //icmp期待创建session响应方向报文的nat处理
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   hooknum))
				err = NF_DROP;
			goto out;
		} else if (IS_ENABLED(CONFIG_IPV6) && proto == htons(ETH_P_IPV6)) {
		        //ipv6 icmpv6 nat处理
			__be16 frag_off;
			u8 nexthdr = ipv6_hdr(skb)->nexthdr;
			int hdrlen = ipv6_skip_exthdr(skb,
						      sizeof(struct ipv6hdr),
						      &nexthdr, &frag_off);

			if (hdrlen >= 0 && nexthdr == IPPROTO_ICMPV6) {
				if (!nf_nat_icmpv6_reply_translation(skb, ct,
								     ctinfo,
								     hooknum,
								     hdrlen))
					err = NF_DROP;
				goto out;
			}
		}
		/* Non-ICMP, fall thru to initialize if needed. */
		fallthrough;
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
	    //检查是否需要做nat，如果没有做完，则做。
		if (!nf_nat_initialized(ct, maniptype)) {
			/* Initialize according to the NAT action. */
			err = (range && range->flags & NF_NAT_RANGE_MAP_IPS)
				/* Action is set up to establish a new
				 * mapping.
				 */
				? nf_nat_setup_info(ct, range, maniptype)
				: nf_nat_alloc_null_binding(ct, hooknum);
			if (err != NF_ACCEPT)
				goto out;
		}
		break;

	case IP_CT_ESTABLISHED:
	case IP_CT_ESTABLISHED_REPLY:
		break;

	default:
		err = NF_DROP;
		goto out;
	}

	err = nf_nat_packet(ct, ctinfo, hooknum, skb);
out:
	return err;
}
#endif /* CONFIG_NF_NAT */

//为ct设置mark
static void tcf_ct_act_set_mark(struct nf_conn *ct, u32 mark, u32 mask)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)
	u32 new_mark;

	if (!mask)
		return;

	new_mark = mark | (ct->mark & ~(mask));
	if (ct->mark != new_mark) {
		ct->mark = new_mark;
		if (nf_ct_is_confirmed(ct))
			nf_conntrack_event_cache(IPCT_MARK, ct);
	}
#endif
}

//为ct设置lables
static void tcf_ct_act_set_labels(struct nf_conn *ct,
				  u32 *labels,
				  u32 *labels_m)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)
	size_t labels_sz = sizeof_field(struct tcf_ct_params, labels);

	if (!memchr_inv(labels_m, 0, labels_sz))
		return;

	nf_connlabels_replace(ct, labels, labels_m, 4);
#endif
}

//针对ct做nat处理
static int tcf_ct_act_nat(struct sk_buff *skb,
			  struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  int ct_action,
			  struct nf_nat_range2 *range,
			  bool commit)
{
#if IS_ENABLED(CONFIG_NF_NAT)
	int err;
	enum nf_nat_manip_type maniptype;

	/*非nat act，则跳出*/
	if (!(ct_action & TCA_CT_ACT_NAT))
		return NF_ACCEPT;

	/* Add NAT extension if not confirmed yet. */
	//ct没有confirmed且添加nat扩展不成功，则丢包，不能nat
	if (!nf_ct_is_confirmed(ct) && !nf_ct_nat_ext_add(ct))
		return NF_DROP;   /* Can't NAT. */

	//确定做何种nat
	//非new状态，且已做snat,dnat，则反方向与正方向状态不一致
	if (ctinfo != IP_CT_NEW && (ct->status & IPS_NAT_MASK) &&
	    (ctinfo != IP_CT_RELATED || commit)) {
		/* NAT an established or related connection like before. */
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
			/* This is the REPLY direction for a connection
			 * for which NAT was applied in the forward
			 * direction.  Do the reverse NAT.
			 */
			maniptype = ct->status & IPS_SRC_NAT
				? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC;
		else
			maniptype = ct->status & IPS_SRC_NAT
				? NF_NAT_MANIP_SRC : NF_NAT_MANIP_DST;
	} else if (ct_action & TCA_CT_ACT_NAT_SRC) {
		maniptype = NF_NAT_MANIP_SRC;
	} else if (ct_action & TCA_CT_ACT_NAT_DST) {
		maniptype = NF_NAT_MANIP_DST;
	} else {
		return NF_ACCEPT;
	}

	//做第一次nat
	err = ct_nat_execute(skb, ct, ctinfo, range, maniptype/*要做的nat类型*/);

	//如果ct要求做两次nat,则本次依据上次处理情况，做另一个nat
	if (err == NF_ACCEPT &&
	    ct->status & IPS_SRC_NAT && ct->status & IPS_DST_NAT) {
		if (maniptype == NF_NAT_MANIP_SRC)
			maniptype = NF_NAT_MANIP_DST;
		else
			maniptype = NF_NAT_MANIP_SRC;

		//做第二次nat
		err = ct_nat_execute(skb, ct, ctinfo, range, maniptype);
	}
	return err;
#else
	return NF_ACCEPT;
#endif
}

//执行ct action
//用于为skb关联其对应的ct;或者为skb创建对应的ct
static int tcf_ct_act(struct sk_buff *skb, const struct tc_action *a,
		      struct tcf_result *res)
{
    /*取报文所在的net namespace*/
	struct net *net = dev_net(skb->dev);
	bool cached, commit, clear, force;
	enum ip_conntrack_info ctinfo;
	struct tcf_ct *c = to_ct(a);
	struct nf_conn *tmpl = NULL;
	struct nf_hook_state state;
	int nh_ofs, err, retval;
	struct tcf_ct_params *p;
	/*是否需要跳过向flow table下发此ct*/
	bool skip_add = false;
	bool defrag = false;
	struct nf_conn *ct;
	u8 family;

	p = rcu_dereference_bh(c->params);

	/*取此ct action的处理结果*/
	retval = READ_ONCE(c->tcf_action);
	/*向kernel添加新的ct*/
	commit = p->ct_action & TCA_CT_ACT_COMMIT;
	/*清除skb的ct信息，ct将被移除*/
	clear = p->ct_action & TCA_CT_ACT_CLEAR;
	/*只容许源方向建立ct*/
	force = p->ct_action & TCA_CT_ACT_FORCE;
	/*取此ct的连接跟踪模板*/
	tmpl = p->tmpl;

	/*更新此action的lastuse时间及firstuse时间*/
	tcf_lastuse_update(&c->tcf_tm);

	if (clear) {
		qdisc_skb_cb(skb)->post_ct = false;
		//如果需要清除ct,则将skb中的ct清除掉
		ct = nf_ct_get(skb, &ctinfo);
		if (ct) {
		    /*减少ct引用计数，将skb置为未tracked*/
			nf_conntrack_put(&ct->ct_general);
			nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
		}

		/*此时为untracked标记*/
		goto out_clear;
	}

	//目前仅支持对ipv4,ipv6进行ct创建
	family = tcf_ct_skb_nf_family(skb);
	if (family == NFPROTO_UNSPEC)
		goto drop;

	/* The conntrack module expects to be working at L3.
	 * We also try to pull the IPv4/6 header to linear area
	 */
	//使skb->data指向l3头部
	nh_ofs = skb_network_offset(skb);
	skb_pull_rcsum(skb, nh_ofs);

	//处理分片重组
	err = tcf_ct_handle_fragments(net, skb, family, p->zone, &defrag);
	if (err == -EINPROGRESS) {
	    /*报文被分片表缓存*/
		retval = TC_ACT_STOLEN;
		goto out;
	}
	if (err)
		goto drop;

	err = tcf_ct_skb_network_trim(skb, family);
	if (err)
		goto drop;

	/* If we are recirculating packets to match on ct fields and
	 * committing with a separate ct action, then we don't need to
	 * actually run the packet through conntrack twice unless it's for a
	 * different zone.
	 */
	//如上面注释所言，确定是否使用skb中缓存的，如与待查询的一致，则返回true
	cached = tcf_ct_skb_nfct_cached(net, skb, p->zone, force);
	if (!cached) {
	    //当前skb没有对应的ct或者已创建的ct,但不符合当前ct action要求,再次执行action创建
		if (!commit && tcf_ct_flow_table_lookup(p, skb, family)) {
		    /*不要求commit,且netfilter table中已存在，跳过创建*/
			skip_add = true;
			goto do_nat;
		}

		//没有缓存,也没有查找到，执行创建
		/* Associate skb with specified zone. */
		if (tmpl) {
			ct = nf_ct_get(skb, &ctinfo);
			if (skb_nfct(skb))
				nf_conntrack_put(skb_nfct(skb));
			nf_conntrack_get(&tmpl->ct_general);
			/*将此ct模板赋给skb,并置new状态*/
			nf_ct_set(skb, tmpl, IP_CT_NEW);
		}

		//模拟netfilter上下文，创建ct
		state.hook = NF_INET_PRE_ROUTING;
		state.net = net;
		state.pf = family;
		err = nf_conntrack_in(skb, &state);
		if (err != NF_ACCEPT)
			goto out_push;
	}

do_nat:
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto out_push;
	nf_ct_deliver_cached_events(ct);

	//针对ct做报文nat
	err = tcf_ct_act_nat(skb, ct, ctinfo, p->ct_action, &p->range, commit);
	if (err != NF_ACCEPT)
		goto drop;

	if (commit) {
	    /*XXX在这个位置做ct数量限制*/
		//如果指定了commit,则将ct置为confirm,并设置packet对应的mark,labels
		tcf_ct_act_set_mark(ct, p->mark, p->mark_mask);
		tcf_ct_act_set_labels(ct, p->labels, p->labels_mask);

		/* This will take care of sending queued events
		 * even if the connection is already confirmed.
		 */
		//confirm此ct
		nf_conntrack_confirm(skb);
	} else if (!skip_add) {
	    /*不需要跳过添加，则向flowtable中添加此ct*/
		tcf_ct_flow_table_process_conn(p->ct_ft, ct, ctinfo);
	}

out_push:
    /*还原到原来的skb->data*/
	skb_push_rcsum(skb, nh_ofs);

out:
	qdisc_skb_cb(skb)->post_ct = true;
out_clear:
    	/*更新报文统计计数及字节数*/
	tcf_action_update_bstats(&c->common, skb);
	if (defrag)
		qdisc_skb_cb(skb)->pkt_len = skb->len;
	return retval;

drop:
	tcf_action_inc_drop_qstats(&c->common);
	return TC_ACT_SHOT;
}

static const struct nla_policy ct_policy[TCA_CT_MAX + 1] = {
	[TCA_CT_ACTION] = { .type = NLA_U16 },
	[TCA_CT_PARMS] = NLA_POLICY_EXACT_LEN(sizeof(struct tc_ct)),
	[TCA_CT_ZONE] = { .type = NLA_U16 },
	[TCA_CT_MARK] = { .type = NLA_U32 },
	[TCA_CT_MARK_MASK] = { .type = NLA_U32 },
	[TCA_CT_LABELS] = { .type = NLA_BINARY,
			    .len = 128 / BITS_PER_BYTE },
	[TCA_CT_LABELS_MASK] = { .type = NLA_BINARY,
				 .len = 128 / BITS_PER_BYTE },
	[TCA_CT_NAT_IPV4_MIN] = { .type = NLA_U32 },
	[TCA_CT_NAT_IPV4_MAX] = { .type = NLA_U32 },
	[TCA_CT_NAT_IPV6_MIN] = NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[TCA_CT_NAT_IPV6_MAX] = NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[TCA_CT_NAT_PORT_MIN] = { .type = NLA_U16 },
	[TCA_CT_NAT_PORT_MAX] = { .type = NLA_U16 },
};

static int tcf_ct_fill_params_nat(struct tcf_ct_params *p,
				  struct tc_ct *parm,
				  struct nlattr **tb,
				  struct netlink_ext_ack *extack)
{
	struct nf_nat_range2 *range;

	/*action没有指定做nat,退出*/
	if (!(p->ct_action & TCA_CT_ACT_NAT))
		return 0;

	/*没有配置nat功能，退出*/
	if (!IS_ENABLED(CONFIG_NF_NAT)) {
		NL_SET_ERR_MSG_MOD(extack, "Netfilter nat isn't enabled in kernel");
		return -EOPNOTSUPP;
	}

	/*当前仅支持snat,dnat两种功能*/
	if (!(p->ct_action & (TCA_CT_ACT_NAT_SRC | TCA_CT_ACT_NAT_DST)))
		return 0;

	/*当前不支持snat与dnat出时存在*/
	if ((p->ct_action & TCA_CT_ACT_NAT_SRC) &&
	    (p->ct_action & TCA_CT_ACT_NAT_DST)) {
		NL_SET_ERR_MSG_MOD(extack, "dnat and snat can't be enabled at the same time");
		return -EOPNOTSUPP;
	}

	range = &p->range;
	if (tb[TCA_CT_NAT_IPV4_MIN]) {
	    /*ipv4地址段*/
		struct nlattr *max_attr = tb[TCA_CT_NAT_IPV4_MAX];

		p->ipv4_range = true;
		range->flags |= NF_NAT_RANGE_MAP_IPS;
		range->min_addr.ip =
			nla_get_in_addr(tb[TCA_CT_NAT_IPV4_MIN]);

		range->max_addr.ip = max_attr ?
				     nla_get_in_addr(max_attr) :
				     range->min_addr.ip;
	} else if (tb[TCA_CT_NAT_IPV6_MIN]) {
	    /*ipv6地址段*/
		struct nlattr *max_attr = tb[TCA_CT_NAT_IPV6_MAX];

		p->ipv4_range = false;
		range->flags |= NF_NAT_RANGE_MAP_IPS;
		range->min_addr.in6 =
			nla_get_in6_addr(tb[TCA_CT_NAT_IPV6_MIN]);

		range->max_addr.in6 = max_attr ?
				      nla_get_in6_addr(max_attr) :
				      range->min_addr.in6;
	}

	/*port范围填充*/
	if (tb[TCA_CT_NAT_PORT_MIN]) {
		range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
		range->min_proto.all = nla_get_be16(tb[TCA_CT_NAT_PORT_MIN]);

		range->max_proto.all = tb[TCA_CT_NAT_PORT_MAX] ?
				       nla_get_be16(tb[TCA_CT_NAT_PORT_MAX]) :
				       range->min_proto.all;
	}

	return 0;
}

/*设置ct key与val*/
static void tcf_ct_set_key_val(struct nlattr **tb,
			       void *val/*出参，tb中val_type对应的值*/, int val_type,
			       void *mask/*出参，tb中mask_type对应的值*/, int mask_type,
			       int len/*val类型的值长度*/)
{
    /*val_type如不存在，则返回*/
	if (!tb[val_type])
		return;

	/*利用val_type填充val*/
	nla_memcpy(val, tb[val_type], len);

	/*mask如不存在，则不再处理*/
	if (!mask)
		return;

	/*如果mask_type存在，则按mask_type要求填充，否则填充为全ff*/
	if (mask_type == TCA_CT_UNSPEC || !tb[mask_type])
		memset(mask, 0xff, len);
	else
		nla_memcpy(mask, tb[mask_type], len);
}

static int tcf_ct_fill_params(struct net *net,
			      struct tcf_ct_params *p/*出参*/,
			      struct tc_ct *parm,
			      struct nlattr **tb,
			      struct netlink_ext_ack *extack)
{
    /*取当前net namespace中ct的私有数据*/
	struct tc_ct_action_net *tn = net_generic(net, ct_net_id);
	struct nf_conntrack_zone zone;
	struct nf_conn *tmpl;
	int err;

	p->zone = NF_CT_DEFAULT_ZONE_ID;

	tcf_ct_set_key_val(tb,
			   &p->ct_action, TCA_CT_ACTION,
			   NULL, TCA_CT_UNSPEC,
			   sizeof(p->ct_action));

	/*要求清除ct*/
	if (p->ct_action & TCA_CT_ACT_CLEAR)
		return 0;

	/*填充nat参数*/
	err = tcf_ct_fill_params_nat(p, parm, tb, extack);
	if (err)
		return err;

	/*ct mark填充*/
	if (tb[TCA_CT_MARK]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack mark isn't enabled.");
			return -EOPNOTSUPP;
		}
		tcf_ct_set_key_val(tb,
				   &p->mark, TCA_CT_MARK,
				   &p->mark_mask, TCA_CT_MARK_MASK,
				   sizeof(p->mark));
	}

	/*ct labels填充*/
	if (tb[TCA_CT_LABELS]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack labels isn't enabled.");
			return -EOPNOTSUPP;
		}

		if (!tn->labels) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to set connlabel length");
			return -EOPNOTSUPP;
		}
		tcf_ct_set_key_val(tb,
				   p->labels, TCA_CT_LABELS,
				   p->labels_mask, TCA_CT_LABELS_MASK,
				   sizeof(p->labels));
	}

	/*ct zone填充*/
	if (tb[TCA_CT_ZONE]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_ZONES)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack zones isn't enabled.");
			return -EOPNOTSUPP;
		}

		tcf_ct_set_key_val(tb,
				   &p->zone, TCA_CT_ZONE,
				   NULL, TCA_CT_UNSPEC,
				   sizeof(p->zone));
	}

	if (p->zone == NF_CT_DEFAULT_ZONE_ID)
		return 0;

	/*初始化zone,申请tmpl连接*/
	nf_ct_zone_init(&zone, p->zone, NF_CT_DEFAULT_ZONE_DIR, 0);
	tmpl = nf_ct_tmpl_alloc(net, &zone, GFP_KERNEL);
	if (!tmpl) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to allocate conntrack template");
		return -ENOMEM;
	}

	//设置此ct confirmed
	__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
	/*增加此ct引用计数*/
	nf_conntrack_get(&tmpl->ct_general);
	/*设置ct模板*/
	p->tmpl = tmpl;

	return 0;
}

static int tcf_ct_init(struct net *net, struct nlattr *nla,
		       struct nlattr *est, struct tc_action **a,
		       int replace, int bind, bool rtnl_held,
		       struct tcf_proto *tp, u32 flags,
		       struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, ct_net_id);
	struct tcf_ct_params *params = NULL;
	struct nlattr *tb[TCA_CT_MAX + 1];
	struct tcf_chain *goto_ch = NULL;
	struct tc_ct *parm;
	struct tcf_ct *c;
	int err, res = 0;
	u32 index;

	if (!nla) {
		NL_SET_ERR_MSG_MOD(extack, "Ct requires attributes to be passed");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_CT_MAX, nla, ct_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_CT_PARMS]) {
		NL_SET_ERR_MSG_MOD(extack, "Missing required ct parameters");
		return -EINVAL;
	}
	parm = nla_data(tb[TCA_CT_PARMS]);
	index = parm->index;
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;

	if (!err) {
		err = tcf_idr_create_from_flags(tn, index, est, a,
						&act_ct_ops, bind, flags);
		if (err) {
			tcf_idr_cleanup(tn, index);
			return err;
		}
		res = ACT_P_CREATED;
	} else {
		if (bind)
			return 0;

		if (!replace) {
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
	}
	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto cleanup;

	c = to_ct(*a);

	/*申请并填充ct parameter*/
	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (unlikely(!params)) {
		err = -ENOMEM;
		goto cleanup;
	}

	err = tcf_ct_fill_params(net, params/*出参*/, parm, tb, extack);
	if (err)
		goto cleanup;

	err = tcf_ct_flow_table_get(params);
	if (err)
		goto cleanup;

	spin_lock_bh(&c->tcf_lock);
	/*设置a,要求跳到那个chain*/
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
	params = rcu_replace_pointer(c->params, params,
				     lockdep_is_held(&c->tcf_lock));
	spin_unlock_bh(&c->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	if (params)
		call_rcu(&params->rcu, tcf_ct_params_free);

	return res;

cleanup:
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	kfree(params);
	tcf_idr_release(*a, bind);
	return err;
}

static void tcf_ct_cleanup(struct tc_action *a)
{
	struct tcf_ct_params *params;
	struct tcf_ct *c = to_ct(a);

	params = rcu_dereference_protected(c->params, 1);
	if (params)
		call_rcu(&params->rcu, tcf_ct_params_free);
}

static int tcf_ct_dump_key_val(struct sk_buff *skb,
			       void *val, int val_type,
			       void *mask, int mask_type,
			       int len)
{
	int err;

	if (mask && !memchr_inv(mask, 0, len))
		return 0;

	err = nla_put(skb, val_type, len, val);
	if (err)
		return err;

	if (mask_type != TCA_CT_UNSPEC) {
		err = nla_put(skb, mask_type, len, mask);
		if (err)
			return err;
	}

	return 0;
}

static int tcf_ct_dump_nat(struct sk_buff *skb, struct tcf_ct_params *p)
{
	struct nf_nat_range2 *range = &p->range;

	if (!(p->ct_action & TCA_CT_ACT_NAT))
		return 0;

	if (!(p->ct_action & (TCA_CT_ACT_NAT_SRC | TCA_CT_ACT_NAT_DST)))
		return 0;

	if (range->flags & NF_NAT_RANGE_MAP_IPS) {
		if (p->ipv4_range) {
			if (nla_put_in_addr(skb, TCA_CT_NAT_IPV4_MIN,
					    range->min_addr.ip))
				return -1;
			if (nla_put_in_addr(skb, TCA_CT_NAT_IPV4_MAX,
					    range->max_addr.ip))
				return -1;
		} else {
			if (nla_put_in6_addr(skb, TCA_CT_NAT_IPV6_MIN,
					     &range->min_addr.in6))
				return -1;
			if (nla_put_in6_addr(skb, TCA_CT_NAT_IPV6_MAX,
					     &range->max_addr.in6))
				return -1;
		}
	}

	if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		if (nla_put_be16(skb, TCA_CT_NAT_PORT_MIN,
				 range->min_proto.all))
			return -1;
		if (nla_put_be16(skb, TCA_CT_NAT_PORT_MAX,
				 range->max_proto.all))
			return -1;
	}

	return 0;
}

static inline int tcf_ct_dump(struct sk_buff *skb, struct tc_action *a,
			      int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_ct *c = to_ct(a);
	struct tcf_ct_params *p;

	struct tc_ct opt = {
		.index   = c->tcf_index,
		.refcnt  = refcount_read(&c->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&c->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

	spin_lock_bh(&c->tcf_lock);
	p = rcu_dereference_protected(c->params,
				      lockdep_is_held(&c->tcf_lock));
	opt.action = c->tcf_action;

	if (tcf_ct_dump_key_val(skb,
				&p->ct_action, TCA_CT_ACTION,
				NULL, TCA_CT_UNSPEC,
				sizeof(p->ct_action)))
		goto nla_put_failure;

	if (p->ct_action & TCA_CT_ACT_CLEAR)
		goto skip_dump;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_MARK) &&
	    tcf_ct_dump_key_val(skb,
				&p->mark, TCA_CT_MARK,
				&p->mark_mask, TCA_CT_MARK_MASK,
				sizeof(p->mark)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS) &&
	    tcf_ct_dump_key_val(skb,
				p->labels, TCA_CT_LABELS,
				p->labels_mask, TCA_CT_LABELS_MASK,
				sizeof(p->labels)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_ZONES) &&
	    tcf_ct_dump_key_val(skb,
				&p->zone, TCA_CT_ZONE,
				NULL, TCA_CT_UNSPEC,
				sizeof(p->zone)))
		goto nla_put_failure;

	if (tcf_ct_dump_nat(skb, p))
		goto nla_put_failure;

skip_dump:
	if (nla_put(skb, TCA_CT_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	tcf_tm_dump(&t, &c->tcf_tm);
	if (nla_put_64bit(skb, TCA_CT_TM, sizeof(t), &t, TCA_CT_PAD))
		goto nla_put_failure;
	spin_unlock_bh(&c->tcf_lock);

	return skb->len;
nla_put_failure:
	spin_unlock_bh(&c->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_ct_walker(struct net *net, struct sk_buff *skb,
			 struct netlink_callback *cb, int type,
			 const struct tc_action_ops *ops,
			 struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, ct_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_ct_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, ct_net_id);

	return tcf_idr_search(tn, a, index);
}

static void tcf_stats_update(struct tc_action *a, u64 bytes, u64 packets,
			     u64 drops, u64 lastuse, bool hw)
{
	struct tcf_ct *c = to_ct(a);

	tcf_action_update_stats(a, bytes, packets, drops, hw);
	c->tcf_tm.lastuse = max_t(u64, c->tcf_tm.lastuse, lastuse);
}

static struct tc_action_ops act_ct_ops = {
	.kind		=	"ct",
	.id		=	TCA_ID_CT,
	.owner		=	THIS_MODULE,
	.act		=	tcf_ct_act,
	.dump		=	tcf_ct_dump,
	.init		=	tcf_ct_init,
	.cleanup	=	tcf_ct_cleanup,
	.walk		=	tcf_ct_walker,
	.lookup		=	tcf_ct_search,
	.stats_update	=	tcf_stats_update,
	.size		=	sizeof(struct tcf_ct),
};

/*ct action在pernet时需要的初始化*/
static __net_init int ct_init_net(struct net *net)
{
	unsigned int n_bits = sizeof_field(struct tcf_ct_params, labels) * 8;
	struct tc_ct_action_net *tn = net_generic(net, ct_net_id);

	/*ct是否包含lables*/
	if (nf_connlabels_get(net, n_bits - 1)) {
		tn->labels = false;
		pr_err("act_ct: Failed to set connlabels length");
	} else {
		tn->labels = true;
	}

	return tc_action_net_init(net, &tn->tn, &act_ct_ops);
}

static void __net_exit ct_exit_net(struct list_head *net_list)
{
	struct net *net;

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list) {
		struct tc_ct_action_net *tn = net_generic(net, ct_net_id);

		if (tn->labels)
			nf_connlabels_put(net);
	}
	rtnl_unlock();

	tc_action_net_exit(net_list, ct_net_id);
}

/*ct action在per net namespace时需要执行的操作*/
static struct pernet_operations ct_net_ops = {
	.init = ct_init_net,
	.exit_batch = ct_exit_net,
	.id   = &ct_net_id,
	.size = sizeof(struct tc_ct_action_net),
};

//注册ct action
static int __init ct_init_module(void)
{
	int err;

	act_ct_wq = alloc_ordered_workqueue("act_ct_workqueue", 0);
	if (!act_ct_wq)
		return -ENOMEM;

	err = tcf_ct_flow_tables_init();
	if (err)
		goto err_tbl_init;

	/*注册ct action*/
	err = tcf_register_action(&act_ct_ops, &ct_net_ops);
	if (err)
		goto err_register;

	static_branch_inc(&tcf_frag_xmit_count);

	return 0;

err_register:
	tcf_ct_flow_tables_uninit();
err_tbl_init:
	destroy_workqueue(act_ct_wq);
	return err;
}

static void __exit ct_cleanup_module(void)
{
	static_branch_dec(&tcf_frag_xmit_count);
	tcf_unregister_action(&act_ct_ops, &ct_net_ops);
	tcf_ct_flow_tables_uninit();
	destroy_workqueue(act_ct_wq);
}

module_init(ct_init_module);
module_exit(ct_cleanup_module);
MODULE_AUTHOR("Paul Blakey <paulb@mellanox.com>");
MODULE_AUTHOR("Yossi Kuperman <yossiku@mellanox.com>");
MODULE_AUTHOR("Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>");
MODULE_DESCRIPTION("Connection tracking action");
MODULE_LICENSE("GPL v2");
