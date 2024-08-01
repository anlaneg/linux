/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <linux/refcount.h>
#include <net/flow.h>
#include <net/rtnetlink.h>
#include <net/fib_notifier.h>
#include <linux/indirect_call_wrapper.h>

struct fib_kuid_range {
	kuid_t start;
	kuid_t end;
};

/*策略规则*/
struct fib_rule {
	struct list_head	list;
	int			iifindex;//inport对应的ifindex(为0时不匹配）
	int			oifindex;//outport对应的ifindex
	u32			mark;//mark，通过ip rule 中的fwmark指定
	u32			mark_mask;//mark的掩码
	u32			flags;
	u32			table;//规则从属于那个路由表
	u8			action;//规则的action（例如FR_ACT_GOTO）
	u8			l3mdev;
	u8                      proto;//路由协议类型
	u8			ip_proto;//4层协议号
	u32			target;//goto action时记录要跳转到哪个目标上继续查询
	__be64			tun_id;//隧道id号
	struct fib_rule __rcu	*ctarget;//跳转动作对应的rule
	struct net		*fr_net;//从属于那个namespace

	refcount_t		refcnt;
	/*规则对应的优先级*/
	u32			pref;
	int			suppress_ifgroup;
	int			suppress_prefixlen;
	char			iifname[IFNAMSIZ];//inport名称
	char			oifname[IFNAMSIZ];//outport名称
	struct fib_kuid_range	uid_range;//记录用户传入的范围
	struct fib_rule_port_range	sport_range;//源port范围
	struct fib_rule_port_range	dport_range;//目的port范围
	struct rcu_head		rcu;
};

struct fib_lookup_arg {
	void			*lookup_ptr;
	const void		*lookup_data;
	void			*result;/*保存查询到的路由结果*/
	struct fib_rule		*rule;/*保存命中的策略*/
	u32			table;
	int			flags;
#define FIB_LOOKUP_NOREF		1
#define FIB_LOOKUP_IGNORE_LINKSTATE	2
};

//不同协议族通过此结构定义其适合的策略路由
struct fib_rules_ops {
	//指明ops属于哪个协议族
	int			family;
	struct list_head	list;
	//规则大小（支持的规则结构体大小）
	int			rule_size;
	//此协议族地址大小（字节为单位）
	int			addr_size;
	int			unresolved_rules;
	int			nr_goto_rules;
	unsigned int		fib_rules_seq;

	//用于执行规则action
	int			(*action)(struct fib_rule *,
					  struct flowi *, int,
					  struct fib_lookup_arg *);
	//结果阻止，检查是否不想要的结果，如果是返回True
	bool			(*suppress)(struct fib_rule *, int,
					    struct fib_lookup_arg *);
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);
	//完成配置设置
	int			(*configure)(struct fib_rule *,
					     struct sk_buff *,
					     struct fib_rule_hdr *,
					     struct nlattr **,
					     struct netlink_ext_ack *);
	int			(*delete)(struct fib_rule *);
	/*给定规则fib_rule及fib_rule_hdr,检查两者是否相等*/
	int			(*compare)(struct fib_rule *,
					   struct fib_rule_hdr *,
					   struct nlattr **);
	int			(*fill)(struct fib_rule *, struct sk_buff *,
					struct fib_rule_hdr *);
	size_t			(*nlmsg_payload)(struct fib_rule *);

	/* Called after modifications to the rules set, must flush
	 * the route cache if one exists. */
	void			(*flush_cache)(struct fib_rules_ops *ops);

	int			nlgroup;
	struct list_head	rules_list;/*所有已配置的策略路由*/
	struct module		*owner;
	struct net		*fro_net;
	struct rcu_head		rcu;
};

struct fib_rule_notifier_info {
	struct fib_notifier_info info; /* must be first */
	struct fib_rule *rule;
};

//引用fib规则
static inline void fib_rule_get(struct fib_rule *rule)
{
	refcount_inc(&rule->refcnt);
}

static inline void fib_rule_put(struct fib_rule *rule)
{
	if (refcount_dec_and_test(&rule->refcnt))
		kfree_rcu(rule, rcu);
}

#ifdef CONFIG_NET_L3_MASTER_DEV
static inline u32 fib_rule_get_table(struct fib_rule *rule,
				     struct fib_lookup_arg *arg)
{
	/*l3mdev标记存在时，要查询的表为arg->table*/
	return rule->l3mdev ? arg->table : rule->table;
}
#else
//由fib_rule获取其对应的fib表编号
static inline u32 fib_rule_get_table(struct fib_rule *rule,
				     struct fib_lookup_arg *arg)
{
	return rule->table;
}
#endif

//取fib rule配置的表号
static inline u32 frh_get_table(struct fib_rule_hdr *frh, struct nlattr **nla)
{
	if (nla[FRA_TABLE])
		return nla_get_u32(nla[FRA_TABLE]);
	return frh->table;
}

static inline bool fib_rule_port_range_set(const struct fib_rule_port_range *range)
{
	return range->start != 0 && range->end != 0;
}

static inline bool fib_rule_port_inrange(const struct fib_rule_port_range *a,
					 __be16 port)
{
	return ntohs(port) >= a->start &&
		ntohs(port) <= a->end;
}

static inline bool fib_rule_port_range_valid(const struct fib_rule_port_range *a)
{
	return a->start != 0 && a->end != 0 && a->end < 0xffff &&
		a->start <= a->end;
}

static inline bool fib_rule_port_range_compare(struct fib_rule_port_range *a,
					       struct fib_rule_port_range *b)
{
	return a->start == b->start &&
		a->end == b->end;
}

static inline bool fib_rule_requires_fldissect(struct fib_rule *rule)
{
	return rule->iifindex != LOOPBACK_IFINDEX && (rule->ip_proto ||
		fib_rule_port_range_set(&rule->sport_range) ||
		fib_rule_port_range_set(&rule->dport_range));
}

struct fib_rules_ops *fib_rules_register(const struct fib_rules_ops *,
					 struct net *);
void fib_rules_unregister(struct fib_rules_ops *);

int fib_rules_lookup(struct fib_rules_ops *, struct flowi *, int flags,
		     struct fib_lookup_arg *);
int fib_default_rule_add(struct fib_rules_ops *, u32 pref, u32 table);
bool fib_rule_matchall(const struct fib_rule *rule);
int fib_rules_dump(struct net *net, struct notifier_block *nb, int family,
		   struct netlink_ext_ack *extack);
unsigned int fib_rules_seq_read(struct net *net, int family);

int fib_nl_newrule(struct sk_buff *skb, struct nlmsghdr *nlh,
		   struct netlink_ext_ack *extack);
int fib_nl_delrule(struct sk_buff *skb, struct nlmsghdr *nlh,
		   struct netlink_ext_ack *extack);

INDIRECT_CALLABLE_DECLARE(int fib6_rule_match(struct fib_rule *rule,
					    struct flowi *fl, int flags));
INDIRECT_CALLABLE_DECLARE(int fib4_rule_match(struct fib_rule *rule,
					    struct flowi *fl, int flags));

INDIRECT_CALLABLE_DECLARE(int fib6_rule_action(struct fib_rule *rule,
			    struct flowi *flp, int flags,
			    struct fib_lookup_arg *arg));
INDIRECT_CALLABLE_DECLARE(int fib4_rule_action(struct fib_rule *rule,
			    struct flowi *flp, int flags,
			    struct fib_lookup_arg *arg));

INDIRECT_CALLABLE_DECLARE(bool fib6_rule_suppress(struct fib_rule *rule,
						int flags,
						struct fib_lookup_arg *arg));
INDIRECT_CALLABLE_DECLARE(bool fib4_rule_suppress(struct fib_rule *rule,
						int flags,
						struct fib_lookup_arg *arg));
#endif
