/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NFNETLINK_H
#define _NFNETLINK_H

#include <linux/netlink.h>
#include <linux/capability.h>
#include <net/netlink.h>
#include <uapi/linux/netfilter/nfnetlink.h>

struct nfnl_callback {
    //在subsys加锁情况下执行的call
	int (*call)(struct net *net, struct sock *nl, struct sk_buff *skb,
		    const struct nlmsghdr *nlh,
		    const struct nlattr * const cda[],
		    struct netlink_ext_ack *extack);
	//在rcu读锁情况下执行的call
	int (*call_rcu)(struct net *net, struct sock *nl, struct sk_buff *skb,
			const struct nlmsghdr *nlh,
			const struct nlattr * const cda[],
			struct netlink_ext_ack *extack);
	//在批处理型消息情况下执行的call
	int (*call_batch)(struct net *net, struct sock *nl, struct sk_buff *skb,
			  const struct nlmsghdr *nlh,
			  const struct nlattr * const cda[],
			  struct netlink_ext_ack *extack);
	//支持的netlink属性策略（用于属性解析）
	const struct nla_policy *policy;	/* netlink attribute policy */
	//支持的netlink属性最大数目
	const u_int16_t attr_count;		/* number of nlattr's */
};

enum nfnl_abort_action {
	NFNL_ABORT_NONE		= 0,
	NFNL_ABORT_AUTOLOAD,
	NFNL_ABORT_VALIDATE,
};

//定义netfilter netlink子系统
struct nfnetlink_subsystem {
    	//子系统名称
	const char *name;
	//子系统id号
	__u8 subsys_id;			/* nfnetlink subsystem ID */
	/*回调函数数组大小*/
	__u8 cb_count;			/* number of callbacks */
	//回调函数数组（通过cb_id处理相应消息）
	const struct nfnl_callback *cb;	/* callback for individual types */
	struct module *owner;
	//用于处理批量消息时的变更提交
	int (*commit)(struct net *net, struct sk_buff *skb);
	//变更中止
	int (*abort)(struct net *net, struct sk_buff *skb,
		     enum nfnl_abort_action action);
	//无论最终是commit或者abort，均用于执行cleanup
	void (*cleanup)(struct net *net);
	//批量型消息时，校验genid
	bool (*valid_genid)(struct net *net, u32 genid);
};

int nfnetlink_subsys_register(const struct nfnetlink_subsystem *n);
int nfnetlink_subsys_unregister(const struct nfnetlink_subsystem *n);

int nfnetlink_has_listeners(struct net *net, unsigned int group);
int nfnetlink_send(struct sk_buff *skb, struct net *net, u32 portid,
		   unsigned int group, int echo, gfp_t flags);
int nfnetlink_set_err(struct net *net, u32 portid, u32 group, int error);
int nfnetlink_unicast(struct sk_buff *skb, struct net *net, u32 portid);

static inline u16 nfnl_msg_type(u8 subsys, u8 msg_type)
{
	return subsys << 8 | msg_type;
}

void nfnl_lock(__u8 subsys_id);
void nfnl_unlock(__u8 subsys_id);
#ifdef CONFIG_PROVE_LOCKING
bool lockdep_nfnl_is_held(__u8 subsys_id);
#else
static inline bool lockdep_nfnl_is_held(__u8 subsys_id)
{
	return true;
}
#endif /* CONFIG_PROVE_LOCKING */

#define MODULE_ALIAS_NFNL_SUBSYS(subsys) \
	MODULE_ALIAS("nfnetlink-subsys-" __stringify(subsys))

#endif	/* _NFNETLINK_H */
