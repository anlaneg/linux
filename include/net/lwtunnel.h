/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_LWTUNNEL_H
#define __NET_LWTUNNEL_H 1

#include <linux/lwtunnel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/route.h>

#define LWTUNNEL_HASH_BITS   7
#define LWTUNNEL_HASH_SIZE   (1 << LWTUNNEL_HASH_BITS)

/* lw tunnel state flags */
#define LWTUNNEL_STATE_OUTPUT_REDIRECT	BIT(0)
#define LWTUNNEL_STATE_INPUT_REDIRECT	BIT(1)
#define LWTUNNEL_STATE_XMIT_REDIRECT	BIT(2)

enum {
	LWTUNNEL_XMIT_DONE,
	LWTUNNEL_XMIT_CONTINUE,
};


struct lwtunnel_state {
	__u16		type;
	__u16		flags;
	__u16		headroom;
	atomic_t	refcnt;
	/*保存原始的路由output函数*/
	int		(*orig_output)(struct net *net, struct sock *sk, struct sk_buff *skb);
	/*保存原始的路由input函数*/
	int		(*orig_input)(struct sk_buff *);
	struct		rcu_head rcu;
	/*私有结构*/
	__u8            data[];
};

struct lwtunnel_encap_ops {
    /*隧道初始化，配置来源于ip route*/
	int (*build_state)(struct net *net, struct nlattr *encap/*轻量隧道配置*/,
			   unsigned int family, const void *cfg/*从属的路由配置*/,
			   struct lwtunnel_state **ts/*出参，依据encap,cfg产生隧道state*/,
			   struct netlink_ext_ack *extack);
	/*销毁隧道state时使用*/
	void (*destroy_state)(struct lwtunnel_state *lws);
	/*路由output钩子点，由传输层到网络层*/
	int (*output)(struct net *net, struct sock *sk, struct sk_buff *skb);
	/*路由input钩子点，由网络层到传输层*/
	int (*input)(struct sk_buff *skb);
	/*netlink封装，将tunnel信息填充到skb*/
	int (*fill_encap)(struct sk_buff *skb,
			  struct lwtunnel_state *lwtstate);
	/*netlink封装时，tunnel信息占用的内存长度*/
	int (*get_encap_size)(struct lwtunnel_state *lwtstate);
	/*比对两个tunnel state是否相等（方便删除时匹配用）*/
	int (*cmp_encap)(struct lwtunnel_state *a, struct lwtunnel_state *b);
	/*ip报文逐片发送时，调用此钩子*/
	int (*xmit)(struct sk_buff *skb);

	struct module *owner;
};

#ifdef CONFIG_LWTUNNEL

DECLARE_STATIC_KEY_FALSE(nf_hooks_lwtunnel_enabled);

void lwtstate_free(struct lwtunnel_state *lws);

static inline struct lwtunnel_state *
lwtstate_get(struct lwtunnel_state *lws)
{
	if (lws)
		atomic_inc(&lws->refcnt);

	return lws;
}

static inline void lwtstate_put(struct lwtunnel_state *lws)
{
	if (!lws)
		return;

	if (atomic_dec_and_test(&lws->refcnt))
		lwtstate_free(lws);
}

/*检查是否为轻量级tunnel的output redirect*/
static inline bool lwtunnel_output_redirect(struct lwtunnel_state *lwtstate)
{
	if (lwtstate && (lwtstate->flags & LWTUNNEL_STATE_OUTPUT_REDIRECT))
		return true;

	return false;
}

/*检查是否为轻量级tunnel的input redirect*/
static inline bool lwtunnel_input_redirect(struct lwtunnel_state *lwtstate)
{
	if (lwtstate && (lwtstate->flags & LWTUNNEL_STATE_INPUT_REDIRECT))
		return true;

	return false;
}

static inline bool lwtunnel_xmit_redirect(struct lwtunnel_state *lwtstate)
{
	if (lwtstate && (lwtstate->flags & LWTUNNEL_STATE_XMIT_REDIRECT))
		return true;

	return false;
}

static inline unsigned int lwtunnel_headroom(struct lwtunnel_state *lwtstate,
					     unsigned int mtu)
{
	if ((lwtunnel_xmit_redirect(lwtstate) ||
	     lwtunnel_output_redirect(lwtstate)) && lwtstate->headroom < mtu)
		return lwtstate->headroom;

	return 0;
}

int lwtunnel_encap_add_ops(const struct lwtunnel_encap_ops *op,
			   unsigned int num);
int lwtunnel_encap_del_ops(const struct lwtunnel_encap_ops *op,
			   unsigned int num);
int lwtunnel_valid_encap_type(u16 encap_type,
			      struct netlink_ext_ack *extack);
int lwtunnel_valid_encap_type_attr(struct nlattr *attr, int len,
				   struct netlink_ext_ack *extack);
int lwtunnel_build_state(struct net *net, u16 encap_type,
			 struct nlattr *encap,
			 unsigned int family, const void *cfg,
			 struct lwtunnel_state **lws,
			 struct netlink_ext_ack *extack);
int lwtunnel_fill_encap(struct sk_buff *skb, struct lwtunnel_state *lwtstate,
			int encap_attr, int encap_type_attr);
int lwtunnel_get_encap_size(struct lwtunnel_state *lwtstate);
struct lwtunnel_state *lwtunnel_state_alloc(int hdr_len);
int lwtunnel_cmp_encap(struct lwtunnel_state *a, struct lwtunnel_state *b);
int lwtunnel_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int lwtunnel_input(struct sk_buff *skb);
int lwtunnel_xmit(struct sk_buff *skb);
int bpf_lwt_push_ip_encap(struct sk_buff *skb, void *hdr, u32 len,
			  bool ingress);

static inline void lwtunnel_set_redirect(struct dst_entry *dst)
{
	if (lwtunnel_output_redirect(dst->lwtstate)) {
		dst->lwtstate->orig_output = dst->output;
		/*轻量级隧道执行output输出*/
		dst->output = lwtunnel_output;
	}
	if (lwtunnel_input_redirect(dst->lwtstate)) {
		dst->lwtstate->orig_input = dst->input;
		dst->input = lwtunnel_input;
	}
}
#else

static inline void lwtstate_free(struct lwtunnel_state *lws)
{
}

static inline struct lwtunnel_state *
lwtstate_get(struct lwtunnel_state *lws)
{
	return lws;
}

static inline void lwtstate_put(struct lwtunnel_state *lws)
{
}

static inline bool lwtunnel_output_redirect(struct lwtunnel_state *lwtstate)
{
	return false;
}

static inline bool lwtunnel_input_redirect(struct lwtunnel_state *lwtstate)
{
	return false;
}

static inline bool lwtunnel_xmit_redirect(struct lwtunnel_state *lwtstate)
{
	return false;
}

static inline void lwtunnel_set_redirect(struct dst_entry *dst)
{
}

static inline unsigned int lwtunnel_headroom(struct lwtunnel_state *lwtstate,
					     unsigned int mtu)
{
	return 0;
}

static inline int lwtunnel_encap_add_ops(const struct lwtunnel_encap_ops *op,
					 unsigned int num)
{
	return -EOPNOTSUPP;

}

static inline int lwtunnel_encap_del_ops(const struct lwtunnel_encap_ops *op,
					 unsigned int num)
{
	return -EOPNOTSUPP;
}

static inline int lwtunnel_valid_encap_type(u16 encap_type,
					    struct netlink_ext_ack *extack)
{
	NL_SET_ERR_MSG(extack, "CONFIG_LWTUNNEL is not enabled in this kernel");
	return -EOPNOTSUPP;
}
static inline int lwtunnel_valid_encap_type_attr(struct nlattr *attr, int len,
						 struct netlink_ext_ack *extack)
{
	/* return 0 since we are not walking attr looking for
	 * RTA_ENCAP_TYPE attribute on nexthops.
	 */
	return 0;
}

static inline int lwtunnel_build_state(struct net *net, u16 encap_type,
				       struct nlattr *encap,
				       unsigned int family, const void *cfg,
				       struct lwtunnel_state **lws,
				       struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

static inline int lwtunnel_fill_encap(struct sk_buff *skb,
				      struct lwtunnel_state *lwtstate,
				      int encap_attr, int encap_type_attr)
{
	return 0;
}

static inline int lwtunnel_get_encap_size(struct lwtunnel_state *lwtstate)
{
	return 0;
}

static inline struct lwtunnel_state *lwtunnel_state_alloc(int hdr_len)
{
	return NULL;
}

static inline int lwtunnel_cmp_encap(struct lwtunnel_state *a,
				     struct lwtunnel_state *b)
{
	return 0;
}

static inline int lwtunnel_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

static inline int lwtunnel_input(struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

static inline int lwtunnel_xmit(struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_LWTUNNEL */

#define MODULE_ALIAS_RTNL_LWT(encap_type) MODULE_ALIAS("rtnl-lwt-" __stringify(encap_type))

#endif /* __NET_LWTUNNEL_H */
