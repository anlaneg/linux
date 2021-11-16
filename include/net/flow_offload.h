#ifndef _NET_FLOW_OFFLOAD_H
#define _NET_FLOW_OFFLOAD_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <net/flow_dissector.h>

struct flow_match {
	struct flow_dissector	*dissector;/*指向flow_key信息*/
	void			*mask;/*指向掩码*/
	void			*key;/*指向匹配条件*/
};

struct flow_match_meta {
	struct flow_dissector_key_meta *key, *mask;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key, *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key, *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key, *mask;
};

struct flow_match_vlan {
	struct flow_dissector_key_vlan *key, *mask;
};

struct flow_match_ipv4_addrs {
	struct flow_dissector_key_ipv4_addrs *key, *mask;
};

struct flow_match_ipv6_addrs {
	struct flow_dissector_key_ipv6_addrs *key, *mask;
};

struct flow_match_ip {
	struct flow_dissector_key_ip *key, *mask;
};

struct flow_match_ports {
	struct flow_dissector_key_ports *key, *mask;
};

struct flow_match_icmp {
	struct flow_dissector_key_icmp *key, *mask;
};

struct flow_match_tcp {
	struct flow_dissector_key_tcp *key, *mask;
};

struct flow_match_mpls {
	struct flow_dissector_key_mpls *key, *mask;
};

struct flow_match_enc_keyid {
	struct flow_dissector_key_keyid *key, *mask;
};

struct flow_match_enc_opts {
	struct flow_dissector_key_enc_opts *key, *mask;
};

struct flow_match_ct {
	struct flow_dissector_key_ct *key, *mask;
};

struct flow_rule;

void flow_rule_match_meta(const struct flow_rule *rule,
			  struct flow_match_meta *out);
void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out);
void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out);
void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out);
void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out);
void flow_rule_match_cvlan(const struct flow_rule *rule,
			   struct flow_match_vlan *out);
void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out);
void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out);
void flow_rule_match_ip(const struct flow_rule *rule,
			struct flow_match_ip *out);
void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out);
void flow_rule_match_tcp(const struct flow_rule *rule,
			 struct flow_match_tcp *out);
void flow_rule_match_icmp(const struct flow_rule *rule,
			  struct flow_match_icmp *out);
void flow_rule_match_mpls(const struct flow_rule *rule,
			  struct flow_match_mpls *out);
void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out);
void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out);
void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out);
void flow_rule_match_enc_ip(const struct flow_rule *rule,
			    struct flow_match_ip *out);
void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out);
void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out);
void flow_rule_match_enc_opts(const struct flow_rule *rule,
			      struct flow_match_enc_opts *out);
void flow_rule_match_ct(const struct flow_rule *rule,
			struct flow_match_ct *out);

enum flow_action_id {
	//接受报文
	FLOW_ACTION_ACCEPT		= 0,
	//报文丢弃
	FLOW_ACTION_DROP,
	FLOW_ACTION_TRAP,
	//chain跳转（需设置chain_index)
	FLOW_ACTION_GOTO,
	//报文重定向到设备（需要设置dev)
	FLOW_ACTION_REDIRECT,
	FLOW_ACTION_MIRRED,
	FLOW_ACTION_REDIRECT_INGRESS,
	FLOW_ACTION_MIRRED_INGRESS,
	//报文vlan添加(需要设置vlan)
	FLOW_ACTION_VLAN_PUSH,
	//报文vlan移除（无参数）
	FLOW_ACTION_VLAN_POP,
	//报文vlan修改（需要设置vlan)
	FLOW_ACTION_VLAN_MANGLE,
	//报文封装隧道（需要设置tunnel)
	FLOW_ACTION_TUNNEL_ENCAP,
	//报文解隧道（无参数）
	FLOW_ACTION_TUNNEL_DECAP,
	//直接修改某字段
	FLOW_ACTION_MANGLE,
	//在字段上加上某常量形成设置
	FLOW_ACTION_ADD,
	FLOW_ACTION_CSUM,
	FLOW_ACTION_MARK,
	FLOW_ACTION_PTYPE,
	FLOW_ACTION_PRIORITY,
	FLOW_ACTION_WAKE,
	FLOW_ACTION_QUEUE,
	FLOW_ACTION_SAMPLE,
	FLOW_ACTION_POLICE,
	FLOW_ACTION_CT,
	FLOW_ACTION_CT_METADATA,
	FLOW_ACTION_MPLS_PUSH,
	FLOW_ACTION_MPLS_POP,
	FLOW_ACTION_MPLS_MANGLE,
	FLOW_ACTION_GATE,
	FLOW_ACTION_PPPOE_PUSH,
	NUM_FLOW_ACTIONS,
};

/* This is mirroring enum pedit_header_type definition for easy mapping between
 * tc pedit action. Legacy TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK is mapped to
 * FLOW_ACT_MANGLE_UNSPEC, which is supported by no driver.
 */
enum flow_action_mangle_base {
	FLOW_ACT_MANGLE_UNSPEC		= 0,
	/*以太头更新*/
	FLOW_ACT_MANGLE_HDR_TYPE_ETH,
	/*ipv4头部更新*/
	FLOW_ACT_MANGLE_HDR_TYPE_IP4,
	/*ipv6头部更新*/
	FLOW_ACT_MANGLE_HDR_TYPE_IP6,
	/*tcp头部更新*/
	FLOW_ACT_MANGLE_HDR_TYPE_TCP,
	/*udp头部更新*/
	FLOW_ACT_MANGLE_HDR_TYPE_UDP,
};

enum flow_action_hw_stats_bit {
	FLOW_ACTION_HW_STATS_IMMEDIATE_BIT,
	FLOW_ACTION_HW_STATS_DELAYED_BIT,
	FLOW_ACTION_HW_STATS_DISABLED_BIT,

	FLOW_ACTION_HW_STATS_NUM_BITS
};

enum flow_action_hw_stats {
	FLOW_ACTION_HW_STATS_IMMEDIATE =
		BIT(FLOW_ACTION_HW_STATS_IMMEDIATE_BIT),
	FLOW_ACTION_HW_STATS_DELAYED = BIT(FLOW_ACTION_HW_STATS_DELAYED_BIT),
	FLOW_ACTION_HW_STATS_ANY = FLOW_ACTION_HW_STATS_IMMEDIATE |
				   FLOW_ACTION_HW_STATS_DELAYED,
	FLOW_ACTION_HW_STATS_DISABLED =
		BIT(FLOW_ACTION_HW_STATS_DISABLED_BIT),
	//不关心硬件中的统计信息
	FLOW_ACTION_HW_STATS_DONT_CARE = BIT(FLOW_ACTION_HW_STATS_NUM_BITS) - 1,
};

typedef void (*action_destr)(void *priv);

struct flow_action_cookie {
	u32 cookie_len;
	u8 cookie[];
};

struct flow_action_cookie *flow_action_cookie_create(void *data,
						     unsigned int len,
						     gfp_t gfp);
void flow_action_cookie_destroy(struct flow_action_cookie *cookie);

struct flow_action_entry {
	//action 类别
	enum flow_action_id		id;
	enum flow_action_hw_stats	hw_stats;
	action_destr			destructor;
	/*destructor回调的参数*/
	void				*destructor_priv;
	//action对应的参数
	union {
		//goto chain对应的chain_index
		u32			chain_index;	/* FLOW_ACTION_GOTO */

		//mirror,redirect对应的目标设备
		struct net_device	*dev;		/* FLOW_ACTION_REDIRECT */

		//vlan添加对应的参数
		struct {				/* FLOW_ACTION_VLAN */
			u16		vid;//vlan id
			__be16		proto;//vlan对应的ethertype
			u8		prio;//vlan优先级
		} vlan;
		struct {				/* FLOW_ACTION_MANGLE */
							/* FLOW_ACTION_ADD */
		    //修改的字段所处头部类型
			enum flow_action_mangle_base htype;
			//自头部位置到字段的偏移量
			u32		offset;
			u32		mask;
			//要设置的值
			u32		val;
		} mangle;
		//隧道封装参数
		struct ip_tunnel_info	*tunnel;	/* FLOW_ACTION_TUNNEL_ENCAP */
		//指出需要更新哪些层的checksum
		u32			csum_flags;	/* FLOW_ACTION_CSUM */

		u32			mark;		/* FLOW_ACTION_MARK */
		u16                     ptype;          /* FLOW_ACTION_PTYPE */
		u32			priority;	/* FLOW_ACTION_PRIORITY */
		struct {				/* FLOW_ACTION_QUEUE */
			u32		ctx;
			u32		index;
			u8		vf;
		} queue;

		struct {				/* FLOW_ACTION_SAMPLE */
			struct psample_group	*psample_group;
			u32			rate;
			u32			trunc_size;
			bool			truncate;
		} sample;

		struct {				/* FLOW_ACTION_POLICE */
			u32			index;
			u32			burst;
			u64			rate_bytes_ps;
			u64			burst_pkt;
			u64			rate_pkt_ps;
			u32			mtu;
		} police;
		struct {				/* FLOW_ACTION_CT */
			int action;
			u16 zone;
			struct nf_flowtable *flow_table;
		} ct;
		/*ct的metadata*/
		struct {
			unsigned long cookie;
			u32 mark;
			u32 labels[4];
			bool orig_dir;
		} ct_metadata;
		struct {				/* FLOW_ACTION_MPLS_PUSH */
			u32		label;
			__be16		proto;
			u8		tc;
			u8		bos;
			u8		ttl;
		} mpls_push;
		struct {				/* FLOW_ACTION_MPLS_POP */
			__be16		proto;
		} mpls_pop;
		struct {				/* FLOW_ACTION_MPLS_MANGLE */
			u32		label;
			u8		tc;
			u8		bos;
			u8		ttl;
		} mpls_mangle;
		struct {
			u32		index;
			s32		prio;
			u64		basetime;
			u64		cycletime;
			u64		cycletimeext;
			u32		num_entries;
			struct action_gate_entry *entries;
		} gate;
		struct {				/* FLOW_ACTION_PPPOE_PUSH */
			u16		sid;
		} pppoe;
	};
	struct flow_action_cookie *cookie; /* user defined action cookie */
};

struct flow_action {
	unsigned int			num_entries;//action数目
	struct flow_action_entry	entries[];/*记录flow动作*/
};

static inline bool flow_action_has_entries(const struct flow_action *action)
{
	return action->num_entries;
}

/**
 * flow_offload_has_one_action() - check if exactly one action is present
 * @action: tc filter flow offload action
 *
 * Returns true if exactly one action is present.
 */
static inline bool flow_offload_has_one_action(const struct flow_action *action)
{
	return action->num_entries == 1;
}

#define flow_action_for_each(__i, __act, __actions)			\
        for (__i = 0, __act = &(__actions)->entries[0];			\
	     __i < (__actions)->num_entries;				\
	     __act = &(__actions)->entries[++__i])

static inline bool
flow_action_mixed_hw_stats_check(const struct flow_action *action,
				 struct netlink_ext_ack *extack)
{
	const struct flow_action_entry *action_entry;
	u8 last_hw_stats;
	int i;

	if (flow_offload_has_one_action(action))
		return true;

	flow_action_for_each(i, action_entry, action) {
		if (i && action_entry->hw_stats != last_hw_stats) {
			NL_SET_ERR_MSG_MOD(extack, "Mixing HW stats types for actions is not supported");
			return false;
		}
		last_hw_stats = action_entry->hw_stats;
	}
	return true;
}

static inline const struct flow_action_entry *
flow_action_first_entry_get(const struct flow_action *action)
{
	WARN_ON(!flow_action_has_entries(action));
	return &action->entries[0];
}

static inline bool
__flow_action_hw_stats_check(const struct flow_action *action,
			     struct netlink_ext_ack *extack,
			     bool check_allow_bit,
			     enum flow_action_hw_stats_bit allow_bit)
{
	const struct flow_action_entry *action_entry;

	if (!flow_action_has_entries(action))
		return true;
	if (!flow_action_mixed_hw_stats_check(action, extack))
		return false;

	action_entry = flow_action_first_entry_get(action);

	/* Zero is not a legal value for hw_stats, catch anyone passing it */
	WARN_ON_ONCE(!action_entry->hw_stats);

	if (!check_allow_bit &&
	    ~action_entry->hw_stats & FLOW_ACTION_HW_STATS_ANY) {
		NL_SET_ERR_MSG_MOD(extack, "Driver supports only default HW stats type \"any\"");
		return false;
	} else if (check_allow_bit &&
		   !(action_entry->hw_stats & BIT(allow_bit))) {
		NL_SET_ERR_MSG_MOD(extack, "Driver does not support selected HW stats type");
		return false;
	}
	return true;
}

static inline bool
flow_action_hw_stats_check(const struct flow_action *action,
			   struct netlink_ext_ack *extack,
			   enum flow_action_hw_stats_bit allow_bit)
{
	return __flow_action_hw_stats_check(action, extack, true, allow_bit);
}

static inline bool
flow_action_basic_hw_stats_check(const struct flow_action *action,
				 struct netlink_ext_ack *extack)
{
	return __flow_action_hw_stats_check(action, extack, false, 0);
}

struct flow_rule {
    //规则的匹配情况
	struct flow_match	match;
	//规则的动作情况
	struct flow_action	action;
};

struct flow_rule *flow_rule_alloc(unsigned int num_actions);

//检查rule的match字段中是否有指定key
static inline bool flow_rule_match_key(const struct flow_rule *rule,
				       enum flow_dissector_key_id key)
{
	return dissector_uses_key(rule->match.dissector, key);
}

struct flow_stats {
	u64	pkts;
	u64	bytes;
	u64	drops;
	u64	lastused;
	enum flow_action_hw_stats used_hw_stats;
	bool used_hw_stats_valid;
};

static inline void flow_stats_update(struct flow_stats *flow_stats,
				     u64 bytes, u64 pkts,
				     u64 drops, u64 lastused,
				     enum flow_action_hw_stats used_hw_stats)
{
	flow_stats->pkts	+= pkts;
	flow_stats->bytes	+= bytes;
	flow_stats->drops	+= drops;
	flow_stats->lastused	= max_t(u64, flow_stats->lastused, lastused);

	/* The driver should pass value with a maximum of one bit set.
	 * Passing FLOW_ACTION_HW_STATS_ANY is invalid.
	 */
	WARN_ON(used_hw_stats == FLOW_ACTION_HW_STATS_ANY);
	flow_stats->used_hw_stats |= used_hw_stats;
	flow_stats->used_hw_stats_valid = true;
}

enum flow_block_command {
	FLOW_BLOCK_BIND,
	FLOW_BLOCK_UNBIND,
};

enum flow_block_binder_type {
	FLOW_BLOCK_BINDER_TYPE_UNSPEC,
	FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS,
	FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS,
	FLOW_BLOCK_BINDER_TYPE_RED_EARLY_DROP,
	FLOW_BLOCK_BINDER_TYPE_RED_MARK,
};

struct flow_block {
    //用于挂接flow_block_offload回调
	struct list_head cb_list;
};

struct netlink_ext_ack;

struct flow_block_offload {
	enum flow_block_command command;/*正在执行的cmd*/
	enum flow_block_binder_type binder_type;/*binder方向*/
	bool block_shared;/*是否为共享型block*/
	bool unlocked_driver_cb;
	struct net *net;/*bo所属的net namespace*/
	struct flow_block *block;
	struct list_head cb_list;
	struct list_head *driver_block_list;/*指明当前从属于驱动的哪个block_list*/
	struct netlink_ext_ack *extack;/*netlink应答信息*/
	struct Qdisc *sch;
	struct list_head *cb_list_head;
};

enum tc_setup_type;
typedef int flow_setup_cb_t(enum tc_setup_type type, void *type_data,
			    void *cb_priv);

struct flow_block_cb;

struct flow_block_indr {
    /*用于串接在flow_block_indr_list链上*/
	struct list_head		list;
	/*间接绑定的上层设备，例如vxlan_sys_4789*/
	struct net_device		*dev;
	struct Qdisc			*sch;
	/*间接绑定block方向类型*/
	enum flow_block_binder_type	binder_type;
	void				*data;
	/*间接回调的私有数据*/
	void				*cb_priv;
	/*当flow_block_indr被移除时调用*/
	void				(*cleanup)(struct flow_block_cb *block_cb);
};

struct flow_block_cb {
    /*用于将当前结构挂接在driver自已的链表上*/
	struct list_head	driver_list;
	/*用于挂接在flow_block_offload->cb_list上*/
	struct list_head	list;
	/*block回调函数*/
	flow_setup_cb_t		*cb;
	/*回调标识（私有数据），与cb合起来唯一确定flow_block_cb*/
	void			*cb_ident;
	/*block回调函数参数*/
	void			*cb_priv;
	/*此flow block callback被释放时调用*/
	void			(*release)(void *cb_priv);
	/*间接绑定参数情况*/
	struct flow_block_indr	indr;
	unsigned int		refcnt;
};

struct flow_block_cb *flow_block_cb_alloc(flow_setup_cb_t *cb,
					  void *cb_ident, void *cb_priv,
					  void (*release)(void *cb_priv));
struct flow_block_cb *flow_indr_block_cb_alloc(flow_setup_cb_t *cb,
					       void *cb_ident, void *cb_priv,
					       void (*release)(void *cb_priv),
					       struct flow_block_offload *bo,
					       struct net_device *dev,
					       struct Qdisc *sch, void *data,
					       void *indr_cb_priv,
					       void (*cleanup)(struct flow_block_cb *block_cb));
void flow_block_cb_free(struct flow_block_cb *block_cb);

struct flow_block_cb *flow_block_cb_lookup(struct flow_block *block,
					   flow_setup_cb_t *cb, void *cb_ident);

void *flow_block_cb_priv(struct flow_block_cb *block_cb);
void flow_block_cb_incref(struct flow_block_cb *block_cb);
unsigned int flow_block_cb_decref(struct flow_block_cb *block_cb);

//将block_cb挂接在offload->cb_list上
static inline void flow_block_cb_add(struct flow_block_cb *block_cb,
				     struct flow_block_offload *offload)
{
	list_add_tail(&block_cb->list, &offload->cb_list);
}

//将block_cb自offload->cb_list上移除
static inline void flow_block_cb_remove(struct flow_block_cb *block_cb,
					struct flow_block_offload *offload)
{
	list_move(&block_cb->list, &offload->cb_list);
}

static inline void flow_indr_block_cb_remove(struct flow_block_cb *block_cb,
					     struct flow_block_offload *offload)
{
	list_del(&block_cb->indr.list);
	list_move(&block_cb->list, &offload->cb_list);
}

bool flow_block_cb_is_busy(flow_setup_cb_t *cb, void *cb_ident,
			   struct list_head *driver_block_list);

int flow_block_cb_setup_simple(struct flow_block_offload *f,
			       struct list_head *driver_list,
			       flow_setup_cb_t *cb,
			       void *cb_ident, void *cb_priv, bool ingress_only);

enum flow_cls_command {
	FLOW_CLS_REPLACE,/*flow class的替换*/
	FLOW_CLS_DESTROY,
	FLOW_CLS_STATS,
	FLOW_CLS_TMPLT_CREATE,
	FLOW_CLS_TMPLT_DESTROY,
};

struct flow_cls_common_offload {
	u32 chain_index;/*chain索引*/
	__be16 protocol;
	u32 prio;
	struct netlink_ext_ack *extack;
};

struct flow_cls_offload {
	struct flow_cls_common_offload common;
	enum flow_cls_command command;
	unsigned long cookie;/*用于标识flow*/
	struct flow_rule *rule;
	struct flow_stats stats;
	u32 classid;
};

static inline struct flow_rule *
flow_cls_offload_flow_rule(struct flow_cls_offload *flow_cmd)
{
	return flow_cmd->rule;
}

static inline void flow_block_init(struct flow_block *flow_block)
{
	INIT_LIST_HEAD(&flow_block->cb_list);
}

typedef int flow_indr_block_bind_cb_t(struct net_device *dev, struct Qdisc *sch, void *cb_priv,
				      enum tc_setup_type type, void *type_data,
				      void *data,
				      void (*cleanup)(struct flow_block_cb *block_cb));

int flow_indr_dev_register(flow_indr_block_bind_cb_t *cb, void *cb_priv);
void flow_indr_dev_unregister(flow_indr_block_bind_cb_t *cb, void *cb_priv,
			      void (*release)(void *cb_priv));
int flow_indr_dev_setup_offload(struct net_device *dev, struct Qdisc *sch,
				enum tc_setup_type type, void *data,
				struct flow_block_offload *bo,
				void (*cleanup)(struct flow_block_cb *block_cb));

#endif /* _NET_FLOW_OFFLOAD_H */
