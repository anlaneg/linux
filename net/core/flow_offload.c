/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/flow_offload.h>
#include <linux/rtnetlink.h>
#include <linux/mutex.h>
#include <linux/rhashtable.h>

//申请最多支持num_actions个动作的flow_rule
struct flow_rule *flow_rule_alloc(unsigned int num_actions)
{
	struct flow_rule *rule;
	int i;

	rule = kzalloc(struct_size(rule, action.entries, num_actions),
		       GFP_KERNEL);
	if (!rule)
		return NULL;

	rule->action.num_entries = num_actions;
	/* Pre-fill each action hw_stats with DONT_CARE.
	 * Caller can override this if it wants stats for a given action.
	 */
	for (i = 0; i < num_actions; i++)
		rule->action.entries[i].hw_stats = FLOW_ACTION_HW_STATS_DONT_CARE;

	return rule;
}
EXPORT_SYMBOL(flow_rule_alloc);

//提取match中指定type的key,mask填充到out中
#define FLOW_DISSECTOR_MATCH(__rule, __type, __out)				\
	const struct flow_match *__m = &(__rule)->match;			\
	struct flow_dissector *__d = (__m)->dissector;				\
	/*取__type对应的key*/									\
	(__out)->key = skb_flow_dissector_target(__d, __type, (__m)->key);	\
	/*取__type对应的mask*/\
	(__out)->mask = skb_flow_dissector_target(__d, __type, (__m)->mask);	\

void flow_rule_match_meta(const struct flow_rule *rule,
			  struct flow_match_meta *out)
{
    //提供rule中的meta字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_META, out);
}
EXPORT_SYMBOL(flow_rule_match_meta);

void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out)
{
    //提供rule中的basic字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_BASIC, out);
}
EXPORT_SYMBOL(flow_rule_match_basic);

void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out)
{
    //提供rule中的controll字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CONTROL, out);
}
EXPORT_SYMBOL(flow_rule_match_control);

void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out)
{
    //提供rule中的eth_addr字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_eth_addrs);

void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out)
{
    //提供rule中的vlan字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_VLAN, out);
}
EXPORT_SYMBOL(flow_rule_match_vlan);

void flow_rule_match_cvlan(const struct flow_rule *rule,
			   struct flow_match_vlan *out)
{
    //提供rule中的内层vlan字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CVLAN, out);
}
EXPORT_SYMBOL(flow_rule_match_cvlan);

void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out)
{
    //提供rule中的ipv4源目的地址字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_ipv4_addrs);

void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out)
{
    //提供rule中的ipv6源目的地址字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_ipv6_addrs);

void flow_rule_match_ip(const struct flow_rule *rule,
			struct flow_match_ip *out)
{
    //提供rule中的ipv4层可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IP, out);
}
EXPORT_SYMBOL(flow_rule_match_ip);

void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out)
{
    //提供rule中的可匹配port字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_PORTS, out);
}
EXPORT_SYMBOL(flow_rule_match_ports);

void flow_rule_match_tcp(const struct flow_rule *rule,
			 struct flow_match_tcp *out)
{
    //提供rule中的tcp可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_TCP, out);
}
EXPORT_SYMBOL(flow_rule_match_tcp);

void flow_rule_match_icmp(const struct flow_rule *rule,
			  struct flow_match_icmp *out)
{
    //提供rule中的icmp可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ICMP, out);
}
EXPORT_SYMBOL(flow_rule_match_icmp);

void flow_rule_match_mpls(const struct flow_rule *rule,
			  struct flow_match_mpls *out)
{
    //提供rule中的mpls可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_MPLS, out);
}
EXPORT_SYMBOL(flow_rule_match_mpls);


void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out)
{
    //提供rule中的隧道control可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_control);

void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out)
{
    //提供rule中隧道的ipv4源目的地址字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ipv4_addrs);

void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out)
{
    //提供rule中隧道的ipv6源目的地址字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ipv6_addrs);

void flow_rule_match_enc_ip(const struct flow_rule *rule,
			    struct flow_match_ip *out)
{
    //提供rule中隧道的ipv4层可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IP, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ip);

void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out)
{
    //提供rule中隧道的port可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_PORTS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ports);

void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out)
{
    //提供rule中隧道的keyid可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_KEYID, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_keyid);

void flow_rule_match_enc_opts(const struct flow_rule *rule,
			      struct flow_match_enc_opts *out)
{
    //提供rule中隧道的opts可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_OPTS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_opts);

/*创建flow action cookie,cookie结构体后加一个len长度的内存，用于保存私有data*/
struct flow_action_cookie *flow_action_cookie_create(void *data,
						     unsigned int len,
						     gfp_t gfp)
{
	struct flow_action_cookie *cookie;

	cookie = kmalloc(sizeof(*cookie) + len, gfp);
	if (!cookie)
		return NULL;
	cookie->cookie_len = len;
	memcpy(cookie->cookie, data, len);
	return cookie;
}
EXPORT_SYMBOL(flow_action_cookie_create);

/*flow action cookie删除*/
void flow_action_cookie_destroy(struct flow_action_cookie *cookie)
{
	kfree(cookie);
}
EXPORT_SYMBOL(flow_action_cookie_destroy);

void flow_rule_match_ct(const struct flow_rule *rule,
			struct flow_match_ct *out)
{
    //提供rule中ct相关可匹配字段信息
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CT, out);
}
EXPORT_SYMBOL(flow_rule_match_ct);

/*构造流的block回调*/
struct flow_block_cb *flow_block_cb_alloc(flow_setup_cb_t *cb,
					  void *cb_ident, void *cb_priv,
					  void (*release)(void *cb_priv))
{
	struct flow_block_cb *block_cb;

	block_cb = kzalloc(sizeof(*block_cb), GFP_KERNEL);
	if (!block_cb)
		return ERR_PTR(-ENOMEM);

	block_cb->cb = cb;
	block_cb->cb_ident = cb_ident;
	block_cb->cb_priv = cb_priv;
	/*设置block callback释放回调*/
	block_cb->release = release;

	return block_cb;
}
EXPORT_SYMBOL(flow_block_cb_alloc);

/*实现流 block callback的回收，如有release函数，则释放时会被调用*/
void flow_block_cb_free(struct flow_block_cb *block_cb)
{
	if (block_cb->release)
		block_cb->release(block_cb->cb_priv);

	kfree(block_cb);
}
EXPORT_SYMBOL(flow_block_cb_free);

//通过cb,cb_ident 查询flow_block_cb
struct flow_block_cb *flow_block_cb_lookup(struct flow_block *block,
					   flow_setup_cb_t *cb, void *cb_ident)
{
	struct flow_block_cb *block_cb;

	list_for_each_entry(block_cb, &block->cb_list, list) {
		if (block_cb->cb == cb &&
		    block_cb->cb_ident == cb_ident)
			return block_cb;
	}

	return NULL;
}
EXPORT_SYMBOL(flow_block_cb_lookup);

//返回block_cb私有数据
void *flow_block_cb_priv(struct flow_block_cb *block_cb)
{
	return block_cb->cb_priv;
}
EXPORT_SYMBOL(flow_block_cb_priv);

//增加flow block callback的引用计数
void flow_block_cb_incref(struct flow_block_cb *block_cb)
{
	block_cb->refcnt++;
}
EXPORT_SYMBOL(flow_block_cb_incref);

//减少flow block callback的引用计数
unsigned int flow_block_cb_decref(struct flow_block_cb *block_cb)
{
	return --block_cb->refcnt;
}
EXPORT_SYMBOL(flow_block_cb_decref);

/*通过cb_ident,cb在driver_block_list上查询block_cb,如果找到，则返回true,否则false*/
bool flow_block_cb_is_busy(flow_setup_cb_t *cb, void *cb_ident,
			   struct list_head *driver_block_list)
{
	struct flow_block_cb *block_cb;

	list_for_each_entry(block_cb, driver_block_list, driver_list) {
		if (block_cb->cb == cb &&
		    block_cb->cb_ident == cb_ident)
			return true;
	}

	return false;
}
EXPORT_SYMBOL(flow_block_cb_is_busy);

//向driver_block_list及 flow_block_offload注册或解注册flow block callback
int flow_block_cb_setup_simple(struct flow_block_offload *f,
			       struct list_head *driver_block_list,
			       flow_setup_cb_t *cb/*回调函数*/,
			       void *cb_ident, void *cb_priv/*回调函数参数*/,
			       bool ingress_only/*仅ingress方向*/)
{
	struct flow_block_cb *block_cb;

	if (ingress_only &&
	    f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
	    /*如果仅容许ingress方向，但binder_type不为ingress,则返回失败*/
		return -EOPNOTSUPP;

	f->driver_block_list = driver_block_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
	    /*检查cb是否存在*/
		if (flow_block_cb_is_busy(cb, cb_ident, driver_block_list))
			return -EBUSY;

		block_cb = flow_block_cb_alloc(cb, cb_ident, cb_priv, NULL);
		if (IS_ERR(block_cb))
			return PTR_ERR(block_cb);

		/*将block_cb加入到f中*/
		flow_block_cb_add(block_cb, f);
		/*将block_cb加入到driver_block_list中*/
		list_add_tail(&block_cb->driver_list, driver_block_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
	    /*如果cb不存在，则返回失败*/
		block_cb = flow_block_cb_lookup(f->block, cb, cb_ident);
		if (!block_cb)
			return -ENOENT;

		/*将block_cb自f中移除*/
		flow_block_cb_remove(block_cb, f);
		/*将block_cb自driver_block_list中移除*/
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(flow_block_cb_setup_simple);

//保护flow_block_indr_dev_list
static DEFINE_MUTEX(flow_indr_block_lock);
/*用于串连系统中所有flow_block_cb*/
static LIST_HEAD(flow_block_indr_list);
/*用于串连系统中所有flow_indr_dev*/
static LIST_HEAD(flow_block_indr_dev_list);

struct flow_indr_dev {
	struct list_head		list;
	flow_indr_block_bind_cb_t	*cb;/*block bind回调*/
	void				*cb_priv;/*回调参数*/
	refcount_t			refcnt;/*引用计数*/
	struct rcu_head			rcu;
};

/*构造flow indrect device*/
static struct flow_indr_dev *flow_indr_dev_alloc(flow_indr_block_bind_cb_t *cb,
						 void *cb_priv)
{
	struct flow_indr_dev *indr_dev;

	indr_dev = kmalloc(sizeof(*indr_dev), GFP_KERNEL);
	if (!indr_dev)
		return NULL;

	indr_dev->cb		= cb;
	indr_dev->cb_priv	= cb_priv;
	refcount_set(&indr_dev->refcnt, 1);

	return indr_dev;
}

/*注册间接设备的block bind回调，例如vxlan设备需要据此完成offload*/
int flow_indr_dev_register(flow_indr_block_bind_cb_t *cb, void *cb_priv)
{
	struct flow_indr_dev *indr_dev;

	mutex_lock(&flow_indr_block_lock);
	/*遍历flow_block_indr_dev_list上已注册的所有indrect dev,如果已存在待注册项，则返回0*/
	list_for_each_entry(indr_dev, &flow_block_indr_dev_list, list) {
		if (indr_dev->cb == cb &&
		    indr_dev->cb_priv == cb_priv) {
		    /*如果已存在此注册，则增加引用计数*/
			refcount_inc(&indr_dev->refcnt);
			mutex_unlock(&flow_indr_block_lock);
			return 0;
		}
	}

	//没有注册，则构造indrect dev,并将其挂接在flow_block_indr_dev_list
	indr_dev = flow_indr_dev_alloc(cb, cb_priv);
	if (!indr_dev) {
		mutex_unlock(&flow_indr_block_lock);
		return -ENOMEM;
	}

	list_add(&indr_dev->list, &flow_block_indr_dev_list);
	mutex_unlock(&flow_indr_block_lock);

	return 0;
}
EXPORT_SYMBOL(flow_indr_dev_register);

//自flow_block_indr_list移除指定setup_cb回调，并将其收集在cleanup_list上
static void __flow_block_indr_cleanup(void (*release)(void *cb_priv),
				      void *cb_priv,
				      struct list_head *cleanup_list)
{
	struct flow_block_cb *this, *next;

	list_for_each_entry_safe(this, next, &flow_block_indr_list, indr.list) {
		if (this->release == release &&
		    this->indr.cb_priv == cb_priv) {
		    /*release回调与间接cb_priv一起唯一确定一个flow_block_cb*/
			list_move(&this->indr.list, cleanup_list);
			return;
		}
	}
}

//将flow_block_cb自cleanup_list上移除，并调用cleanup回调
static void flow_block_indr_notify(struct list_head *cleanup_list)
{
	struct flow_block_cb *this, *next;

	list_for_each_entry_safe(this, next, cleanup_list, indr.list) {
		list_del(&this->indr.list);
		this->indr.cleanup(this);
	}
}

//通过给定参数，移除flow indrect dev
void flow_indr_dev_unregister(flow_indr_block_bind_cb_t *cb, void *cb_priv,
			      void (*release)(void *cb_priv))
{
	struct flow_indr_dev *this, *next, *indr_dev = NULL;
	LIST_HEAD(cleanup_list);

	mutex_lock(&flow_indr_block_lock);
	list_for_each_entry_safe(this, next, &flow_block_indr_dev_list, list) {
		if (this->cb == cb &&
		    this->cb_priv == cb_priv &&
		    refcount_dec_and_test(&this->refcnt)) {
		    /*引用计数减为0，执行移除*/
			indr_dev = this;
			list_del(&indr_dev->list);
			//在flow_block_indr_dev_list上完成移除
			break;
		}
	}

	if (!indr_dev) {
	    //无对应dev，跳出
		mutex_unlock(&flow_indr_block_lock);
		return;
	}

	//在flow_block_indr_list链表上完成移除
	//收集setup_cb到cleanup_list
	__flow_block_indr_cleanup(release, cb_priv, &cleanup_list);
	mutex_unlock(&flow_indr_block_lock);

	//调用cleanup_list上所有元素的cleanup回调
	flow_block_indr_notify(&cleanup_list);
	kfree(indr_dev);
}
EXPORT_SYMBOL(flow_indr_dev_unregister);

//初始化flow block callback
static void flow_block_indr_init(struct flow_block_cb *flow_block,
				 struct flow_block_offload *bo,
				 struct net_device *dev, struct Qdisc *sch, void *data,
				 void *cb_priv,
				 void (*cleanup/*cb被移除时调用*/)(struct flow_block_cb *block_cb))
{
	flow_block->indr.binder_type = bo->binder_type;
	flow_block->indr.data = data;
	flow_block->indr.cb_priv = cb_priv;
	flow_block->indr.dev = dev;
	flow_block->indr.sch = sch;
	flow_block->indr.cleanup = cleanup;
}

/*api,构造flow_block_cb,按command解绑定/绑定 block_cb*/
struct flow_block_cb *flow_indr_block_cb_alloc(flow_setup_cb_t *cb,
					       void *cb_ident/*回调标识*/, void *cb_priv/*回调参数*/,
					       void (*release/*flow_block_cb释放时回调*/)(void *cb_priv),
					       struct flow_block_offload *bo,
					       struct net_device *dev/*被间接绑定的上层设备，例如vxlan_sys_4789*/,
					       struct Qdisc *sch, void *data,
					       void *indr_cb_priv,
					       void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_block_cb *block_cb;

	block_cb = flow_block_cb_alloc(cb, cb_ident, cb_priv, release);
	if (IS_ERR(block_cb))
		goto out;

	//初始化block_cb，并将其绑定到block间接回调链上
	flow_block_indr_init(block_cb, bo, dev, sch, data, indr_cb_priv, cleanup);
	list_add(&block_cb->indr.list, &flow_block_indr_list);

out:
	return block_cb;
}
EXPORT_SYMBOL(flow_indr_block_cb_alloc);

//dev未提供ndo_setup_tc回调，通过此函数间接触发block bind回调，例如触发vxlan设备的offload
int flow_indr_dev_setup_offload(struct net_device *dev/*offload关联的设备，例如vxlan_sys_4789*/, struct Qdisc *sch,
				enum tc_setup_type type, void *data,
				struct flow_block_offload *bo,
				void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_indr_dev *this;

	mutex_lock(&flow_indr_block_lock);
	/*触发系统所有间接设备block bind回调，不关心返回值,由各回调自行检查处理*/
	list_for_each_entry(this, &flow_block_indr_dev_list, list)
		this->cb(dev, sch, this->cb_priv, type, bo, data, cleanup);

	mutex_unlock(&flow_indr_block_lock);

	/*bo的cb_list不能为空*/
	return list_empty(&bo->cb_list) ? -EOPNOTSUPP : 0;
}
EXPORT_SYMBOL(flow_indr_dev_setup_offload);
