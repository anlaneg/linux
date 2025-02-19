// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/cls_api.c	Packet classifier API.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Changes:
 *
 * Eduardo J. Blanco <ejbs@netlabs.com.uy> :990222: kmod support
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <linux/rhashtable.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_csum.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_police.h>
#include <net/tc_act/tc_sample.h>
#include <net/tc_act/tc_skbedit.h>
#include <net/tc_act/tc_ct.h>
#include <net/tc_act/tc_mpls.h>
#include <net/tc_act/tc_gate.h>
#include <net/flow_offload.h>
#include <net/tc_wrapper.h>

/* The list of all installed classifier types */
static LIST_HEAD(tcf_proto_base);//系统所有分类器ops均注册在此链上

/* Protects list of registered TC modules. It is pure SMP lock. */
static DEFINE_RWLOCK(cls_mod_lock);

static struct xarray tcf_exts_miss_cookies_xa;
struct tcf_exts_miss_cookie_node {
	const struct tcf_chain *chain;
	const struct tcf_proto *tp;
	const struct tcf_exts *exts;
	u32 chain_index;
	u32 tp_prio;
	u32 handle;
	u32 miss_cookie_base;
	struct rcu_head rcu;
};

/* Each tc action entry cookie will be comprised of 32bit miss_cookie_base +
 * action index in the exts tc actions array.
 */
union tcf_exts_miss_cookie {
	struct {
		u32 miss_cookie_base;
		u32 act_index;
	};
	u64 miss_cookie;
};

#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
static int
tcf_exts_miss_cookie_base_alloc(struct tcf_exts *exts, struct tcf_proto *tp,
				u32 handle)
{
	struct tcf_exts_miss_cookie_node *n;
	static u32 next;
	int err;

	if (WARN_ON(!handle || !tp->ops->get_exts))
		return -EINVAL;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->chain_index = tp->chain->index;
	n->chain = tp->chain;
	n->tp_prio = tp->prio;
	n->tp = tp;
	n->exts = exts;
	n->handle = handle;

	err = xa_alloc_cyclic(&tcf_exts_miss_cookies_xa, &n->miss_cookie_base,
			      n, xa_limit_32b, &next, GFP_KERNEL);
	if (err)
		goto err_xa_alloc;

	exts->miss_cookie_node = n;
	return 0;

err_xa_alloc:
	kfree(n);
	return err;
}

static void tcf_exts_miss_cookie_base_destroy(struct tcf_exts *exts)
{
	struct tcf_exts_miss_cookie_node *n;

	if (!exts->miss_cookie_node)
		return;

	n = exts->miss_cookie_node;
	xa_erase(&tcf_exts_miss_cookies_xa, n->miss_cookie_base);
	kfree_rcu(n, rcu);
}

static struct tcf_exts_miss_cookie_node *
tcf_exts_miss_cookie_lookup(u64 miss_cookie, int *act_index)
{
	union tcf_exts_miss_cookie mc = { .miss_cookie = miss_cookie, };

	*act_index = mc.act_index;
	return xa_load(&tcf_exts_miss_cookies_xa, mc.miss_cookie_base);
}
#else /* IS_ENABLED(CONFIG_NET_TC_SKB_EXT) */
static int
tcf_exts_miss_cookie_base_alloc(struct tcf_exts *exts, struct tcf_proto *tp,
				u32 handle)
{
	return 0;
}

static void tcf_exts_miss_cookie_base_destroy(struct tcf_exts *exts)
{
}
#endif /* IS_ENABLED(CONFIG_NET_TC_SKB_EXT) */

static u64 tcf_exts_miss_cookie_get(u32 miss_cookie_base, int act_index)
{
	union tcf_exts_miss_cookie mc = { .act_index = act_index, };

	if (!miss_cookie_base)
		return 0;

	mc.miss_cookie_base = miss_cookie_base;
	return mc.miss_cookie;
}

#ifdef CONFIG_NET_CLS_ACT
DEFINE_STATIC_KEY_FALSE(tc_skb_ext_tc);
EXPORT_SYMBOL(tc_skb_ext_tc);

void tc_skb_ext_tc_enable(void)
{
	static_branch_inc(&tc_skb_ext_tc);
}
EXPORT_SYMBOL(tc_skb_ext_tc_enable);

void tc_skb_ext_tc_disable(void)
{
	static_branch_dec(&tc_skb_ext_tc);
}
EXPORT_SYMBOL(tc_skb_ext_tc_disable);
#endif

static u32 destroy_obj_hashfn(const struct tcf_proto *tp)
{
	return jhash_3words(tp->chain->index, tp->prio,
			    (__force __u32)tp->protocol, 0);
}

static void tcf_proto_signal_destroying(struct tcf_chain *chain,
					struct tcf_proto *tp)
{
	struct tcf_block *block = chain->block;

	mutex_lock(&block->proto_destroy_lock);
	hash_add_rcu(block->proto_destroy_ht, &tp->destroy_ht_node,
		     destroy_obj_hashfn(tp));
	mutex_unlock(&block->proto_destroy_lock);
}

static bool tcf_proto_cmp(const struct tcf_proto *tp1,
			  const struct tcf_proto *tp2)
{
	return tp1->chain->index == tp2->chain->index &&
	       tp1->prio == tp2->prio &&
	       tp1->protocol == tp2->protocol;
}

static bool tcf_proto_exists_destroying(struct tcf_chain *chain,
					struct tcf_proto *tp)
{
	u32 hash = destroy_obj_hashfn(tp);
	struct tcf_proto *iter;
	bool found = false;

	rcu_read_lock();
	hash_for_each_possible_rcu(chain->block->proto_destroy_ht, iter,
				   destroy_ht_node, hash) {
		if (tcf_proto_cmp(tp, iter)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

static void
tcf_proto_signal_destroyed(struct tcf_chain *chain, struct tcf_proto *tp)
{
	struct tcf_block *block = chain->block;

	mutex_lock(&block->proto_destroy_lock);
	if (hash_hashed(&tp->destroy_ht_node))
		hash_del_rcu(&tp->destroy_ht_node);
	mutex_unlock(&block->proto_destroy_lock);
}

/* Find classifier type by string name */
//通过分类器名称查找分类器ops
static const struct tcf_proto_ops *__tcf_proto_lookup_ops(const char *kind)
{
	const struct tcf_proto_ops *t, *res = NULL;

	if (kind) {
		read_lock(&cls_mod_lock);
		list_for_each_entry(t, &tcf_proto_base, head) {
			if (strcmp(kind, t->kind) == 0) {
				if (try_module_get(t->owner))
					res = t;
				break;
			}
		}
		read_unlock(&cls_mod_lock);
	}
	return res;
}

/*通过kind查找对应的分类器,支持动态加载*/
static const struct tcf_proto_ops *
tcf_proto_lookup_ops(const char *kind, bool rtnl_held,
		     struct netlink_ext_ack *extack)
{
	const struct tcf_proto_ops *ops;

	/*通过kind查找对应的ops*/
	ops = __tcf_proto_lookup_ops(kind);
	if (ops)
		return ops;
#ifdef CONFIG_MODULES
	//如果没有查找到，则动态请求加载指定module
	if (rtnl_held)
		rtnl_unlock();
	request_module("cls_%s", kind);
	if (rtnl_held)
		rtnl_lock();
	//加载module后再查询一遍
	ops = __tcf_proto_lookup_ops(kind);
	/* We dropped the RTNL semaphore in order to perform
	 * the module load. So, even if we succeeded in loading
	 * the module we have to replay the request. We indicate
	 * this using -EAGAIN.
	 */
	if (ops) {
		module_put(ops->owner);
		return ERR_PTR(-EAGAIN);
	}
#endif
	NL_SET_ERR_MSG(extack, "TC classifier not found");
	return ERR_PTR(-ENOENT);
}

/* Register(unregister) new classifier type */
//注册filter分类器ops
int register_tcf_proto_ops(struct tcf_proto_ops *ops)
{
	struct tcf_proto_ops *t;
	int rc = -EEXIST;

	write_lock(&cls_mod_lock);
	list_for_each_entry(t, &tcf_proto_base, head)
		if (!strcmp(ops->kind, t->kind))
			goto out;

	list_add_tail(&ops->head, &tcf_proto_base);
	rc = 0;
out:
	write_unlock(&cls_mod_lock);
	return rc;
}
EXPORT_SYMBOL(register_tcf_proto_ops);

static struct workqueue_struct *tc_filter_wq;

//解注册分类器ops
void unregister_tcf_proto_ops(struct tcf_proto_ops *ops)
{
	struct tcf_proto_ops *t;
	int rc = -ENOENT;

	/* Wait for outstanding call_rcu()s, if any, from a
	 * tcf_proto_ops's destroy() handler.
	 */
	rcu_barrier();
	flush_workqueue(tc_filter_wq);

	write_lock(&cls_mod_lock);
	list_for_each_entry(t, &tcf_proto_base, head) {
		if (t == ops) {
			list_del(&t->head);
			rc = 0;
			break;
		}
	}
	write_unlock(&cls_mod_lock);

	WARN(rc, "unregister tc filter kind(%s) failed %d\n", ops->kind, rc);
}
EXPORT_SYMBOL(unregister_tcf_proto_ops);

//初始化rcu work,在合适时机将rwork加入队列统一处理
bool tcf_queue_work(struct rcu_work *rwork, work_func_t func)
{
	INIT_RCU_WORK(rwork, func);
	return queue_rcu_work(tc_filter_wq, rwork);
}
EXPORT_SYMBOL(tcf_queue_work);

/* Select new prio value from the range, managed by kernel. */

static inline u32 tcf_auto_prio(struct tcf_proto *tp)
{
	u32 first = TC_H_MAKE(0xC0000000U, 0U);

	if (tp)
		//当前这个tp是排在我们后面的，我们需要排在它前面，我们要比它的优先级小。
	    //如有tp,则按tp获得优先级
		first = tp->prio - 1;

	return TC_H_MAJ(first);
}

static bool tcf_proto_check_kind(struct nlattr *kind, char *name)
{
	if (kind)
		return nla_strscpy(name, kind, IFNAMSIZ) < 0;
	memset(name, 0, IFNAMSIZ);
	return false;
}

//检查kind对应的ops->flags是否有TCF_PROTO_OPS_DOIT_UNLOCKED标记
static bool tcf_proto_is_unlocked(const char *kind)
{
	const struct tcf_proto_ops *ops;
	bool ret;

	if (strlen(kind) == 0)
	    /*kind为空，未加锁*/
		return false;

	ops = tcf_proto_lookup_ops(kind, false, NULL);
	/* On error return false to take rtnl lock. Proto lookup/create
	 * functions will perform lookup again and properly handle errors.
	 */
	if (IS_ERR(ops))
		return false;

	/*检查此tcf是否需要unlocked,当前只有flower支持此标记*/
	ret = !!(ops->flags & TCF_PROTO_OPS_DOIT_UNLOCKED);
	module_put(ops->owner);
	return ret;
}

//创建tcf_proto对象
static struct tcf_proto *tcf_proto_create(const char *kind/*分类过滤器名称*/, u32 protocol,
					  u32 prio/*优先级*/, struct tcf_chain *chain/*tp所属的chain*/,
					  bool rtnl_held,
					  struct netlink_ext_ack *extack)
{
	struct tcf_proto *tp;
	int err;

	//申请分类器
	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return ERR_PTR(-ENOBUFS);

	//通过kind查出tc filter protocol对应的ops
	tp->ops = tcf_proto_lookup_ops(kind, rtnl_held, extack);
	if (IS_ERR(tp->ops)) {
		err = PTR_ERR(tp->ops);
		goto errout;
	}
	//使用ops的分类函数,做为tp的分类函数
	tp->classify = tp->ops->classify;
	//指定要分类的协议
	tp->protocol = protocol;
	tp->prio = prio;
	tp->chain = chain;
	spin_lock_init(&tp->lock);
	refcount_set(&tp->refcnt, 1);

	//初始化相应的分类器
	err = tp->ops->init(tp);
	if (err) {
		module_put(tp->ops->owner);
		goto errout;
	}
	return tp;

errout:
	kfree(tp);
	return ERR_PTR(err);
}

//分类器引用计数增加
static void tcf_proto_get(struct tcf_proto *tp)
{
	refcount_inc(&tp->refcnt);
}

static void tcf_chain_put(struct tcf_chain *chain);

static void tcf_proto_destroy(struct tcf_proto *tp, bool rtnl_held,
			      bool sig_destroy, struct netlink_ext_ack *extack)
{
	tp->ops->destroy(tp, rtnl_held, extack);
	if (sig_destroy)
		tcf_proto_signal_destroyed(tp->chain, tp);
	tcf_chain_put(tp->chain);
	module_put(tp->ops->owner);//减少对module的引用
	kfree_rcu(tp, rcu);
}

//分类器引用计数减少
static void tcf_proto_put(struct tcf_proto *tp, bool rtnl_held,
			  struct netlink_ext_ack *extack)
{
	if (refcount_dec_and_test(&tp->refcnt))
		tcf_proto_destroy(tp, rtnl_held, true, extack);
}

static bool tcf_proto_check_delete(struct tcf_proto *tp)
{
	if (tp->ops->delete_empty)
		return tp->ops->delete_empty(tp);

	tp->deleting = true;
	return tp->deleting;
}

static void tcf_proto_mark_delete(struct tcf_proto *tp)
{
	spin_lock(&tp->lock);
	tp->deleting = true;
	spin_unlock(&tp->lock);
}

//检查分类器是否正在删除
static bool tcf_proto_is_deleting(struct tcf_proto *tp)
{
	bool deleting;

	spin_lock(&tp->lock);
	deleting = tp->deleting;
	spin_unlock(&tp->lock);

	return deleting;
}

#define ASSERT_BLOCK_LOCKED(block)					\
	lockdep_assert_held(&(block)->lock)

struct tcf_filter_chain_list_item {
	struct list_head list;
	/*chain head替换回调*/
	tcf_chain_head_change_t *chain_head_change;
	void *chain_head_change_priv;
};

//在给定block上创建指定index的chain
static struct tcf_chain *tcf_chain_create(struct tcf_block *block,
					  u32 chain_index/*chain索引*/)
{
	struct tcf_chain *chain;

	ASSERT_BLOCK_LOCKED(block);

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (!chain)
		return NULL;
	//将新创建的chain挂在block上
	list_add_tail_rcu(&chain->list, &block->chain_list);
	mutex_init(&chain->filter_chain_lock);
	chain->block = block;
	chain->index = chain_index;
	chain->refcnt = 1;
	if (!chain->index)
		//0号chain为首个chain
		block->chain0.chain = chain;
	return chain;
}

//更改chain_list的first_tp为tp_head
static void tcf_chain_head_change_item(struct tcf_filter_chain_list_item *item,
				       struct tcf_proto *tp_head)
{
	if (item->chain_head_change)
		/*修改tp list*/
		item->chain_head_change(tp_head, item->chain_head_change_priv);
}

//chain的首个tp发生变更，触发相应回调，更新首个tp_head
static void tcf_chain0_head_change(struct tcf_chain *chain,
				   struct tcf_proto *tp_head)
{
	struct tcf_filter_chain_list_item *item;
	struct tcf_block *block = chain->block;

	if (chain->index)
		//仅对chain0执行触发
		return;

	mutex_lock(&block->lock);
	//触发已注册的所有回调
	list_for_each_entry(item, &block->chain0.filter_chain_list, list)
		tcf_chain_head_change_item(item, tp_head);
	mutex_unlock(&block->lock);
}

/* Returns true if block can be safely freed. */

static bool tcf_chain_detach(struct tcf_chain *chain)
{
	struct tcf_block *block = chain->block;

	ASSERT_BLOCK_LOCKED(block);

	list_del_rcu(&chain->list);
	if (!chain->index)
		block->chain0.chain = NULL;

	if (list_empty(&block->chain_list) &&
	    refcount_read(&block->refcnt) == 0)
		return true;

	return false;
}

static void tcf_block_destroy(struct tcf_block *block)
{
	mutex_destroy(&block->lock);
	mutex_destroy(&block->proto_destroy_lock);
	xa_destroy(&block->ports);
	kfree_rcu(block, rcu);
}

static void tcf_chain_destroy(struct tcf_chain *chain, bool free_block)
{
	struct tcf_block *block = chain->block;

	mutex_destroy(&chain->filter_chain_lock);
	kfree_rcu(chain, rcu);
	if (free_block)
		tcf_block_destroy(block);
}

static void tcf_chain_hold(struct tcf_chain *chain)
{
	ASSERT_BLOCK_LOCKED(chain->block);

	++chain->refcnt;
}

/*检查此chain是否仅包含action*/
static bool tcf_chain_held_by_acts_only(struct tcf_chain *chain)
{
	ASSERT_BLOCK_LOCKED(chain->block);

	/* In case all the references are action references, this
	 * chain should not be shown to the user.
	 */
	return chain->refcnt == chain->action_refcnt;
}

//通过chain_index在block中查找对应的chain
static struct tcf_chain *tcf_chain_lookup(struct tcf_block *block,
					  u32 chain_index)
{
	struct tcf_chain *chain;

	ASSERT_BLOCK_LOCKED(block);

	list_for_each_entry(chain, &block->chain_list, list) {
		if (chain->index == chain_index)
			return chain;
	}
	return NULL;
}

#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
static struct tcf_chain *tcf_chain_lookup_rcu(const struct tcf_block *block,
					      u32 chain_index)
{
	struct tcf_chain *chain;

	list_for_each_entry_rcu(chain, &block->chain_list, list) {
		if (chain->index == chain_index)
			return chain;
	}
	return NULL;
}
#endif

static int tc_chain_notify(struct tcf_chain *chain, struct sk_buff *oskb,
			   u32 seq, u16 flags, int event, bool unicast,
			   struct netlink_ext_ack *extack);

//自block中获取或创建指定chain_index的链
static struct tcf_chain *__tcf_chain_get(struct tcf_block *block,
					 u32 chain_index, bool create,
					 bool by_act)
{
	struct tcf_chain *chain = NULL;
	bool is_first_reference;

	mutex_lock(&block->lock);
	chain = tcf_chain_lookup(block, chain_index);
	if (chain) {
		tcf_chain_hold(chain);
	} else {
		//如果没有查找到指定chain,如有必要，则创建此chain
		if (!create)
			goto errout;
		chain = tcf_chain_create(block, chain_index);
		if (!chain)
			goto errout;
	}

	if (by_act)
		++chain->action_refcnt;
	is_first_reference = chain->refcnt - chain->action_refcnt == 1;
	mutex_unlock(&block->lock);

	/* Send notification only in case we got the first
	 * non-action reference. Until then, the chain acts only as
	 * a placeholder for actions pointing to it and user ought
	 * not know about them.
	 */
	if (is_first_reference && !by_act)
		tc_chain_notify(chain, NULL, 0, NLM_F_CREATE | NLM_F_EXCL,
				RTM_NEWCHAIN, false, NULL);

	return chain;

errout:
	mutex_unlock(&block->lock);
	return chain;
}

//查找（创建）指定index的chain
static struct tcf_chain *tcf_chain_get(struct tcf_block *block, u32 chain_index,
				       bool create)
{
	return __tcf_chain_get(block, chain_index, create, false);
}

//获取对应的chain,如果chain不存在，则创建
struct tcf_chain *tcf_chain_get_by_act(struct tcf_block *block, u32 chain_index)
{
	return __tcf_chain_get(block, chain_index, true, true);
}
EXPORT_SYMBOL(tcf_chain_get_by_act);

static void tc_chain_tmplt_del(const struct tcf_proto_ops *tmplt_ops,
			       void *tmplt_priv);
static int tc_chain_notify_delete(const struct tcf_proto_ops *tmplt_ops,
				  void *tmplt_priv, u32 chain_index,
				  struct tcf_block *block, struct sk_buff *oskb,
				  u32 seq, u16 flags);

static void __tcf_chain_put(struct tcf_chain *chain, bool by_act,
			    bool explicitly_created)
{
	struct tcf_block *block = chain->block;
	const struct tcf_proto_ops *tmplt_ops;
	unsigned int refcnt, non_act_refcnt;
	bool free_block = false;
	void *tmplt_priv;

	mutex_lock(&block->lock);
	if (explicitly_created) {
		if (!chain->explicitly_created) {
			mutex_unlock(&block->lock);
			return;
		}
		chain->explicitly_created = false;
	}

	if (by_act)
		chain->action_refcnt--;

	/* tc_chain_notify_delete can't be called while holding block lock.
	 * However, when block is unlocked chain can be changed concurrently, so
	 * save these to temporary variables.
	 */
	refcnt = --chain->refcnt;
	non_act_refcnt = refcnt - chain->action_refcnt;
	tmplt_ops = chain->tmplt_ops;
	tmplt_priv = chain->tmplt_priv;

	if (non_act_refcnt == chain->explicitly_created && !by_act) {
		if (non_act_refcnt == 0)
			tc_chain_notify_delete(tmplt_ops, tmplt_priv,
					       chain->index, block, NULL, 0, 0);
		/* Last reference to chain, no need to lock. */
		chain->flushing = false;
	}

	if (refcnt == 0)
		free_block = tcf_chain_detach(chain);
	mutex_unlock(&block->lock);

	if (refcnt == 0) {
		tc_chain_tmplt_del(tmplt_ops, tmplt_priv);
		tcf_chain_destroy(chain, free_block);
	}
}

static void tcf_chain_put(struct tcf_chain *chain)
{
	__tcf_chain_put(chain, false, false);
}

void tcf_chain_put_by_act(struct tcf_chain *chain)
{
	__tcf_chain_put(chain, true, false);
}
EXPORT_SYMBOL(tcf_chain_put_by_act);

static void tcf_chain_put_explicitly_created(struct tcf_chain *chain)
{
	__tcf_chain_put(chain, false, true);
}

/*移除chain上所有tcf_proto*/
static void tcf_chain_flush(struct tcf_chain *chain, bool rtnl_held)
{
	struct tcf_proto *tp, *tp_next;

	mutex_lock(&chain->filter_chain_lock);
	tp = tcf_chain_dereference(chain->filter_chain, chain);
	while (tp) {
	    /*存入rcu，后续一并移除*/
		tp_next = rcu_dereference_protected(tp->next, 1);
		tcf_proto_signal_destroying(chain, tp);
		tp = tp_next;
	}
	/*指明此chain为空*/
	tp = tcf_chain_dereference(chain->filter_chain, chain);
	RCU_INIT_POINTER(chain->filter_chain, NULL);
	tcf_chain0_head_change(chain, NULL);
	chain->flushing = true;
	mutex_unlock(&chain->filter_chain_lock);

	while (tp) {
		tp_next = rcu_dereference_protected(tp->next, 1);
		tcf_proto_put(tp, rtnl_held, NULL);
		tp = tp_next;
	}
}

static int tcf_block_setup(struct tcf_block *block,
			   struct flow_block_offload *bo);

static void tcf_block_offload_init(struct flow_block_offload *bo,
				   struct net_device *dev, struct Qdisc *sch,
				   enum flow_block_command command,
				   enum flow_block_binder_type binder_type,
				   struct flow_block *flow_block,
				   bool shared, struct netlink_ext_ack *extack)
{
	bo->net = dev_net(dev);
	bo->command = command;
	bo->binder_type = binder_type;
	bo->block = flow_block;
	bo->block_shared = shared;
	bo->extack = extack;
	bo->sch = sch;
	bo->cb_list_head = &flow_block->cb_list;
	INIT_LIST_HEAD(&bo->cb_list);
}

static void tcf_block_unbind(struct tcf_block *block,
			     struct flow_block_offload *bo);

static void tc_block_indr_cleanup(struct flow_block_cb *block_cb)
{
	struct tcf_block *block = block_cb->indr.data;
	struct net_device *dev = block_cb->indr.dev;
	struct Qdisc *sch = block_cb->indr.sch;
	struct netlink_ext_ack extack = {};
	struct flow_block_offload bo = {};

	//构建unbind command的bo
	tcf_block_offload_init(&bo, dev, sch, FLOW_BLOCK_UNBIND,
			       block_cb->indr.binder_type,
			       &block->flow_block, tcf_block_shared(block),
			       &extack);
	rtnl_lock();
	down_write(&block->cb_lock);
	list_del(&block_cb->driver_list);
	list_move(&block_cb->list, &bo.cb_list);
	//执行unbind
	tcf_block_unbind(block, &bo);
	up_write(&block->cb_lock);
	rtnl_unlock();
}

static bool tcf_block_offload_in_use(struct tcf_block *block)
{
	return atomic_read(&block->offloadcnt);
}

//tc filter触发block offload命令
static int tcf_block_offload_cmd(struct tcf_block *block,
				 struct net_device *dev, struct Qdisc *sch,
				 struct tcf_block_ext_info *ei,
				 enum flow_block_command command/*block子命令*/,
				 struct netlink_ext_ack *extack)
{
	struct flow_block_offload bo = {};

	//初始化flow block offload
	tcf_block_offload_init(&bo, dev, sch, command, ei->binder_type/*offload的方向*/,
			       &block->flow_block, tcf_block_shared(block)/*是否为share block*/,
			       extack);

	//如果dev有ndo_setup_tc回调，则触发tc_setup_block
	if (dev->netdev_ops->ndo_setup_tc) {
		int err;

		/*tc setup block情况下，回调需要填充并返回bo结构体*/
		err = dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_BLOCK, &bo);
		if (err < 0) {
			if (err != -EOPNOTSUPP)
				NL_SET_ERR_MSG(extack, "Driver ndo_setup_tc failed");
			return err;
		}

		return tcf_block_setup(block, &bo);
	}


	/*当dev没有ndo_setup_tc回调时，例如vxlan设备，间接触发tc_setup_block*/
	flow_indr_dev_setup_offload(dev, sch, TC_SETUP_BLOCK, block, &bo,
				    tc_block_indr_cleanup);
	/*为此block增加新的bo*/
	tcf_block_setup(block, &bo);

	return -EOPNOTSUPP;
}

static int tcf_block_offload_bind(struct tcf_block *block, struct Qdisc *q,
				  struct tcf_block_ext_info *ei,
				  struct netlink_ext_ack *extack)
{
    //取队列从属的net_device
	struct net_device *dev = q->dev_queue->dev;
	int err;

	down_write(&block->cb_lock);

	/* If tc offload feature is disabled and the block we try to bind
	 * to already has some offloaded filters, forbid to bind.
	 */
	if (dev->netdev_ops->ndo_setup_tc &&
	    !tc_can_offload(dev) &&
	    tcf_block_offload_in_use(block)) {
	    /*有ndo_setup_tc,但没有开启offload,此block上offload数非0，则告警，不容许bond(这样后面调不了reoffload接口）*/
		NL_SET_ERR_MSG(extack, "Bind to offloaded block failed as dev has offload disabled");
		err = -EOPNOTSUPP;
		goto err_unlock;
	}

	//触发block卸载的block bind命令
	err = tcf_block_offload_cmd(block, dev, q, ei, FLOW_BLOCK_BIND, extack);
	if (err == -EOPNOTSUPP)
		goto no_offload_dev_inc;
	if (err)
		goto err_unlock;

	up_write(&block->cb_lock);
	return 0;

no_offload_dev_inc:
	if (tcf_block_offload_in_use(block))
		goto err_unlock;

	err = 0;
	block->nooffloaddevcnt++;
err_unlock:
	up_write(&block->cb_lock);
	return err;
}

/*block解绑*/
static void tcf_block_offload_unbind(struct tcf_block *block, struct Qdisc *q,
				     struct tcf_block_ext_info *ei)
{
	struct net_device *dev = q->dev_queue->dev;
	int err;

	down_write(&block->cb_lock);
	/*block与dev相互解绑*/
	err = tcf_block_offload_cmd(block, dev, q, ei, FLOW_BLOCK_UNBIND, NULL);
	if (err == -EOPNOTSUPP)
		goto no_offload_dev_dec;
	up_write(&block->cb_lock);
	return;

no_offload_dev_dec:
	WARN_ON(block->nooffloaddevcnt-- == 0);
	up_write(&block->cb_lock);
}

static int
tcf_chain0_head_change_cb_add(struct tcf_block *block,
			      struct tcf_block_ext_info *ei,
			      struct netlink_ext_ack *extack)
{
	struct tcf_filter_chain_list_item *item;
	struct tcf_chain *chain0;

	//申请item,并用ei构造item的函数及参数
	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		NL_SET_ERR_MSG(extack, "Memory allocation for head change callback item failed");
		return -ENOMEM;
	}

	//回调函数及其参数
	item->chain_head_change = ei->chain_head_change;
	item->chain_head_change_priv = ei->chain_head_change_priv;

	mutex_lock(&block->lock);
	chain0 = block->chain0.chain;
	if (chain0)
		tcf_chain_hold(chain0);
	else
		//将item加入到chain0.filter_chain_list中
		list_add(&item->list, &block->chain0.filter_chain_list);
	mutex_unlock(&block->lock);

	if (chain0) {
		struct tcf_proto *tp_head;

		mutex_lock(&chain0->filter_chain_lock);

		tp_head = tcf_chain_dereference(chain0->filter_chain, chain0);
		if (tp_head)
			//针对已知的tp_head,为了一致性，目前我们要加入change回调，故在加入前，先触发此回调
			tcf_chain_head_change_item(item, tp_head);

		mutex_lock(&block->lock);
		//再将item加入到filter_chain_list上
		list_add(&item->list, &block->chain0.filter_chain_list);
		mutex_unlock(&block->lock);

		mutex_unlock(&chain0->filter_chain_lock);
		tcf_chain_put(chain0);
	}

	return 0;
}

static void
tcf_chain0_head_change_cb_del(struct tcf_block *block,
			      struct tcf_block_ext_info *ei)
{
	struct tcf_filter_chain_list_item *item;

	mutex_lock(&block->lock);
	list_for_each_entry(item, &block->chain0.filter_chain_list, list) {
		if ((!ei->chain_head_change && !ei->chain_head_change_priv) ||
		    (item->chain_head_change == ei->chain_head_change &&
		     item->chain_head_change_priv == ei->chain_head_change_priv)) {
			if (block->chain0.chain)
				//更改首个tp_head为NULL
				tcf_chain_head_change_item(item, NULL);
			list_del(&item->list);
			mutex_unlock(&block->lock);

			kfree(item);
			return;
		}
	}
	mutex_unlock(&block->lock);
	WARN_ON(1);
}

struct tcf_net {
	spinlock_t idr_lock; /* Protects idr */
	struct idr idr;/*记录block index与block指针的映射关系*/
};

static unsigned int tcf_net_id;

//block信息插入，分配block_index
static int tcf_block_insert(struct tcf_block *block, struct net *net,
			    struct netlink_ext_ack *extack)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);
	int err;

	idr_preload(GFP_KERNEL);
	spin_lock(&tn->idr_lock);
	/*要求自idr中分配block->index对应的编号*/
	err = idr_alloc_u32(&tn->idr, block, &block->index, block->index,
			    GFP_NOWAIT);
	spin_unlock(&tn->idr_lock);
	idr_preload_end();

	/*分配index*/
	return err;
}

//block映射信息移除
static void tcf_block_remove(struct tcf_block *block, struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	spin_lock(&tn->idr_lock);
	idr_remove(&tn->idr, block->index);
	spin_unlock(&tn->idr_lock);
}

//创建tcf block
static struct tcf_block *tcf_block_create(struct net *net, struct Qdisc *q,
					  u32 block_index/*block索引*/,
					  struct netlink_ext_ack *extack)
{
	struct tcf_block *block;

	block = kzalloc(sizeof(*block), GFP_KERNEL);
	if (!block) {
		NL_SET_ERR_MSG(extack, "Memory allocation for block failed");
		return ERR_PTR(-ENOMEM);
	}
	mutex_init(&block->lock);
	mutex_init(&block->proto_destroy_lock);
	init_rwsem(&block->cb_lock);
	flow_block_init(&block->flow_block);
	INIT_LIST_HEAD(&block->chain_list);
	INIT_LIST_HEAD(&block->owner_list);
	INIT_LIST_HEAD(&block->chain0.filter_chain_list);

	refcount_set(&block->refcnt, 1);
	block->net = net;
	block->index = block_index;/*此值非0时，为share block*/
	xa_init(&block->ports);

	/* Don't store q pointer for blocks which are shared */
	//针对非share block,block指向queue
	if (!tcf_block_shared(block))
		block->q = q;
	return block;
}

//通过block_index返回对应的tcf_block
struct tcf_block *tcf_block_lookup(struct net *net, u32 block_index)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	return idr_find(&tn->idr, block_index);
}
EXPORT_SYMBOL(tcf_block_lookup);

/*给定block_index查询block*/
static struct tcf_block *tcf_block_refcnt_get(struct net *net, u32 block_index)
{
	struct tcf_block *block;

	rcu_read_lock();
	//查对应的block并增加引用计数
	block = tcf_block_lookup(net, block_index);
	if (block && !refcount_inc_not_zero(&block->refcnt))
		block = NULL;
	rcu_read_unlock();

	return block;
}

//自block中依据chain获取next chain，如果chain为NULL，则取首个chain (仅包含action的chain将被跳过）
static struct tcf_chain *
__tcf_get_next_chain(struct tcf_block *block, struct tcf_chain *chain)
{
	mutex_lock(&block->lock);
	if (chain)
		//给定了chain,取next chain
		chain = list_is_last(&chain->list, &block->chain_list) ?
			NULL /*chain为last,则返回NULL*/: list_next_entry(chain, list)/*非last返回next*/;
	else
		//未给定chain,则取首个chain
		chain = list_first_entry_or_null(&block->chain_list,
						 struct tcf_chain, list);

	/*如果chain中仅包含action，则跳过*/
	/* skip all action-only chains */
	while (chain && tcf_chain_held_by_acts_only(chain))
		chain = list_is_last(&chain->list, &block->chain_list) ?
			NULL : list_next_entry(chain, list);

	if (chain)
		tcf_chain_hold(chain);
	mutex_unlock(&block->lock);

	return chain;
}

/* Function to be used by all clients that want to iterate over all chains on
 * block. It properly obtains block->lock and takes reference to chain before
 * returning it. Users of this function must be tolerant to concurrent chain
 * insertion/deletion or ensure that no concurrent chain modification is
 * possible. Note that all netlink dump callbacks cannot guarantee to provide
 * consistent dump because rtnl lock is released each time skb is filled with
 * data and sent to user-space.
 */
//由chain获取next_chain,并减少对chain的引用
struct tcf_chain *
tcf_get_next_chain(struct tcf_block *block, struct tcf_chain *chain)
{
	struct tcf_chain *chain_next = __tcf_get_next_chain(block, chain);

	if (chain)
		tcf_chain_put(chain);

	return chain_next;
}
EXPORT_SYMBOL(tcf_get_next_chain);

//在chain上获取下一个tp(传入tp为NULL时，返回首个tp)
static struct tcf_proto *
__tcf_get_next_proto(struct tcf_chain *chain, struct tcf_proto *tp)
{
	u32 prio = 0;

	ASSERT_RTNL();
	mutex_lock(&chain->filter_chain_lock);

	if (!tp) {
		//取首个tp
		tp = tcf_chain_dereference(chain->filter_chain, chain);
	} else if (tcf_proto_is_deleting(tp)) {
		/* 'deleting' flag is set and chain->filter_chain_lock was
		 * unlocked, which means next pointer could be invalid. Restart
		 * search.
		 */
		prio = tp->prio + 1;/*如果此tp正在被移除，则通过优先级获取下一个tp*/
		tp = tcf_chain_dereference(chain->filter_chain, chain);

		for (; tp; tp = tcf_chain_dereference(tp->next, chain))
			if (!tp->deleting/*跳过正在被删除的tp*/ && tp->prio >= prio)
				break;
	} else {
		//取下一个tp
		tp = tcf_chain_dereference(tp->next, chain);
	}

	if (tp)
		tcf_proto_get(tp);

	mutex_unlock(&chain->filter_chain_lock);

	return tp;
}

/* Function to be used by all clients that want to iterate over all tp's on
 * chain. Users of this function must be tolerant to concurrent tp
 * insertion/deletion or ensure that no concurrent chain modification is
 * possible. Note that all netlink dump callbacks cannot guarantee to provide
 * consistent dump because rtnl lock is released each time skb is filled with
 * data and sent to user-space.
 */
//自chain上，依据tp获取下一个分类器
struct tcf_proto *
tcf_get_next_proto(struct tcf_chain *chain, struct tcf_proto *tp)
{
	struct tcf_proto *tp_next = __tcf_get_next_proto(chain, tp);

	if (tp)
		tcf_proto_put(tp, true, NULL);

	return tp_next;
}
EXPORT_SYMBOL(tcf_get_next_proto);

static void tcf_block_flush_all_chains(struct tcf_block *block, bool rtnl_held)
{
	struct tcf_chain *chain;

	/* Last reference to block. At this point chains cannot be added or
	 * removed concurrently.
	 */
	for (chain = tcf_get_next_chain(block, NULL);
	     chain;
	     chain = tcf_get_next_chain(block, chain)) {
		tcf_chain_put_explicitly_created(chain);
		tcf_chain_flush(chain, rtnl_held);
	}
}

/* Lookup Qdisc and increments its reference counter.
 * Set parent, if necessary.
 */
static int __tcf_qdisc_find(struct net *net, struct Qdisc **q/*出参，dev对应的qdisc*/,
			    u32 *parent/*队列index，如果为空，则使用dev->qdisc*/, int ifindex/*规则所属的dev对应的ifindex*/, bool rtnl_held,
			    struct netlink_ext_ack *extack)
{
	const struct Qdisc_class_ops *cops;
	struct net_device *dev;
	int err = 0;

	if (ifindex == TCM_IFINDEX_MAGIC_BLOCK)
	    /*share block直接返回*/
		return 0;

	rcu_read_lock();

	/* Find link */
	//通过ifindex获取到指定的网络设备
	dev = dev_get_by_index_rcu(net, ifindex);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}

	/* Find qdisc */
	if (!*parent) {
		//未指定parent,默认取dev对应的root qdisc，并更新parent
		*q = rcu_dereference(dev->qdisc);
		*parent = (*q)->handle;
	} else {
		//取parent指定的q
		*q = qdisc_lookup_rcu(dev, TC_H_MAJ(*parent));
		if (!*q) {
			NL_SET_ERR_MSG(extack, "Parent Qdisc doesn't exists");
			err = -EINVAL;
			goto errout_rcu;
		}
	}

	/*增加q的引用计数*/
	*q = qdisc_refcount_inc_nz(*q);
	if (!*q) {
		NL_SET_ERR_MSG(extack, "Parent Qdisc doesn't exists");
		err = -EINVAL;
		goto errout_rcu;
	}

	/* Is it classful? */
	cops = (*q)->ops->cl_ops;
	if (!cops) {
	    /*必须支持分类操作*/
		NL_SET_ERR_MSG(extack, "Qdisc not classful");
		err = -EINVAL;
		goto errout_qdisc;
	}

	if (!cops->tcf_block) {
	    /*必须支持blocks*/
		NL_SET_ERR_MSG(extack, "Class doesn't support blocks");
		err = -EOPNOTSUPP;
		goto errout_qdisc;
	}

errout_rcu:
	/* At this point we know that qdisc is not noop_qdisc,
	 * which means that qdisc holds a reference to net_device
	 * and we hold a reference to qdisc, so it is safe to release
	 * rcu read lock.
	 */
	rcu_read_unlock();
	return err;

errout_qdisc:
	rcu_read_unlock();

	if (rtnl_held)
		qdisc_put(*q);
	else
		qdisc_put_unlocked(*q);
	*q = NULL;

	return err;
}

/*通过parent中的classid查找其对应的cl*/
static int __tcf_qdisc_cl_find(struct Qdisc *q, u32 parent, unsigned long *cl/*出参，此parent对应的class*/,
			       int ifindex, struct netlink_ext_ack *extack)
{
	if (ifindex == TCM_IFINDEX_MAGIC_BLOCK)
	    /*share block直接返回*/
		return 0;

	/* Do we search for filter, attached to class? */
	if (TC_H_MIN(parent)) {
		const struct Qdisc_class_ops *cops = q->ops->cl_ops;

		/*依据classid查找对应class*/
		*cl = cops->find(q, parent);
		if (*cl == 0) {
			NL_SET_ERR_MSG(extack, "Specified class doesn't exist");
			return -ENOENT;
		}
	}

	return 0;
}

//给定block_index查找tc filter block
static struct tcf_block *__tcf_block_find(struct net *net, struct Qdisc *q,
					  unsigned long cl, int ifindex,
					  u32 block_index,
					  struct netlink_ext_ack *extack)
{
	struct tcf_block *block;

	if (ifindex == TCM_IFINDEX_MAGIC_BLOCK) {
		//share block情况下，block index是全局的，我们需要使用block_index获取block
		block = tcf_block_refcnt_get(net, block_index);
		if (!block) {
			NL_SET_ERR_MSG(extack, "Block of given index was not found");
			return ERR_PTR(-EINVAL);
		}
	} else {
		const struct Qdisc_class_ops *cops = q->ops->cl_ops;

		//通过class获取其对应的非共享block
		block = cops->tcf_block(q, cl, extack);
		if (!block)
			return ERR_PTR(-EINVAL);

		if (tcf_block_shared(block)) {
		    /*这种情况下不容许share block走这个流程，其应走上面的流程*/
			NL_SET_ERR_MSG(extack, "This filter block is shared. Please use the block index to manipulate the filters");
			return ERR_PTR(-EOPNOTSUPP);
		}

		/* Always take reference to block in order to support execution
		 * of rules update path of cls API without rtnl lock. Caller
		 * must release block when it is finished using it. 'if' block
		 * of this conditional obtain reference to block by calling
		 * tcf_block_refcnt_get().
		 */
		refcount_inc(&block->refcnt);
	}

	return block;
}

static void __tcf_block_put(struct tcf_block *block, struct Qdisc *q,
			    struct tcf_block_ext_info *ei, bool rtnl_held)
{
	if (refcount_dec_and_mutex_lock(&block->refcnt, &block->lock)) {
		/* Flushing/putting all chains will cause the block to be
		 * deallocated when last chain is freed. However, if chain_list
		 * is empty, block has to be manually deallocated. After block
		 * reference counter reached 0, it is no longer possible to
		 * increment it or add new chains to block.
		 */
		bool free_block = list_empty(&block->chain_list);

		mutex_unlock(&block->lock);
		if (tcf_block_shared(block))
			tcf_block_remove(block, block->net);

		if (q)
		    //block unbind处理，关联到q->dev_queue->dev,触发driver执行FLOW_BLOCK_UNBIND
			tcf_block_offload_unbind(block, q, ei);

		if (free_block)
			tcf_block_destroy(block);
		else
			tcf_block_flush_all_chains(block, rtnl_held);
	} else if (q) {
		tcf_block_offload_unbind(block, q, ei);
	}
}

static void tcf_block_refcnt_put(struct tcf_block *block, bool rtnl_held)
{
	__tcf_block_put(block, NULL, NULL, rtnl_held);
}

/* Find tcf block.
 * Set q, parent, cl when appropriate.
 */
//队列分绑定一个或多个class,class有一个或多个对应的block
static struct tcf_block *tcf_block_find(struct net *net, struct Qdisc **q,
					u32 *parent, unsigned long *cl,
					int ifindex, u32 block_index,
					struct netlink_ext_ack *extack)
{
	struct tcf_block *block;
	int err = 0;

	ASSERT_RTNL();

	//先查qdisc
	err = __tcf_qdisc_find(net, q, parent, ifindex, true, extack);
	if (err)
		goto errout;

	//确定对应的class
	err = __tcf_qdisc_cl_find(*q, *parent, cl, ifindex, extack);
	if (err)
		goto errout_qdisc;

	//通过对应的分类找到相应的block
	block = __tcf_block_find(net, *q, *cl, ifindex, block_index, extack);
	if (IS_ERR(block)) {
		err = PTR_ERR(block);
		goto errout_qdisc;
	}

	return block;

errout_qdisc:
	if (*q)
		qdisc_put(*q);
errout:
	*q = NULL;
	return ERR_PTR(err);
}

static void tcf_block_release(struct Qdisc *q, struct tcf_block *block,
			      bool rtnl_held)
{
	if (!IS_ERR_OR_NULL(block))
		tcf_block_refcnt_put(block, rtnl_held);

	if (q) {
		if (rtnl_held)
			qdisc_put(q);
		else
			qdisc_put_unlocked(q);
	}
}

struct tcf_block_owner_item {
	struct list_head list;
	struct Qdisc *q;
	enum flow_block_binder_type binder_type;
};

static void
tcf_block_owner_netif_keep_dst(struct tcf_block *block,
			       struct Qdisc *q,
			       enum flow_block_binder_type binder_type)
{
	if (block->keep_dst &&
	    binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS &&
	    binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS)
		netif_keep_dst(qdisc_dev(q));
}

void tcf_block_netif_keep_dst(struct tcf_block *block)
{
	struct tcf_block_owner_item *item;

	block->keep_dst = true;
	list_for_each_entry(item, &block->owner_list, list)
		tcf_block_owner_netif_keep_dst(block, item->q,
					       item->binder_type);
}
EXPORT_SYMBOL(tcf_block_netif_keep_dst);

//记录block从属的排除规则及绑定类型
static int tcf_block_owner_add(struct tcf_block *block,
			       struct Qdisc *q,
			       enum flow_block_binder_type binder_type)
{
	struct tcf_block_owner_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;
	//对应的排队规则，绑定类型
	item->q = q;
	item->binder_type = binder_type;
	list_add(&item->list, &block->owner_list);
	return 0;
}

static void tcf_block_owner_del(struct tcf_block *block,
				struct Qdisc *q,
				enum flow_block_binder_type binder_type)
{
	struct tcf_block_owner_item *item;

	list_for_each_entry(item, &block->owner_list, list) {
		if (item->q == q && item->binder_type == binder_type) {
			list_del(&item->list);
			kfree(item);
			return;
		}
	}
	WARN_ON(1);
}

//创建或查询tcf_block
static bool tcf_block_tracks_dev(struct tcf_block *block/*出参，创建或查询好的block*/,
				 struct tcf_block_ext_info *ei/*block扩展参数*/)
{
	return tcf_block_shared(block) &&
	       (ei->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS ||
		ei->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS);
}

int tcf_block_get_ext(struct tcf_block **p_block, struct Qdisc *q,
		      struct tcf_block_ext_info *ei,
		      struct netlink_ext_ack *extack)
{
	struct net_device *dev = qdisc_dev(q);
	struct net *net = qdisc_net(q);
	struct tcf_block *block = NULL;
	int err;

	//已设置block index,直接获取block,如block不存在，则创建block
	if (ei->block_index)
		/* block_index not 0 means the shared block is requested */
		block = tcf_block_refcnt_get(net, ei->block_index);

	if (!block) {
		//block不存在，需要创建指定索引的block
		block = tcf_block_create(net, q, ei->block_index, extack);
		if (IS_ERR(block))
			return PTR_ERR(block);
		if (tcf_block_shared(block)) {
			//针对共享block,强制分配编号
			err = tcf_block_insert(block, net, extack);
			if (err)
			    //编号分配失败（已占用）
				goto err_block_insert;
		}
	}

	//为block添加owner
	err = tcf_block_owner_add(block, q, ei->binder_type);
	if (err)
		goto err_block_owner_add;

	tcf_block_owner_netif_keep_dst(block, q, ei->binder_type);

	//为block添加tp_head change回调
	err = tcf_chain0_head_change_cb_add(block, ei, extack);
	if (err)
		goto err_chain0_head_change_cb_add;

	//block bind处理，关联到q->dev_queue->dev,触发driver执行FLOW_BLOCK_BIND
	err = tcf_block_offload_bind(block, q, ei, extack);
	if (err)
		goto err_block_offload_bind;

	if (tcf_block_tracks_dev(block, ei)) {
		err = xa_insert(&block->ports, dev->ifindex, dev, GFP_KERNEL);
		if (err) {
			NL_SET_ERR_MSG(extack, "block dev insert failed");
			goto err_dev_insert;
		}
	}

	*p_block = block;
	return 0;

err_dev_insert:
err_block_offload_bind:
	tcf_chain0_head_change_cb_del(block, ei);
err_chain0_head_change_cb_add:
	tcf_block_owner_del(block, q, ei->binder_type);
err_block_owner_add:
err_block_insert:
	tcf_block_refcnt_put(block, true);
	return err;
}
EXPORT_SYMBOL(tcf_block_get_ext);

//设置filter_chain=tp_head
static void tcf_chain_head_change_dflt(struct tcf_proto *tp_head, void *priv)
{
	struct tcf_proto __rcu **p_filter_chain = priv;

	rcu_assign_pointer(*p_filter_chain, tp_head);
}

//创建block
int tcf_block_get(struct tcf_block **p_block,
		  struct tcf_proto __rcu **p_filter_chain, struct Qdisc *q,
		  struct netlink_ext_ack *extack)
{
	struct tcf_block_ext_info ei = {
		.chain_head_change = tcf_chain_head_change_dflt,
		.chain_head_change_priv = p_filter_chain,
	};

	WARN_ON(!p_filter_chain);
	//创建block
	return tcf_block_get_ext(p_block, q, &ei, extack);
}
EXPORT_SYMBOL(tcf_block_get);

/* XXX: Standalone actions are not allowed to jump to any chain, and bound
 * actions should be all removed after flushing.
 */
void tcf_block_put_ext(struct tcf_block *block, struct Qdisc *q,
		       struct tcf_block_ext_info *ei)
{
	struct net_device *dev = qdisc_dev(q);

	if (!block)
		return;
	if (tcf_block_tracks_dev(block, ei))
		xa_erase(&block->ports, dev->ifindex);
	tcf_chain0_head_change_cb_del(block, ei);
	tcf_block_owner_del(block, q, ei->binder_type);

	__tcf_block_put(block, q, ei, true);
}
EXPORT_SYMBOL(tcf_block_put_ext);

void tcf_block_put(struct tcf_block *block)
{
	struct tcf_block_ext_info ei = {0, };

	if (!block)
		return;
	tcf_block_put_ext(block, block->q, &ei);
}

EXPORT_SYMBOL(tcf_block_put);

//遍历block上所有chain,遍历chain上所有tp,针对每个tp调用tp->ops->reoffload
static int
tcf_block_playback_offloads(struct tcf_block *block, flow_setup_cb_t *cb/*驱动提供的回调函数*/,
			    void *cb_priv/*回调的私有数据*/, bool add/*是否规则新增*/, bool offload_in_use,
			    struct netlink_ext_ack *extack/*netlink应答控制信息*/)
{
	struct tcf_chain *chain, *chain_prev;
	struct tcf_proto *tp, *tp_prev;
	int err;

	lockdep_assert_held(&block->cb_lock);

	for (chain = __tcf_get_next_chain(block, NULL);/*取block上首个chain*/
	     chain;
	     chain_prev = chain,/*保存上一个chain*/
		     chain = __tcf_get_next_chain(block, chain),/*取下一个chain*/
		     tcf_chain_put(chain_prev)/*减少chain_prev的计数*/) {
		if (chain->tmplt_ops && add)
			chain->tmplt_ops->tmplt_reoffload(chain, true, cb,
							  cb_priv);
		//遍历此chain上所有tp
		for (tp = __tcf_get_next_proto(chain, NULL)/*取首个tp*/; tp;
		     tp_prev = tp,/*保存上一个tp*/
			     tp = __tcf_get_next_proto(chain, tp),/*取下一个tp*/
			     tcf_proto_put(tp_prev, true, NULL)/*减少tp_prv的计数*/) {
			//调用reoffload，完成此tp的规则再下发
			if (tp->ops->reoffload) {
				err = tp->ops->reoffload(tp, add, cb, cb_priv,
							 extack);
				if (err && add)
				    /*添加时出错，执行删除*/
					goto err_playback_remove;
			} else if (add && offload_in_use) {
				err = -EOPNOTSUPP;
				NL_SET_ERR_MSG(extack, "Filter HW offload failed - classifier without re-offloading support");
				goto err_playback_remove;
			}
		}
		if (chain->tmplt_ops && !add)
			chain->tmplt_ops->tmplt_reoffload(chain, false, cb,
							  cb_priv);
	}

	return 0;

err_playback_remove:
	tcf_proto_put(tp, true, NULL);
	tcf_chain_put(chain);
	tcf_block_playback_offloads(block, cb, cb_priv, false, offload_in_use,
				    extack);
	return err;
}

//在block上增加新的bo
static int tcf_block_bind(struct tcf_block *block,
			  struct flow_block_offload *bo)
{
	struct flow_block_cb *block_cb, *next;
	int err, i = 0;

	lockdep_assert_held(&block->cb_lock);

	//block bind成功，block可能上已有规则，这里使block上所有chain(chain上所有tp,针对每个tp调用reoffload)
	list_for_each_entry(block_cb, &bo->cb_list, list) {
		err = tcf_block_playback_offloads(block, block_cb->cb,
						  block_cb->cb_priv, true,
						  tcf_block_offload_in_use(block),
						  bo->extack);
		if (err)
			goto err_unroll;
		if (!bo->unlocked_driver_cb)
			block->lockeddevcnt++;

		i++;
	}

	//为block增加新的bo
	list_splice(&bo->cb_list, &block->flow_block.cb_list);

	return 0;

err_unroll:
	list_for_each_entry_safe(block_cb, next, &bo->cb_list, list) {
		list_del(&block_cb->driver_list);
		if (i-- > 0) {
			list_del(&block_cb->list);
			tcf_block_playback_offloads(block, block_cb->cb,
						    block_cb->cb_priv, false,
						    tcf_block_offload_in_use(block),
						    NULL);
			if (!bo->unlocked_driver_cb)
				block->lockeddevcnt--;
		}
		flow_block_cb_free(block_cb);
	}

	return err;
}

/*将此设备上已offload的规则解绑*/
static void tcf_block_unbind(struct tcf_block *block,
			     struct flow_block_offload *bo)
{
	struct flow_block_cb *block_cb, *next;

	lockdep_assert_held(&block->cb_lock);

	//遍历bo->cb_list,针对所有tp执行reoffload完成规则移除
	list_for_each_entry_safe(block_cb, next, &bo->cb_list, list) {
		tcf_block_playback_offloads(block, block_cb->cb,
					    block_cb->cb_priv, false,/*指明为规则移除*/
					    tcf_block_offload_in_use(block),
					    NULL);
		list_del(&block_cb->list);
		flow_block_cb_free(block_cb);
		if (!bo->unlocked_driver_cb)
			block->lockeddevcnt--;
	}
}

static int tcf_block_setup(struct tcf_block *block,
			   struct flow_block_offload *bo)
{
	int err;

	switch (bo->command) {
	case FLOW_BLOCK_BIND:
	    //bond情况下，需要将driver填充好的bo更新到block上
		err = tcf_block_bind(block, bo);
		break;
	case FLOW_BLOCK_UNBIND:
	    //移除block上指定的bo
		err = 0;
		tcf_block_unbind(block, bo);
		break;
	default:
		WARN_ON_ONCE(1);
		err = -EOPNOTSUPP;
	}

	return err;
}

/* Main classifier routine: scans classifier chain attached
 * to this qdisc, (optionally) tests for protocol and asks
 * specific classifiers.
 */
//tc报文分类入口(过滤器分类）
static inline int __tcf_classify(struct sk_buff *skb,
				 const struct tcf_proto *tp,
				 const struct tcf_proto *orig_tp,
				 struct tcf_result *res/*分类结果*/,
				 bool compat_mode,
				 struct tcf_exts_miss_cookie_node *n,
				 int act_index,
				 u32 *last_executed_chain/*上次执行时的chain*/)
{
#ifdef CONFIG_NET_CLS_ACT
	const int max_reclassify_loop = 16;
	const struct tcf_proto *first_tp;
	int limit = 0;

reclassify:
#endif
	//遍历tp列表，检查哪条tp可对此报文进行分类（按协议划分）
	for (; tp; tp = rcu_dereference_bh(tp->next)) {
		//取出报文对应的protocol(三层类型）
		__be16 protocol = skb_protocol(skb, false);
		int err = 0;

		if (n) {
			struct tcf_exts *exts;

			if (n->tp_prio != tp->prio)
				continue;

			/* We re-lookup the tp and chain based on index instead
			 * of having hard refs and locks to them, so do a sanity
			 * check if any of tp,chain,exts was replaced by the
			 * time we got here with a cookie from hardware.
			 */
			if (unlikely(n->tp != tp || n->tp->chain != n->chain ||
				     !tp->ops->get_exts)) {
				tcf_set_drop_reason(skb,
						    SKB_DROP_REASON_TC_COOKIE_ERROR);
				return TC_ACT_SHOT;
			}

			exts = tp->ops->get_exts(tp, n->handle);
			if (unlikely(!exts || n->exts != exts)) {
				tcf_set_drop_reason(skb,
						    SKB_DROP_REASON_TC_COOKIE_ERROR);
				return TC_ACT_SHOT;
			}

			n = NULL;
			err = tcf_exts_exec_ex(skb, exts, act_index, res);
		} else {
			//忽略掉protocol不匹配的tp
			if (tp->protocol != protocol &&
			    tp->protocol != htons(ETH_P_ALL))
				continue;

			//针对skb使用tp进行分类(例如flower的classify函数）
			err = tc_classify(skb, tp, res);
		}
#ifdef CONFIG_NET_CLS_ACT
		if (unlikely(err == TC_ACT_RECLASSIFY && !compat_mode)) {
			//执行重新分类
			first_tp = orig_tp;
			*last_executed_chain = first_tp->chain->index;
			goto reset;
		} else if (unlikely(TC_ACT_EXT_CMP(err, TC_ACT_GOTO_CHAIN))) {
			//跳到指定chain并继续匹配
			first_tp = res->goto_tp;
			*last_executed_chain = err & TC_ACT_EXT_VAL_MASK;
			goto reset;
		}
#endif
		if (err >= 0)
			return err;
	}

	if (unlikely(n)) {
		tcf_set_drop_reason(skb,
				    SKB_DROP_REASON_TC_COOKIE_ERROR);
		return TC_ACT_SHOT;
	}

	return TC_ACT_UNSPEC; /* signal: continue lookup */
#ifdef CONFIG_NET_CLS_ACT
reset:
	//最多仅容许 max_reclassify_loop 次重查
	if (unlikely(limit++ >= max_reclassify_loop)) {
		net_notice_ratelimited("%u: reclassify loop, rule prio %u, protocol %02x\n",
				       tp->chain->block->index,
				       tp->prio & 0xffff,
				       ntohs(tp->protocol));
		tcf_set_drop_reason(skb,
				    SKB_DROP_REASON_TC_RECLASSIFY_LOOP);
		return TC_ACT_SHOT;
	}

	//自first_tp开始进行新的查找
	tp = first_tp;
	goto reclassify;
#endif
}

int tcf_classify(struct sk_buff *skb,
		 const struct tcf_block *block,
		 const struct tcf_proto *tp,
		 struct tcf_result *res, bool compat_mode)
{
#if !IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
	u32 last_executed_chain = 0;

	return __tcf_classify(skb, tp, tp, res, compat_mode, NULL, 0,
			      &last_executed_chain);
#else
	/*开启了skb扩展，则从skb扩展中获取chain信息，容许硬件执行一半后再upcall*/
	u32 last_executed_chain = tp ? tp->chain->index : 0;
	struct tcf_exts_miss_cookie_node *n = NULL;
	const struct tcf_proto *orig_tp = tp;
	struct tc_skb_ext *ext;
	int act_index = 0;
	int ret;

	if (block) {
		ext = skb_ext_find(skb, TC_SKB_EXT);

		if (ext && (ext->chain || ext->act_miss)) {
			struct tcf_chain *fchain;
			u32 chain;

			if (ext->act_miss) {
				n = tcf_exts_miss_cookie_lookup(ext->act_miss_cookie,
								&act_index);
				if (!n) {
					tcf_set_drop_reason(skb,
							    SKB_DROP_REASON_TC_COOKIE_ERROR);
					return TC_ACT_SHOT;
				}

				chain = n->chain_index;
			} else {
				chain = ext->chain;
			}

			fchain = tcf_chain_lookup_rcu(block, chain);
			if (!fchain) {
				tcf_set_drop_reason(skb,
						    SKB_DROP_REASON_TC_CHAIN_NOTFOUND);

				return TC_ACT_SHOT;
			}

			/* Consume, so cloned/redirect skbs won't inherit ext */
			skb_ext_del(skb, TC_SKB_EXT);

			tp = rcu_dereference_bh(fchain->filter_chain);
			last_executed_chain = fchain->index;
		}
	}

	ret = __tcf_classify(skb, tp, orig_tp, res, compat_mode, n, act_index,
			     &last_executed_chain);

	if (tc_skb_ext_tc_enabled()) {
		/* If we missed on some chain */
		if (ret == TC_ACT_UNSPEC && last_executed_chain) {
			struct tc_skb_cb *cb = tc_skb_cb(skb);

	    		/*向skb中添加扩展，记录当前执行到哪个chain*/
			ext = tc_skb_ext_alloc(skb);
			if (WARN_ON_ONCE(!ext)) {
				tcf_set_drop_reason(skb, SKB_DROP_REASON_NOMEM);
				return TC_ACT_SHOT;
			}
			ext->chain = last_executed_chain;
			ext->mru = cb->mru;
			ext->post_ct = cb->post_ct;
			ext->post_ct_snat = cb->post_ct_snat;
			ext->post_ct_dnat = cb->post_ct_dnat;
			ext->zone = cb->zone;
		}
	}

	return ret;
#endif
}
EXPORT_SYMBOL(tcf_classify);

struct tcf_chain_info {
	struct tcf_proto __rcu **pprev;//链上指向某tp的前向指针
	struct tcf_proto __rcu *next;//链上指向某tp的后向指针
};

static struct tcf_proto *tcf_chain_tp_prev(struct tcf_chain *chain,
					   struct tcf_chain_info *chain_info)
{
	return tcf_chain_dereference(*chain_info->pprev, chain);
}

//向chain中插入分类器
static int tcf_chain_tp_insert(struct tcf_chain *chain,
			       struct tcf_chain_info *chain_info,
			       struct tcf_proto *tp)
{
	if (chain->flushing)
		return -EAGAIN;

	RCU_INIT_POINTER(tp->next, tcf_chain_tp_prev(chain, chain_info));
	if (*chain_info->pprev == chain->filter_chain)
		//首个tp
		//chain->filter_chain上原来为空,新需要插入tp,触发对filter_list更新，
		//从而使tcf_classficy可以遍历tp
		tcf_chain0_head_change(chain, tp);
	tcf_proto_get(tp);
	//修改*chain_info->prev指向tp,完成tp插入
	rcu_assign_pointer(*chain_info->pprev, tp);

	return 0;
}

//删除tp
static void tcf_chain_tp_remove(struct tcf_chain *chain,
				struct tcf_chain_info *chain_info,
				struct tcf_proto *tp)
{
	//取下一个tp
	struct tcf_proto *next = tcf_chain_dereference(chain_info->next, chain);

	//标记删除
	tcf_proto_mark_delete(tp);

	//如果首个tp被删除，则执行tp变更通知
	if (tp == chain->filter_chain)
		tcf_chain0_head_change(chain, next);
	//指针变更
	RCU_INIT_POINTER(*chain_info->pprev, next);
}

static struct tcf_proto *tcf_chain_tp_find(struct tcf_chain *chain,
					   struct tcf_chain_info *chain_info,
					   u32 protocol, u32 prio,
					   bool prio_allocate);

/* Try to insert new proto.
 * If proto with specified priority already exists, free new proto
 * and return existing one.
 */

static struct tcf_proto *tcf_chain_tp_insert_unique(struct tcf_chain *chain,
						    struct tcf_proto *tp_new,
						    u32 protocol, u32 prio,
						    bool rtnl_held)
{
	struct tcf_chain_info chain_info;
	struct tcf_proto *tp;
	int err = 0;

	mutex_lock(&chain->filter_chain_lock);

	if (tcf_proto_exists_destroying(chain, tp_new)) {
		mutex_unlock(&chain->filter_chain_lock);
		tcf_proto_destroy(tp_new, rtnl_held, false, NULL);
		return ERR_PTR(-EAGAIN);
	}

	/*确定挺入的位置*/
	tp = tcf_chain_tp_find(chain, &chain_info,
			       protocol, prio, false);
	if (!tp)
		//原来没有tp,则插入新的tp
		err = tcf_chain_tp_insert(chain, &chain_info, tp_new);
	mutex_unlock(&chain->filter_chain_lock);

	if (tp) {
		//原来有tp,则销毁tp_new
		tcf_proto_destroy(tp_new, rtnl_held, false, NULL);
		tp_new = tp;
	} else if (err) {
		tcf_proto_destroy(tp_new, rtnl_held, false, NULL);
		tp_new = ERR_PTR(err);
	}

	return tp_new;
}

static void tcf_chain_tp_delete_empty(struct tcf_chain *chain,
				      struct tcf_proto *tp, bool rtnl_held,
				      struct netlink_ext_ack *extack)
{
	struct tcf_chain_info chain_info;
	struct tcf_proto *tp_iter;
	struct tcf_proto **pprev;
	struct tcf_proto *next;

	mutex_lock(&chain->filter_chain_lock);

	/* Atomically find and remove tp from chain. */
	for (pprev = &chain->filter_chain;
	     (tp_iter = tcf_chain_dereference(*pprev, chain));
	     pprev = &tp_iter->next) {
		if (tp_iter == tp) {
			chain_info.pprev = pprev;
			chain_info.next = tp_iter->next;
			WARN_ON(tp_iter->deleting);
			break;
		}
	}
	/* Verify that tp still exists and no new filters were inserted
	 * concurrently.
	 * Mark tp for deletion if it is empty.
	 */
	if (!tp_iter || !tcf_proto_check_delete(tp)) {
		mutex_unlock(&chain->filter_chain_lock);
		return;
	}

	tcf_proto_signal_destroying(chain, tp);
	next = tcf_chain_dereference(chain_info.next, chain);
	if (tp == chain->filter_chain)
		tcf_chain0_head_change(chain, next);
	RCU_INIT_POINTER(*chain_info.pprev, next);
	mutex_unlock(&chain->filter_chain_lock);

	tcf_proto_put(tp, rtnl_held, extack);
}

/**/
static struct tcf_proto *tcf_chain_tp_find(struct tcf_chain *chain,
					   struct tcf_chain_info *chain_info/*出参，返回待插入的位置信息*/,
					   u32 protocol, u32 prio,
					   bool prio_allocate)
{
	struct tcf_proto **pprev;
	struct tcf_proto *tp;

	/* Check the chain for existence of proto-tcf with this priority */
	//遍历filtr_chain链，链上每一个元素为一个tp
	for (pprev = &chain->filter_chain;
	     (tp = tcf_chain_dereference(*pprev, chain));
	     pprev = &tp->next) {
		//优先级必须查等，否则直接发返回NULL
		if (tp->prio >= prio) {
			if (tp->prio == prio) {
				//如果要申请，则存在返失败，否则要求协议号必须相等
				if (prio_allocate ||
				    (tp->protocol != protocol && protocol))
					return ERR_PTR(-EINVAL);
			} else {
				tp = NULL;
			}
			break;
		}
	}

	//设置chain_info,1.使其指示待插入tp要写入的位置（此指针指向下一个元素）
	//2.保存当前tp指向的下一个元素
	chain_info->pprev = pprev;
	if (tp) {
		chain_info->next = tp->next;
		tcf_proto_get(tp);
	} else {
		chain_info->next = NULL;
	}
	return tp;
}

static int tcf_fill_node(struct net *net, struct sk_buff *skb,
			 struct tcf_proto *tp/*待dump的filter*/, struct tcf_block *block,
			 struct Qdisc *q, u32 parent, void *fh,
			 u32 portid, u32 seq, u16 flags, int event,
			 bool terse_dump, bool rtnl_held,
			 struct netlink_ext_ack *extack)
{
	struct tcmsg *tcm;
	struct nlmsghdr  *nlh;
	unsigned char *b = skb_tail_pointer(skb);

	/*构造nlmsghdr*/
	nlh = nlmsg_put(skb, portid, seq, event, sizeof(*tcm), flags);
	if (!nlh)
		goto out_nlmsg_trim;
	tcm = nlmsg_data(nlh);
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm__pad1 = 0;
	tcm->tcm__pad2 = 0;
	if (q) {
		tcm->tcm_ifindex = qdisc_dev(q)->ifindex;
		tcm->tcm_parent = parent;
	} else {
		tcm->tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
		tcm->tcm_block_index = block->index;
	}
	tcm->tcm_info = TC_H_MAKE(tp->prio, tp->protocol);
	//存入filter名称
	if (nla_put_string(skb, TCA_KIND, tp->ops->kind))
		goto nla_put_failure;

	//存入chain索引
	if (nla_put_u32(skb, TCA_CHAIN, tp->chain->index))
		goto nla_put_failure;

	if (!fh) {
		tcm->tcm_handle = 0;
	} else if (terse_dump) {
		if (tp->ops->terse_dump) {
			if (tp->ops->terse_dump(net, tp, fh, skb, tcm,
						rtnl_held) < 0)
				goto nla_put_failure;
		} else {
			goto cls_op_not_supp;
		}
	} else {
		//执行filter的dump输出，并进行netlink封装
		if (tp->ops->dump &&
		    tp->ops->dump(net, tp, fh, skb, tcm, rtnl_held) < 0)
			goto nla_put_failure;
	}

	if (extack && extack->_msg &&
	    nla_put_string(skb, TCA_EXT_WARN_MSG, extack->_msg))
		goto nla_put_failure;

	nlh->nlmsg_len = skb_tail_pointer(skb) - b;

	return skb->len;

out_nlmsg_trim:
nla_put_failure:
cls_op_not_supp:
	nlmsg_trim(skb, b);
	return -1;
}

static int tfilter_notify(struct net *net, struct sk_buff *oskb,
			  struct nlmsghdr *n, struct tcf_proto *tp,
			  struct tcf_block *block, struct Qdisc *q,
			  u32 parent, void *fh, int event, bool unicast/*是否单播发送*/,
			  bool rtnl_held, struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	int err = 0;

	if (!unicast && !rtnl_notify_needed(net, n->nlmsg_flags, RTNLGRP_TC))
		return 0;

	/*申请skb*/
	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	//填充tp信息
	if (tcf_fill_node(net, skb, tp, block, q, parent, fh, portid,
			  n->nlmsg_seq, n->nlmsg_flags, event,
			  false, rtnl_held, extack) <= 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	if (unicast)
	    	/*单播完成报文发送*/
		err = rtnl_unicast(skb, net, portid);
	else
		err = rtnetlink_send(skb, net, portid, RTNLGRP_TC,
				     n->nlmsg_flags & NLM_F_ECHO);
	return err;
}

static int tfilter_del_notify(struct net *net, struct sk_buff *oskb,
			      struct nlmsghdr *n, struct tcf_proto *tp,
			      struct tcf_block *block, struct Qdisc *q,
			      u32 parent, void *fh, bool *last, bool rtnl_held,
			      struct netlink_ext_ack *extack)
{
	struct sk_buff *skb;
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	int err;

	if (!rtnl_notify_needed(net, n->nlmsg_flags, RTNLGRP_TC))
		return tp->ops->delete(tp, fh, last, rtnl_held, extack);

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tcf_fill_node(net, skb, tp, block, q, parent, fh, portid,
			  n->nlmsg_seq, n->nlmsg_flags, RTM_DELTFILTER,
			  false, rtnl_held, extack) <= 0) {
		NL_SET_ERR_MSG(extack, "Failed to build del event notification");
		kfree_skb(skb);
		return -EINVAL;
	}

	err = tp->ops->delete(tp, fh, last, rtnl_held, extack);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	err = rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			     n->nlmsg_flags & NLM_F_ECHO);
	if (err < 0)
		NL_SET_ERR_MSG(extack, "Failed to send filter delete notification");

	return err;
}

static void tfilter_notify_chain(struct net *net, struct sk_buff *oskb,
				 struct tcf_block *block, struct Qdisc *q,
				 u32 parent, struct nlmsghdr *n,
				 struct tcf_chain *chain, int event,
				 struct netlink_ext_ack *extack)
{
	struct tcf_proto *tp;

	/*遍历chain上所有tcf_proto,触发event事件通知*/
	for (tp = tcf_get_next_proto(chain, NULL);
	     tp; tp = tcf_get_next_proto(chain, tp))
		tfilter_notify(net, oskb, n, tp, block, q, parent, NULL,
			       event, false, true, extack);
}

static void tfilter_put(struct tcf_proto *tp, void *fh)
{
	if (tp->ops->put && fh)
		tp->ops->put(tp, fh);
}

static bool is_qdisc_ingress(__u32 classid)
{
	return (TC_H_MIN(classid) == TC_H_MIN(TC_H_MIN_INGRESS));
}

//netlink收到tc新加filter的命令后，此函数将被调用
static int tc_new_tfilter(struct sk_buff *skb, struct nlmsghdr *n/*netlink消息头*/,
			  struct netlink_ext_ack *extack/*出参，ack时使用*/)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	char name[IFNAMSIZ];
	struct tcmsg *t;
	u32 protocol;
	u32 prio;
	bool prio_allocate/*prio是否自动申请的*/;
	u32 parent;
	u32 chain_index;
	struct Qdisc *q;
	struct tcf_chain_info chain_info;
	struct tcf_chain *chain;
	struct tcf_block *block;
	struct tcf_proto *tp;
	unsigned long cl;
	void *fh;
	int err;
	int tp_created;
	/*标记是否已执行加锁：rtnl_lock*/
	bool rtnl_held = false;
	u32 flags;

replay:
	tp_created = 0;

	//消息解析及校验
	err = nlmsg_parse_deprecated(n, sizeof(*t)/*消息头部大小*/, tca/*按属性指向属性数组*/, TCA_MAX,
				     rtm_tca_policy, extack);
	if (err < 0)
		return err;

	t = nlmsg_data(n);

	//提取filter对应报文类型
	protocol = TC_H_MIN(t->tcm_info);
	//filter对应的优先级
	prio = TC_H_MAJ(t->tcm_info);
	/*默认优先级不申请*/
	prio_allocate = false;
	parent = t->tcm_parent;
	tp = NULL;
	cl = 0;
	block = NULL;
	q = NULL;
	chain = NULL;
	flags = 0;

	//如果未指定prio,有CREATE标记，则需要申请优先级，这里先使用一个临时值
	if (prio == 0) {
		/* If no priority is provided by the user,
		 * we allocate one.
		 */
		if (n->nlmsg_flags & NLM_F_CREATE) {
			prio = TC_H_MAKE(0x80000000U, 0U);
			prio_allocate = true;
		} else {
			NL_SET_ERR_MSG(extack, "Invalid filter command with priority of zero");
			return -ENOENT;
		}
	}

	/*查找qdisc,注：这里要求此qdisc支持class分类，且支持block*/
	/* Find head of filter chain. */

	err = __tcf_qdisc_find(net, &q, &parent, t->tcm_ifindex, false, extack);
	if (err)
		return err;

	/*kind名称长度检查，并设置到name*/
	if (tcf_proto_check_kind(tca[TCA_KIND], name)) {
		NL_SET_ERR_MSG(extack, "Specified TC filter name too long");
		err = -EINVAL;
		goto errout;
	}

	/* Take rtnl mutex if rtnl_held was set to true on previous iteration,
	 * block is shared (no qdisc found), qdisc is not unlocked, classifier
	 * type is not specified, classifier is not unlocked.
	 */
	if (rtnl_held ||
	    (q && !(q->ops->cl_ops->flags & QDISC_CLASS_OPS_DOIT_UNLOCKED)) ||
	    !tcf_proto_is_unlocked(name)) {
	    /*ops需要进行加锁，执行加锁*/
		rtnl_held = true;
		rtnl_lock();
	}

	//通过qdisc查找cl
	err = __tcf_qdisc_cl_find(q, parent, &cl, t->tcm_ifindex, extack);
	if (err)
		goto errout;

	//通过q,cl,查找block（支持share block,非share block获取）
	block = __tcf_block_find(net, q, cl, t->tcm_ifindex, t->tcm_block_index,
				 extack);
	if (IS_ERR(block)) {
		err = PTR_ERR(block);
		goto errout;
	}
	block->classid = parent;

	//取配置的chain索引
	chain_index = tca[TCA_CHAIN] ? nla_get_u32(tca[TCA_CHAIN]) : 0;
	if (chain_index > TC_ACT_EXT_VAL_MASK) {
		NL_SET_ERR_MSG(extack, "Specified chain index exceeds upper limit");
		err = -EINVAL;
		goto errout;
	}

	//创建或获取指定index的chain
	chain = tcf_chain_get(block, chain_index, true);
	if (!chain) {
		NL_SET_ERR_MSG(extack, "Cannot create specified filter chain");
		err = -ENOMEM;
		goto errout;
	}

	//在chain上按prio,protocol查找指定的tc filter protocol分类器
	mutex_lock(&chain->filter_chain_lock);
	tp = tcf_chain_tp_find(chain, &chain_info, protocol,
			       prio, prio_allocate);
	if (IS_ERR(tp)) {
		//查找中出现错误（有冲突）
		NL_SET_ERR_MSG(extack, "Filter with specified priority/protocol not found");
		err = PTR_ERR(tp);
		goto errout_locked;
	}

	if (tp == NULL) {
		//未找到对应的tc filter protocol分类器，创建它
		struct tcf_proto *tp_new = NULL;

		if (chain->flushing) {
			err = -EAGAIN;
			goto errout_locked;
		}

		/* Proto-tcf does not exist, create new one */

		if (tca[TCA_KIND] == NULL || !protocol) {
			NL_SET_ERR_MSG(extack, "Filter kind and protocol must be specified");
			err = -EINVAL;
			goto errout_locked;
		}

		if (!(n->nlmsg_flags & NLM_F_CREATE)) {
			NL_SET_ERR_MSG(extack, "Need both RTM_NEWTFILTER and NLM_F_CREATE to create a new filter");
			err = -ENOENT;
			goto errout_locked;
		}

		/*自动申请比较小的优先级*/
		if (prio_allocate)
			prio = tcf_auto_prio(tcf_chain_tp_prev(chain,
							       &chain_info));

		mutex_unlock(&chain->filter_chain_lock);
		/*按参数创建tcf_proto*/
		tp_new = tcf_proto_create(name, protocol, prio, chain,
					  rtnl_held, extack);
		if (IS_ERR(tp_new)) {
			err = PTR_ERR(tp_new);
			goto errout_tp;
		}

		tp_created = 1;
		//将tp_new加入到chain中
		tp = tcf_chain_tp_insert_unique(chain, tp_new, protocol, prio,
						rtnl_held);
		if (IS_ERR(tp)) {
			err = PTR_ERR(tp);
			goto errout_tp;
		}
	} else {
		mutex_unlock(&chain->filter_chain_lock);
	}

	//kind必须与tp->ops的kind一致
	if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], tp->ops->kind)) {
		NL_SET_ERR_MSG(extack, "Specified filter kind does not match existing one");
		err = -EINVAL;
		goto errout;
	}

	//在tp中通过t->tcm_handle查找指定tfilter
	fh = tp->ops->get(tp, t->tcm_handle);

	if (!fh) {
		//没有找到对应的规则，但没有create标记，告错
		if (!(n->nlmsg_flags & NLM_F_CREATE)) {
			NL_SET_ERR_MSG(extack, "Need both RTM_NEWTFILTER and NLM_F_CREATE to create a new filter");
			err = -ENOENT;
			goto errout;
		}
	} else if (n->nlmsg_flags & NLM_F_EXCL) {
		//找到了相应的规则，有excl标记，报错，规则已存在
		tfilter_put(tp, fh);
		NL_SET_ERR_MSG(extack, "Filter already exists");
		err = -EEXIST;
		goto errout;
	}

	//chain如果有模块ops,则必须要与创建的是同一类型
	if (chain->tmplt_ops && chain->tmplt_ops != tp->ops) {
		tfilter_put(tp, fh);
		NL_SET_ERR_MSG(extack, "Chain template is set to a different filter kind");
		err = -EINVAL;
		goto errout;
	}

	if (!(n->nlmsg_flags & NLM_F_CREATE))
		flags |= TCA_ACT_FLAGS_REPLACE;
	if (!rtnl_held)
		flags |= TCA_ACT_FLAGS_NO_RTNL;
	if (is_qdisc_ingress(parent))
		flags |= TCA_ACT_FLAGS_AT_INGRESS;
	//新增规则或者改变规则(例如flower对应的cls_fl_ops）
	err = tp->ops->change(net, skb, tp, cl, t->tcm_handle, tca, &fh/*入参旧规则，出参新规则*/,
			      flags, extack);
	if (err == 0) {
	    /*执行成功，知会newtfilter规则新建/变更*/
		tfilter_notify(net, skb, n, tp, block, q, parent, fh,
			       RTM_NEWTFILTER, false/*组播通知*/, rtnl_held, extack);
		tfilter_put(tp, fh);
		/* q pointer is NULL for shared blocks */
		if (q)
			q->flags &= ~TCQ_F_CAN_BYPASS;
	}

errout:
	if (err && tp_created)
		tcf_chain_tp_delete_empty(chain, tp, rtnl_held, NULL);
errout_tp:
	if (chain) {
		if (tp && !IS_ERR(tp))
			tcf_proto_put(tp, rtnl_held, NULL);
		if (!tp_created)
			tcf_chain_put(chain);
	}
	tcf_block_release(q, block, rtnl_held);

	if (rtnl_held)
		rtnl_unlock();

	if (err == -EAGAIN) {
		/* Take rtnl lock in case EAGAIN is caused by concurrent flush
		 * of target chain.
		 */
		rtnl_held = true;
		/* Replay the request. */
		goto replay;
	}
	return err;

errout_locked:
	mutex_unlock(&chain->filter_chain_lock);
	goto errout;
}

//filter删除实现
static int tc_del_tfilter(struct sk_buff *skb, struct nlmsghdr *n,
			  struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	char name[IFNAMSIZ];
	struct tcmsg *t;
	u32 protocol;
	u32 prio;
	u32 parent;
	u32 chain_index;
	struct Qdisc *q = NULL;
	struct tcf_chain_info chain_info;
	struct tcf_chain *chain = NULL;
	struct tcf_block *block = NULL;
	struct tcf_proto *tp = NULL;
	unsigned long cl = 0;
	void *fh = NULL;
	int err;
	bool rtnl_held = false;

	err = nlmsg_parse_deprecated(n, sizeof(*t), tca, TCA_MAX,
				     rtm_tca_policy, extack);
	if (err < 0)
		return err;

	t = nlmsg_data(n);
	protocol = TC_H_MIN(t->tcm_info);
	prio = TC_H_MAJ(t->tcm_info);
	parent = t->tcm_parent;

	if (prio == 0 && (protocol || t->tcm_handle || tca[TCA_KIND])) {
		NL_SET_ERR_MSG(extack, "Cannot flush filters with protocol, handle or kind set");
		return -ENOENT;
	}

	/* Find head of filter chain. */

	err = __tcf_qdisc_find(net, &q, &parent, t->tcm_ifindex, false, extack);
	if (err)
		return err;

	if (tcf_proto_check_kind(tca[TCA_KIND], name)) {
		NL_SET_ERR_MSG(extack, "Specified TC filter name too long");
		err = -EINVAL;
		goto errout;
	}
	/* Take rtnl mutex if flushing whole chain, block is shared (no qdisc
	 * found), qdisc is not unlocked, classifier type is not specified,
	 * classifier is not unlocked.
	 */
	if (!prio ||
	    (q && !(q->ops->cl_ops->flags & QDISC_CLASS_OPS_DOIT_UNLOCKED)) ||
	    !tcf_proto_is_unlocked(name)) {
		rtnl_held = true;
		rtnl_lock();
	}

	err = __tcf_qdisc_cl_find(q, parent, &cl, t->tcm_ifindex, extack);
	if (err)
		goto errout;

	block = __tcf_block_find(net, q, cl, t->tcm_ifindex, t->tcm_block_index,
				 extack);
	if (IS_ERR(block)) {
		err = PTR_ERR(block);
		goto errout;
	}

	chain_index = tca[TCA_CHAIN] ? nla_get_u32(tca[TCA_CHAIN]) : 0;
	if (chain_index > TC_ACT_EXT_VAL_MASK) {
		NL_SET_ERR_MSG(extack, "Specified chain index exceeds upper limit");
		err = -EINVAL;
		goto errout;
	}
	chain = tcf_chain_get(block, chain_index, false);
	if (!chain) {
		/* User requested flush on non-existent chain. Nothing to do,
		 * so just return success.
		 */
		if (prio == 0) {
			err = 0;
			goto errout;
		}
		NL_SET_ERR_MSG(extack, "Cannot find specified filter chain");
		err = -ENOENT;
		goto errout;
	}

	if (prio == 0) {
		tfilter_notify_chain(net, skb, block, q, parent, n,
				     chain, RTM_DELTFILTER, extack);
		tcf_chain_flush(chain, rtnl_held);
		err = 0;
		goto errout;
	}

	mutex_lock(&chain->filter_chain_lock);
	tp = tcf_chain_tp_find(chain, &chain_info, protocol,
			       prio, false);
	if (!tp || IS_ERR(tp)) {
		NL_SET_ERR_MSG(extack, "Filter with specified priority/protocol not found");
		err = tp ? PTR_ERR(tp) : -ENOENT;
		goto errout_locked;
	} else if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], tp->ops->kind)) {
		NL_SET_ERR_MSG(extack, "Specified filter kind does not match existing one");
		err = -EINVAL;
		goto errout_locked;
	} else if (t->tcm_handle == 0) {
		tcf_proto_signal_destroying(chain, tp);
		tcf_chain_tp_remove(chain, &chain_info, tp);
		mutex_unlock(&chain->filter_chain_lock);

		tcf_proto_put(tp, rtnl_held, NULL);
		tfilter_notify(net, skb, n, tp, block, q, parent, fh,
			       RTM_DELTFILTER, false, rtnl_held, extack);
		err = 0;
		goto errout;
	}
	mutex_unlock(&chain->filter_chain_lock);

	fh = tp->ops->get(tp, t->tcm_handle);

	if (!fh) {
		NL_SET_ERR_MSG(extack, "Specified filter handle not found");
		err = -ENOENT;
	} else {
		bool last;

		err = tfilter_del_notify(net, skb, n, tp, block, q, parent, fh,
					 &last, rtnl_held, extack);

		if (err)
			goto errout;
		if (last)
			tcf_chain_tp_delete_empty(chain, tp, rtnl_held, extack);
	}

errout:
	if (chain) {
		if (tp && !IS_ERR(tp))
			tcf_proto_put(tp, rtnl_held, NULL);
		tcf_chain_put(chain);
	}
	tcf_block_release(q, block, rtnl_held);

	if (rtnl_held)
		rtnl_unlock();

	return err;

errout_locked:
	mutex_unlock(&chain->filter_chain_lock);
	goto errout;
}

//kernel提供对外filter获取接口
static int tc_get_tfilter(struct sk_buff *skb, struct nlmsghdr *n,
			  struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	char name[IFNAMSIZ];
	struct tcmsg *t;
	u32 protocol;
	u32 prio;
	u32 parent;
	u32 chain_index;
	struct Qdisc *q = NULL;
	struct tcf_chain_info chain_info;
	struct tcf_chain *chain = NULL;
	struct tcf_block *block = NULL;
	struct tcf_proto *tp = NULL;
	unsigned long cl = 0;
	void *fh = NULL;
	int err;
	bool rtnl_held = false;

	err = nlmsg_parse_deprecated(n, sizeof(*t), tca, TCA_MAX,
				     rtm_tca_policy, extack);
	if (err < 0)
		return err;

	t = nlmsg_data(n);
	protocol = TC_H_MIN(t->tcm_info);
	prio = TC_H_MAJ(t->tcm_info);
	parent = t->tcm_parent;

	if (prio == 0) {
		NL_SET_ERR_MSG(extack, "Invalid filter command with priority of zero");
		return -ENOENT;
	}

	/* Find head of filter chain. */

	err = __tcf_qdisc_find(net, &q, &parent, t->tcm_ifindex, false, extack);
	if (err)
		return err;

	if (tcf_proto_check_kind(tca[TCA_KIND], name)) {
		NL_SET_ERR_MSG(extack, "Specified TC filter name too long");
		err = -EINVAL;
		goto errout;
	}
	/* Take rtnl mutex if block is shared (no qdisc found), qdisc is not
	 * unlocked, classifier type is not specified, classifier is not
	 * unlocked.
	 */
	if ((q && !(q->ops->cl_ops->flags & QDISC_CLASS_OPS_DOIT_UNLOCKED)) ||
	    !tcf_proto_is_unlocked(name)) {
		rtnl_held = true;
		rtnl_lock();
	}

	err = __tcf_qdisc_cl_find(q, parent, &cl, t->tcm_ifindex, extack);
	if (err)
		goto errout;

	block = __tcf_block_find(net, q, cl, t->tcm_ifindex, t->tcm_block_index,
				 extack);
	if (IS_ERR(block)) {
		err = PTR_ERR(block);
		goto errout;
	}

	chain_index = tca[TCA_CHAIN] ? nla_get_u32(tca[TCA_CHAIN]) : 0;
	if (chain_index > TC_ACT_EXT_VAL_MASK) {
		NL_SET_ERR_MSG(extack, "Specified chain index exceeds upper limit");
		err = -EINVAL;
		goto errout;
	}
	chain = tcf_chain_get(block, chain_index, false);
	if (!chain) {
		NL_SET_ERR_MSG(extack, "Cannot find specified filter chain");
		err = -EINVAL;
		goto errout;
	}

	mutex_lock(&chain->filter_chain_lock);
	tp = tcf_chain_tp_find(chain, &chain_info, protocol,
			       prio, false);
	mutex_unlock(&chain->filter_chain_lock);
	if (!tp || IS_ERR(tp)) {
		NL_SET_ERR_MSG(extack, "Filter with specified priority/protocol not found");
		err = tp ? PTR_ERR(tp) : -ENOENT;
		goto errout;
	} else if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], tp->ops->kind)) {
		NL_SET_ERR_MSG(extack, "Specified filter kind does not match existing one");
		err = -EINVAL;
		goto errout;
	}

	fh = tp->ops->get(tp, t->tcm_handle);

	if (!fh) {
		NL_SET_ERR_MSG(extack, "Specified filter handle not found");
		err = -ENOENT;
	} else {
		err = tfilter_notify(net, skb, n, tp, block, q, parent,
				     fh, RTM_NEWTFILTER, true, rtnl_held, NULL);
		if (err < 0)
			NL_SET_ERR_MSG(extack, "Failed to send filter notify message");
	}

	tfilter_put(tp, fh);
errout:
	if (chain) {
		if (tp && !IS_ERR(tp))
			tcf_proto_put(tp, rtnl_held, NULL);
		tcf_chain_put(chain);
	}
	tcf_block_release(q, block, rtnl_held);

	if (rtnl_held)
		rtnl_unlock();

	return err;
}

struct tcf_dump_args {
	struct tcf_walker w;
	struct sk_buff *skb;/*dump要填充的skb*/
	struct netlink_callback *cb;
	struct tcf_block *block;/*当前dump的block*/
	struct Qdisc *q;/*当前dump对应的qdisc*/
	u32 parent;
	bool terse_dump;/*是否使能精简dump*/
};

//完成tp dump
static int tcf_node_dump(struct tcf_proto *tp, void *n, struct tcf_walker *arg)
{
	struct tcf_dump_args *a = (void *)arg;
	struct net *net = sock_net(a->skb->sk);

	//调用tc->dump将tp dump到a->skb中
	return tcf_fill_node(net, a->skb, tp, a->block, a->q, a->parent,
			     n, NETLINK_CB(a->cb->skb).portid,
			     a->cb->nlh->nlmsg_seq, NLM_F_MULTI,
			     RTM_NEWTFILTER, a->terse_dump, true, NULL);
}

//chain上所有的tp dump
static bool tcf_chain_dump(struct tcf_chain *chain, struct Qdisc *q, u32 parent,
			   struct sk_buff *skb, struct netlink_callback *cb/*netlink回调上下文*/,
			   long index_start, long *p_index/*入出参，tp起始索引*/, bool terse/*是否采用简短模式dump*/)
{
	struct net *net = sock_net(skb->sk);
	struct tcf_block *block = chain->block;
	struct tcmsg *tcm = nlmsg_data(cb->nlh);
	struct tcf_proto *tp, *tp_prev;
	struct tcf_dump_args arg;

	//遍历chain上的filter,针对filter进行dump
	for (tp = __tcf_get_next_proto(chain, NULL);
	     tp;
	     tp_prev = tp,
		     tp = __tcf_get_next_proto(chain, tp),
		     tcf_proto_put(tp_prev, true, NULL),
		     (*p_index)++) {
	    /*未达到dump起始位置，不处理*/
		if (*p_index < index_start)
			continue;
		if (TC_H_MAJ(tcm->tcm_info) &&
		    TC_H_MAJ(tcm->tcm_info) != tp->prio)
			continue;
		if (TC_H_MIN(tcm->tcm_info) &&
		    TC_H_MIN(tcm->tcm_info) != tp->protocol)
			continue;
		/*找到首个需要dump的位置，将cb->args[1]置为0*/
		if (*p_index > index_start)
			memset(&cb->args[1], 0,
			       sizeof(cb->args) - sizeof(cb->args[0]));
		if (cb->args[1] == 0) {
			if (tcf_fill_node(net, skb, tp, block, q, parent, NULL,
					  NETLINK_CB(cb->skb).portid,
					  cb->nlh->nlmsg_seq, NLM_F_MULTI,
					  RTM_NEWTFILTER, false, true, NULL) <= 0)
				goto errout;
			cb->args[1] = 1;
		}
		/*无walk回调，忽略*/
		if (!tp->ops->walk)
			continue;

		/*指定回调为tc filter填充函数*/
		arg.w.fn = tcf_node_dump;
		arg.skb = skb;
		arg.cb = cb;
		arg.block = block;
		arg.q = q;
		arg.parent = parent;
		arg.w.stop = 0;
		arg.w.skip = cb->args[1] - 1;
		arg.w.count = 0;
		arg.w.cookie = cb->args[2];
		arg.terse_dump = terse;
		tp->ops->walk(tp, &arg.w, true);
		cb->args[2] = arg.w.cookie;
		/*记录下一次dump对应的id号*/
		cb->args[1] = arg.w.count + 1;
		if (arg.w.stop)
			goto errout;
	}
	return true;

errout:
	tcf_proto_put(tp, true, NULL);
	return false;
}

static const struct nla_policy tcf_tfilter_dump_policy[TCA_MAX + 1] = {
	[TCA_CHAIN]      = { .type = NLA_U32 },
	[TCA_DUMP_FLAGS] = NLA_POLICY_BITFIELD32(TCA_DUMP_FLAGS_TERSE),
};

/* called with RTNL */
//tc提供的filter dump对外接口
static int tc_dump_tfilter(struct sk_buff *skb/*待填充的skb*/, struct netlink_callback *cb)
{
	struct tcf_chain *chain, *chain_prev;
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	struct Qdisc *q = NULL;
	struct tcf_block *block;
	struct tcmsg *tcm = nlmsg_data(cb->nlh);
	/*简短模式*/
	bool terse_dump = false;
	long index_start;
	long index;
	u32 parent;
	int err;

	if (nlmsg_len(cb->nlh) < sizeof(*tcm))
		return skb->len;

	err = nlmsg_parse_deprecated(cb->nlh, sizeof(*tcm), tca, TCA_MAX,
				     tcf_tfilter_dump_policy, cb->extack);
	if (err)
		return err;

	/*检查是否采用简短模式进行dump*/
	if (tca[TCA_DUMP_FLAGS]) {
		struct nla_bitfield32 flags =
			nla_get_bitfield32(tca[TCA_DUMP_FLAGS]);

		terse_dump = flags.value & TCA_DUMP_FLAGS_TERSE;
	}

	if (tcm->tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK) {
		block = tcf_block_refcnt_get(net, tcm->tcm_block_index);
		if (!block)
			goto out;
		/* If we work with block index, q is NULL and parent value
		 * will never be used in the following code. The check
		 * in tcf_fill_node prevents it. However, compiler does not
		 * see that far, so set parent to zero to silence the warning
		 * about parent being uninitialized.
		 */
		parent = 0;
	} else {
		const struct Qdisc_class_ops *cops;
		struct net_device *dev;
		unsigned long cl = 0;

		//由ifindex取得对应的netdev
		dev = __dev_get_by_index(net, tcm->tcm_ifindex);
		if (!dev)
			return skb->len;

		parent = tcm->tcm_parent;
		if (!parent)
			q = rtnl_dereference(dev->qdisc);
		else
			q = qdisc_lookup(dev, TC_H_MAJ(tcm->tcm_parent));
		if (!q)
			goto out;
		cops = q->ops->cl_ops;
		if (!cops)
			goto out;
		if (!cops->tcf_block)
			goto out;
		/*获得class分类*/
		if (TC_H_MIN(tcm->tcm_parent)) {
			cl = cops->find(q, tcm->tcm_parent);
			if (cl == 0)
				goto out;
		}
		/*获得class分类对应的block*/
		block = cops->tcf_block(q, cl, NULL);
		if (!block)
			goto out;
		parent = block->classid;
		if (tcf_block_shared(block))
			q = NULL;
	}

	//记录起始位置
	index_start = cb->args[0];
	index = 0;

	/*遍历block上的chain，针对chain进行dump*/
	for (chain = __tcf_get_next_chain(block, NULL);
	     chain;
	     chain_prev = chain,
		     chain = __tcf_get_next_chain(block, chain),
		     tcf_chain_put(chain_prev)) {
		if (tca[TCA_CHAIN] &&
		    nla_get_u32(tca[TCA_CHAIN]) != chain->index)
			continue;
		if (!tcf_chain_dump(chain, q, parent, skb, cb,
				    index_start, &index, terse_dump)) {
			tcf_chain_put(chain);
			err = -EMSGSIZE;
			break;
		}
	}

	if (tcm->tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK)
		tcf_block_refcnt_put(block, true);
	/*记录下次tp index*/
	cb->args[0] = index;

out:
	/* If we did no progress, the error (EMSGSIZE) is real */
	if (skb->len == 0 && err)
		return err;
	/*返回dump长度*/
	return skb->len;
}

static int tc_chain_fill_node(const struct tcf_proto_ops *tmplt_ops,
			      void *tmplt_priv, u32 chain_index,
			      struct net *net, struct sk_buff *skb,
			      struct tcf_block *block,
			      u32 portid, u32 seq, u16 flags, int event,
			      struct netlink_ext_ack *extack)
{
	unsigned char *b = skb_tail_pointer(skb);
	const struct tcf_proto_ops *ops;
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;
	void *priv;

	ops = tmplt_ops;
	priv = tmplt_priv;

	nlh = nlmsg_put(skb, portid, seq, event, sizeof(*tcm), flags);
	if (!nlh)
		goto out_nlmsg_trim;
	tcm = nlmsg_data(nlh);
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm__pad1 = 0;
	tcm->tcm__pad2 = 0;
	tcm->tcm_handle = 0;
	if (block->q) {
		tcm->tcm_ifindex = qdisc_dev(block->q)->ifindex;
		tcm->tcm_parent = block->q->handle;
	} else {
		tcm->tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
		tcm->tcm_block_index = block->index;
	}

	if (nla_put_u32(skb, TCA_CHAIN, chain_index))
		goto nla_put_failure;

	if (ops) {
		if (nla_put_string(skb, TCA_KIND, ops->kind))
			goto nla_put_failure;
		if (ops->tmplt_dump(skb, net, priv) < 0)
			goto nla_put_failure;
	}

	if (extack && extack->_msg &&
	    nla_put_string(skb, TCA_EXT_WARN_MSG, extack->_msg))
		goto out_nlmsg_trim;

	nlh->nlmsg_len = skb_tail_pointer(skb) - b;

	return skb->len;

out_nlmsg_trim:
nla_put_failure:
	nlmsg_trim(skb, b);
	return -EMSGSIZE;
}

static int tc_chain_notify(struct tcf_chain *chain, struct sk_buff *oskb,
			   u32 seq, u16 flags, int event, bool unicast,
			   struct netlink_ext_ack *extack)
{
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	struct tcf_block *block = chain->block;
	struct net *net = block->net;
	struct sk_buff *skb;
	int err = 0;

	if (!unicast && !rtnl_notify_needed(net, flags, RTNLGRP_TC))
		return 0;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tc_chain_fill_node(chain->tmplt_ops, chain->tmplt_priv,
			       chain->index, net, skb, block, portid,
			       seq, flags, event, extack) <= 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	if (unicast)
		err = rtnl_unicast(skb, net, portid);
	else
		err = rtnetlink_send(skb, net, portid, RTNLGRP_TC,
				     flags & NLM_F_ECHO);

	return err;
}

static int tc_chain_notify_delete(const struct tcf_proto_ops *tmplt_ops,
				  void *tmplt_priv, u32 chain_index,
				  struct tcf_block *block, struct sk_buff *oskb,
				  u32 seq, u16 flags)
{
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	struct net *net = block->net;
	struct sk_buff *skb;

	if (!rtnl_notify_needed(net, flags, RTNLGRP_TC))
		return 0;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tc_chain_fill_node(tmplt_ops, tmplt_priv, chain_index, net, skb,
			       block, portid, seq, flags, RTM_DELCHAIN, NULL) <= 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC, flags & NLM_F_ECHO);
}

/*创建sepecify template chain*/
static int tc_chain_tmplt_add(struct tcf_chain *chain, struct net *net,
			      struct nlattr **tca,
			      struct netlink_ext_ack *extack)
{
	const struct tcf_proto_ops *ops;
	char name[IFNAMSIZ];
	void *tmplt_priv;

	/* If kind is not set, user did not specify template. */
	if (!tca[TCA_KIND])
	    /*未设置kind,返回*/
		return 0;

	if (tcf_proto_check_kind(tca[TCA_KIND], name)) {
	    /*传入的名称过长*/
		NL_SET_ERR_MSG(extack, "Specified TC chain template name too long");
		return -EINVAL;
	}

	/*按名称查找ops*/
	ops = tcf_proto_lookup_ops(name, true, extack);
	if (IS_ERR(ops))
		return PTR_ERR(ops);
	/*必须要提供以下三个回调*/
	if (!ops->tmplt_create || !ops->tmplt_destroy || !ops->tmplt_dump ||
	    !ops->tmplt_reoffload) {
		NL_SET_ERR_MSG(extack, "Chain templates are not supported with specified classifier");
		module_put(ops->owner);
		return -EOPNOTSUPP;
	}

	/*构造chain的私有数据*/
	tmplt_priv = ops->tmplt_create(net, chain, tca, extack);
	if (IS_ERR(tmplt_priv)) {
		module_put(ops->owner);
		return PTR_ERR(tmplt_priv);
	}
	chain->tmplt_ops = ops;
	chain->tmplt_priv = tmplt_priv;
	return 0;
}

static void tc_chain_tmplt_del(const struct tcf_proto_ops *tmplt_ops,
			       void *tmplt_priv)
{
	/* If template ops are set, no work to do for us. */
	if (!tmplt_ops)
		return;

	tmplt_ops->tmplt_destroy(tmplt_priv);
	module_put(tmplt_ops->owner);
}

/* Add/delete/get a chain */

//添加新的chain
static int tc_ctl_chain(struct sk_buff *skb, struct nlmsghdr *n,
			struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	struct tcmsg *t;
	u32 parent;
	u32 chain_index;
	struct Qdisc *q;
	struct tcf_chain *chain;
	struct tcf_block *block;
	unsigned long cl;
	int err;

replay:
	q = NULL;
	err = nlmsg_parse_deprecated(n, sizeof(*t), tca, TCA_MAX,
				     rtm_tca_policy, extack);
	if (err < 0)
		return err;

	t = nlmsg_data(n);
	parent = t->tcm_parent;
	cl = 0;

	//先确认chain所属的block
	block = tcf_block_find(net, &q, &parent, &cl,
			       t->tcm_ifindex, t->tcm_block_index, extack);
	if (IS_ERR(block))
		return PTR_ERR(block);

	//取出chain_index
	chain_index = tca[TCA_CHAIN] ? nla_get_u32(tca[TCA_CHAIN]) : 0;
	if (chain_index > TC_ACT_EXT_VAL_MASK) {
		NL_SET_ERR_MSG(extack, "Specified chain index exceeds upper limit");
		err = -EINVAL;
		goto errout_block;
	}

	mutex_lock(&block->lock);
	//在block上查询chain_index对应的chain
	chain = tcf_chain_lookup(block, chain_index);
	if (n->nlmsg_type == RTM_NEWCHAIN) {
		//当前操作新建chain时，如果chain不为空，则创建
		if (chain) {
			if (tcf_chain_held_by_acts_only(chain)) {
				/* The chain exists only because there is
				 * some action referencing it.
				 */
				tcf_chain_hold(chain);
			} else {
				NL_SET_ERR_MSG(extack, "Filter chain already exists");
				err = -EEXIST;
				goto errout_block_locked;
			}
		} else {
			if (!(n->nlmsg_flags & NLM_F_CREATE)) {
				NL_SET_ERR_MSG(extack, "Need both RTM_NEWCHAIN and NLM_F_CREATE to create a new chain");
				err = -ENOENT;
				goto errout_block_locked;
			}
			//创建chain
			chain = tcf_chain_create(block, chain_index);
			if (!chain) {
				NL_SET_ERR_MSG(extack, "Failed to create filter chain");
				err = -ENOMEM;
				goto errout_block_locked;
			}
		}
	} else {
		if (!chain || tcf_chain_held_by_acts_only(chain)) {
			NL_SET_ERR_MSG(extack, "Cannot find specified filter chain");
			err = -EINVAL;
			goto errout_block_locked;
		}
		tcf_chain_hold(chain);
	}

	if (n->nlmsg_type == RTM_NEWCHAIN) {
		/* Modifying chain requires holding parent block lock. In case
		 * the chain was successfully added, take a reference to the
		 * chain. This ensures that an empty chain does not disappear at
		 * the end of this function.
		 */
		tcf_chain_hold(chain);
		chain->explicitly_created = true;
	}
	mutex_unlock(&block->lock);

	switch (n->nlmsg_type) {
	case RTM_NEWCHAIN:
	    /*处理chain templates更新*/
		err = tc_chain_tmplt_add(chain, net, tca, extack);
		if (err) {
			tcf_chain_put_explicitly_created(chain);
			goto errout;
		}

		tc_chain_notify(chain, NULL, 0, NLM_F_CREATE | NLM_F_EXCL,
				RTM_NEWCHAIN, false, extack);
		break;
	case RTM_DELCHAIN:
	    /*完成chain移除*/
		tfilter_notify_chain(net, skb, block, q, parent, n,
				     chain, RTM_DELTFILTER, extack);
		/* Flush the chain first as the user requested chain removal. */
		tcf_chain_flush(chain, true);
		/* In case the chain was successfully deleted, put a reference
		 * to the chain previously taken during addition.
		 */
		tcf_chain_put_explicitly_created(chain);
		break;
	case RTM_GETCHAIN:
		err = tc_chain_notify(chain, skb, n->nlmsg_seq,
				      n->nlmsg_flags, n->nlmsg_type, true, extack);
		if (err < 0)
			NL_SET_ERR_MSG(extack, "Failed to send chain notify message");
		break;
	default:
		err = -EOPNOTSUPP;
		NL_SET_ERR_MSG(extack, "Unsupported message type");
		goto errout;
	}

errout:
	tcf_chain_put(chain);
errout_block:
	tcf_block_release(q, block, true);
	if (err == -EAGAIN)
		/* Replay the request. */
		goto replay;
	return err;

errout_block_locked:
	mutex_unlock(&block->lock);
	goto errout_block;
}

/* called with RTNL */
static int tc_dump_chain(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	struct Qdisc *q = NULL;
	struct tcf_block *block;
	struct tcmsg *tcm = nlmsg_data(cb->nlh);
	struct tcf_chain *chain;
	long index_start;
	long index;
	int err;

	if (nlmsg_len(cb->nlh) < sizeof(*tcm))
		return skb->len;

	err = nlmsg_parse_deprecated(cb->nlh, sizeof(*tcm), tca, TCA_MAX,
				     rtm_tca_policy, cb->extack);
	if (err)
		return err;

	if (tcm->tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK) {
		block = tcf_block_refcnt_get(net, tcm->tcm_block_index);
		if (!block)
			goto out;
	} else {
		const struct Qdisc_class_ops *cops;
		struct net_device *dev;
		unsigned long cl = 0;

		dev = __dev_get_by_index(net, tcm->tcm_ifindex);
		if (!dev)
			return skb->len;

		if (!tcm->tcm_parent)
			q = rtnl_dereference(dev->qdisc);
		else
			q = qdisc_lookup(dev, TC_H_MAJ(tcm->tcm_parent));

		if (!q)
			goto out;
		cops = q->ops->cl_ops;
		if (!cops)
			goto out;
		if (!cops->tcf_block)
			goto out;
		if (TC_H_MIN(tcm->tcm_parent)) {
			cl = cops->find(q, tcm->tcm_parent);
			if (cl == 0)
				goto out;
		}
		block = cops->tcf_block(q, cl, NULL);
		if (!block)
			goto out;
		if (tcf_block_shared(block))
			q = NULL;
	}

	index_start = cb->args[0];
	index = 0;

	mutex_lock(&block->lock);
	list_for_each_entry(chain, &block->chain_list, list) {
		if ((tca[TCA_CHAIN] &&
		     nla_get_u32(tca[TCA_CHAIN]) != chain->index))
			continue;
		if (index < index_start) {
			index++;
			continue;
		}
		if (tcf_chain_held_by_acts_only(chain))
			continue;
		err = tc_chain_fill_node(chain->tmplt_ops, chain->tmplt_priv,
					 chain->index, net, skb, block,
					 NETLINK_CB(cb->skb).portid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 RTM_NEWCHAIN, NULL);
		if (err <= 0)
			break;
		index++;
	}
	mutex_unlock(&block->lock);

	if (tcm->tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK)
		tcf_block_refcnt_put(block, true);
	cb->args[0] = index;

out:
	/* If we did no progress, the error (EMSGSIZE) is real */
	if (skb->len == 0 && err)
		return err;
	return skb->len;
}

int tcf_exts_init_ex(struct tcf_exts *exts, struct net *net, int action,
		     int police, struct tcf_proto *tp, u32 handle,
		     bool use_action_miss)
{
	int err = 0;

#ifdef CONFIG_NET_CLS_ACT
	exts->type = 0;
	exts->nr_actions = 0;
	exts->miss_cookie_node = NULL;
	/* Note: we do not own yet a reference on net.
	 * This reference might be taken later from tcf_exts_get_net().
	 */
	exts->net = net;
	exts->actions = kcalloc(TCA_ACT_MAX_PRIO, sizeof(struct tc_action *),
				GFP_KERNEL);
	if (!exts->actions)
		return -ENOMEM;
#endif

	exts->action = action;
	exts->police = police;

	if (!use_action_miss)
		return 0;

	err = tcf_exts_miss_cookie_base_alloc(exts, tp, handle);
	if (err)
		goto err_miss_alloc;

	return 0;

err_miss_alloc:
	tcf_exts_destroy(exts);
#ifdef CONFIG_NET_CLS_ACT
	exts->actions = NULL;
#endif
	return err;
}
EXPORT_SYMBOL(tcf_exts_init_ex);

void tcf_exts_destroy(struct tcf_exts *exts)
{
	tcf_exts_miss_cookie_base_destroy(exts);

#ifdef CONFIG_NET_CLS_ACT
	if (exts->actions) {
		tcf_action_destroy(exts->actions, TCA_ACT_UNBIND);
		kfree(exts->actions);
	}
	exts->nr_actions = 0;
#endif
}
EXPORT_SYMBOL(tcf_exts_destroy);

//解析actions
int tcf_exts_validate_ex(struct net *net, struct tcf_proto *tp, struct nlattr **tb,
			 struct nlattr *rate_tlv, struct tcf_exts *exts/*规则对应的待填充action*/,
			 u32 flags, u32 fl_flags, struct netlink_ext_ack *extack)
{
#ifdef CONFIG_NET_CLS_ACT
	{
		int init_res[TCA_ACT_MAX_PRIO] = {};
		struct tc_action *act;
		size_t attr_size = 0;

		if (exts->police && tb[exts->police]) {
			struct tc_action_ops *a_o;

			flags |= TCA_ACT_FLAGS_POLICE | TCA_ACT_FLAGS_BIND;
			a_o = tc_action_load_ops(tb[exts->police], flags,
						 extack);
			if (IS_ERR(a_o))
				return PTR_ERR(a_o);
			//如果指定了exts->police,且其对应的netlink字段存在，则解析exts->police对应的action
			act = tcf_action_init_1(net, tp, tb[exts->police],
						rate_tlv, a_o, init_res, flags,
						extack);
			module_put(a_o->owner);
			if (IS_ERR(act))
				return PTR_ERR(act);

			act->type = exts->type = TCA_OLD_COMPAT;
			exts->actions[0] = act;
			exts->nr_actions = 1;
			tcf_idr_insert_many(exts->actions, init_res);
		} else if (exts->action && tb[exts->action]) {
			int err;

            //解析并生成action,容许action bind
			flags |= TCA_ACT_FLAGS_BIND;
			err = tcf_action_init(net, tp, tb[exts->action]/*要解析的action*/,
					      rate_tlv, exts->actions/*待填充的action*/, init_res,
					      &attr_size, flags, fl_flags,
					      extack);
			if (err < 0)
				return err;
			exts->nr_actions = err;
		}
	}
#else
	if ((exts->action && tb[exts->action]) ||
	    (exts->police && tb[exts->police])) {
		NL_SET_ERR_MSG(extack, "Classifier actions are not supported per compile options (CONFIG_NET_CLS_ACT)");
		return -EOPNOTSUPP;
	}
#endif

	return 0;
}
EXPORT_SYMBOL(tcf_exts_validate_ex);

int tcf_exts_validate(struct net *net, struct tcf_proto *tp, struct nlattr **tb,
		      struct nlattr *rate_tlv, struct tcf_exts *exts,
		      u32 flags, struct netlink_ext_ack *extack)
{
	return tcf_exts_validate_ex(net, tp, tb, rate_tlv, exts,
				    flags, 0, extack);
}
EXPORT_SYMBOL(tcf_exts_validate);

void tcf_exts_change(struct tcf_exts *dst, struct tcf_exts *src)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tcf_exts old = *dst;

	*dst = *src;
	tcf_exts_destroy(&old);
#endif
}
EXPORT_SYMBOL(tcf_exts_change);

#ifdef CONFIG_NET_CLS_ACT
/*返回第一个action*/
static struct tc_action *tcf_exts_first_act(struct tcf_exts *exts)
{
	if (exts->nr_actions == 0)
		return NULL;
	else
		return exts->actions[0];
}
#endif

/*filter action信息dump*/
int tcf_exts_dump(struct sk_buff *skb, struct tcf_exts *exts)
{
#ifdef CONFIG_NET_CLS_ACT
	struct nlattr *nest;

	if (exts->action && tcf_exts_has_actions(exts)) {
		/*
		 * again for backward compatible mode - we want
		 * to work with both old and new modes of entering
		 * tc data even if iproute2  was newer - jhs
		 */
		if (exts->type != TCA_OLD_COMPAT) {
			nest = nla_nest_start_noflag(skb, exts->action);
			if (nest == NULL)
				goto nla_put_failure;

			if (tcf_action_dump(skb, exts->actions, 0, 0, false)
			    < 0)
				goto nla_put_failure;
			nla_nest_end(skb, nest);
		} else if (exts->police) {
			struct tc_action *act = tcf_exts_first_act(exts);
			nest = nla_nest_start_noflag(skb, exts->police);
			if (nest == NULL || !act)
				goto nla_put_failure;
			if (tcf_action_dump_old(skb, act, 0, 0) < 0)
				goto nla_put_failure;
			nla_nest_end(skb, nest);
		}
	}
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
#else
	return 0;
#endif
}
EXPORT_SYMBOL(tcf_exts_dump);

int tcf_exts_terse_dump(struct sk_buff *skb, struct tcf_exts *exts)
{
#ifdef CONFIG_NET_CLS_ACT
	struct nlattr *nest;

	if (!exts->action || !tcf_exts_has_actions(exts))
		return 0;

	nest = nla_nest_start_noflag(skb, exts->action);
	if (!nest)
		goto nla_put_failure;

	if (tcf_action_dump(skb, exts->actions, 0, 0, true) < 0)
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
#else
	return 0;
#endif
}
EXPORT_SYMBOL(tcf_exts_terse_dump);

int tcf_exts_dump_stats(struct sk_buff *skb, struct tcf_exts *exts)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tc_action *a = tcf_exts_first_act(exts);
	if (a != NULL && tcf_action_copy_stats(skb, a, 1) < 0)
		return -1;
#endif
	return 0;
}
EXPORT_SYMBOL(tcf_exts_dump_stats);

static void tcf_block_offload_inc(struct tcf_block *block, u32 *flags)
{
	if (*flags & TCA_CLS_FLAGS_IN_HW)
	    /*block已有offload标识，则跳出*/
		return;
	/*标记已offload到hw*/
	*flags |= TCA_CLS_FLAGS_IN_HW;
	atomic_inc(&block->offloadcnt);
}

static void tcf_block_offload_dec(struct tcf_block *block, u32 *flags)
{
	if (!(*flags & TCA_CLS_FLAGS_IN_HW))
		return;
	*flags &= ~TCA_CLS_FLAGS_IN_HW;
	atomic_dec(&block->offloadcnt);
}

static void tc_cls_offload_cnt_update(struct tcf_block *block,
				      struct tcf_proto *tp, u32 *cnt,
				      u32 *flags, u32 diff, bool add)
{
	lockdep_assert_held(&block->cb_lock);

	spin_lock(&tp->lock);
	if (add) {
		if (!*cnt)
		    //为flag设置in-hw标记
			tcf_block_offload_inc(block, flags);
		*cnt += diff;
	} else {
		*cnt -= diff;
		if (!*cnt)
			tcf_block_offload_dec(block, flags);
	}
	spin_unlock(&tp->lock);
}

static void
tc_cls_offload_cnt_reset(struct tcf_block *block, struct tcf_proto *tp,
			 u32 *cnt, u32 *flags)
{
	lockdep_assert_held(&block->cb_lock);

	spin_lock(&tp->lock);
	tcf_block_offload_dec(block, flags);
	*cnt = 0;
	spin_unlock(&tp->lock);
}

//执行cb_list上挂接的所有callback
static int
__tc_setup_cb_call(struct tcf_block *block, enum tc_setup_type type/*回调类型*/,
		   void *type_data/*此type对应的参数*/, bool err_stop/*出错时，是否需要停下来*/)
{
	struct flow_block_cb *block_cb;
	int ok_count = 0;
	int err;

	//遍历cb_list，逐个执行cb调用（tcf_block_bind函数负责挂接cb)
	list_for_each_entry(block_cb, &block->flow_block.cb_list, list) {
		err = block_cb->cb(type/*type类型的setup*/, type_data, block_cb->cb_priv);
		if (err) {
			//出错，如果出错需要停止，则返回error
			if (err_stop)
				return err;
		} else {
			ok_count++;
		}
	}
	return ok_count;
}

int tc_setup_cb_call(struct tcf_block *block, enum tc_setup_type type,
		     void *type_data/*此type回调对应的参数*/, bool err_stop/*出错是否停止*/, bool rtnl_held/*是否持有锁*/)
{
	bool take_rtnl = READ_ONCE(block->lockeddevcnt) && !rtnl_held;
	int ok_count;

retry:
	if (take_rtnl)
		rtnl_lock();
	down_read(&block->cb_lock);
	/* Need to obtain rtnl lock if block is bound to devs that require it.
	 * In block bind code cb_lock is obtained while holding rtnl, so we must
	 * obtain the locks in same order here.
	 */
	if (!rtnl_held && !take_rtnl && block->lockeddevcnt) {
		up_read(&block->cb_lock);
		take_rtnl = true;
		goto retry;
	}

	//执行cb_list上挂接的所有callback
	ok_count = __tc_setup_cb_call(block, type, type_data, err_stop);

	up_read(&block->cb_lock);
	if (take_rtnl)
		rtnl_unlock();
	return ok_count;
}
EXPORT_SYMBOL(tc_setup_cb_call);

/* Non-destructive filter add. If filter that wasn't already in hardware is
 * successfully offloaded, increment block offloads counter. On failure,
 * previously offloaded filter is considered to be intact and offloads counter
 * is not decremented.
 */

int tc_setup_cb_add(struct tcf_block *block, struct tcf_proto *tp/*filter规则*/,
		    enum tc_setup_type type, void *type_data/*setup回调对应的参数*/, bool err_stop/*出错是否停止*/,
		    u32 *flags/*出参*/, unsigned int *in_hw_count, bool rtnl_held/*是否持有rtnl_lock*/)
{
	bool take_rtnl = READ_ONCE(block->lockeddevcnt) && !rtnl_held;
	int ok_count;

retry:
	if (take_rtnl)
		rtnl_lock();
	down_read(&block->cb_lock);
	/* Need to obtain rtnl lock if block is bound to devs that require it.
	 * In block bind code cb_lock is obtained while holding rtnl, so we must
	 * obtain the locks in same order here.
	 */
	if (!rtnl_held && !take_rtnl && block->lockeddevcnt) {
		up_read(&block->cb_lock);
		take_rtnl = true;
		goto retry;
	}

	/* Make sure all netdevs sharing this block are offload-capable. */
	if (block->nooffloaddevcnt && err_stop) {
		ok_count = -EOPNOTSUPP;
		goto err_unlock;
	}

	/*触发驱动回调*/
	ok_count = __tc_setup_cb_call(block, type, type_data, err_stop);
	if (ok_count < 0)
		goto err_unlock;

	/*规则已下发给硬件，没有出错，这里记录下此规则*/
	if (tp->ops->hw_add)
		tp->ops->hw_add(tp, type_data);
	if (ok_count > 0)
	    //下发没有出错
		tc_cls_offload_cnt_update(block, tp, in_hw_count, flags,
					  ok_count, true/*flow增加*/);
err_unlock:
	up_read(&block->cb_lock);
	if (take_rtnl)
		rtnl_unlock();
	return min(ok_count, 0);
}
EXPORT_SYMBOL(tc_setup_cb_add);

/* Destructive filter replace. If filter that wasn't already in hardware is
 * successfully offloaded, increment block offload counter. On failure,
 * previously offloaded filter is considered to be destroyed and offload counter
 * is decremented.
 */

int tc_setup_cb_replace(struct tcf_block *block, struct tcf_proto *tp,
			enum tc_setup_type type, void *type_data, bool err_stop,
			u32 *old_flags, unsigned int *old_in_hw_count,
			u32 *new_flags, unsigned int *new_in_hw_count,
			bool rtnl_held)
{
	bool take_rtnl = READ_ONCE(block->lockeddevcnt) && !rtnl_held;
	int ok_count;

retry:
	if (take_rtnl)
		rtnl_lock();
	down_read(&block->cb_lock);
	/* Need to obtain rtnl lock if block is bound to devs that require it.
	 * In block bind code cb_lock is obtained while holding rtnl, so we must
	 * obtain the locks in same order here.
	 */
	if (!rtnl_held && !take_rtnl && block->lockeddevcnt) {
		up_read(&block->cb_lock);
		take_rtnl = true;
		goto retry;
	}

	/* Make sure all netdevs sharing this block are offload-capable. */
	if (block->nooffloaddevcnt && err_stop) {
		ok_count = -EOPNOTSUPP;
		goto err_unlock;
	}

	tc_cls_offload_cnt_reset(block, tp, old_in_hw_count, old_flags);
	if (tp->ops->hw_del)
		tp->ops->hw_del(tp, type_data);

	ok_count = __tc_setup_cb_call(block, type, type_data, err_stop);
	if (ok_count < 0)
		goto err_unlock;

	/*触发硬件规则添加*/
	if (tp->ops->hw_add)
		tp->ops->hw_add(tp, type_data);
	if (ok_count > 0)
		tc_cls_offload_cnt_update(block, tp, new_in_hw_count,
					  new_flags, ok_count, true);
err_unlock:
	up_read(&block->cb_lock);
	if (take_rtnl)
		rtnl_unlock();
	return min(ok_count, 0);
}
EXPORT_SYMBOL(tc_setup_cb_replace);

/* Destroy filter and decrement block offload counter, if filter was previously
 * offloaded.
 */

int tc_setup_cb_destroy(struct tcf_block *block, struct tcf_proto *tp,
			enum tc_setup_type type, void *type_data, bool err_stop,
			u32 *flags, unsigned int *in_hw_count, bool rtnl_held)
{
	bool take_rtnl = READ_ONCE(block->lockeddevcnt) && !rtnl_held;
	int ok_count;

retry:
	if (take_rtnl)
		rtnl_lock();
	down_read(&block->cb_lock);
	/* Need to obtain rtnl lock if block is bound to devs that require it.
	 * In block bind code cb_lock is obtained while holding rtnl, so we must
	 * obtain the locks in same order here.
	 */
	if (!rtnl_held && !take_rtnl && block->lockeddevcnt) {
		up_read(&block->cb_lock);
		take_rtnl = true;
		goto retry;
	}

	ok_count = __tc_setup_cb_call(block, type, type_data, err_stop);

	tc_cls_offload_cnt_reset(block, tp, in_hw_count, flags);
	if (tp->ops->hw_del)
		tp->ops->hw_del(tp, type_data);

	up_read(&block->cb_lock);
	if (take_rtnl)
		rtnl_unlock();
	return min(ok_count, 0);
}
EXPORT_SYMBOL(tc_setup_cb_destroy);

int tc_setup_cb_reoffload(struct tcf_block *block, struct tcf_proto *tp,
			  bool add, flow_setup_cb_t *cb/*驱动回调函数*/,
			  enum tc_setup_type type, void *type_data,
			  void *cb_priv, u32 *flags, unsigned int *in_hw_count)
{
    /*执行驱动回调*/
	int err = cb(type, type_data, cb_priv);

	if (err) {
		if (add && tc_skip_sw(*flags))
			return err;
	} else {
		tc_cls_offload_cnt_update(block, tp, in_hw_count, flags, 1,
					  add);
	}

	return 0;
}
EXPORT_SYMBOL(tc_setup_cb_reoffload);

static int tcf_act_get_user_cookie(struct flow_action_entry *entry,
				   const struct tc_action *act)
{
	struct tc_cookie *user_cookie;
	int err = 0;

	rcu_read_lock();
	user_cookie = rcu_dereference(act->user_cookie);
	if (user_cookie) {
		entry->user_cookie = flow_action_cookie_create(user_cookie->data,
							       user_cookie->len,
							       GFP_ATOMIC);
		if (!entry->user_cookie)
			err = -ENOMEM;
	}
	rcu_read_unlock();
	return err;
}

static void tcf_act_put_user_cookie(struct flow_action_entry *entry)
{
	flow_action_cookie_destroy(entry->user_cookie);
}

void tc_cleanup_offload_action(struct flow_action *flow_action)
{
	struct flow_action_entry *entry;
	int i;

	flow_action_for_each(i, entry, flow_action) {
		tcf_act_put_user_cookie(entry);
		if (entry->destructor)
			entry->destructor(entry->destructor_priv);
	}
}
EXPORT_SYMBOL(tc_cleanup_offload_action);

/*触发action offload,转换action 到flow_action_entry*/
static int tc_setup_offload_act(struct tc_action *act,
				struct flow_action_entry *entry,
				u32 *index_inc,
				struct netlink_ext_ack *extack)
{
#ifdef CONFIG_NET_CLS_ACT
	/*交给各action进行offload转换*/
	if (act->ops->offload_act_setup) {
		return act->ops->offload_act_setup(act, entry, index_inc, true,
						   extack);
	} else {
		NL_SET_ERR_MSG(extack, "Action does not support offload");
		return -EOPNOTSUPP;
	}
#else
	return 0;
#endif
}

//实现tc规则action转换为flow_action
int tc_setup_action(struct flow_action *flow_action/*出参，记录转换后的tcf action*/,
		    struct tc_action *actions[]/*tc规则action*/,
		    u32 miss_cookie_base,
		    struct netlink_ext_ack *extack)
{
	int i, j, k, index, err = 0;
	struct tc_action *act;

	BUILD_BUG_ON(TCA_ACT_HW_STATS_ANY != FLOW_ACTION_HW_STATS_ANY);
	BUILD_BUG_ON(TCA_ACT_HW_STATS_IMMEDIATE != FLOW_ACTION_HW_STATS_IMMEDIATE);
	BUILD_BUG_ON(TCA_ACT_HW_STATS_DELAYED != FLOW_ACTION_HW_STATS_DELAYED);

	if (!actions)
		return 0;

	j = 0;

	//采用act遍历exts->actions,实现tc action向flow_action_entry转换
	tcf_act_for_each_action(i, act, actions) {
		struct flow_action_entry *entry;

		//待填充的entry
		entry = &flow_action->entries[j];
		spin_lock_bh(&act->tcfa_lock);
		err = tcf_act_get_user_cookie(entry, act);
		if (err)
			goto err_out_locked;

		index = 0;
		/*针对此action由相应回调完成转换*/
		err = tc_setup_offload_act(act, entry, &index, extack);
		if (err)
			goto err_out_locked;

		for (k = 0; k < index ; k++) {
			entry[k].hw_stats = tc_act_hw_stats(act->hw_stats);
			entry[k].hw_index = act->tcfa_index;
			entry[k].cookie = (unsigned long)act;
			entry[k].miss_cookie =
				tcf_exts_miss_cookie_get(miss_cookie_base, i);
		}

		j += index;

		spin_unlock_bh(&act->tcfa_lock);
	}

err_out:
	if (err)
		tc_cleanup_offload_action(flow_action);

	return err;
err_out_locked:
	spin_unlock_bh(&act->tcfa_lock);
	goto err_out;
}

int tc_setup_offload_action(struct flow_action *flow_action,
			    const struct tcf_exts *exts,
			    struct netlink_ext_ack *extack)
{
#ifdef CONFIG_NET_CLS_ACT
	u32 miss_cookie_base;

	if (!exts)
		return 0;

	miss_cookie_base = exts->miss_cookie_node ?
			   exts->miss_cookie_node->miss_cookie_base : 0;
	/*action转换*/
	return tc_setup_action(flow_action, exts->actions, miss_cookie_base,
			       extack);
#else
	return 0;
#endif
}
EXPORT_SYMBOL(tc_setup_offload_action);

//获得action的数目
unsigned int tcf_exts_num_actions(struct tcf_exts *exts)
{
	unsigned int num_acts = 0;
	struct tc_action *act;
	int i;

	tcf_exts_for_each_action(i, act, exts) {
		if (is_tcf_pedit(act))
			num_acts += tcf_pedit_nkeys(act);
		else
			num_acts++;
	}
	return num_acts;
}
EXPORT_SYMBOL(tcf_exts_num_actions);

#ifdef CONFIG_NET_CLS_ACT
static int tcf_qevent_parse_block_index(struct nlattr *block_index_attr,
					u32 *p_block_index,
					struct netlink_ext_ack *extack)
{
    /*自attr中取block_index*/
	*p_block_index = nla_get_u32(block_index_attr);
	if (!*p_block_index) {
		NL_SET_ERR_MSG(extack, "Block number may not be zero");
		return -EINVAL;
	}

	return 0;
}

int tcf_qevent_init(struct tcf_qevent *qe, struct Qdisc *sch,
		    enum flow_block_binder_type binder_type,
		    struct nlattr *block_index_attr/*block index属性*/,
		    struct netlink_ext_ack *extack)
{
	u32 block_index;
	int err;

	if (!block_index_attr)
		return 0;

	err = tcf_qevent_parse_block_index(block_index_attr, &block_index, extack);
	if (err)
		return err;

	/*构造qe*/
	qe->info.binder_type = binder_type;
	qe->info.chain_head_change = tcf_chain_head_change_dflt;
	qe->info.chain_head_change_priv = &qe->filter_chain;
	qe->info.block_index = block_index;

	return tcf_block_get_ext(&qe->block, sch, &qe->info, extack);
}
EXPORT_SYMBOL(tcf_qevent_init);

void tcf_qevent_destroy(struct tcf_qevent *qe, struct Qdisc *sch)
{
	if (qe->info.block_index)
		tcf_block_put_ext(qe->block, sch, &qe->info);
}
EXPORT_SYMBOL(tcf_qevent_destroy);

int tcf_qevent_validate_change(struct tcf_qevent *qe, struct nlattr *block_index_attr,
			       struct netlink_ext_ack *extack)
{
	u32 block_index;
	int err;

	if (!block_index_attr)
		return 0;

	err = tcf_qevent_parse_block_index(block_index_attr, &block_index, extack);
	if (err)
		return err;

	/* Bounce newly-configured block or change in block. */
	if (block_index != qe->info.block_index) {
		NL_SET_ERR_MSG(extack, "Change of blocks is not supported");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(tcf_qevent_validate_change);

struct sk_buff *tcf_qevent_handle(struct tcf_qevent *qe, struct Qdisc *sch, struct sk_buff *skb,
				  struct sk_buff **to_free, int *ret)
{
	struct tcf_result cl_res;
	struct tcf_proto *fl;

	if (!qe->info.block_index)
		return skb;

	fl = rcu_dereference_bh(qe->filter_chain);

	switch (tcf_classify(skb, NULL, fl, &cl_res, false)) {
	case TC_ACT_SHOT:
		qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		*ret = __NET_XMIT_BYPASS;
		return NULL;
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
	case TC_ACT_TRAP:
		__qdisc_drop(skb, to_free);
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	case TC_ACT_REDIRECT:
		skb_do_redirect(skb);
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	}

	return skb;
}
EXPORT_SYMBOL(tcf_qevent_handle);

int tcf_qevent_dump(struct sk_buff *skb, int attr_name, struct tcf_qevent *qe)
{
	if (!qe->info.block_index)
		return 0;
	return nla_put_u32(skb, attr_name, qe->info.block_index);
}
EXPORT_SYMBOL(tcf_qevent_dump);
#endif

static __net_init int tcf_net_init(struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	spin_lock_init(&tn->idr_lock);
	idr_init(&tn->idr);
	return 0;
}

static void __net_exit tcf_net_exit(struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	idr_destroy(&tn->idr);
}

static struct pernet_operations tcf_net_ops = {
	.init = tcf_net_init,
	.exit = tcf_net_exit,
	.id   = &tcf_net_id,
	.size = sizeof(struct tcf_net),
};

static int __init tc_filter_init(void)
{
	int err;

	tc_filter_wq = alloc_ordered_workqueue("tc_filter_workqueue", 0);
	if (!tc_filter_wq)
		return -ENOMEM;

	err = register_pernet_subsys(&tcf_net_ops);
	if (err)
		goto err_register_pernet_subsys;

	xa_init_flags(&tcf_exts_miss_cookies_xa, XA_FLAGS_ALLOC1);

	//注册tc的newfilter处理函数
	rtnl_register(PF_UNSPEC, RTM_NEWTFILTER, tc_new_tfilter, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	//注册tc的delfilter处理函数
	rtnl_register(PF_UNSPEC, RTM_DELTFILTER, tc_del_tfilter, NULL,
		      RTNL_FLAG_DOIT_UNLOCKED);
	//注册tc的show或list filter处理函数
	rtnl_register(PF_UNSPEC, RTM_GETTFILTER, tc_get_tfilter,
		      tc_dump_tfilter, RTNL_FLAG_DOIT_UNLOCKED);
	//创建chain
	rtnl_register(PF_UNSPEC, RTM_NEWCHAIN, tc_ctl_chain, NULL, 0);
	//删除chain
	rtnl_register(PF_UNSPEC, RTM_DELCHAIN, tc_ctl_chain, NULL, 0);
	//list chain
	rtnl_register(PF_UNSPEC, RTM_GETCHAIN, tc_ctl_chain,
		      tc_dump_chain, 0);

	return 0;

err_register_pernet_subsys:
	destroy_workqueue(tc_filter_wq);
	return err;
}

subsys_initcall(tc_filter_init);
