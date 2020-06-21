/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_SCHED_GENERIC_H
#define __NET_SCHED_GENERIC_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/percpu.h>
#include <linux/dynamic_queue_limits.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <net/gen_stats.h>
#include <net/rtnetlink.h>
#include <net/flow_offload.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;
struct bpf_flow_keys;

struct qdisc_rate_table {
	struct tc_ratespec rate;
	u32		data[256];
	struct qdisc_rate_table *next;
	int		refcnt;
};

enum qdisc_state_t {
	__QDISC_STATE_SCHED,
	__QDISC_STATE_DEACTIVATED,
};

struct qdisc_size_table {
	struct rcu_head		rcu;
	struct list_head	list;
	struct tc_sizespec	szopts;
	int			refcnt;
	u16			data[];
};

/* similar to sk_buff_head, but skb->prev pointer is undefined. */
struct qdisc_skb_head {
	struct sk_buff	*head;//队头
	struct sk_buff	*tail;//队尾
	__u32		qlen;//队列长度
	spinlock_t	lock;
};

struct Qdisc {
	//入队函数（来源于ops成员中的enqueue)
	int 			(*enqueue)(struct sk_buff *skb,
					   struct Qdisc *sch,
					   struct sk_buff **to_free);
	//出队函数（来源于ops成员的enqueue)
	struct sk_buff *	(*dequeue)(struct Qdisc *sch);
	unsigned int		flags;
	//内建队列
#define TCQ_F_BUILTIN		1
//ingress队列标记
#define TCQ_F_INGRESS		2
#define TCQ_F_CAN_BYPASS	4
#define TCQ_F_MQROOT		8
#define TCQ_F_ONETXQUEUE	0x10 /* dequeue_skb() can assume all skbs are for
				      * q->dev_queue : It can test
				      * netif_xmit_frozen_or_stopped() before
				      * dequeueing next packet.
				      * Its true for MQ/MQPRIO slaves, or non
				      * multiqueue device.
				      */
#define TCQ_F_WARN_NONWC	(1 << 16)
	//采用percpu的统计信息
#define TCQ_F_CPUSTATS		0x20 /* run using percpu statistics */
#define TCQ_F_NOPARENT		0x40 /* root of its hierarchy :
				      * qdisc_tree_decrease_qlen() should stop.
				      */
	//dump不可见队列
#define TCQ_F_INVISIBLE		0x80 /* invisible by default in dump */
#define TCQ_F_NOLOCK		0x100 /* qdisc does not require locking */
#define TCQ_F_OFFLOADED		0x200 /* qdisc is offloaded to HW */
	u32			limit;//队列容许的最大长度
	//队列操作集
	const struct Qdisc_ops	*ops;
	struct qdisc_size_table	__rcu *stab;
	//用于将队列加入hashtable
	struct hlist_node       hash;
	//队列id号
	u32			handle;
	u32			parent;//父Qdisc id号

	//队列对应的netdev_queue
	struct netdev_queue	*dev_queue;

	struct net_rate_estimator __rcu *rate_est;
	//基本统计信息
	struct gnet_stats_basic_cpu __percpu *cpu_bstats;
	//队列统计信息
	struct gnet_stats_queue	__percpu *cpu_qstats;
	//qdisc为了内存对齐，浪费了头部padded字节的内存（记录起来方便释放）
	int			padded;
	refcount_t		refcnt;

	/*
	 * For performance sake on SMP, we put highly modified fields at the end
	 */
	struct sk_buff_head	gso_skb ____cacheline_aligned_in_smp;
	struct qdisc_skb_head	q;//保存skb的队列
	struct gnet_stats_basic_packed bstats;
	seqcount_t		running;
	struct gnet_stats_queue	qstats;
	unsigned long		state;
	struct Qdisc            *next_sched;
	//已出队的报文，但其对应的txq与前面出队的报文不相等
	struct sk_buff_head	skb_bad_txq;

	spinlock_t		busylock ____cacheline_aligned_in_smp;
	spinlock_t		seqlock;

	/* for NOLOCK qdisc, true if there are no enqueued skbs */
	//标明队列为空
	bool			empty;
	struct rcu_head		rcu;
};

static inline void qdisc_refcount_inc(struct Qdisc *qdisc)
{
	if (qdisc->flags & TCQ_F_BUILTIN)
		return;
	refcount_inc(&qdisc->refcnt);
}

/* Intended to be used by unlocked users, when concurrent qdisc release is
 * possible.
 */

static inline struct Qdisc *qdisc_refcount_inc_nz(struct Qdisc *qdisc)
{
	if (qdisc->flags & TCQ_F_BUILTIN)
		return qdisc;
	if (refcount_inc_not_zero(&qdisc->refcnt))
		return qdisc;
	return NULL;
}

static inline bool qdisc_is_running(struct Qdisc *qdisc)
{
	if (qdisc->flags & TCQ_F_NOLOCK)
		return spin_is_locked(&qdisc->seqlock);
	return (raw_read_seqcount(&qdisc->running) & 1) ? true : false;
}

/*qdisc是否为percpu的状态统计*/
static inline bool qdisc_is_percpu_stats(const struct Qdisc *q)
{
	return q->flags & TCQ_F_CPUSTATS;
}

static inline bool qdisc_is_empty(const struct Qdisc *qdisc)
{
	if (qdisc_is_percpu_stats(qdisc))
		return READ_ONCE(qdisc->empty);
	return !READ_ONCE(qdisc->q.qlen);
}

static inline bool qdisc_run_begin(struct Qdisc *qdisc)
{
	if (qdisc->flags & TCQ_F_NOLOCK) {
		if (!spin_trylock(&qdisc->seqlock))
			return false;
		WRITE_ONCE(qdisc->empty, false);
	} else if (qdisc_is_running(qdisc)) {
		//如果此qdisc已被running,则直接返回
		return false;
	}
	/* Variant of write_seqcount_begin() telling lockdep a trylock
	 * was attempted.
	 */
	//此cpu获得权利进入，指明running,排除其它cpu
	raw_write_seqcount_begin(&qdisc->running);
	seqcount_acquire(&qdisc->running.dep_map, 0, 1, _RET_IP_);
	return true;
}

static inline void qdisc_run_end(struct Qdisc *qdisc)
{
	write_seqcount_end(&qdisc->running);
	if (qdisc->flags & TCQ_F_NOLOCK)
		spin_unlock(&qdisc->seqlock);
}

//检查队列是否可以批量出队
static inline bool qdisc_may_bulk(const struct Qdisc *qdisc)
{
	return qdisc->flags & TCQ_F_ONETXQUEUE;
}

static inline int qdisc_avail_bulklimit(const struct netdev_queue *txq)
{
#ifdef CONFIG_BQL
	/* Non-BQL migrated drivers will return 0, too. */
	return dql_avail(&txq->dql);
#else
	return 0;
#endif
}

struct Qdisc_class_ops {
	unsigned int		flags;
	/* Child qdisc manipulation */
	//通过tcmsg获得qisc对应的具体netdev_queue队列
	struct netdev_queue *	(*select_queue)(struct Qdisc *, struct tcmsg *);
	//用于将一个排队规则绑定到一个类，并返回先前绑定到这个类的排队规则
	int			(*graft)(struct Qdisc *, unsigned long cl/*类*/,
					struct Qdisc */*新的队列*/, struct Qdisc **/*出参，旧的队列*/,
					struct netlink_ext_ack *extack);
	//获取当前绑定到指定类cl的排队规则
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);
	//队列长度发生变换时，调用
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
	//给定classid，返回此队列上绑定的对应class
	unsigned long		(*find)(struct Qdisc *, u32 classid);
	int			(*change)(struct Qdisc *, u32, u32,
					struct nlattr **, unsigned long *,
					struct netlink_ext_ack *);
	int			(*delete)(struct Qdisc *, unsigned long);
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);

	/* Filter manipulation */
	//通过不同的分类编号(arg)返回对应的block
	struct tcf_block *	(*tcf_block)(struct Qdisc *sch,
					     unsigned long arg,
					     struct netlink_ext_ack *extack);
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid);
	void			(*unbind_tcf)(struct Qdisc *, unsigned long);

	/* rtnetlink specific */
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

/* Qdisc_class_ops flag values */

/* Implements API that doesn't require rtnl lock */
enum qdisc_class_ops_flags {
	QDISC_CLASS_OPS_DOIT_UNLOCKED = 1,
};

//排队规则操作集
struct Qdisc_ops {
    //用于将不同类型的qdisc ops串起来
	struct Qdisc_ops	*next;
	//分类操作集
	const struct Qdisc_class_ops	*cl_ops;
	char			id[IFNAMSIZ];//ops的唯一标识
	//创建qdisc时，会在struct Qdisc后面添加一个priv_size大小
	int			priv_size;
	unsigned int		static_flags;

	//使报文入队（如果不提供此回调，则给值为noop_qdisc_ops.enqueue）
	int 			(*enqueue)(struct sk_buff *skb,
					   struct Qdisc *sch,
					   struct sk_buff **to_free);
	//出队一个报文（如果不提供此回调，则给值为noop_qdisc_ops.dequeue）
	struct sk_buff *	(*dequeue)(struct Qdisc *);
	//peek一个报文，返回但不出队（如果不提供此回调，则给值为noop_qdisc_ops.peek）
	struct sk_buff *	(*peek)(struct Qdisc *);

	//通过配置初始化队列
	int			(*init)(struct Qdisc *sch, struct nlattr *arg,
					struct netlink_ext_ack *extack);
	//清空队列
	void			(*reset)(struct Qdisc *);
	//队列销毁
	void			(*destroy)(struct Qdisc *);
	//队列配置变更
	int			(*change)(struct Qdisc *sch,
					  struct nlattr *arg,
					  struct netlink_ext_ack *extack);
	void			(*attach)(struct Qdisc *sch);
	//更新tx队列长度
	int			(*change_tx_queue_len)(struct Qdisc *, unsigned int);

	//负责dump内容到skb
	int			(*dump)(struct Qdisc *, struct sk_buff *);
	int			(*dump_stats)(struct Qdisc *, struct gnet_dump *);

	//设置ingress block
	void			(*ingress_block_set)(struct Qdisc *sch,
						     u32 block_index);
	//设置egress block,使其与指定index关联
	void			(*egress_block_set)(struct Qdisc *sch,
						    u32 block_index);
	/*取sch对应的ingress block index*/
	u32			(*ingress_block_get)(struct Qdisc *sch);
	/*取sch对应的egress block index*/
	u32			(*egress_block_get)(struct Qdisc *sch);

	struct module		*owner;
};


struct tcf_result {
	union {
		struct {
			unsigned long	class;//class地址
			u32		classid;//class id号
		};
		const struct tcf_proto *goto_tp;

		/* used in the skb_tc_reinsert function */
		struct {
			bool		ingress;
			struct gnet_stats_queue *qstats;
		};
	};
};

struct tcf_chain;

struct tcf_proto_ops {
	//用于挂接tcf_proto_base
	struct list_head	head;
	//分类器名称
	char			kind[IFNAMSIZ];
	//对报文进行分类处理，返回报文类别
	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);
	//对新在创建的分类器进行初始化
	int			(*init)(struct tcf_proto*);
	//销毁分类器
	void			(*destroy)(struct tcf_proto *tp, bool rtnl_held,
					   struct netlink_ext_ack *extack);
	//通过handle获取指定规则
	void*			(*get)(struct tcf_proto*, u32 handle);
	void			(*put)(struct tcf_proto *tp, void *f);
	int			(*change)(struct net *net, struct sk_buff *,
					struct tcf_proto*, unsigned long,
					u32 handle, struct nlattr **,
					void **, bool, bool,
					struct netlink_ext_ack *);
	int			(*delete)(struct tcf_proto *tp, void *arg,
					  bool *last, bool rtnl_held,
					  struct netlink_ext_ack *);
	bool			(*delete_empty)(struct tcf_proto *tp);
	void			(*walk)(struct tcf_proto *tp,
					struct tcf_walker *arg, bool rtnl_held);
	int			(*reoffload)(struct tcf_proto *tp, bool add,
					     flow_setup_cb_t *cb, void *cb_priv,
					     struct netlink_ext_ack *extack);
	void			(*hw_add)(struct tcf_proto *tp,
					  void *type_data);
	void			(*hw_del)(struct tcf_proto *tp,
					  void *type_data);
	void			(*bind_class)(void *, u32, unsigned long,
					      void *, unsigned long);
	void *			(*tmplt_create)(struct net *net,
						struct tcf_chain *chain,
						struct nlattr **tca,
						struct netlink_ext_ack *extack);
	void			(*tmplt_destroy)(void *tmplt_priv);

	/* rtnetlink specific */
	int			(*dump)(struct net*, struct tcf_proto*, void *,
					struct sk_buff *skb, struct tcmsg*,
					bool);
	int			(*terse_dump)(struct net *net,
					      struct tcf_proto *tp, void *fh,
					      struct sk_buff *skb,
					      struct tcmsg *t, bool rtnl_held);
	int			(*tmplt_dump)(struct sk_buff *skb,
					      struct net *net,
					      void *tmplt_priv);

	struct module		*owner;
	int			flags;
};

/* Classifiers setting TCF_PROTO_OPS_DOIT_UNLOCKED in tcf_proto_ops->flags
 * are expected to implement tcf_proto_ops->delete_empty(), otherwise race
 * conditions can occur when filters are inserted/deleted simultaneously.
 */
enum tcf_proto_ops_flags {
	TCF_PROTO_OPS_DOIT_UNLOCKED = 1,
};

//应该是tcf=traffic classify filter，流分类过滤
//此实现为通过protocol执行分类过滤
struct tcf_proto {
	/* Fast access part */
	struct tcf_proto __rcu	*next;//串在chain->filter_chain链上
	void __rcu		*root;

	/* called under RCU BH lock*/
	//报文分类函数，来源于struct tcf_proto_ops
	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto */*执行分类的分类器*/,
					    struct tcf_result */*出参，分类结果*/);
	__be16			protocol;//支持的协议

	/* All the rest */
	u32			prio;//优先级
	void			*data;
	//操作集
	const struct tcf_proto_ops	*ops;
	struct tcf_chain	*chain;//tp所属的chain
	/* Lock protects tcf_proto shared state and can be used by unlocked
	 * classifiers to protect their private data.
	 */
	spinlock_t		lock;
	bool			deleting;
	refcount_t		refcnt;//引用计数
	struct rcu_head		rcu;
	struct hlist_node	destroy_ht_node;
};

struct qdisc_skb_cb {
	struct {
		unsigned int		pkt_len;
		u16			slave_dev_queue_mapping;
		u16			tc_classid;
	};
#define QDISC_CB_PRIV_LEN 20
	unsigned char		data[QDISC_CB_PRIV_LEN];
};

typedef void tcf_chain_head_change_t(struct tcf_proto *tp_head, void *priv);

struct tcf_chain {
	/* Protects filter_chain. */
	struct mutex filter_chain_lock;
	//用于挂接分类器
	struct tcf_proto __rcu *filter_chain;
	struct list_head list;//用于串连至block->chain_list
	struct tcf_block *block;//指向所属的block
	u32 index; /* chain index 索引号*/
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;//mask模板
	struct rcu_head rcu;
};

struct tcf_block {
	/* Lock protects tcf_block and lifetime-management data of chains
	 * attached to the block (refcnt, action_refcnt, explicitly_created).
	 */
	struct mutex lock;
	struct list_head chain_list;//用于记录在此block下所有的struct tcf_chain
	u32 index; /* block index for shared blocks */ //对应的id
	u32 classid; /* which class this block belongs to */
	refcount_t refcnt;
	struct net *net;//所属net
	struct Qdisc *q;//所属的Qdisc
	struct rw_semaphore cb_lock; /* protects cb_list and offload counters */
	struct flow_block flow_block;
	//用于挂接struct tcf_block_owner_item类型
	struct list_head owner_list;
	bool keep_dst;
	atomic_t offloadcnt; /* Number of oddloaded filters */
	unsigned int nooffloaddevcnt; /* Number of devs unable to do offload */
	unsigned int lockeddevcnt; /* Number of devs that require rtnl lock. */
	struct {
		struct tcf_chain *chain;//首个chain
		//用于串多个tcf_filter_chain_list_item,记录chain_head_change回调函数及参数
		struct list_head filter_chain_list;
	} chain0;
	struct rcu_head rcu;
	DECLARE_HASHTABLE(proto_destroy_ht, 7);
	struct mutex proto_destroy_lock; /* Lock for proto_destroy hashtable. */
};

#ifdef CONFIG_PROVE_LOCKING
static inline bool lockdep_tcf_chain_is_locked(struct tcf_chain *chain)
{
	return lockdep_is_held(&chain->filter_chain_lock);
}

static inline bool lockdep_tcf_proto_is_locked(struct tcf_proto *tp)
{
	return lockdep_is_held(&tp->lock);
}
#else
static inline bool lockdep_tcf_chain_is_locked(struct tcf_block *chain)
{
	return true;
}

static inline bool lockdep_tcf_proto_is_locked(struct tcf_proto *tp)
{
	return true;
}
#endif /* #ifdef CONFIG_PROVE_LOCKING */

#define tcf_chain_dereference(p, chain)					\
	rcu_dereference_protected(p, lockdep_tcf_chain_is_locked(chain))

#define tcf_proto_dereference(p, tp)					\
	rcu_dereference_protected(p, lockdep_tcf_proto_is_locked(tp))

static inline void qdisc_cb_private_validate(const struct sk_buff *skb, int sz)
{
	struct qdisc_skb_cb *qcb;

	BUILD_BUG_ON(sizeof(skb->cb) < offsetof(struct qdisc_skb_cb, data) + sz);
	BUILD_BUG_ON(sizeof(qcb->data) < sz);
}

static inline int qdisc_qlen_cpu(const struct Qdisc *q)
{
	return this_cpu_ptr(q->cpu_qstats)->qlen;
}

static inline int qdisc_qlen(const struct Qdisc *q)
{
	return q->q.qlen;
}

static inline int qdisc_qlen_sum(const struct Qdisc *q)
{
	__u32 qlen = q->qstats.qlen;
	int i;

	if (qdisc_is_percpu_stats(q)) {
		for_each_possible_cpu(i)
			qlen += per_cpu_ptr(q->cpu_qstats, i)->qlen;
	} else {
		qlen += q->q.qlen;
	}

	return qlen;
}

static inline struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

static inline spinlock_t *qdisc_lock(struct Qdisc *qdisc)
{
	return &qdisc->q.lock;
}

static inline struct Qdisc *qdisc_root(const struct Qdisc *qdisc)
{
	struct Qdisc *q = rcu_dereference_rtnl(qdisc->dev_queue->qdisc);

	return q;
}

static inline struct Qdisc *qdisc_root_bh(const struct Qdisc *qdisc)
{
	return rcu_dereference_bh(qdisc->dev_queue->qdisc);
}

static inline struct Qdisc *qdisc_root_sleeping(const struct Qdisc *qdisc)
{
	return qdisc->dev_queue->qdisc_sleeping;
}

/* The qdisc root lock is a mechanism by which to top level
 * of a qdisc tree can be locked from any qdisc node in the
 * forest.  This allows changing the configuration of some
 * aspect of the qdisc tree while blocking out asynchronous
 * qdisc access in the packet processing paths.
 *
 * It is only legal to do this when the root will not change
 * on us.  Otherwise we'll potentially lock the wrong qdisc
 * root.  This is enforced by holding the RTNL semaphore, which
 * all users of this lock accessor must do.
 */
static inline spinlock_t *qdisc_root_lock(const struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root(qdisc);

	ASSERT_RTNL();
	return qdisc_lock(root);
}

static inline spinlock_t *qdisc_root_sleeping_lock(const struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root_sleeping(qdisc);

	ASSERT_RTNL();
	return qdisc_lock(root);
}

static inline seqcount_t *qdisc_root_sleeping_running(const struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root_sleeping(qdisc);

	ASSERT_RTNL();
	return &root->running;
}

//排队规则对应的dev
static inline struct net_device *qdisc_dev(const struct Qdisc *qdisc)
{
	return qdisc->dev_queue->dev;
}

static inline void sch_tree_lock(const struct Qdisc *q)
{
	spin_lock_bh(qdisc_root_sleeping_lock(q));
}

static inline void sch_tree_unlock(const struct Qdisc *q)
{
	spin_unlock_bh(qdisc_root_sleeping_lock(q));
}

extern struct Qdisc noop_qdisc;
extern struct Qdisc_ops noop_qdisc_ops;
extern struct Qdisc_ops pfifo_fast_ops;
extern struct Qdisc_ops mq_qdisc_ops;
extern struct Qdisc_ops noqueue_qdisc_ops;
extern const struct Qdisc_ops *default_qdisc_ops;
static inline const struct Qdisc_ops *
get_default_qdisc_ops(const struct net_device *dev, int ntx)
{
	return ntx < dev->real_num_tx_queues ?
			default_qdisc_ops : &pfifo_fast_ops;
}

struct Qdisc_class_common {
	u32			classid;
	struct hlist_node	hnode;
};

struct Qdisc_class_hash {
	struct hlist_head	*hash;//桶指针
	unsigned int		hashsize;//桶数
	unsigned int		hashmask;//hash表hashcode对应的掩码
	unsigned int		hashelems;
};

static inline unsigned int qdisc_class_hash(u32 id, u32 mask)
{
	id ^= id >> 8;
	id ^= id >> 4;
	return id & mask;
}

//返回id号class
static inline struct Qdisc_class_common *
qdisc_class_find(const struct Qdisc_class_hash *hash, u32 id)
{
	struct Qdisc_class_common *cl;
	unsigned int h;

	if (!id)
		return NULL;

	h = qdisc_class_hash(id, hash->hashmask);
	hlist_for_each_entry(cl, &hash->hash[h], hnode) {
		if (cl->classid == id)
			return cl;
	}
	return NULL;
}

static inline int tc_classid_to_hwtc(struct net_device *dev, u32 classid)
{
	u32 hwtc = TC_H_MIN(classid) - TC_H_MIN_PRIORITY;

	return (hwtc < netdev_get_num_tc(dev)) ? hwtc : -EINVAL;
}

int qdisc_class_hash_init(struct Qdisc_class_hash *);
void qdisc_class_hash_insert(struct Qdisc_class_hash *,
			     struct Qdisc_class_common *);
void qdisc_class_hash_remove(struct Qdisc_class_hash *,
			     struct Qdisc_class_common *);
void qdisc_class_hash_grow(struct Qdisc *, struct Qdisc_class_hash *);
void qdisc_class_hash_destroy(struct Qdisc_class_hash *);

int dev_qdisc_change_tx_queue_len(struct net_device *dev);
void dev_init_scheduler(struct net_device *dev);
void dev_shutdown(struct net_device *dev);
void dev_activate(struct net_device *dev);
void dev_deactivate(struct net_device *dev);
void dev_deactivate_many(struct list_head *head);
struct Qdisc *dev_graft_qdisc(struct netdev_queue *dev_queue,
			      struct Qdisc *qdisc);
void qdisc_reset(struct Qdisc *qdisc);
void qdisc_put(struct Qdisc *qdisc);
void qdisc_put_unlocked(struct Qdisc *qdisc);
void qdisc_tree_reduce_backlog(struct Qdisc *qdisc, int n, int len);
#ifdef CONFIG_NET_SCHED
int qdisc_offload_dump_helper(struct Qdisc *q, enum tc_setup_type type,
			      void *type_data);
void qdisc_offload_graft_helper(struct net_device *dev, struct Qdisc *sch,
				struct Qdisc *new, struct Qdisc *old,
				enum tc_setup_type type, void *type_data,
				struct netlink_ext_ack *extack);
#else
static inline int
qdisc_offload_dump_helper(struct Qdisc *q, enum tc_setup_type type,
			  void *type_data)
{
	q->flags &= ~TCQ_F_OFFLOADED;
	return 0;
}

static inline void
qdisc_offload_graft_helper(struct net_device *dev, struct Qdisc *sch,
			   struct Qdisc *new, struct Qdisc *old,
			   enum tc_setup_type type, void *type_data,
			   struct netlink_ext_ack *extack)
{
}
#endif
struct Qdisc *qdisc_alloc(struct netdev_queue *dev_queue,
			  const struct Qdisc_ops *ops,
			  struct netlink_ext_ack *extack);
void qdisc_free(struct Qdisc *qdisc);
struct Qdisc *qdisc_create_dflt(struct netdev_queue *dev_queue,
				const struct Qdisc_ops *ops, u32 parentid,
				struct netlink_ext_ack *extack);
void __qdisc_calculate_pkt_len(struct sk_buff *skb,
			       const struct qdisc_size_table *stab);
int skb_do_redirect(struct sk_buff *);

static inline bool skb_at_tc_ingress(const struct sk_buff *skb)
{
#ifdef CONFIG_NET_CLS_ACT
	return skb->tc_at_ingress;
#else
	return false;
#endif
}

static inline bool skb_skip_tc_classify(struct sk_buff *skb)
{
#ifdef CONFIG_NET_CLS_ACT
	if (skb->tc_skip_classify) {
		skb->tc_skip_classify = 0;
		return true;
	}
#endif
	return false;
}

/* Reset all TX qdiscs greater than index of a device.  */
static inline void qdisc_reset_all_tx_gt(struct net_device *dev, unsigned int i)
{
	struct Qdisc *qdisc;

	for (; i < dev->num_tx_queues; i++) {
		qdisc = rtnl_dereference(netdev_get_tx_queue(dev, i)->qdisc);
		if (qdisc) {
			spin_lock_bh(qdisc_lock(qdisc));
			qdisc_reset(qdisc);
			spin_unlock_bh(qdisc_lock(qdisc));
		}
	}
}

/* Are all TX queues of the device empty?  */
static inline bool qdisc_all_tx_empty(const struct net_device *dev)
{
	unsigned int i;

	rcu_read_lock();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		const struct Qdisc *q = rcu_dereference(txq->qdisc);

		if (!qdisc_is_empty(q)) {
			rcu_read_unlock();
			return false;
		}
	}
	rcu_read_unlock();
	return true;
}

/* Are any of the TX qdiscs changing?  */
static inline bool qdisc_tx_changing(const struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (rcu_access_pointer(txq->qdisc) != txq->qdisc_sleeping)
			return true;
	}
	return false;
}

/* Is the device using the noop qdisc on all queues?  */
static inline bool qdisc_tx_is_noop(const struct net_device *dev)
{
	//是否所有tx队列的qdisc均为noop_qdisc?
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (rcu_access_pointer(txq->qdisc) != &noop_qdisc)
			return false;
	}
	return true;
}

static inline unsigned int qdisc_pkt_len(const struct sk_buff *skb)
{
	return qdisc_skb_cb(skb)->pkt_len;
}

/* additional qdisc xmit flags (NET_XMIT_MASK in linux/netdevice.h) */
enum net_xmit_qdisc_t {
	__NET_XMIT_STOLEN = 0x00010000,
	__NET_XMIT_BYPASS = 0x00020000,
};

#ifdef CONFIG_NET_CLS_ACT
#define net_xmit_drop_count(e)	((e) & __NET_XMIT_STOLEN ? 0 : 1)
#else
#define net_xmit_drop_count(e)	(1)
#endif

static inline void qdisc_calculate_pkt_len(struct sk_buff *skb,
					   const struct Qdisc *sch)
{
#ifdef CONFIG_NET_SCHED
	struct qdisc_size_table *stab = rcu_dereference_bh(sch->stab);

	if (stab)
		__qdisc_calculate_pkt_len(skb, stab);
#endif
}

static inline int qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				struct sk_buff **to_free)
{
	qdisc_calculate_pkt_len(skb, sch);
	return sch->enqueue(skb, sch, to_free);
}

static inline void _bstats_update(struct gnet_stats_basic_packed *bstats,
				  __u64 bytes, __u32 packets)
{
	bstats->bytes += bytes;
	bstats->packets += packets;
}

static inline void bstats_update(struct gnet_stats_basic_packed *bstats,
				 const struct sk_buff *skb)
{
	_bstats_update(bstats,
		       qdisc_pkt_len(skb)/*报文字节数*/,
		       skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs/*报文数目*/ : 1);
}

static inline void _bstats_cpu_update(struct gnet_stats_basic_cpu *bstats,
				      __u64 bytes, __u32 packets)
{
	u64_stats_update_begin(&bstats->syncp);
	_bstats_update(&bstats->bstats, bytes, packets);
	u64_stats_update_end(&bstats->syncp);
}

static inline void bstats_cpu_update(struct gnet_stats_basic_cpu *bstats,
				     const struct sk_buff *skb)
{
	u64_stats_update_begin(&bstats->syncp);
	bstats_update(&bstats->bstats, skb);
	u64_stats_update_end(&bstats->syncp);
}

static inline void qdisc_bstats_cpu_update(struct Qdisc *sch,
					   const struct sk_buff *skb)
{
	bstats_cpu_update(this_cpu_ptr(sch->cpu_bstats), skb);
}

static inline void qdisc_bstats_update(struct Qdisc *sch,
				       const struct sk_buff *skb)
{
	bstats_update(&sch->bstats, skb);
}

static inline void qdisc_qstats_backlog_dec(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog -= qdisc_pkt_len(skb);
}

static inline void qdisc_qstats_cpu_backlog_dec(struct Qdisc *sch,
						const struct sk_buff *skb)
{
	this_cpu_sub(sch->cpu_qstats->backlog, qdisc_pkt_len(skb));
}

static inline void qdisc_qstats_backlog_inc(struct Qdisc *sch,
					    const struct sk_buff *skb)
{
	sch->qstats.backlog += qdisc_pkt_len(skb);
}

static inline void qdisc_qstats_cpu_backlog_inc(struct Qdisc *sch,
						const struct sk_buff *skb)
{
	this_cpu_add(sch->cpu_qstats->backlog, qdisc_pkt_len(skb));
}

static inline void qdisc_qstats_cpu_qlen_inc(struct Qdisc *sch)
{
	this_cpu_inc(sch->cpu_qstats->qlen);
}

static inline void qdisc_qstats_cpu_qlen_dec(struct Qdisc *sch)
{
	this_cpu_dec(sch->cpu_qstats->qlen);
}

static inline void qdisc_qstats_cpu_requeues_inc(struct Qdisc *sch)
{
	this_cpu_inc(sch->cpu_qstats->requeues);
}

static inline void __qdisc_qstats_drop(struct Qdisc *sch, int count)
{
	sch->qstats.drops += count;
}

//增加丢包计数
static inline void qstats_drop_inc(struct gnet_stats_queue *qstats)
{
	qstats->drops++;
}

static inline void qstats_overlimit_inc(struct gnet_stats_queue *qstats)
{
	qstats->overlimits++;
}

//增加队列丢包数
static inline void qdisc_qstats_drop(struct Qdisc *sch)
{
	qstats_drop_inc(&sch->qstats);
}

//增加percpu丢包数
static inline void qdisc_qstats_cpu_drop(struct Qdisc *sch)
{
	this_cpu_inc(sch->cpu_qstats->drops);
}

static inline void qdisc_qstats_overlimit(struct Qdisc *sch)
{
	sch->qstats.overlimits++;
}

static inline int qdisc_qstats_copy(struct gnet_dump *d, struct Qdisc *sch)
{
	__u32 qlen = qdisc_qlen_sum(sch);

	return gnet_stats_copy_queue(d, sch->cpu_qstats, &sch->qstats, qlen);
}

static inline void qdisc_qstats_qlen_backlog(struct Qdisc *sch,  __u32 *qlen,
					     __u32 *backlog)
{
	struct gnet_stats_queue qstats = { 0 };
	__u32 len = qdisc_qlen_sum(sch);

	__gnet_stats_copy_queue(&qstats, sch->cpu_qstats, &sch->qstats, len);
	*qlen = qstats.qlen;
	*backlog = qstats.backlog;
}

static inline void qdisc_tree_flush_backlog(struct Qdisc *sch)
{
	__u32 qlen, backlog;

	qdisc_qstats_qlen_backlog(sch, &qlen, &backlog);
	qdisc_tree_reduce_backlog(sch, qlen, backlog);
}

static inline void qdisc_purge_queue(struct Qdisc *sch)
{
	__u32 qlen, backlog;

	qdisc_qstats_qlen_backlog(sch, &qlen, &backlog);
	qdisc_reset(sch);
	qdisc_tree_reduce_backlog(sch, qlen, backlog);
}

static inline void qdisc_skb_head_init(struct qdisc_skb_head *qh)
{
	qh->head = NULL;
	qh->tail = NULL;
	qh->qlen = 0;
}

//将skb加入到qh结尾
static inline void __qdisc_enqueue_tail(struct sk_buff *skb,
					struct qdisc_skb_head *qh)
{
	struct sk_buff *last = qh->tail;

	if (last) {
		skb->next = NULL;
		last->next = skb;
		qh->tail = skb;
	} else {
	    //首包情况
		qh->tail = skb;
		qh->head = skb;
	}
	qh->qlen++;
}

//将skb入队列sch尾部，增加backlog长度
static inline int qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch)
{
	__qdisc_enqueue_tail(skb, &sch->q);
	qdisc_qstats_backlog_inc(sch, skb);
	return NET_XMIT_SUCCESS;
}

static inline void __qdisc_enqueue_head(struct sk_buff *skb,
					struct qdisc_skb_head *qh)
{
	skb->next = qh->head;

	if (!qh->head)
		qh->tail = skb;
	qh->head = skb;
	qh->qlen++;
}

//自qh队列中出一个skb
static inline struct sk_buff *__qdisc_dequeue_head(struct qdisc_skb_head *qh)
{
	struct sk_buff *skb = qh->head;

	if (likely(skb != NULL)) {
		//将skb自qh->head上移除，队列长度减1
		qh->head = skb->next;
		qh->qlen--;
		//队列为空情况
		if (qh->head == NULL)
			qh->tail = NULL;
		//返回的skb其next为空
		skb->next = NULL;
	}

	return skb;
}

//自先进先出队列的头部位置出队一个报文
static inline struct sk_buff *qdisc_dequeue_head(struct Qdisc *sch)
{
	struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

	if (likely(skb != NULL)) {
		qdisc_qstats_backlog_dec(sch, skb);
		qdisc_bstats_update(sch, skb);
	}

	return skb;
}

/* Instead of calling kfree_skb() while root qdisc lock is held,
 * queue the skb for future freeing at end of __dev_xmit_skb()
 */
static inline void __qdisc_drop(struct sk_buff *skb, struct sk_buff **to_free)
{
	//将skb串在to_free链上
	skb->next = *to_free;
	*to_free = skb;
}

static inline void __qdisc_drop_all(struct sk_buff *skb,
				    struct sk_buff **to_free)
{
	if (skb->prev)
		skb->prev->next = *to_free;
	else
		skb->next = *to_free;
	*to_free = skb;
}

//将队头的第一个报文出队，将其存入到to_free中
static inline unsigned int __qdisc_queue_drop_head(struct Qdisc *sch,
						   struct qdisc_skb_head *qh,
						   struct sk_buff **to_free)
{
	struct sk_buff *skb = __qdisc_dequeue_head(qh);

	if (likely(skb != NULL)) {
	    //返回队列长度
		unsigned int len = qdisc_pkt_len(skb);

		qdisc_qstats_backlog_dec(sch, skb);
		__qdisc_drop(skb, to_free);
		return len;
	}

	return 0;
}

static inline unsigned int qdisc_queue_drop_head(struct Qdisc *sch,
						 struct sk_buff **to_free)
{
	return __qdisc_queue_drop_head(sch, &sch->q, to_free);
}

//返回队列元素（不出队）
static inline struct sk_buff *qdisc_peek_head(struct Qdisc *sch)
{
	const struct qdisc_skb_head *qh = &sch->q;

	return qh->head;
}

/* generic pseudo peek method for non-work-conserving qdisc */
static inline struct sk_buff *qdisc_peek_dequeued(struct Qdisc *sch)
{
	struct sk_buff *skb = skb_peek(&sch->gso_skb);

	/* we can reuse ->gso_skb because peek isn't called for root qdiscs */
	if (!skb) {
		skb = sch->dequeue(sch);

		if (skb) {
			__skb_queue_head(&sch->gso_skb, skb);
			/* it's still part of the queue */
			qdisc_qstats_backlog_inc(sch, skb);
			sch->q.qlen++;
		}
	}

	return skb;
}

static inline void qdisc_update_stats_at_dequeue(struct Qdisc *sch,
						 struct sk_buff *skb)
{
	if (qdisc_is_percpu_stats(sch)) {
		qdisc_qstats_cpu_backlog_dec(sch, skb);
		qdisc_bstats_cpu_update(sch, skb);
		qdisc_qstats_cpu_qlen_dec(sch);
	} else {
		qdisc_qstats_backlog_dec(sch, skb);
		qdisc_bstats_update(sch, skb);
		sch->q.qlen--;
	}
}

static inline void qdisc_update_stats_at_enqueue(struct Qdisc *sch,
						 unsigned int pkt_len)
{
	if (qdisc_is_percpu_stats(sch)) {
		qdisc_qstats_cpu_qlen_inc(sch);
		this_cpu_add(sch->cpu_qstats->backlog, pkt_len);
	} else {
		sch->qstats.backlog += pkt_len;
		sch->q.qlen++;
	}
}

/* use instead of qdisc->dequeue() for all qdiscs queried with ->peek() */
static inline struct sk_buff *qdisc_dequeue_peeked(struct Qdisc *sch)
{
	struct sk_buff *skb = skb_peek(&sch->gso_skb);

	if (skb) {
		skb = __skb_dequeue(&sch->gso_skb);
		if (qdisc_is_percpu_stats(sch)) {
			qdisc_qstats_cpu_backlog_dec(sch, skb);
			qdisc_qstats_cpu_qlen_dec(sch);
		} else {
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
		}
	} else {
		skb = sch->dequeue(sch);
	}

	return skb;
}

static inline void __qdisc_reset_queue(struct qdisc_skb_head *qh)
{
	/*
	 * We do not know the backlog in bytes of this list, it
	 * is up to the caller to correct it
	 */
	ASSERT_RTNL();
	if (qh->qlen) {
		rtnl_kfree_skbs(qh->head, qh->tail);

		qh->head = NULL;
		qh->tail = NULL;
		qh->qlen = 0;
	}
}

static inline void qdisc_reset_queue(struct Qdisc *sch)
{
	__qdisc_reset_queue(&sch->q);
	sch->qstats.backlog = 0;
}

static inline struct Qdisc *qdisc_replace(struct Qdisc *sch, struct Qdisc *new,
					  struct Qdisc **pold)
{
	struct Qdisc *old;

	sch_tree_lock(sch);
	old = *pold;//保存旧队列
	*pold = new;//更新为new队列
	if (old != NULL)
		qdisc_tree_flush_backlog(old);
	sch_tree_unlock(sch);

	return old;//返回旧队列
}

static inline void rtnl_qdisc_drop(struct sk_buff *skb, struct Qdisc *sch)
{
	rtnl_kfree_skbs(skb, skb);
	qdisc_qstats_drop(sch);
}

static inline int qdisc_drop_cpu(struct sk_buff *skb, struct Qdisc *sch,
				 struct sk_buff **to_free)
{
	//指明skb需要丢弃
	__qdisc_drop(skb, to_free);
	qdisc_qstats_cpu_drop(sch);

	return NET_XMIT_DROP;
}

//在sch上执行丢包
static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	__qdisc_drop(skb, to_free);
	qdisc_qstats_drop(sch);

	return NET_XMIT_DROP;
}

static inline int qdisc_drop_all(struct sk_buff *skb, struct Qdisc *sch,
				 struct sk_buff **to_free)
{
	__qdisc_drop_all(skb, to_free);
	qdisc_qstats_drop(sch);

	return NET_XMIT_DROP;
}

/* Length to Time (L2T) lookup in a qdisc_rate_table, to determine how
   long it will take to send a packet given its size.
 */
static inline u32 qdisc_l2t(struct qdisc_rate_table* rtab, unsigned int pktlen)
{
	int slot = pktlen + rtab->rate.cell_align + rtab->rate.overhead;
	if (slot < 0)
		slot = 0;
	slot >>= rtab->rate.cell_log;
	if (slot > 255)
		return rtab->data[255]*(slot >> 8) + rtab->data[slot & 0xFF];
	return rtab->data[slot];
}

struct psched_ratecfg {
	u64	rate_bytes_ps; /* bytes per second */
	u32	mult;
	u16	overhead;
	u8	linklayer;
	u8	shift;
};

static inline u64 psched_l2t_ns(const struct psched_ratecfg *r,
				unsigned int len)
{
	len += r->overhead;

	if (unlikely(r->linklayer == TC_LINKLAYER_ATM))
		return ((u64)(DIV_ROUND_UP(len,48)*53) * r->mult) >> r->shift;

	return ((u64)len * r->mult) >> r->shift;
}

void psched_ratecfg_precompute(struct psched_ratecfg *r,
			       const struct tc_ratespec *conf,
			       u64 rate64);

static inline void psched_ratecfg_getrate(struct tc_ratespec *res,
					  const struct psched_ratecfg *r)
{
	memset(res, 0, sizeof(*res));

	/* legacy struct tc_ratespec has a 32bit @rate field
	 * Qdisc using 64bit rate should add new attributes
	 * in order to maintain compatibility.
	 */
	res->rate = min_t(u64, r->rate_bytes_ps, ~0U);

	res->overhead = r->overhead;
	res->linklayer = (r->linklayer & TC_LINKLAYER_MASK);
}

/* Mini Qdisc serves for specific needs of ingress/clsact Qdisc.
 * The fast path only needs to access filter list and to update stats
 */
struct mini_Qdisc {
	struct tcf_proto *filter_list;
	struct tcf_block *block;
	struct gnet_stats_basic_cpu __percpu *cpu_bstats;
	struct gnet_stats_queue	__percpu *cpu_qstats;
	struct rcu_head rcu;
};

static inline void mini_qdisc_bstats_cpu_update(struct mini_Qdisc *miniq,
						const struct sk_buff *skb)
{
	bstats_cpu_update(this_cpu_ptr(miniq->cpu_bstats), skb);
}

static inline void mini_qdisc_qstats_cpu_drop(struct mini_Qdisc *miniq)
{
	this_cpu_inc(miniq->cpu_qstats->drops);
}

struct mini_Qdisc_pair {
	//切换着使用以下变量，p_miniq指向本次生效的miniq,另一个为上次生效的miniq
	struct mini_Qdisc miniq1;
	struct mini_Qdisc miniq2;
	struct mini_Qdisc __rcu **p_miniq;//本次生效的miniq
};

void mini_qdisc_pair_swap(struct mini_Qdisc_pair *miniqp,
			  struct tcf_proto *tp_head);
void mini_qdisc_pair_init(struct mini_Qdisc_pair *miniqp, struct Qdisc *qdisc,
			  struct mini_Qdisc __rcu **p_miniq);
void mini_qdisc_pair_block_init(struct mini_Qdisc_pair *miniqp,
				struct tcf_block *block);

//按res结果，报文或重新进入协议栈或者直接被发送出去
static inline int skb_tc_reinsert(struct sk_buff *skb, struct tcf_result *res)
{
	return res->ingress ? netif_receive_skb(skb) : dev_queue_xmit(skb);
}

#endif
