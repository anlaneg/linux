// SPDX-License-Identifier: GPL-2.0-or-later
/* net/sched/sch_ingress.c - Ingress and clsact qdisc
 *
 * Authors:     Jamal Hadi Salim 1999
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/tcx.h>

struct ingress_sched_data {
	struct tcf_block *block;/*ingress对应的block*/
	struct tcf_block_ext_info block_info;
	struct mini_Qdisc_pair miniqp;
};

static struct Qdisc *ingress_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

//通过classid返回class,默认+1
static unsigned long ingress_find(struct Qdisc *sch, u32 classid)
{
	return TC_H_MIN(classid) + 1;
}

//返回此classid绑定到哪个class
static unsigned long ingress_bind_filter(struct Qdisc *sch,
					 unsigned long parent, u32 classid)
{
	return ingress_find(sch, classid);
}

static void ingress_unbind_filter(struct Qdisc *sch, unsigned long cl)
{
}

static void ingress_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
}

//返回ingress对应的block
static struct tcf_block *ingress_tcf_block(struct Qdisc *sch, unsigned long cl,
					   struct netlink_ext_ack *extack)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	return q->block;
}

/*为miniqp指定新的tp_head,解决匹配哪些规则的问题*/
static void clsact_chain_head_change(struct tcf_proto *tp_head, void *priv)
{
	struct mini_Qdisc_pair *miniqp = priv;

	//miniqp->filter_list指定为tp_head
	mini_qdisc_pair_swap(miniqp, tp_head);
};

//ingress队列设置ingress block_index
static void ingress_ingress_block_set(struct Qdisc *sch, u32 block_index)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	q->block_info.block_index = block_index;
}

/*取ingress block index*/
static u32 ingress_ingress_block_get(struct Qdisc *sch)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	return q->block_info.block_index;
}

//ingress qdisc初始化
static int ingress_init(struct Qdisc *sch/*要初始化的qdisc*/, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct bpf_mprog_entry *entry;
	bool created;
	int err;

	if (sch->parent != TC_H_INGRESS)
		return -EOPNOTSUPP;

	//当前初始化ingress队列，故指明需要ingress钩子点处理
	net_inc_ingress_queue();

	entry = tcx_entry_fetch_or_create(dev, true, &created);
	if (!entry)
		return -ENOMEM;
	tcx_miniq_set_active(entry, true);
	//初始化q->miniqp,并使dev->miniq_ingress指向它
	mini_qdisc_pair_init(&q->miniqp, sch, &tcx_entry(entry)->miniq);
	if (created)
		tcx_entry_update(dev, entry, true);

	q->block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS;
	q->block_info.chain_head_change = clsact_chain_head_change;
	q->block_info.chain_head_change_priv = &q->miniqp;

	err = tcf_block_get_ext(&q->block, sch, &q->block_info, extack);
	if (err)
		return err;

	/*指向q->block*/
	mini_qdisc_pair_block_init(&q->miniqp, q->block);

	return 0;
}

static void ingress_destroy(struct Qdisc *sch)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct bpf_mprog_entry *entry = rtnl_dereference(dev->tcx_ingress);

	if (sch->parent != TC_H_INGRESS)
		return;

	tcf_block_put_ext(q->block, sch, &q->block_info);

	if (entry) {
		tcx_miniq_set_active(entry, false);
		if (!tcx_entry_is_active(entry)) {
			tcx_entry_update(dev, NULL, true);
			tcx_entry_free(entry);
		}
	}

	net_dec_ingress_queue();
}

static int ingress_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nlattr *nest;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops ingress_class_ops = {
	.flags		=	QDISC_CLASS_OPS_DOIT_UNLOCKED,
	.leaf		=	ingress_leaf,
	.find		=	ingress_find,
	.walk		=	ingress_walk,
	.tcf_block	=	ingress_tcf_block,
	.bind_tcf	=	ingress_bind_filter,
	.unbind_tcf	=	ingress_unbind_filter,
};

//ingress qdisc 操作集
static struct Qdisc_ops ingress_qdisc_ops __read_mostly = {
	.cl_ops			=	&ingress_class_ops,/*ingress的分类操作集*/
	.id			=	"ingress",
	.priv_size		=	sizeof(struct ingress_sched_data),
	.static_flags		=	TCQ_F_INGRESS | TCQ_F_CPUSTATS,
	.init			=	ingress_init,
	.destroy		=	ingress_destroy,
	.dump			=	ingress_dump,
	.ingress_block_set	=	ingress_ingress_block_set,
	.ingress_block_get	=	ingress_ingress_block_get,
	.owner			=	THIS_MODULE,
};

struct clsact_sched_data {
	struct tcf_block *ingress_block;//ingress使用的block
	struct tcf_block *egress_block;//egress使用block
	struct tcf_block_ext_info ingress_block_info;//ingress信息
	struct tcf_block_ext_info egress_block_info;//egress信息
	struct mini_Qdisc_pair miniqp_ingress;
	struct mini_Qdisc_pair miniqp_egress;
};

/*除ingress,egress外，其它均返回零*/
static unsigned long clsact_find(struct Qdisc *sch, u32 classid)
{
	switch (TC_H_MIN(classid)) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
	case TC_H_MIN(TC_H_MIN_EGRESS):
		return TC_H_MIN(classid);
	default:
		//默认返回分类0
		return 0;
	}
}

static unsigned long clsact_bind_filter(struct Qdisc *sch,
					unsigned long parent, u32 classid)
{
	return clsact_find(sch, classid);
}

//给定分类编号，获得相应block
static struct tcf_block *clsact_tcf_block(struct Qdisc *sch, unsigned long cl,
					  struct netlink_ext_ack *extack)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	switch (cl) {
	case TC_H_MIN(TC_H_MIN_INGRESS):
			//使用ingress对应block
		return q->ingress_block;
	case TC_H_MIN(TC_H_MIN_EGRESS):
			//使用egress对应block
		return q->egress_block;
	default:
		return NULL;
	}
}

/*ingress block index设置*/
static void clsact_ingress_block_set(struct Qdisc *sch, u32 block_index)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	q->ingress_block_info.block_index = block_index;
}

/*egress block index设置*/
static void clsact_egress_block_set(struct Qdisc *sch, u32 block_index)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	q->egress_block_info.block_index = block_index;
}

/*取ingress block index*/
static u32 clsact_ingress_block_get(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	return q->ingress_block_info.block_index;
}

/*取egress block index*/
static u32 clsact_egress_block_get(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	return q->egress_block_info.block_index;
}

//ingress ,egress block同时创建
static int clsact_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct bpf_mprog_entry *entry;
	bool created;
	int err;

	if (sch->parent != TC_H_CLSACT)
		return -EOPNOTSUPP;

	net_inc_ingress_queue();
	net_inc_egress_queue();

	entry = tcx_entry_fetch_or_create(dev, true, &created);
	if (!entry)
		return -ENOMEM;
	tcx_miniq_set_active(entry, true);
	//初始化ingress
	mini_qdisc_pair_init(&q->miniqp_ingress, sch, &tcx_entry(entry)->miniq);
	if (created)
		tcx_entry_update(dev, entry, true);

	q->ingress_block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS;
	q->ingress_block_info.chain_head_change = clsact_chain_head_change;
	q->ingress_block_info.chain_head_change_priv = &q->miniqp_ingress;

	//创建ingress block
	err = tcf_block_get_ext(&q->ingress_block, sch, &q->ingress_block_info,
				extack);
	if (err)
		return err;

	mini_qdisc_pair_block_init(&q->miniqp_ingress, q->ingress_block);

	entry = tcx_entry_fetch_or_create(dev, false, &created);
	if (!entry)
		return -ENOMEM;
	tcx_miniq_set_active(entry, true);
	//初始化egress
	mini_qdisc_pair_init(&q->miniqp_egress, sch, &tcx_entry(entry)->miniq);
	if (created)
		tcx_entry_update(dev, entry, false);

	q->egress_block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS;
	q->egress_block_info.chain_head_change = clsact_chain_head_change;
	q->egress_block_info.chain_head_change_priv = &q->miniqp_egress;

	//创建egress block
	return tcf_block_get_ext(&q->egress_block, sch, &q->egress_block_info, extack);
}

static void clsact_destroy(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct bpf_mprog_entry *ingress_entry = rtnl_dereference(dev->tcx_ingress);
	struct bpf_mprog_entry *egress_entry = rtnl_dereference(dev->tcx_egress);

	if (sch->parent != TC_H_CLSACT)
		return;

	tcf_block_put_ext(q->ingress_block, sch, &q->ingress_block_info);
	tcf_block_put_ext(q->egress_block, sch, &q->egress_block_info);

	if (ingress_entry) {
		tcx_miniq_set_active(ingress_entry, false);
		if (!tcx_entry_is_active(ingress_entry)) {
			tcx_entry_update(dev, NULL, true);
			tcx_entry_free(ingress_entry);
		}
	}

	if (egress_entry) {
		tcx_miniq_set_active(egress_entry, false);
		if (!tcx_entry_is_active(egress_entry)) {
			tcx_entry_update(dev, NULL, false);
			tcx_entry_free(egress_entry);
		}
	}

	net_dec_ingress_queue();
	net_dec_egress_queue();
}

/*同时支持ingress,egress*/
static const struct Qdisc_class_ops clsact_class_ops = {
	.flags		=	QDISC_CLASS_OPS_DOIT_UNLOCKED,
	.leaf		=	ingress_leaf,
	.find		=	clsact_find,
	.walk		=	ingress_walk,
	.tcf_block	=	clsact_tcf_block,
	.bind_tcf	=	clsact_bind_filter,
	.unbind_tcf	=	ingress_unbind_filter,
};

static struct Qdisc_ops clsact_qdisc_ops __read_mostly = {
	.cl_ops			=	&clsact_class_ops,
	.id			=	"clsact",
	.priv_size		=	sizeof(struct clsact_sched_data),
	.static_flags		=	TCQ_F_INGRESS | TCQ_F_CPUSTATS,
	//同时初始化ingress,egress qdisc
	.init			=	clsact_init,
	.destroy		=	clsact_destroy,
	.dump			=	ingress_dump,
	.ingress_block_set	=	clsact_ingress_block_set,
	.egress_block_set	=	clsact_egress_block_set,
	.ingress_block_get	=	clsact_ingress_block_get,
	.egress_block_get	=	clsact_egress_block_get,
	.owner			=	THIS_MODULE,
};

static int __init ingress_module_init(void)
{
	int ret;

	//注册ingress的排队规则
	ret = register_qdisc(&ingress_qdisc_ops);
	if (!ret) {
		//注册成功，注册clsact排队规则
		ret = register_qdisc(&clsact_qdisc_ops);
		if (ret)
		    /*不成功，解注册ingress的排队规则*/
			unregister_qdisc(&ingress_qdisc_ops);
	}

	return ret;
}

static void __exit ingress_module_exit(void)
{
	unregister_qdisc(&ingress_qdisc_ops);
	unregister_qdisc(&clsact_qdisc_ops);
}

module_init(ingress_module_init);
module_exit(ingress_module_exit);

MODULE_ALIAS("sch_clsact");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ingress and clsact based ingress and egress qdiscs");
