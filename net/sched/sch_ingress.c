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

struct ingress_sched_data {
	struct tcf_block *block;
	struct tcf_block_ext_info block_info;
	struct mini_Qdisc_pair miniqp;
};

static struct Qdisc *ingress_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

//通过classid返回class
static unsigned long ingress_find(struct Qdisc *sch, u32 classid)
{
	return TC_H_MIN(classid) + 1;
}

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

static void clsact_chain_head_change(struct tcf_proto *tp_head, void *priv)
{
	struct mini_Qdisc_pair *miniqp = priv;

	//miniqp->filter_list指定为tp_head
	mini_qdisc_pair_swap(miniqp, tp_head);
};

//设置ingress block_index
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

static int ingress_init(struct Qdisc *sch/*要初始化的qdisc*/, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	struct ingress_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	net_inc_ingress_queue();

	//使对miniqp的修改可以修改dev->miniq_ingress
	mini_qdisc_pair_init(&q->miniqp, sch, &dev->miniq_ingress);

	q->block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS;
	q->block_info.chain_head_change = clsact_chain_head_change;
	q->block_info.chain_head_change_priv = &q->miniqp;

	return tcf_block_get_ext(&q->block, sch, &q->block_info, extack);
}

static void ingress_destroy(struct Qdisc *sch)
{
	struct ingress_sched_data *q = qdisc_priv(sch);

	tcf_block_put_ext(q->block, sch, &q->block_info);
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
	.cl_ops			=	&ingress_class_ops,
	.id			=	"ingress",
	.priv_size		=	sizeof(struct ingress_sched_data),
	.static_flags		=	TCQ_F_CPUSTATS,
	.init			=	ingress_init,
	.destroy		=	ingress_destroy,
	.dump			=	ingress_dump,
	.ingress_block_set	=	ingress_ingress_block_set,
	.ingress_block_get	=	ingress_ingress_block_get,
	.owner			=	THIS_MODULE,
};

struct clsact_sched_data {
	struct tcf_block *ingress_block;//ingress使用block
	struct tcf_block *egress_block;//egress使用block
	struct tcf_block_ext_info ingress_block_info;//ingress信息
	struct tcf_block_ext_info egress_block_info;//egress信息
	struct mini_Qdisc_pair miniqp_ingress;
	struct mini_Qdisc_pair miniqp_egress;
};

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

static void clsact_ingress_block_set(struct Qdisc *sch, u32 block_index)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	q->ingress_block_info.block_index = block_index;
}

static void clsact_egress_block_set(struct Qdisc *sch, u32 block_index)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	q->egress_block_info.block_index = block_index;
}

static u32 clsact_ingress_block_get(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	return q->ingress_block_info.block_index;
}

static u32 clsact_egress_block_get(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	return q->egress_block_info.block_index;
}

//ingress ,egress block创建
static int clsact_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct clsact_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int err;

	net_inc_ingress_queue();
	net_inc_egress_queue();

	//初始化ingress
	mini_qdisc_pair_init(&q->miniqp_ingress, sch, &dev->miniq_ingress);

	q->ingress_block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS;
	q->ingress_block_info.chain_head_change = clsact_chain_head_change;
	q->ingress_block_info.chain_head_change_priv = &q->miniqp_ingress;

	//创建ingress block
	err = tcf_block_get_ext(&q->ingress_block, sch, &q->ingress_block_info,
				extack);
	if (err)
		return err;

	//初始化egress
	mini_qdisc_pair_init(&q->miniqp_egress, sch, &dev->miniq_egress);

	q->egress_block_info.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS;
	q->egress_block_info.chain_head_change = clsact_chain_head_change;
	q->egress_block_info.chain_head_change_priv = &q->miniqp_egress;

	//创建egress block
	return tcf_block_get_ext(&q->egress_block, sch, &q->egress_block_info, extack);
}

static void clsact_destroy(struct Qdisc *sch)
{
	struct clsact_sched_data *q = qdisc_priv(sch);

	tcf_block_put_ext(q->egress_block, sch, &q->egress_block_info);
	tcf_block_put_ext(q->ingress_block, sch, &q->ingress_block_info);

	net_dec_ingress_queue();
	net_dec_egress_queue();
}

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
	.static_flags		=	TCQ_F_CPUSTATS,
	//初始化ingress qdisc
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
