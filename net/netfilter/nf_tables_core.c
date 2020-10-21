// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/static_key.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_log.h>
#include <net/netfilter/nft_meta.h>

//有trace标记的报文，将被记录
static noinline void __nft_trace_packet(struct nft_traceinfo *info,
					const struct nft_chain *chain,
					enum nft_trace_types type)
{
	const struct nft_pktinfo *pkt = info->pkt;

	if (!info->trace || !pkt->skb->nf_trace)
		return;

	info->chain = chain;
	info->type = type;

	nft_trace_notify(info);
}

static inline void nft_trace_packet(struct nft_traceinfo *info,
				    const struct nft_chain *chain,
				    const struct nft_rule *rule,
				    enum nft_trace_types type)
{
	if (static_branch_unlikely(&nft_trace_enabled)) {
		info->rule = rule;
		__nft_trace_packet(info, chain, type);
	}
}

static void nft_bitwise_fast_eval(const struct nft_expr *expr,
				  struct nft_regs *regs)
{
	const struct nft_bitwise_fast_expr *priv = nft_expr_priv(expr);
	u32 *src = &regs->data[priv->sreg];
	u32 *dst = &regs->data[priv->dreg];

	*dst = (*src & priv->mask) ^ priv->xor;
}

//如果regs->data中的值与priv->data相等，则返回，否则置为nft_break
static void nft_cmp_fast_eval(const struct nft_expr *expr,
			      struct nft_regs *regs)
{
	const struct nft_cmp_fast_expr *priv = nft_expr_priv(expr);

	if (((regs->data[priv->sreg] & priv->mask) == priv->data) ^ priv->inv)
		return;
	regs->verdict.code = NFT_BREAK;
}

static bool nft_payload_fast_eval(const struct nft_expr *expr,
				  struct nft_regs *regs,
				  const struct nft_pktinfo *pkt)
{
	const struct nft_payload *priv = nft_expr_priv(expr);
	const struct sk_buff *skb = pkt->skb;
	u32 *dest = &regs->data[priv->dreg];
	unsigned char *ptr;

	if (priv->base == NFT_PAYLOAD_NETWORK_HEADER)
		ptr = skb_network_header(skb);
	else {
		if (!pkt->tprot_set)
			return false;
		ptr = skb_network_header(skb) + pkt->xt.thoff;
	}

	ptr += priv->offset;

	if (unlikely(ptr + priv->len > skb_tail_pointer(skb)))
		return false;

	*dest = 0;
	if (priv->len == 2)
		*(u16 *)dest = *(u16 *)ptr;
	else if (priv->len == 4)
		*(u32 *)dest = *(u32 *)ptr;
	else
		*(u8 *)dest = *(u8 *)ptr;
	return true;
}

DEFINE_STATIC_KEY_FALSE(nft_counters_enabled);

static noinline void nft_update_chain_stats(const struct nft_chain *chain,
					    const struct nft_pktinfo *pkt)
{
	struct nft_base_chain *base_chain;
	struct nft_stats __percpu *pstats;
	struct nft_stats *stats;

	base_chain = nft_base_chain(chain);

	rcu_read_lock();
	pstats = READ_ONCE(base_chain->stats);
	if (pstats) {
		local_bh_disable();
		stats = this_cpu_ptr(pstats);
		u64_stats_update_begin(&stats->syncp);
		stats->pkts++;
		stats->bytes += pkt->skb->len;
		u64_stats_update_end(&stats->syncp);
		local_bh_enable();
	}
	rcu_read_unlock();
}

struct nft_jumpstack {
	const struct nft_chain	*chain;
	struct nft_rule	*const *rules;
};

//执行表达式
static void expr_call_ops_eval(const struct nft_expr *expr,
			       struct nft_regs *regs,
			       struct nft_pktinfo *pkt)
{
#ifdef CONFIG_RETPOLINE
    //取ops的执行函数
	unsigned long e = (unsigned long)expr->ops->eval;
#define X(e, fun) \
    /*如果e是指定的回调函数，则直接调用此函数，用于优化*/\
	do { if ((e) == (unsigned long)(fun)) \
		return fun(expr, regs, pkt); } while (0)

	X(e, nft_payload_eval);
	X(e, nft_cmp_eval);
	X(e, nft_meta_get_eval);
	X(e, nft_lookup_eval);
	X(e, nft_range_eval);
	X(e, nft_immediate_eval);
	X(e, nft_byteorder_eval);
	X(e, nft_dynset_eval);
	X(e, nft_rt_get_eval);
	X(e, nft_bitwise_eval);
#undef  X
#endif /* CONFIG_RETPOLINE */
	//通过ops的eval回调完成表达式执行
	expr->ops->eval(expr, regs, pkt);
}

//进行chain的查询
unsigned int
nft_do_chain(struct nft_pktinfo *pkt, void *priv/*要执行规则的chain*/)
{
	const struct nft_chain *chain = priv, *basechain = chain;
	const struct net *net = nft_net(pkt);
	struct nft_rule *const *rules;
	const struct nft_rule *rule;
	const struct nft_expr *expr, *last;
	struct nft_regs regs;
	unsigned int stackptr = 0;
	struct nft_jumpstack jumpstack[NFT_JUMP_STACK_SIZE];
	bool genbit = READ_ONCE(net->nft.gencursor);
	struct nft_traceinfo info;

	info.trace = false;
	if (static_branch_unlikely(&nft_trace_enabled))
		nft_trace_init(&info, pkt, &regs.verdict, basechain);
do_chain:
	if (genbit)
		rules = rcu_dereference(chain->rules_gen_1);
	else
		rules = rcu_dereference(chain->rules_gen_0);

next_rule:
	rule = *rules;
	regs.verdict.code = NFT_CONTINUE;
	//遍历rules数组，针对每个rule的表达式进行执行
	for (; *rules ; rules++) {
		rule = *rules;
		/*遍历rule中的所有表达式*/
		nft_rule_for_each_expr(expr, last, rule) {
			if (expr->ops == &nft_cmp_fast_ops)
			    /*小于4字节的相等比对处理*/
				nft_cmp_fast_eval(expr, &regs);
			else if (expr->ops == &nft_bitwise_fast_ops)
				nft_bitwise_fast_eval(expr, &regs);
			else if (expr->ops != &nft_payload_fast_ops ||
				 !nft_payload_fast_eval(expr, &regs, pkt))
			    /*执行表达式*/
				expr_call_ops_eval(expr, &regs, pkt);

			/*匹配结果不是continue,则直接break,停止规则匹配*/
			if (regs.verdict.code != NFT_CONTINUE)
				break;
		}

		//此规则所有表达式均执行完成，如果为break或者continue,
		//则认为规则未匹配，继续遍历rule
		switch (regs.verdict.code) {
		case NFT_BREAK:
			regs.verdict.code = NFT_CONTINUE;
			continue;
		case NFT_CONTINUE:
		    //跟踪报文的命中情况
			nft_trace_packet(&info, chain, rule,
					 NFT_TRACETYPE_RULE);
			continue;
		}

		//与规则匹配
		break;
	}

	//检查对报文的结果
	switch (regs.verdict.code & NF_VERDICT_MASK) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
	case NF_STOLEN:
	    //返回规则结果（入队，接受，丢包...)
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RULE);
		return regs.verdict.code;
	}

	switch (regs.verdict.code) {
	case NFT_JUMP:
		if (WARN_ON_ONCE(stackptr >= NFT_JUMP_STACK_SIZE))
		    //栈超限
			return NF_DROP;
		//将当前chain及rule压栈
		jumpstack[stackptr].chain = chain;
		jumpstack[stackptr].rules = rules + 1;
		stackptr++;
		fallthrough;
	case NFT_GOTO:
	    //跳到指定chcain上运行
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RULE);

		chain = regs.verdict.chain;
		goto do_chain;
	case NFT_CONTINUE:
	case NFT_RETURN:
	    //退出匹配
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RETURN);
		break;
	default:
		WARN_ON(1);
	}

	//弹出堆栈后，继续匹配
	if (stackptr > 0) {
		stackptr--;
		chain = jumpstack[stackptr].chain;
		rules = jumpstack[stackptr].rules;
		goto next_rule;
	}

	nft_trace_packet(&info, basechain, NULL, NFT_TRACETYPE_POLICY);

	if (static_branch_unlikely(&nft_counters_enabled))
		nft_update_chain_stats(basechain, pkt);

	//如果整个链都没有规则匹配，则使用链的policy做为结果
	return nft_base_chain(basechain)->policy;
}
EXPORT_SYMBOL_GPL(nft_do_chain);

//netfilter支持的基本表达式类型
static struct nft_expr_type *nft_basic_types[] = {
	&nft_imm_type,
	&nft_cmp_type,
	&nft_lookup_type,
	&nft_bitwise_type,
	&nft_byteorder_type,
	&nft_payload_type,
	&nft_dynset_type,
	&nft_range_type,
	&nft_meta_type,
	&nft_rt_type,
	&nft_exthdr_type,
};

static struct nft_object_type *nft_basic_objects[] = {
#ifdef CONFIG_NETWORK_SECMARK
	&nft_secmark_obj_type,
#endif
};

int __init nf_tables_core_module_init(void)
{
	int err, i, j = 0;

	//注册netfilter object基础类型
	for (i = 0; i < ARRAY_SIZE(nft_basic_objects); i++) {
		err = nft_register_obj(nft_basic_objects[i]);
		if (err)
			goto err;
	}

	//注册netfilter的基本表达式type
	for (j = 0; j < ARRAY_SIZE(nft_basic_types); j++) {
		err = nft_register_expr(nft_basic_types[j]);
		if (err)
			goto err;
	}

	return 0;

err:
	while (j-- > 0)
		nft_unregister_expr(nft_basic_types[j]);

	while (i-- > 0)
		nft_unregister_obj(nft_basic_objects[i]);

	return err;
}

void nf_tables_core_module_exit(void)
{
	int i;

	i = ARRAY_SIZE(nft_basic_types);
	while (i-- > 0)
		nft_unregister_expr(nft_basic_types[i]);

	i = ARRAY_SIZE(nft_basic_objects);
	while (i-- > 0)
		nft_unregister_obj(nft_basic_objects[i]);
}
