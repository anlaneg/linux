/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_GACT_H
#define __NET_TC_GACT_H

#include <net/act_api.h>
#include <linux/tc_act/tc_gact.h>

struct tcf_gact {
	struct tc_action	common;
#ifdef CONFIG_GACT_PROB
	u16			tcfg_ptype;
	u16			tcfg_pval;
	int			tcfg_paction;
	atomic_t		packets;
#endif
};
#define to_gact(a) ((struct tcf_gact *)a)

//检测gact的opcode是否等于act
static inline bool __is_tcf_gact_act(const struct tc_action *a, int act,
				     bool is_ext)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tcf_gact *gact;

	//如果act不为gact,则返回false
	if (a->ops && a->ops->id != TCA_ID_GACT)
		return false;

	gact = to_gact(a);
	/*非扩展action,直接执行action匹配*/
	if ((!is_ext && gact->tcf_action == act) ||
			/*如果是扩展action,则取值扩展位后进行action比对*/
	    (is_ext && TC_ACT_EXT_CMP(gact->tcf_action, act)))
		return true;

#endif
	return false;
}

//action是否为gact且为act_ok
static inline bool is_tcf_gact_ok(const struct tc_action *a)
{
	return __is_tcf_gact_act(a, TC_ACT_OK, false);
}

static inline bool is_tcf_gact_shot(const struct tc_action *a)
{
	return __is_tcf_gact_act(a, TC_ACT_SHOT, false);
}

static inline bool is_tcf_gact_trap(const struct tc_action *a)
{
	return __is_tcf_gact_act(a, TC_ACT_TRAP, false);
}

//action是否为gact且为goto_chain
static inline bool is_tcf_gact_goto_chain(const struct tc_action *a)
{
	return __is_tcf_gact_act(a, TC_ACT_GOTO_CHAIN, true);
}

//获取goto action需要跳转至的chain_index
static inline u32 tcf_gact_goto_chain_index(const struct tc_action *a)
{
	return READ_ONCE(a->tcfa_action) & TC_ACT_EXT_VAL_MASK;
}

#endif /* __NET_TC_GACT_H */
