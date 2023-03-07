/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_PED_H
#define __NET_TC_PED_H

#include <net/act_api.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/types.h>

struct tcf_pedit_key_ex {
	//修改的头部类型
	enum pedit_header_type htype;
	//修改方式
	enum pedit_cmd cmd;
};

struct tcf_pedit_parms {
	//要修改的key参数
	struct tc_pedit_key	*tcfp_keys;
	/*修改方式及修改基准*/
	struct tcf_pedit_key_ex	*tcfp_keys_ex;
	u32 tcfp_off_max_hint;
	unsigned char tcfp_nkeys;//tcfp_keys数目
	unsigned char tcfp_flags;
	struct rcu_head rcu;
};

struct tcf_pedit {
	struct tc_action common;
	struct tcf_pedit_parms __rcu *parms;
};

#define to_pedit(a) ((struct tcf_pedit *)a)
#define to_pedit_parms(a) (rcu_dereference(to_pedit(a)->parms))

/*检查是否为pedit动作（负责报文修改）*/
static inline bool is_tcf_pedit(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->id == TCA_ID_PEDIT)
		return true;
#endif
	return false;
}

static inline int tcf_pedit_nkeys(const struct tc_action *a)
{
	struct tcf_pedit_parms *parms;
	int nkeys;

	rcu_read_lock();
	parms = to_pedit_parms(a);
	nkeys = parms->tcfp_nkeys;
	rcu_read_unlock();

	return nkeys;
}

/*取index号修改对应的修改基准*/
static inline u32 tcf_pedit_htype(const struct tc_action *a, int index)
{
	u32 htype = TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
	struct tcf_pedit_parms *parms;

	rcu_read_lock();
	parms = to_pedit_parms(a);
	if (parms->tcfp_keys_ex)
		htype = parms->tcfp_keys_ex[index].htype;
	rcu_read_unlock();

	return htype;
}

/*取index号修改对应的修改方式（add/set)*/
static inline u32 tcf_pedit_cmd(const struct tc_action *a, int index)
{
	struct tcf_pedit_parms *parms;
	u32 cmd = __PEDIT_CMD_MAX;

	rcu_read_lock();
	parms = to_pedit_parms(a);
	if (parms->tcfp_keys_ex)
		cmd = parms->tcfp_keys_ex[index].cmd;
	rcu_read_unlock();

	return cmd;
}

/*取index号修改对应的mask*/
static inline u32 tcf_pedit_mask(const struct tc_action *a, int index)
{
	struct tcf_pedit_parms *parms;
	u32 mask;

	rcu_read_lock();
	parms = to_pedit_parms(a);
	mask = parms->tcfp_keys[index].mask;
	rcu_read_unlock();

	return mask;
}

/*取index号修改对应的value*/
static inline u32 tcf_pedit_val(const struct tc_action *a, int index)
{
	struct tcf_pedit_parms *parms;
	u32 val;

	rcu_read_lock();
	parms = to_pedit_parms(a);
	val = parms->tcfp_keys[index].val;
	rcu_read_unlock();

	return val;
}

/*取index号修改对应的offset*/
static inline u32 tcf_pedit_offset(const struct tc_action *a, int index)
{
	struct tcf_pedit_parms *parms;
	u32 off;

	rcu_read_lock();
	parms = to_pedit_parms(a);
	off = parms->tcfp_keys[index].off;
	rcu_read_unlock();

	return off;
}
#endif /* __NET_TC_PED_H */
