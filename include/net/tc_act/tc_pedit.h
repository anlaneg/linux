/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_PED_H
#define __NET_TC_PED_H

#include <net/act_api.h>
#include <linux/tc_act/tc_pedit.h>

struct tcf_pedit_key_ex {
	//修改的头部类型
	enum pedit_header_type htype;
	//修改方式
	enum pedit_cmd cmd;
};

struct tcf_pedit {
	struct tc_action	common;
	unsigned char		tcfp_nkeys;//tcfp_keys数目
	unsigned char		tcfp_flags;
	//要修改的key参数
	struct tc_pedit_key	*tcfp_keys;
	/*修改方式及修改基准*/
	struct tcf_pedit_key_ex	*tcfp_keys_ex;
};

#define to_pedit(a) ((struct tcf_pedit *)a)

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
	return to_pedit(a)->tcfp_nkeys;
}

/*取index号修改对应的修改基准*/
static inline u32 tcf_pedit_htype(const struct tc_action *a, int index)
{
	if (to_pedit(a)->tcfp_keys_ex)
		return to_pedit(a)->tcfp_keys_ex[index].htype;

	return TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
}

/*取index号修改对应的修改方式（add/set)*/
static inline u32 tcf_pedit_cmd(const struct tc_action *a, int index)
{
	if (to_pedit(a)->tcfp_keys_ex)
		return to_pedit(a)->tcfp_keys_ex[index].cmd;

	return __PEDIT_CMD_MAX;
}

/*取index号修改对应的mask*/
static inline u32 tcf_pedit_mask(const struct tc_action *a, int index)
{
	return to_pedit(a)->tcfp_keys[index].mask;
}

/*取index号修改对应的value*/
static inline u32 tcf_pedit_val(const struct tc_action *a, int index)
{
	return to_pedit(a)->tcfp_keys[index].val;
}

/*取index号修改对应的offset*/
static inline u32 tcf_pedit_offset(const struct tc_action *a, int index)
{
	return to_pedit(a)->tcfp_keys[index].off;
}
#endif /* __NET_TC_PED_H */
