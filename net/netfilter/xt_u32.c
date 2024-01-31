// SPDX-License-Identifier: GPL-2.0-only
/*
 *	xt_u32 - kernel module to match u32 packet content
 *
 *	Original author: Don Cohen <don@isis.cs3-inc.com>
 *	(C) CC Computer Consultants GmbH, 2007
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_u32.h>

static bool u32_match_it(const struct xt_u32 *data,
			 const struct sk_buff *skb)
{
	const struct xt_u32_test *ct;
	unsigned int testind;
	unsigned int nnums;
	unsigned int nvals;
	unsigned int i;
	__be32 n;
	u_int32_t pos;
	u_int32_t val;
	u_int32_t at;/*记录当前位置*/

	/*
	 * Small example: "0 >> 28 == 4 && 8 & 0xFF0000 >> 16 = 6, 17"
	 * (=IPv4 and (TCP or UDP)). Outer loop runs over the "&&" operands.
	 */
	for (testind = 0; testind < data->ntests; ++testind) {
		ct  = &data->tests[testind];
		at  = 0;
		pos = ct->location[0].number;

		//pos位置必须在skb中有效
		if (skb->len < 4 || pos > skb->len - 4)
			return false;

		//取skb->data中pos位置的值
		if (skb_copy_bits(skb, pos, &n, sizeof(n)) < 0)
			BUG();

		//将报文来的值转发主机序
		val   = ntohl(n);

		//遍历其它操作数
		nnums = ct->nnums;

		/* Inner loop runs over "&", "<<", ">>" and "@" operands */
		for (i = 1; i < nnums; ++i) {
			u_int32_t number = ct->location[i].number;//取第二个操作数
			switch (ct->location[i].nextop) {
			case XT_U32_AND:
				val &= number;
				break;
			case XT_U32_LEFTSH:
				val <<= number;
				break;
			case XT_U32_RIGHTSH:
				val >>= number;
				break;
			case XT_U32_AT:
				if (at + val < at)
					return false;
				at += val;/*更新当前位置*/
				pos = number;
				if (at + 4 < at || skb->len < at + 4 ||
				    pos > skb->len - at - 4)
					return false;

				/*取报文中at位置的数值*/
				if (skb_copy_bits(skb, at + pos, &n,
						    sizeof(n)) < 0)
					BUG();
				val = ntohl(n);
				break;
			}
		}

		/* Run over the "," and ":" operands */
		//检查value值是否在value数组规定的范围以内
		nvals = ct->nvalues;
		for (i = 0; i < nvals; ++i)
			if (ct->value[i].min <= val && val <= ct->value[i].max)
				break;

		//未匹配，返回false
		if (i >= ct->nvalues)
			return false;
	}

	return true;
}

static bool u32_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_u32 *data = par->matchinfo;
	bool ret;

	//执行u32 match（对skb->data中的数据某一个或多个位置的值进行运算，检测）
	ret = u32_match_it(data, skb);
	return ret ^ data->invert;
}

static int u32_mt_checkentry(const struct xt_mtchk_param *par)
{
	const struct xt_u32 *data = par->matchinfo;
	const struct xt_u32_test *ct;
	unsigned int i;

	if (data->ntests > ARRAY_SIZE(data->tests))
		return -EINVAL;

	for (i = 0; i < data->ntests; ++i) {
		ct = &data->tests[i];

		if (ct->nnums > ARRAY_SIZE(ct->location) ||
		    ct->nvalues > ARRAY_SIZE(ct->value))
			return -EINVAL;
	}

	return 0;
}

static struct xt_match xt_u32_mt_reg __read_mostly = {
	.name       = "u32",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = u32_mt,
	.checkentry = u32_mt_checkentry,
	.matchsize  = sizeof(struct xt_u32),
	.me         = THIS_MODULE,
};

//注册u32 match
static int __init u32_mt_init(void)
{
	return xt_register_match(&xt_u32_mt_reg);
}

static void __exit u32_mt_exit(void)
{
	xt_unregister_match(&xt_u32_mt_reg);
}

module_init(u32_mt_init);
module_exit(u32_mt_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: arbitrary byte matching");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_u32");
MODULE_ALIAS("ip6t_u32");
