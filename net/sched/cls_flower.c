// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/cls_flower.c		Flower classifier
 *
 * Copyright (c) 2015 Jiri Pirko <jiri@resnulli.us>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>

#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/mpls.h>

#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/ip.h>
#include <net/flow_dissector.h>
#include <net/geneve.h>
#include <net/vxlan.h>
#include <net/erspan.h>

#include <net/dst.h>
#include <net/dst_metadata.h>

#include <uapi/linux/netfilter/nf_conntrack_common.h>

#define TCA_FLOWER_KEY_CT_FLAGS_MAX \
		((__TCA_FLOWER_KEY_CT_FLAGS_MAX - 1) << 1)
#define TCA_FLOWER_KEY_CT_FLAGS_MASK \
		(TCA_FLOWER_KEY_CT_FLAGS_MAX - 1)

struct fl_flow_key {
	struct flow_dissector_key_meta meta;//入接口
	struct flow_dissector_key_control control;
	struct flow_dissector_key_control enc_control;//隧道方式control
	struct flow_dissector_key_basic basic;//协议号相关
	struct flow_dissector_key_eth_addrs eth;//以太头
	struct flow_dissector_key_vlan vlan;//外层vlan
	struct flow_dissector_key_vlan cvlan;//内层vlan
	union {
		//源目的地址
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	//源目的端口
	struct flow_dissector_key_ports tp;
	//icmp type与code 匹配
	struct flow_dissector_key_icmp icmp;
	//arp协议匹配
	struct flow_dissector_key_arp arp;
	//隧道key匹配
	struct flow_dissector_key_keyid enc_key_id;
	union {
	    //隧道ipv4/ipv6源目的地址匹配
		struct flow_dissector_key_ipv4_addrs enc_ipv4;
		struct flow_dissector_key_ipv6_addrs enc_ipv6;
	};
	//隧道方式传输层配置
	struct flow_dissector_key_ports enc_tp;
	struct flow_dissector_key_mpls mpls;
	//tcp标记位匹配
	struct flow_dissector_key_tcp tcp;
	//tos,ttl匹配支持
	struct flow_dissector_key_ip ip;
	//隧道填充时ttl,tos
	struct flow_dissector_key_ip enc_ip;
	//隧道相关的选项
	struct flow_dissector_key_enc_opts enc_opts;
	union {
		struct flow_dissector_key_ports tp;//传输层匹配
		struct {
			//支持port-range方式匹配
			struct flow_dissector_key_ports tp_min;
			struct flow_dissector_key_ports tp_max;
		};
	} tp_range;
	//ct状态匹配
	struct flow_dissector_key_ct ct;
	struct flow_dissector_key_hash hash;
} __aligned(BITS_PER_LONG / 8); /* Ensure that we can do comparisons as longs. */

struct fl_flow_mask_range {
	unsigned short int start;
	unsigned short int end;
};

struct fl_flow_mask {
	struct fl_flow_key key;
	//key中有效值的起始终止位置
	struct fl_flow_mask_range range;
	//mask上的标记，例如需要执行port range检查
	u32 flags;
	//用于插入到cls_fl_head->ht表中
	struct rhash_head ht_node;
	//hash表，保存filter规则，挂接在此ht上的filter规则均具有相同的mask（用于查询)
	struct rhashtable ht;
	//filter hash表的参数
	struct rhashtable_params filter_ht_params;
	//mask相关的各key的offset
	struct flow_dissector dissector;
	//链表，用于保存在ht中的所有filter规则（用于遍历)
	struct list_head filters;
	struct rcu_work rwork;
	struct list_head list;
	refcount_t refcnt;
};

struct fl_flow_tmplt {
	struct fl_flow_key dummy_key;/*匹配信息*/
	struct fl_flow_key mask;/*匹配的掩码信息*/
	struct flow_dissector dissector;/*记录flow中出现的key及各key在结构fl_flow_key中的offset*/
	struct tcf_chain *chain;/*所属的chain*/
};

struct cls_fl_head {
    //哈希表，用于保存不同mask的rules(用于哈希查询）
	struct rhashtable ht;
	spinlock_t masks_lock; /* Protect masks list */
	//链表，用于保存不同的mask（用于遍历）
	struct list_head masks;
	//已下发至hardware的filter规则
	struct list_head hw_filters;
	struct rcu_work rwork;
	//存储handle与cls_fl_filter之间映射关系
	struct idr handle_idr;
};

struct cls_fl_filter {
    //规则对应的mask
	struct fl_flow_mask *mask;
	//用于将规则挂接到其所属的mask hash表上
	struct rhash_head ht_node;
	//配合mask生在的key
	struct fl_flow_key mkey;
	struct tcf_exts exts;
	struct tcf_result res;
	//match的key
	struct fl_flow_key key;
	struct list_head list;
	//挂接至hw_filters
	struct list_head hw_list;
	//filter的标识，通过handle可以在ht中查询到filter
	u32 handle;
	//filter对应的标记，例如已下发至硬件
	u32 flags;
	u32 in_hw_count;
	struct rcu_work rwork;
	struct net_device *hw_dev;
	/* Flower classifier is unlocked, which means that its reference counter
	 * can be changed concurrently without any kind of external
	 * synchronization. Use atomic reference counter to be concurrency-safe.
	 */
	refcount_t refcnt;
	bool deleted;//标明规则已被删除
};

static const struct rhashtable_params mask_ht_params = {
	.key_offset = offsetof(struct fl_flow_mask, key),
	.key_len = sizeof(struct fl_flow_key),
	.head_offset = offsetof(struct fl_flow_mask, ht_node),
	.automatic_shrinking = true,
};

static unsigned short int fl_mask_range(const struct fl_flow_mask *mask)
{
	return mask->range.end - mask->range.start;
}

//确定mask有效的起始终止位置
static void fl_mask_update_range(struct fl_flow_mask *mask)
{
	const u8 *bytes = (const u8 *) &mask->key;
	size_t size = sizeof(mask->key);
	size_t i, first = 0, last;

	//正向遍历找到起始range起始位置
	for (i = 0; i < size; i++) {
		if (bytes[i]) {
			first = i;
			break;
		}
	}

	//反向遍历找到终止range位置
	last = first;
	for (i = size - 1; i != first; i--) {
		if (bytes[i]) {
			last = i;
			break;
		}
	}

	//记录起始及终止位置
	mask->range.start = rounddown(first, sizeof(long));
	mask->range.end = roundup(last + 1, sizeof(long));
}

static void *fl_key_get_start(struct fl_flow_key *key,
			      const struct fl_flow_mask *mask)
{
	return (u8 *) key + mask->range.start;
}

//填充mkey,使mkey=key&mask
static void fl_set_masked_key(struct fl_flow_key *mkey, struct fl_flow_key *key,
			      struct fl_flow_mask *mask)
{
	//依据mask确定key的有效起始位置及终止位置
	const long *lkey = fl_key_get_start(key, mask);
	const long *lmask = fl_key_get_start(&mask->key, mask);
	long *lmkey = fl_key_get_start(mkey, mask);
	int i;

	//填充mkey,使key&mask后给其赋值
	for (i = 0; i < fl_mask_range(mask); i += sizeof(long))
		*lmkey++ = *lkey++ & *lmask++;
}

static bool fl_mask_fits_tmplt(struct fl_flow_tmplt *tmplt,
			       struct fl_flow_mask *mask)
{
	//mask有效起始位置
	const long *lmask = fl_key_get_start(&mask->key, mask);
	const long *ltmplt;
	int i;

	if (!tmplt)
		return true;
	ltmplt = fl_key_get_start(&tmplt->mask, mask);
	for (i = 0; i < fl_mask_range(mask); i += sizeof(long)) {
		if (~*ltmplt++ & *lmask++)
			/*ltmplt中原没有某位,本次lmask要求此位，故返回false*/
			return false;
	}
	return true;
}

/*将key中mask关心的范围清零*/
static void fl_clear_masked_range(struct fl_flow_key *key,
				  struct fl_flow_mask *mask)
{
	memset(fl_key_get_start(key, mask), 0, fl_mask_range(mask));
}

static bool fl_range_port_dst_cmp(struct cls_fl_filter *filter,
				  struct fl_flow_key *key,
				  struct fl_flow_key *mkey)
{
	u16 min_mask, max_mask, min_val, max_val;

	min_mask = ntohs(filter->mask->key.tp_range.tp_min.dst);
	max_mask = ntohs(filter->mask->key.tp_range.tp_max.dst);
	min_val = ntohs(filter->key.tp_range.tp_min.dst);
	max_val = ntohs(filter->key.tp_range.tp_max.dst);

	if (min_mask && max_mask) {
		if (ntohs(key->tp_range.tp.dst) < min_val ||
		    ntohs(key->tp_range.tp.dst) > max_val)
			return false;

		/* skb does not have min and max values */
		mkey->tp_range.tp_min.dst = filter->mkey.tp_range.tp_min.dst;
		mkey->tp_range.tp_max.dst = filter->mkey.tp_range.tp_max.dst;
	}
	return true;
}

static bool fl_range_port_src_cmp(struct cls_fl_filter *filter,
				  struct fl_flow_key *key,
				  struct fl_flow_key *mkey)
{
	u16 min_mask, max_mask, min_val, max_val;

	min_mask = ntohs(filter->mask->key.tp_range.tp_min.src);
	max_mask = ntohs(filter->mask->key.tp_range.tp_max.src);
	min_val = ntohs(filter->key.tp_range.tp_min.src);
	max_val = ntohs(filter->key.tp_range.tp_max.src);

	if (min_mask && max_mask) {
		if (ntohs(key->tp_range.tp.src) < min_val ||
		    ntohs(key->tp_range.tp.src) > max_val)
			return false;

		/* skb does not have min and max values */
		mkey->tp_range.tp_min.src = filter->mkey.tp_range.tp_min.src;
		mkey->tp_range.tp_max.src = filter->mkey.tp_range.tp_max.src;
	}
	return true;
}

static struct cls_fl_filter *__fl_lookup(struct fl_flow_mask *mask,
					 struct fl_flow_key *mkey)
{
	return rhashtable_lookup_fast(&mask->ht, fl_key_get_start(mkey, mask),
				      mask->filter_ht_params);
}

static struct cls_fl_filter *fl_lookup_range(struct fl_flow_mask *mask,
					     struct fl_flow_key *mkey,
					     struct fl_flow_key *key)
{
	struct cls_fl_filter *filter, *f;

	list_for_each_entry_rcu(filter, &mask->filters, list) {
		if (!fl_range_port_dst_cmp(filter, key, mkey))
			continue;

		if (!fl_range_port_src_cmp(filter, key, mkey))
			continue;

		f = __fl_lookup(mask, mkey);
		if (f)
			return f;
	}
	return NULL;
}

static noinline_for_stack
struct cls_fl_filter *fl_mask_lookup(struct fl_flow_mask *mask, struct fl_flow_key *key)
{
	struct fl_flow_key mkey;

	fl_set_masked_key(&mkey, key, mask);
	if ((mask->flags & TCA_FLOWER_MASK_FLAGS_RANGE))
		return fl_lookup_range(mask, &mkey, key);

	return __fl_lookup(mask, &mkey);
}

static u16 fl_ct_info_to_flower_map[] = {
	[IP_CT_ESTABLISHED] =		TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
					TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED,
	[IP_CT_RELATED] =		TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
					TCA_FLOWER_KEY_CT_FLAGS_RELATED,
	[IP_CT_ESTABLISHED_REPLY] =	TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
					TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED |
					TCA_FLOWER_KEY_CT_FLAGS_REPLY,
	[IP_CT_RELATED_REPLY] =		TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
					TCA_FLOWER_KEY_CT_FLAGS_RELATED |
					TCA_FLOWER_KEY_CT_FLAGS_REPLY,
	[IP_CT_NEW] =			TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
					TCA_FLOWER_KEY_CT_FLAGS_NEW,
};

static int fl_classify(struct sk_buff *skb, const struct tcf_proto *tp,
		       struct tcf_result *res)
{
	struct cls_fl_head *head = rcu_dereference_bh(tp->root);
	bool post_ct = qdisc_skb_cb(skb)->post_ct;
	struct fl_flow_key skb_key;
	struct fl_flow_mask *mask;
	struct cls_fl_filter *f;

	//遍历所有mask
	list_for_each_entry_rcu(mask, &head->masks, list) {
	    /*每次均对control,basic进行清零处理*/
		flow_dissector_init_keys(&skb_key.control, &skb_key.basic);
		/*每次均对mask关心的字段进行清零，准备重新解析*/
		fl_clear_masked_range(&skb_key, mask);

		/*更新meta*/
		skb_flow_dissect_meta(skb, &mask->dissector, &skb_key);
		/* skb_flow_dissect() does not set n_proto in case an unknown
		 * protocol, so do it rather here.
		 */
		/*网络层协议ipv4/ipv6*/
		skb_key.basic.n_proto = skb_protocol(skb, false);
		/*更新隧道信息*/
		skb_flow_dissect_tunnel_info(skb, &mask->dissector, &skb_key);
		/*解析ct相关的字段*/
		skb_flow_dissect_ct(skb, &mask->dissector, &skb_key,
				    fl_ct_info_to_flower_map,
				    ARRAY_SIZE(fl_ct_info_to_flower_map),
				    post_ct);
		/*解析skb->hash*/
		skb_flow_dissect_hash(skb, &mask->dissector, &skb_key);
		/*解析skb中的mask->dissector提及的字段，并将解析结果存入到skb_key中*/
		skb_flow_dissect(skb, &mask->dissector, &skb_key,
				 FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP);
	//解析action
	err = tcf_exts_validate(net, tp, tb, est, &f->exts, flags, extack);
	if (err < 0)
		return err;

	if (tb[TCA_FLOWER_CLASSID]) {
		f->res.classid = nla_get_u32(tb[TCA_FLOWER_CLASSID]);
		if (flags & TCA_ACT_FLAGS_NO_RTNL)
			rtnl_lock();
		tcf_bind_filter(tp, &f->res, base);
		if (flags & TCA_ACT_FLAGS_NO_RTNL)
			rtnl_unlock();
	}

	//解析flower规则中的key,mask
	err = fl_set_key(net, tb, &f->key, &mask->key, extack);
	if (err)
		return err;

	//确定mask的起始终止位置
	fl_mask_update_range(mask);
	//填充f->mkey,使f->mkey = f->key & mask
	fl_set_masked_key(&f->mkey, &f->key, mask);

	if (!fl_mask_fits_tmplt(tmplt, mask)) {
		//mask与模板不一致，如果tmplt为NULL，则返回True
		NL_SET_ERR_MSG_MOD(extack, "Mask does not fit the template");
		return -EINVAL;
	}

	return 0;
}

//将filter加入到hashtable中
static int fl_ht_insert_unique(struct cls_fl_filter *fnew,
			       struct cls_fl_filter *fold,
			       bool *in_ht/*出参，是否存入了hash表*/)
{
	struct fl_flow_mask *mask = fnew->mask;
	int err;

	//将filter加入到hashtable中
	err = rhashtable_lookup_insert_fast(&mask->ht,
					    &fnew->ht_node,
					    mask->filter_ht_params);
	if (err) {
	    /*加入出错，没有存放入hash表*/
		*in_ht = false;
		/* It is okay if filter with same key exists when
		 * overwriting.
		 */
		return fold && err == -EEXIST ? 0 : err;
	}

	*in_ht = true;
	return 0;
}

//添加删除flower规则
static int fl_change(struct net *net, struct sk_buff *in_skb/*netlink消息报文*/,
		     struct tcf_proto *tp, unsigned long base,
		     u32 handle/*规则对应的handle*/, struct nlattr **tca/*netlink消息*/,
		     void **arg/*入参旧规则，出参新规则*/, u32 flags,
		     struct netlink_ext_ack *extack)
{
	struct cls_fl_head *head = fl_head_dereference(tp);
	bool rtnl_held = !(flags & TCA_ACT_FLAGS_NO_RTNL);
	struct cls_fl_filter *fold = *arg;/*旧的规则*/
	struct cls_fl_filter *fnew;/*新规则的内容来源于tca*/
	struct fl_flow_mask *mask;
	struct nlattr **tb;
	bool in_ht;
	int err;

	//flower规则均存在options中
	if (!tca[TCA_OPTIONS]) {
		err = -EINVAL;
		goto errout_fold;
	}

	//申请填充规则mask
	mask = kzalloc(sizeof(struct fl_flow_mask), GFP_KERNEL);
	if (!mask) {
		err = -ENOBUFS;
		goto errout_fold;
	}

	tb = kcalloc(TCA_FLOWER_MAX + 1, sizeof(struct nlattr *), GFP_KERNEL);
	if (!tb) {
		err = -ENOBUFS;
		goto errout_mask_alloc;
	}

	//自tca[TCA_OPTIONS]中解析出flower规则,存入tb
	err = nla_parse_nested_deprecated(tb, TCA_FLOWER_MAX,
					  tca[TCA_OPTIONS], fl_policy, NULL);
	if (err < 0)
		goto errout_tb;

	//当前为change，要求规则handle相等，现在规则handle不相等，报错
	if (fold && handle && fold->handle != handle) {
		err = -EINVAL;
		goto errout_tb;
	}

	//构造新规则
	fnew = kzalloc(sizeof(*fnew), GFP_KERNEL);
	if (!fnew) {
		err = -ENOBUFS;
		goto errout_tb;
	}
	INIT_LIST_HEAD(&fnew->hw_list);
	refcount_set(&fnew->refcnt, 1);

	//初始化新规则的action结构
	err = tcf_exts_init(&fnew->exts, net, TCA_FLOWER_ACT, 0);
	if (err < 0)
		goto errout;

	//解析流的下发方式（不下发至硬件/不下发至软件）
	if (tb[TCA_FLOWER_FLAGS]) {
		fnew->flags = nla_get_u32(tb[TCA_FLOWER_FLAGS]);

		if (!tc_flags_valid(fnew->flags)) {
			err = -EINVAL;
			goto errout;
		}
	}

	//解析flow的key，mask及action
	err = fl_set_parms(net, tp, fnew, mask, base, tb, tca[TCA_RATE],
			   tp->chain->tmplt_priv, flags, extack);
	if (err)
		goto errout;

	//使规则与mask关联，如果mask不存在，则
	err = fl_check_assign_mask(head, fnew, fold, mask);
	if (err)
		goto errout;

	//将filter加入至其对应的mask中
	err = fl_ht_insert_unique(fnew, fold, &in_ht);
	if (err)
		goto errout_mask;

	//如果规则不要求跳过hw,则按要求执行hw的替换
	if (!tc_skip_hw(fnew->flags)) {
		err = fl_hw_replace_filter(tp, fnew, rtnl_held, extack);
		if (err)
			goto errout_ht;
	}

	//标记规则未下载到硬件
	if (!tc_in_hw(fnew->flags))
		fnew->flags |= TCA_CLS_FLAGS_NOT_IN_HW;

	spin_lock(&tp->lock);

	/* tp was deleted concurrently. -EAGAIN will cause caller to lookup
	 * proto again or create new one, if necessary.
	 */
	if (tp->deleting) {
		err = -EAGAIN;
		goto errout_hw;
	}

	if (fold) {
		//有旧的规则，则移除掉旧的规则
		/* Fold filter was deleted concurrently. Retry lookup. */
		if (fold->deleted) {
			err = -EAGAIN;
			goto errout_hw;
		}

		fnew->handle = handle;

		if (!in_ht) {
			//如果不存hashtable中，则将其加入，再统一做删除（为了统一处理）
			struct rhashtable_params params =
				fnew->mask->filter_ht_params;

			err = rhashtable_insert_fast(&fnew->mask->ht,
						     &fnew->ht_node,
						     params);
			if (err)
				goto errout_hw;
			in_ht = true;
		}

		refcount_inc(&fnew->refcnt);
		//执行旧规则删除
		rhashtable_remove_fast(&fold->mask->ht,
				       &fold->ht_node,
				       fold->mask->filter_ht_params);
		//移除掉filter与handle之间的映射关系
		idr_replace(&head->handle_idr, fnew, fnew->handle);
		list_replace_rcu(&fold->list, &fnew->list);
		fold->deleted = true;

		spin_unlock(&tp->lock);

		fl_mask_put(head, fold->mask);
		if (!tc_skip_hw(fold->flags))
			/*自硬件中移除规则*/
			fl_hw_destroy_filter(tp, fold, rtnl_held, NULL);
		tcf_unbind_filter(tp, &fold->res);
		/* Caller holds reference to fold, so refcnt is always > 0
		 * after this.
		 */
		refcount_dec(&fold->refcnt);
		__fl_put(fold);
	} else {
		if (handle) {
			/* user specifies a handle and it doesn't exist */
			//用户指定了一个不存在的handle,申请一个
			err = idr_alloc_u32(&head->handle_idr, fnew, &handle,
					    handle, GFP_ATOMIC);

			/* Filter with specified handle was concurrently
			 * inserted after initial check in cls_api. This is not
			 * necessarily an error if NLM_F_EXCL is not set in
			 * message flags. Returning EAGAIN will cause cls_api to
			 * try to update concurrently inserted rule.
			 */
			if (err == -ENOSPC)
				err = -EAGAIN;
		} else {
			//未指定handle,申请一个
			handle = 1;
			err = idr_alloc_u32(&head->handle_idr, fnew, &handle,
					    INT_MAX, GFP_ATOMIC);
		}
		if (err)
			goto errout_hw;

		refcount_inc(&fnew->refcnt);
		//用于挂接filter到mask->filters链上
		fnew->handle = handle;
		list_add_tail_rcu(&fnew->list, &fnew->mask->filters);
		spin_unlock(&tp->lock);
	}

	*arg = fnew;

	kfree(tb);
	tcf_queue_work(&mask->rwork, fl_uninit_mask_free_work);
	return 0;

errout_ht:
	spin_lock(&tp->lock);
errout_hw:
	fnew->deleted = true;
	spin_unlock(&tp->lock);
	if (!tc_skip_hw(fnew->flags))
		fl_hw_destroy_filter(tp, fnew, rtnl_held, NULL);
	if (in_ht)
		rhashtable_remove_fast(&fnew->mask->ht, &fnew->ht_node,
				       fnew->mask->filter_ht_params);
errout_mask:
	fl_mask_put(head, fnew->mask);
errout:
	__fl_put(fnew);
errout_tb:
	kfree(tb);
errout_mask_alloc:
	tcf_queue_work(&mask->rwork, fl_uninit_mask_free_work);
errout_fold:
	if (fold)
		__fl_put(fold);
	return err;
}

static int fl_delete(struct tcf_proto *tp, void *arg, bool *last/*出参，当前正在删除的flow是否最后一个*/,
		     bool rtnl_held, struct netlink_ext_ack *extack)
{
	struct cls_fl_head *head = fl_head_dereference(tp);
	struct cls_fl_filter *f = arg;
	bool last_on_mask;
	int err = 0;

	//自tp中移除filter
	err = __fl_delete(tp, f, &last_on_mask, rtnl_held, extack);
	//通过检查mask链是否为空
	*last = list_empty(&head->masks);
	__fl_put(f);

	return err;
}

/*遍历tp对应的filter规则*/
static void fl_walk(struct tcf_proto *tp, struct tcf_walker *arg,
		    bool rtnl_held)
{
	struct cls_fl_head *head = fl_head_dereference(tp);
	unsigned long id = arg->cookie, tmp;
	struct cls_fl_filter *f;

	arg->count = arg->skip;

	rcu_read_lock();
	//通过hand->handle_idr遍历每个filter规则
	idr_for_each_entry_continue_ul(&head->handle_idr, f, tmp, id) {
		/* don't return filters that are being deleted */
		if (!refcount_inc_not_zero(&f->refcnt))
		    /*跳过不再引用的flower filter*/
			continue;
		rcu_read_unlock();

		/*采用tp dump每条flower filter规则*/
		if (arg->fn(tp, f, arg) < 0) {
		    /*执行walk回调失败，停止*/
			__fl_put(f);
			arg->stop = 1;
			rcu_read_lock();
			break;
		}
		__fl_put(f);
		arg->count++;
		rcu_read_lock();
	}
	rcu_read_unlock();
	arg->cookie = id;/*记录停止时的id*/
}

//用于获得已下发给hw的filter
static struct cls_fl_filter *
fl_get_next_hw_filter(struct tcf_proto *tp, struct cls_fl_filter *f, bool add)
{
	struct cls_fl_head *head = fl_head_dereference(tp);

	spin_lock(&tp->lock);
	if (list_empty(&head->hw_filters)) {
		//下给hardware的filter为空，返回NULL
		spin_unlock(&tp->lock);
		return NULL;
	}

	if (!f)
		/*未指定时，使用首个filter*/
		f = list_entry(&head->hw_filters, struct cls_fl_filter,
			       hw_list);

	/*返回未被移除的filter*/
	list_for_each_entry_continue(f, &head->hw_filters, hw_list) {
		if (!(add && f->deleted) && refcount_inc_not_zero(&f->refcnt)) {
			spin_unlock(&tp->lock);
			return f;
		}
	}

	spin_unlock(&tp->lock);
	return NULL;
}

static int fl_reoffload(struct tcf_proto *tp, bool add/*是否规则添加*/, flow_setup_cb_t *cb/*针对每条cls_flower执行TC_SETUP_CLSFLOWER*/,
			void *cb_priv/*回调的私有数据*/, struct netlink_ext_ack *extack)
{
	struct tcf_block *block = tp->chain->block;
	struct flow_cls_offload cls_flower = {};
	struct cls_fl_filter *f = NULL;
	int err;

	/* hw_filters list can only be changed by hw offload functions after
	 * obtaining rtnl lock. Make sure it is not changed while reoffload is
	 * iterating it.
	 */
	ASSERT_RTNL();

	//遍历已下发到hardware的所有filter
	while ((f = fl_get_next_hw_filter(tp, f, add))) {
		//将filter构造成cls_flower
		cls_flower.rule =
			flow_rule_alloc(tcf_exts_num_actions(&f->exts));
		if (!cls_flower.rule) {
			__fl_put(f);
			return -ENOMEM;
		}

		tc_cls_common_offload_init(&cls_flower.common, tp, f->flags,
					   extack);
		cls_flower.command = add /*确定规则增删*/ ?
			FLOW_CLS_REPLACE : FLOW_CLS_DESTROY;
		cls_flower.cookie = (unsigned long)f;
		cls_flower.rule->match.dissector = &f->mask->dissector;
		cls_flower.rule->match.mask = &f->mask->key;
		cls_flower.rule->match.key = &f->mkey;

		//实现action转换
		err = tc_setup_flow_action(&cls_flower.rule->action, &f->exts);
		if (err) {
			kfree(cls_flower.rule);
			if (tc_skip_sw(f->flags)) {
				NL_SET_ERR_MSG_MOD(extack, "Failed to setup flow action");
				__fl_put(f);
				return err;
			}
			goto next_flow;
		}

		cls_flower.classid = f->res.classid;

		//执行clsflower回调下发
		err = tc_setup_cb_reoffload(block, tp, add, cb,
					    TC_SETUP_CLSFLOWER, &cls_flower,
					    cb_priv, &f->flags,
					    &f->in_hw_count);
		tc_cleanup_flow_action(&cls_flower.rule->action);
		kfree(cls_flower.rule);

		if (err) {
			__fl_put(f);
			return err;
		}
next_flow:
		__fl_put(f);
	}

	return 0;
}

static void fl_hw_add(struct tcf_proto *tp, void *type_data)
{
	struct flow_cls_offload *cls_flower = type_data;
	struct cls_fl_filter *f =
		(struct cls_fl_filter *) cls_flower->cookie;
	struct cls_fl_head *head = fl_head_dereference(tp);

	spin_lock(&tp->lock);
	list_add(&f->hw_list, &head->hw_filters);
	spin_unlock(&tp->lock);
}

static void fl_hw_del(struct tcf_proto *tp, void *type_data)
{
	struct flow_cls_offload *cls_flower = type_data;
	struct cls_fl_filter *f =
		(struct cls_fl_filter *) cls_flower->cookie;

	spin_lock(&tp->lock);
	if (!list_empty(&f->hw_list))
		list_del_init(&f->hw_list);
	spin_unlock(&tp->lock);
}

/*flower tmplt创建*/
static int fl_hw_create_tmplt(struct tcf_chain *chain/*从属的chain*/,
			      struct fl_flow_tmplt *tmplt)
{
	struct flow_cls_offload cls_flower = {};
	struct tcf_block *block = chain->block;/*取chain对应的block*/

	cls_flower.rule = flow_rule_alloc(0);
	if (!cls_flower.rule)
		return -ENOMEM;

	cls_flower.common.chain_index = chain->index;
	cls_flower.command = FLOW_CLS_TMPLT_CREATE;/*flower模块创建*/
	cls_flower.cookie = (unsigned long) tmplt;/*用tmplt地址指定cookie*/
	cls_flower.rule->match.dissector = &tmplt->dissector;
	cls_flower.rule->match.mask = &tmplt->mask;
	cls_flower.rule->match.key = &tmplt->dummy_key;

	/* We don't care if driver (any of them) fails to handle this
	 * call. It serves just as a hint for it.
	 */
	tc_setup_cb_call(block, TC_SETUP_CLSFLOWER, &cls_flower, false, true);/*触发回调，创建flower*/
	kfree(cls_flower.rule);

	return 0;
}

/*flower tmplt删除*/
static void fl_hw_destroy_tmplt(struct tcf_chain *chain,
				struct fl_flow_tmplt *tmplt)
{
	struct flow_cls_offload cls_flower = {};
	struct tcf_block *block = chain->block;

	cls_flower.common.chain_index = chain->index;
	cls_flower.command = FLOW_CLS_TMPLT_DESTROY;
	cls_flower.cookie = (unsigned long) tmplt;

	tc_setup_cb_call(block, TC_SETUP_CLSFLOWER, &cls_flower, false, true);
}

//通过tca创建tmplt
static void *fl_tmplt_create(struct net *net, struct tcf_chain *chain,
			     struct nlattr **tca,
			     struct netlink_ext_ack *extack)
{
	struct fl_flow_tmplt *tmplt;
	struct nlattr **tb;
	int err;

	/*必须指明options*/
	if (!tca[TCA_OPTIONS])
		return ERR_PTR(-EINVAL);

	/*解析options*/
	tb = kcalloc(TCA_FLOWER_MAX + 1, sizeof(struct nlattr *), GFP_KERNEL);
	if (!tb)
		return ERR_PTR(-ENOBUFS);
	err = nla_parse_nested_deprecated(tb, TCA_FLOWER_MAX,
					  tca[TCA_OPTIONS], fl_policy, NULL);
	if (err)
		goto errout_tb;

	tmplt = kzalloc(sizeof(*tmplt), GFP_KERNEL);
	if (!tmplt) {
		err = -ENOMEM;
		goto errout_tb;
	}

	//解析tb，填充key,mask
	tmplt->chain = chain;
	err = fl_set_key(net, tb, &tmplt->dummy_key, &tmplt->mask, extack);
	if (err)
		goto errout_tmplt;

	//填充dissector
	fl_init_dissector(&tmplt->dissector, &tmplt->mask);

	//在hw中创建tmplt
	err = fl_hw_create_tmplt(chain, tmplt);
	if (err)
		goto errout_tmplt;

	kfree(tb);
	return tmplt;

errout_tmplt:
	kfree(tmplt);
errout_tb:
	kfree(tb);
	return ERR_PTR(err);
}

static void fl_tmplt_destroy(void *tmplt_priv)
{
	struct fl_flow_tmplt *tmplt = tmplt_priv;

	fl_hw_destroy_tmplt(tmplt->chain, tmplt);
	kfree(tmplt);
}

static int fl_dump_key_val(struct sk_buff *skb,
			   void *val, int val_type,
			   void *mask, int mask_type, int len)
{
	int err;

	if (!memchr_inv(mask, 0, len))
		return 0;
	err = nla_put(skb, val_type, len, val);
	if (err)
		return err;
	if (mask_type != TCA_FLOWER_UNSPEC) {
		err = nla_put(skb, mask_type, len, mask);
		if (err)
			return err;
	}
	return 0;
}

static int fl_dump_key_port_range(struct sk_buff *skb, struct fl_flow_key *key,
				  struct fl_flow_key *mask)
{
	if (fl_dump_key_val(skb, &key->tp_range.tp_min.dst,
			    TCA_FLOWER_KEY_PORT_DST_MIN,
			    &mask->tp_range.tp_min.dst, TCA_FLOWER_UNSPEC,
			    sizeof(key->tp_range.tp_min.dst)) ||
	    fl_dump_key_val(skb, &key->tp_range.tp_max.dst,
			    TCA_FLOWER_KEY_PORT_DST_MAX,
			    &mask->tp_range.tp_max.dst, TCA_FLOWER_UNSPEC,
			    sizeof(key->tp_range.tp_max.dst)) ||
	    fl_dump_key_val(skb, &key->tp_range.tp_min.src,
			    TCA_FLOWER_KEY_PORT_SRC_MIN,
			    &mask->tp_range.tp_min.src, TCA_FLOWER_UNSPEC,
			    sizeof(key->tp_range.tp_min.src)) ||
	    fl_dump_key_val(skb, &key->tp_range.tp_max.src,
			    TCA_FLOWER_KEY_PORT_SRC_MAX,
			    &mask->tp_range.tp_max.src, TCA_FLOWER_UNSPEC,
			    sizeof(key->tp_range.tp_max.src)))
		return -1;

	return 0;
}

static int fl_dump_key_mpls_opt_lse(struct sk_buff *skb,
				    struct flow_dissector_key_mpls *mpls_key,
				    struct flow_dissector_key_mpls *mpls_mask,
				    u8 lse_index)
{
	struct flow_dissector_mpls_lse *lse_mask = &mpls_mask->ls[lse_index];
	struct flow_dissector_mpls_lse *lse_key = &mpls_key->ls[lse_index];
	int err;

	err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH,
			 lse_index + 1);
	if (err)
		return err;

	if (lse_mask->mpls_ttl) {
		err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL,
				 lse_key->mpls_ttl);
		if (err)
			return err;
	}
	if (lse_mask->mpls_bos) {
		err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS,
				 lse_key->mpls_bos);
		if (err)
			return err;
	}
	if (lse_mask->mpls_tc) {
		err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_OPT_LSE_TC,
				 lse_key->mpls_tc);
		if (err)
			return err;
	}
	if (lse_mask->mpls_label) {
		err = nla_put_u32(skb, TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL,
				  lse_key->mpls_label);
		if (err)
			return err;
	}

	return 0;
}

static int fl_dump_key_mpls_opts(struct sk_buff *skb,
				 struct flow_dissector_key_mpls *mpls_key,
				 struct flow_dissector_key_mpls *mpls_mask)
{
	struct nlattr *opts;
	struct nlattr *lse;
	u8 lse_index;
	int err;

	opts = nla_nest_start(skb, TCA_FLOWER_KEY_MPLS_OPTS);
	if (!opts)
		return -EMSGSIZE;

	for (lse_index = 0; lse_index < FLOW_DIS_MPLS_MAX; lse_index++) {
		if (!(mpls_mask->used_lses & 1 << lse_index))
			continue;

		lse = nla_nest_start(skb, TCA_FLOWER_KEY_MPLS_OPTS_LSE);
		if (!lse) {
			err = -EMSGSIZE;
			goto err_opts;
		}

		err = fl_dump_key_mpls_opt_lse(skb, mpls_key, mpls_mask,
					       lse_index);
		if (err)
			goto err_opts_lse;
		nla_nest_end(skb, lse);
	}
	nla_nest_end(skb, opts);

	return 0;

err_opts_lse:
	nla_nest_cancel(skb, lse);
err_opts:
	nla_nest_cancel(skb, opts);

	return err;
}

static int fl_dump_key_mpls(struct sk_buff *skb,
			    struct flow_dissector_key_mpls *mpls_key,
			    struct flow_dissector_key_mpls *mpls_mask)
{
	struct flow_dissector_mpls_lse *lse_mask;
	struct flow_dissector_mpls_lse *lse_key;
	int err;

	if (!mpls_mask->used_lses)
		return 0;

	lse_mask = &mpls_mask->ls[0];
	lse_key = &mpls_key->ls[0];

	/* For backward compatibility, don't use the MPLS nested attributes if
	 * the rule can be expressed using the old attributes.
	 */
	if (mpls_mask->used_lses & ~1 ||
	    (!lse_mask->mpls_ttl && !lse_mask->mpls_bos &&
	     !lse_mask->mpls_tc && !lse_mask->mpls_label))
		return fl_dump_key_mpls_opts(skb, mpls_key, mpls_mask);

	if (lse_mask->mpls_ttl) {
		err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_TTL,
				 lse_key->mpls_ttl);
		if (err)
			return err;
	}
	if (lse_mask->mpls_tc) {
		err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_TC,
				 lse_key->mpls_tc);
		if (err)
			return err;
	}
	if (lse_mask->mpls_label) {
		err = nla_put_u32(skb, TCA_FLOWER_KEY_MPLS_LABEL,
				  lse_key->mpls_label);
		if (err)
			return err;
	}
	if (lse_mask->mpls_bos) {
		err = nla_put_u8(skb, TCA_FLOWER_KEY_MPLS_BOS,
				 lse_key->mpls_bos);
		if (err)
			return err;
	}
	return 0;
}

static int fl_dump_key_ip(struct sk_buff *skb, bool encap,
			  struct flow_dissector_key_ip *key,
			  struct flow_dissector_key_ip *mask)
{
	int tos_key = encap ? TCA_FLOWER_KEY_ENC_IP_TOS : TCA_FLOWER_KEY_IP_TOS;
	int ttl_key = encap ? TCA_FLOWER_KEY_ENC_IP_TTL : TCA_FLOWER_KEY_IP_TTL;
	int tos_mask = encap ? TCA_FLOWER_KEY_ENC_IP_TOS_MASK : TCA_FLOWER_KEY_IP_TOS_MASK;
	int ttl_mask = encap ? TCA_FLOWER_KEY_ENC_IP_TTL_MASK : TCA_FLOWER_KEY_IP_TTL_MASK;

	if (fl_dump_key_val(skb, &key->tos, tos_key, &mask->tos, tos_mask, sizeof(key->tos)) ||
	    fl_dump_key_val(skb, &key->ttl, ttl_key, &mask->ttl, ttl_mask, sizeof(key->ttl)))
		return -1;

	return 0;
}

static int fl_dump_key_vlan(struct sk_buff *skb,
			    int vlan_id_key, int vlan_prio_key,
			    struct flow_dissector_key_vlan *vlan_key,
			    struct flow_dissector_key_vlan *vlan_mask)
{
	int err;

	if (!memchr_inv(vlan_mask, 0, sizeof(*vlan_mask)))
		return 0;
	if (vlan_mask->vlan_id) {
		err = nla_put_u16(skb, vlan_id_key,
				  vlan_key->vlan_id);
		if (err)
			return err;
	}
	if (vlan_mask->vlan_priority) {
		err = nla_put_u8(skb, vlan_prio_key,
				 vlan_key->vlan_priority);
		if (err)
			return err;
	}
	return 0;
}

static void fl_get_key_flag(u32 dissector_key, u32 dissector_mask,
			    u32 *flower_key, u32 *flower_mask,
			    u32 flower_flag_bit, u32 dissector_flag_bit)
{
	if (dissector_mask & dissector_flag_bit) {
		*flower_mask |= flower_flag_bit;
		if (dissector_key & dissector_flag_bit)
			*flower_key |= flower_flag_bit;
	}
}

static int fl_dump_key_flags(struct sk_buff *skb, u32 flags_key, u32 flags_mask)
{
	u32 key, mask;
	__be32 _key, _mask;
	int err;

	if (!memchr_inv(&flags_mask, 0, sizeof(flags_mask)))
		return 0;

	key = 0;
	mask = 0;

	fl_get_key_flag(flags_key, flags_mask, &key, &mask,
			TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT, FLOW_DIS_IS_FRAGMENT);
	fl_get_key_flag(flags_key, flags_mask, &key, &mask,
			TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST,
			FLOW_DIS_FIRST_FRAG);

	_key = cpu_to_be32(key);
	_mask = cpu_to_be32(mask);

	err = nla_put(skb, TCA_FLOWER_KEY_FLAGS, 4, &_key);
	if (err)
		return err;

	return nla_put(skb, TCA_FLOWER_KEY_FLAGS_MASK, 4, &_mask);
}

static int fl_dump_key_geneve_opt(struct sk_buff *skb,
				  struct flow_dissector_key_enc_opts *enc_opts)
{
	struct geneve_opt *opt;
	struct nlattr *nest;
	int opt_off = 0;

	nest = nla_nest_start_noflag(skb, TCA_FLOWER_KEY_ENC_OPTS_GENEVE);
	if (!nest)
		goto nla_put_failure;

	while (enc_opts->len > opt_off) {
		opt = (struct geneve_opt *)&enc_opts->data[opt_off];

		if (nla_put_be16(skb, TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS,
				 opt->opt_class))
			goto nla_put_failure;
		if (nla_put_u8(skb, TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE,
			       opt->type))
			goto nla_put_failure;
		if (nla_put(skb, TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA,
			    opt->length * 4, opt->opt_data))
			goto nla_put_failure;

		opt_off += sizeof(struct geneve_opt) + opt->length * 4;
	}
	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int fl_dump_key_vxlan_opt(struct sk_buff *skb,
				 struct flow_dissector_key_enc_opts *enc_opts)
{
	struct vxlan_metadata *md;
	struct nlattr *nest;

	nest = nla_nest_start_noflag(skb, TCA_FLOWER_KEY_ENC_OPTS_VXLAN);
	if (!nest)
		goto nla_put_failure;

	md = (struct vxlan_metadata *)&enc_opts->data[0];
	if (nla_put_u32(skb, TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP, md->gbp))
		goto nla_put_failure;

	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int fl_dump_key_erspan_opt(struct sk_buff *skb,
				  struct flow_dissector_key_enc_opts *enc_opts)
{
	struct erspan_metadata *md;
	struct nlattr *nest;

	nest = nla_nest_start_noflag(skb, TCA_FLOWER_KEY_ENC_OPTS_ERSPAN);
	if (!nest)
		goto nla_put_failure;

	md = (struct erspan_metadata *)&enc_opts->data[0];
	if (nla_put_u8(skb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER, md->version))
		goto nla_put_failure;

	if (md->version == 1 &&
	    nla_put_be32(skb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX, md->u.index))
		goto nla_put_failure;

	if (md->version == 2 &&
	    (nla_put_u8(skb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR,
			md->u.md2.dir) ||
	     nla_put_u8(skb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID,
			get_hwid(&md->u.md2))))
		goto nla_put_failure;

	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int fl_dump_key_ct(struct sk_buff *skb,
			  struct flow_dissector_key_ct *key,
			  struct flow_dissector_key_ct *mask)
{
	if (IS_ENABLED(CONFIG_NF_CONNTRACK) &&
	    fl_dump_key_val(skb, &key->ct_state, TCA_FLOWER_KEY_CT_STATE,
			    &mask->ct_state, TCA_FLOWER_KEY_CT_STATE_MASK,
			    sizeof(key->ct_state)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_ZONES) &&
	    fl_dump_key_val(skb, &key->ct_zone, TCA_FLOWER_KEY_CT_ZONE,
			    &mask->ct_zone, TCA_FLOWER_KEY_CT_ZONE_MASK,
			    sizeof(key->ct_zone)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_MARK) &&
	    fl_dump_key_val(skb, &key->ct_mark, TCA_FLOWER_KEY_CT_MARK,
			    &mask->ct_mark, TCA_FLOWER_KEY_CT_MARK_MASK,
			    sizeof(key->ct_mark)))
		goto nla_put_failure;

	if (IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS) &&
	    fl_dump_key_val(skb, &key->ct_labels, TCA_FLOWER_KEY_CT_LABELS,
			    &mask->ct_labels, TCA_FLOWER_KEY_CT_LABELS_MASK,
			    sizeof(key->ct_labels)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static int fl_dump_key_options(struct sk_buff *skb, int enc_opt_type,
			       struct flow_dissector_key_enc_opts *enc_opts)
{
	struct nlattr *nest;
	int err;

	if (!enc_opts->len)
		return 0;

	nest = nla_nest_start_noflag(skb, enc_opt_type);
	if (!nest)
		goto nla_put_failure;

	switch (enc_opts->dst_opt_type) {
	case TUNNEL_GENEVE_OPT:
		err = fl_dump_key_geneve_opt(skb, enc_opts);
		if (err)
			goto nla_put_failure;
		break;
	case TUNNEL_VXLAN_OPT:
		err = fl_dump_key_vxlan_opt(skb, enc_opts);
		if (err)
			goto nla_put_failure;
		break;
	case TUNNEL_ERSPAN_OPT:
		err = fl_dump_key_erspan_opt(skb, enc_opts);
		if (err)
			goto nla_put_failure;
		break;
	default:
		goto nla_put_failure;
	}
	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int fl_dump_key_enc_opt(struct sk_buff *skb,
			       struct flow_dissector_key_enc_opts *key_opts,
			       struct flow_dissector_key_enc_opts *msk_opts)
{
	int err;

	err = fl_dump_key_options(skb, TCA_FLOWER_KEY_ENC_OPTS, key_opts);
	if (err)
		return err;

	return fl_dump_key_options(skb, TCA_FLOWER_KEY_ENC_OPTS_MASK, msk_opts);
}

/*将flower的key,mask存入到skb中*/
static int fl_dump_key(struct sk_buff *skb, struct net *net,
		       struct fl_flow_key *key, struct fl_flow_key *mask)
{
	if (mask->meta.ingress_ifindex) {
		struct net_device *dev;

		dev = __dev_get_by_index(net, key->meta.ingress_ifindex);
		if (dev && nla_put_string(skb, TCA_FLOWER_INDEV, dev->name))
			goto nla_put_failure;
	}

	if (fl_dump_key_val(skb, key->eth.dst, TCA_FLOWER_KEY_ETH_DST,
			    mask->eth.dst, TCA_FLOWER_KEY_ETH_DST_MASK,
			    sizeof(key->eth.dst)) ||
	    fl_dump_key_val(skb, key->eth.src, TCA_FLOWER_KEY_ETH_SRC,
			    mask->eth.src, TCA_FLOWER_KEY_ETH_SRC_MASK,
			    sizeof(key->eth.src)) ||
	    fl_dump_key_val(skb, &key->basic.n_proto, TCA_FLOWER_KEY_ETH_TYPE,
			    &mask->basic.n_proto, TCA_FLOWER_UNSPEC,
			    sizeof(key->basic.n_proto)))
		goto nla_put_failure;

	if (fl_dump_key_mpls(skb, &key->mpls, &mask->mpls))
		goto nla_put_failure;

	if (fl_dump_key_vlan(skb, TCA_FLOWER_KEY_VLAN_ID,
			     TCA_FLOWER_KEY_VLAN_PRIO, &key->vlan, &mask->vlan))
		goto nla_put_failure;

	if (fl_dump_key_vlan(skb, TCA_FLOWER_KEY_CVLAN_ID,
			     TCA_FLOWER_KEY_CVLAN_PRIO,
			     &key->cvlan, &mask->cvlan) ||
	    (mask->cvlan.vlan_tpid &&
	     nla_put_be16(skb, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
			  key->cvlan.vlan_tpid)))
		goto nla_put_failure;

	if (mask->basic.n_proto) {
		if (mask->cvlan.vlan_tpid) {
			if (nla_put_be16(skb, TCA_FLOWER_KEY_CVLAN_ETH_TYPE,
					 key->basic.n_proto))
				goto nla_put_failure;
		} else if (mask->vlan.vlan_tpid) {
			if (nla_put_be16(skb, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
					 key->basic.n_proto))
				goto nla_put_failure;
		}
	}

	if ((key->basic.n_proto == htons(ETH_P_IP) ||
	     key->basic.n_proto == htons(ETH_P_IPV6)) &&
	    (fl_dump_key_val(skb, &key->basic.ip_proto, TCA_FLOWER_KEY_IP_PROTO,
			    &mask->basic.ip_proto, TCA_FLOWER_UNSPEC,
			    sizeof(key->basic.ip_proto)) ||
	    fl_dump_key_ip(skb, false, &key->ip, &mask->ip)))
		goto nla_put_failure;

	if (key->control.addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    (fl_dump_key_val(skb, &key->ipv4.src, TCA_FLOWER_KEY_IPV4_SRC,
			     &mask->ipv4.src, TCA_FLOWER_KEY_IPV4_SRC_MASK,
			     sizeof(key->ipv4.src)) ||
	     fl_dump_key_val(skb, &key->ipv4.dst, TCA_FLOWER_KEY_IPV4_DST,
			     &mask->ipv4.dst, TCA_FLOWER_KEY_IPV4_DST_MASK,
			     sizeof(key->ipv4.dst))))
		goto nla_put_failure;
	else if (key->control.addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		 (fl_dump_key_val(skb, &key->ipv6.src, TCA_FLOWER_KEY_IPV6_SRC,
				  &mask->ipv6.src, TCA_FLOWER_KEY_IPV6_SRC_MASK,
				  sizeof(key->ipv6.src)) ||
		  fl_dump_key_val(skb, &key->ipv6.dst, TCA_FLOWER_KEY_IPV6_DST,
				  &mask->ipv6.dst, TCA_FLOWER_KEY_IPV6_DST_MASK,
				  sizeof(key->ipv6.dst))))
		goto nla_put_failure;

	if (key->basic.ip_proto == IPPROTO_TCP &&
	    (fl_dump_key_val(skb, &key->tp.src, TCA_FLOWER_KEY_TCP_SRC,
			     &mask->tp.src, TCA_FLOWER_KEY_TCP_SRC_MASK,
			     sizeof(key->tp.src)) ||
	     fl_dump_key_val(skb, &key->tp.dst, TCA_FLOWER_KEY_TCP_DST,
			     &mask->tp.dst, TCA_FLOWER_KEY_TCP_DST_MASK,
			     sizeof(key->tp.dst)) ||
	     fl_dump_key_val(skb, &key->tcp.flags, TCA_FLOWER_KEY_TCP_FLAGS,
			     &mask->tcp.flags, TCA_FLOWER_KEY_TCP_FLAGS_MASK,
			     sizeof(key->tcp.flags))))
		goto nla_put_failure;
	else if (key->basic.ip_proto == IPPROTO_UDP &&
		 (fl_dump_key_val(skb, &key->tp.src, TCA_FLOWER_KEY_UDP_SRC,
				  &mask->tp.src, TCA_FLOWER_KEY_UDP_SRC_MASK,
				  sizeof(key->tp.src)) ||
		  fl_dump_key_val(skb, &key->tp.dst, TCA_FLOWER_KEY_UDP_DST,
				  &mask->tp.dst, TCA_FLOWER_KEY_UDP_DST_MASK,
				  sizeof(key->tp.dst))))
		goto nla_put_failure;
	else if (key->basic.ip_proto == IPPROTO_SCTP &&
		 (fl_dump_key_val(skb, &key->tp.src, TCA_FLOWER_KEY_SCTP_SRC,
				  &mask->tp.src, TCA_FLOWER_KEY_SCTP_SRC_MASK,
				  sizeof(key->tp.src)) ||
		  fl_dump_key_val(skb, &key->tp.dst, TCA_FLOWER_KEY_SCTP_DST,
				  &mask->tp.dst, TCA_FLOWER_KEY_SCTP_DST_MASK,
				  sizeof(key->tp.dst))))
		goto nla_put_failure;
	else if (key->basic.n_proto == htons(ETH_P_IP) &&
		 key->basic.ip_proto == IPPROTO_ICMP &&
		 (fl_dump_key_val(skb, &key->icmp.type,
				  TCA_FLOWER_KEY_ICMPV4_TYPE, &mask->icmp.type,
				  TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,
				  sizeof(key->icmp.type)) ||
		  fl_dump_key_val(skb, &key->icmp.code,
				  TCA_FLOWER_KEY_ICMPV4_CODE, &mask->icmp.code,
				  TCA_FLOWER_KEY_ICMPV4_CODE_MASK,
				  sizeof(key->icmp.code))))
		goto nla_put_failure;
	else if (key->basic.n_proto == htons(ETH_P_IPV6) &&
		 key->basic.ip_proto == IPPROTO_ICMPV6 &&
		 (fl_dump_key_val(skb, &key->icmp.type,
				  TCA_FLOWER_KEY_ICMPV6_TYPE, &mask->icmp.type,
				  TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,
				  sizeof(key->icmp.type)) ||
		  fl_dump_key_val(skb, &key->icmp.code,
				  TCA_FLOWER_KEY_ICMPV6_CODE, &mask->icmp.code,
				  TCA_FLOWER_KEY_ICMPV6_CODE_MASK,
				  sizeof(key->icmp.code))))
		goto nla_put_failure;
	else if ((key->basic.n_proto == htons(ETH_P_ARP) ||
		  key->basic.n_proto == htons(ETH_P_RARP)) &&
		 (fl_dump_key_val(skb, &key->arp.sip,
				  TCA_FLOWER_KEY_ARP_SIP, &mask->arp.sip,
				  TCA_FLOWER_KEY_ARP_SIP_MASK,
				  sizeof(key->arp.sip)) ||
		  fl_dump_key_val(skb, &key->arp.tip,
				  TCA_FLOWER_KEY_ARP_TIP, &mask->arp.tip,
				  TCA_FLOWER_KEY_ARP_TIP_MASK,
				  sizeof(key->arp.tip)) ||
		  fl_dump_key_val(skb, &key->arp.op,
				  TCA_FLOWER_KEY_ARP_OP, &mask->arp.op,
				  TCA_FLOWER_KEY_ARP_OP_MASK,
				  sizeof(key->arp.op)) ||
		  fl_dump_key_val(skb, key->arp.sha, TCA_FLOWER_KEY_ARP_SHA,
				  mask->arp.sha, TCA_FLOWER_KEY_ARP_SHA_MASK,
				  sizeof(key->arp.sha)) ||
		  fl_dump_key_val(skb, key->arp.tha, TCA_FLOWER_KEY_ARP_THA,
				  mask->arp.tha, TCA_FLOWER_KEY_ARP_THA_MASK,
				  sizeof(key->arp.tha))))
		goto nla_put_failure;

	if ((key->basic.ip_proto == IPPROTO_TCP ||
	     key->basic.ip_proto == IPPROTO_UDP ||
	     key->basic.ip_proto == IPPROTO_SCTP) &&
	     fl_dump_key_port_range(skb, key, mask))
		goto nla_put_failure;

	if (key->enc_control.addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    (fl_dump_key_val(skb, &key->enc_ipv4.src,
			    TCA_FLOWER_KEY_ENC_IPV4_SRC, &mask->enc_ipv4.src,
			    TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
			    sizeof(key->enc_ipv4.src)) ||
	     fl_dump_key_val(skb, &key->enc_ipv4.dst,
			     TCA_FLOWER_KEY_ENC_IPV4_DST, &mask->enc_ipv4.dst,
			     TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
			     sizeof(key->enc_ipv4.dst))))
		goto nla_put_failure;
	else if (key->enc_control.addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		 (fl_dump_key_val(skb, &key->enc_ipv6.src,
			    TCA_FLOWER_KEY_ENC_IPV6_SRC, &mask->enc_ipv6.src,
			    TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
			    sizeof(key->enc_ipv6.src)) ||
		 fl_dump_key_val(skb, &key->enc_ipv6.dst,
				 TCA_FLOWER_KEY_ENC_IPV6_DST,
				 &mask->enc_ipv6.dst,
				 TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,
			    sizeof(key->enc_ipv6.dst))))
		goto nla_put_failure;

	if (fl_dump_key_val(skb, &key->enc_key_id, TCA_FLOWER_KEY_ENC_KEY_ID,
			    &mask->enc_key_id, TCA_FLOWER_UNSPEC,
			    sizeof(key->enc_key_id)) ||
	    fl_dump_key_val(skb, &key->enc_tp.src,
			    TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,
			    &mask->enc_tp.src,
			    TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,
			    sizeof(key->enc_tp.src)) ||
	    fl_dump_key_val(skb, &key->enc_tp.dst,
			    TCA_FLOWER_KEY_ENC_UDP_DST_PORT,
			    &mask->enc_tp.dst,
			    TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,
			    sizeof(key->enc_tp.dst)) ||
	    fl_dump_key_ip(skb, true, &key->enc_ip, &mask->enc_ip) ||
	    fl_dump_key_enc_opt(skb, &key->enc_opts, &mask->enc_opts))
		goto nla_put_failure;

	if (fl_dump_key_ct(skb, &key->ct, &mask->ct))
		goto nla_put_failure;

	if (fl_dump_key_flags(skb, key->control.flags, mask->control.flags))
		goto nla_put_failure;

	if (fl_dump_key_val(skb, &key->hash.hash, TCA_FLOWER_KEY_HASH,
			     &mask->hash.hash, TCA_FLOWER_KEY_HASH_MASK,
			     sizeof(key->hash.hash)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

/*flower filter规则dump*/
static int fl_dump(struct net *net, struct tcf_proto *tp/*待dump的filter*/, void *fh/*待封装的flower filter规则*/,
		   struct sk_buff *skb/*待填充的filter*/, struct tcmsg *t, bool rtnl_held)
{
	struct cls_fl_filter *f = fh;
	struct nlattr *nest;
	struct fl_flow_key *key, *mask;
	bool skip_hw;

	if (!f)
		return skb->len;

	t->tcm_handle = f->handle;

	/*flower内容将做为options存放*/
	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	spin_lock(&tp->lock);

	/*存放classid*/
	if (f->res.classid &&
	    nla_put_u32(skb, TCA_FLOWER_CLASSID, f->res.classid))
		goto nla_put_failure_locked;

	/*存入key,mask*/
	key = &f->key;
	mask = &f->mask->key;
	skip_hw = tc_skip_hw(f->flags);

	if (fl_dump_key(skb, net, key, mask))
		goto nla_put_failure_locked;

	/*存入flower的标记*/
	if (f->flags && nla_put_u32(skb, TCA_FLOWER_FLAGS, f->flags))
		goto nla_put_failure_locked;

	spin_unlock(&tp->lock);

	/*更新硬件统计信息*/
	if (!skip_hw)
		fl_hw_update_stats(tp, f, rtnl_held);

	if (nla_put_u32(skb, TCA_FLOWER_IN_HW_COUNT, f->in_hw_count))
		goto nla_put_failure;

	/*dump flower对应的actions*/
	if (tcf_exts_dump(skb, &f->exts))
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	/*dump flower的状态信息*/
	if (tcf_exts_dump_stats(skb, &f->exts) < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure_locked:
	spin_unlock(&tp->lock);
nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static int fl_terse_dump(struct net *net, struct tcf_proto *tp, void *fh,
			 struct sk_buff *skb, struct tcmsg *t, bool rtnl_held)
{
	struct cls_fl_filter *f = fh;
	struct nlattr *nest;
	bool skip_hw;

	if (!f)
		return skb->len;

	t->tcm_handle = f->handle;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	spin_lock(&tp->lock);

	skip_hw = tc_skip_hw(f->flags);

	if (f->flags && nla_put_u32(skb, TCA_FLOWER_FLAGS, f->flags))
		goto nla_put_failure_locked;

	spin_unlock(&tp->lock);

	if (!skip_hw)
		fl_hw_update_stats(tp, f, rtnl_held);

	if (tcf_exts_terse_dump(skb, &f->exts))
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	return skb->len;

nla_put_failure_locked:
	spin_unlock(&tp->lock);
nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static int fl_tmplt_dump(struct sk_buff *skb, struct net *net, void *tmplt_priv)
{
	struct fl_flow_tmplt *tmplt = tmplt_priv;
	struct fl_flow_key *key, *mask;
	struct nlattr *nest;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	key = &tmplt->dummy_key;
	mask = &tmplt->mask;

	if (fl_dump_key(skb, net, key, mask))
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static void fl_bind_class(void *fh, u32 classid, unsigned long cl, void *q,
			  unsigned long base)
{
	struct cls_fl_filter *f = fh;

	if (f && f->res.classid == classid) {
		if (cl)
			__tcf_bind_filter(q, &f->res, base);
		else
			__tcf_unbind_filter(q, &f->res);
	}
}

static bool fl_delete_empty(struct tcf_proto *tp)
{
	struct cls_fl_head *head = fl_head_dereference(tp);

	spin_lock(&tp->lock);
	tp->deleting = idr_is_empty(&head->handle_idr);
	spin_unlock(&tp->lock);

	return tp->deleting;
}

//注册flower关键字对应的ops
static struct tcf_proto_ops cls_fl_ops __read_mostly = {
	.kind		= "flower",
	//执行flower规则匹配
	.classify	= fl_classify,
	.init		= fl_init,
	.destroy	= fl_destroy,
	//通过handle找对应的元素
	.get		= fl_get,
	.put		= fl_put,
	//添加或修改flower规则，并触发向硬件下发
	.change		= fl_change,
	//移除flower规则
	.delete		= fl_delete,
	.delete_empty	= fl_delete_empty,
	.walk		= fl_walk,
	//在次向硬件中下发某条规则
	.reoffload	= fl_reoffload,
	.hw_add		= fl_hw_add,
	.hw_del		= fl_hw_del,
	.dump		= fl_dump,/*dump一条给定的规则*/
	.terse_dump	= fl_terse_dump,
	.bind_class	= fl_bind_class,
	.tmplt_create	= fl_tmplt_create,
	.tmplt_destroy	= fl_tmplt_destroy,
	.tmplt_dump	= fl_tmplt_dump,
	.owner		= THIS_MODULE,
	.flags		= TCF_PROTO_OPS_DOIT_UNLOCKED,
};

//注册flower关键字对应的分类器ops
static int __init cls_fl_init(void)
{
	return register_tcf_proto_ops(&cls_fl_ops);
}

static void __exit cls_fl_exit(void)
{
	unregister_tcf_proto_ops(&cls_fl_ops);
}

module_init(cls_fl_init);
module_exit(cls_fl_exit);

MODULE_AUTHOR("Jiri Pirko <jiri@resnulli.us>");
MODULE_DESCRIPTION("Flower classifier");
MODULE_LICENSE("GPL v2");
