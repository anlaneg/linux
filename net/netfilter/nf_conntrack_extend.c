// SPDX-License-Identifier: GPL-2.0-or-later
/* Structure dynamic extension infrastructure
 * Copyright (C) 2004 Rusty Russell IBM Corporation
 * Copyright (C) 2007 Netfilter Core Team <coreteam@netfilter.org>
 * Copyright (C) 2007 USAGI/WIDE Project <http://www.linux-ipv6.org>
 */
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <net/netfilter/nf_conntrack_timeout.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#include <net/netfilter/nf_conntrack_act_ct.h>
#include <net/netfilter/nf_nat.h>

#define NF_CT_EXT_PREALLOC	128u /* conntrack events are on by default */

atomic_t nf_conntrack_ext_genid __read_mostly = ATOMIC_INIT(1);

static const u8 nf_ct_ext_type_len[NF_CT_EXT_NUM] = {
	[NF_CT_EXT_HELPER] = sizeof(struct nf_conn_help),
#if IS_ENABLED(CONFIG_NF_NAT)
	[NF_CT_EXT_NAT] = sizeof(struct nf_conn_nat),
#endif
	[NF_CT_EXT_SEQADJ] = sizeof(struct nf_conn_seqadj),
	[NF_CT_EXT_ACCT] = sizeof(struct nf_conn_acct),
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	[NF_CT_EXT_ECACHE] = sizeof(struct nf_conntrack_ecache),
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMESTAMP
	[NF_CT_EXT_TSTAMP] = sizeof(struct nf_conn_tstamp),
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMEOUT
	[NF_CT_EXT_TIMEOUT] = sizeof(struct nf_conn_timeout),
#endif
#ifdef CONFIG_NF_CONNTRACK_LABELS
	[NF_CT_EXT_LABELS] = sizeof(struct nf_conn_labels),
#endif
#if IS_ENABLED(CONFIG_NETFILTER_SYNPROXY)
	[NF_CT_EXT_SYNPROXY] = sizeof(struct nf_conn_synproxy),
#endif
#if IS_ENABLED(CONFIG_NET_ACT_CT)
	[NF_CT_EXT_ACT_CT] = sizeof(struct nf_conn_act_ct_ext),
#endif
};

static __always_inline unsigned int total_extension_size(void)
{
	/* remember to add new extensions below */
	BUILD_BUG_ON(NF_CT_EXT_NUM > 10);

	return sizeof(struct nf_ct_ext) +
	       sizeof(struct nf_conn_help)
#if IS_ENABLED(CONFIG_NF_NAT)
		+ sizeof(struct nf_conn_nat)
#endif
		+ sizeof(struct nf_conn_seqadj)
		+ sizeof(struct nf_conn_acct)
#ifdef CONFIG_NF_CONNTRACK_EVENTS
		+ sizeof(struct nf_conntrack_ecache)
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMESTAMP
		+ sizeof(struct nf_conn_tstamp)
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMEOUT
		+ sizeof(struct nf_conn_timeout)
#endif
#ifdef CONFIG_NF_CONNTRACK_LABELS
		+ sizeof(struct nf_conn_labels)
#endif
#if IS_ENABLED(CONFIG_NETFILTER_SYNPROXY)
		+ sizeof(struct nf_conn_synproxy)
#endif
#if IS_ENABLED(CONFIG_NET_ACT_CT)
		+ sizeof(struct nf_conn_act_ct_ext)
#endif
	;
}

//在连接跟踪上创建扩展id需要的内存，并返回创建的内存指针
void *nf_ct_ext_add(struct nf_conn *ct, enum nf_ct_ext_id id, gfp_t gfp)
{
	unsigned int newlen, newoff, oldlen, alloc;
	struct nf_ct_ext *new;

	/* Conntrack must not be confirmed to avoid races on reallocation. */
	WARN_ON(nf_ct_is_confirmed(ct));

	/* struct nf_ct_ext uses u8 to store offsets/size */
	BUILD_BUG_ON(total_extension_size() > 255u);

	if (ct->ext) {
		const struct nf_ct_ext *old = ct->ext;

		//此id已有扩展时直接返回NULL
		if (__nf_ct_ext_exist(old, id))
			return NULL;
		oldlen = old->len;
	} else {
		oldlen = sizeof(*new);
	}

	//如果oldlen非０，则默认跟在旧的扩展后面，如果旧的扩展不存在，则默认在首位置
	newoff = ALIGN(oldlen, __alignof__(struct nf_ct_ext));
	newlen = newoff + nf_ct_ext_type_len[id];

	alloc = max(newlen, NF_CT_EXT_PREALLOC);
	new = krealloc(ct->ext, alloc, gfp);//扩大内存或者申请内存
	if (!new)
		return NULL;

	if (!ct->ext) {
		//首次创建offset全置为０
		memset(new->offset, 0, sizeof(new->offset));
		new->gen_id = atomic_read(&nf_conntrack_ext_genid);
	}

	//记录自已的
	new->offset[id] = newoff;//记录id扩展的内存位置
	new->len = newlen;//记录扩展长度
	memset((void *)new + newoff, 0, newlen - newoff);//初始化id扩展内存

	ct->ext = new;
	return (void *)new + newoff;//返回id扩展内存
}
EXPORT_SYMBOL(nf_ct_ext_add);

/* Use nf_ct_ext_find wrapper. This is only useful for unconfirmed entries. */
void *__nf_ct_ext_find(const struct nf_ct_ext *ext, u8 id)
{
	unsigned int gen_id = atomic_read(&nf_conntrack_ext_genid);
	unsigned int this_id = READ_ONCE(ext->gen_id);

	if (!__nf_ct_ext_exist(ext, id))
		return NULL;

	if (this_id == 0 || ext->gen_id == gen_id)
		return (void *)ext + ext->offset[id];

	return NULL;
}
EXPORT_SYMBOL(__nf_ct_ext_find);

void nf_ct_ext_bump_genid(void)
{
	unsigned int value = atomic_inc_return(&nf_conntrack_ext_genid);

	if (value == UINT_MAX)
		atomic_set(&nf_conntrack_ext_genid, 1);

	msleep(HZ);
}
