/* Structure dynamic extension infrastructure
 * Copyright (C) 2004 Rusty Russell IBM Corporation
 * Copyright (C) 2007 Netfilter Core Team <coreteam@netfilter.org>
 * Copyright (C) 2007 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_extend.h>

//连接跟踪的扩展类型
static struct nf_ct_ext_type __rcu *nf_ct_ext_types[NF_CT_EXT_NUM];
static DEFINE_MUTEX(nf_ct_ext_type_mutex);
#define NF_CT_EXT_PREALLOC	128u /* conntrack events are on by default */

//连接跟踪销毁时各扩展类型需要销毁（遍历并销毁）
void nf_ct_ext_destroy(struct nf_conn *ct)
{
	unsigned int i;
	struct nf_ct_ext_type *t;

	for (i = 0; i < NF_CT_EXT_NUM; i++) {
		rcu_read_lock();
		t = rcu_dereference(nf_ct_ext_types[i]);

		/* Here the nf_ct_ext_type might have been unregisterd.
		 * I.e., it has responsible to cleanup private
		 * area in all conntracks when it is unregisterd.
		 */
		if (t && t->destroy)
			t->destroy(ct);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(nf_ct_ext_destroy);

//在连接跟踪上创建扩展id需要的内存，并返回创建的内存指针
void *nf_ct_ext_add(struct nf_conn *ct, enum nf_ct_ext_id id, gfp_t gfp)
{
	unsigned int newlen, newoff, oldlen, alloc;
	struct nf_ct_ext *old, *new;
	struct nf_ct_ext_type *t;

	/* Conntrack must not be confirmed to avoid races on reallocation. */
	WARN_ON(nf_ct_is_confirmed(ct));

	old = ct->ext;

	if (old) {
		//此id已有扩展时直接返回NULL
		if (__nf_ct_ext_exist(old, id))
			return NULL;
		oldlen = old->len;
	} else {
		oldlen = sizeof(*new);
	}

	rcu_read_lock();
	t = rcu_dereference(nf_ct_ext_types[id]);//取此扩展
	if (!t) {
		rcu_read_unlock();
		return NULL;
	}

	//如果oldlen非０，则默认跟在旧的扩展后面，如果旧的扩展不存在，则默认在首位置
	newoff = ALIGN(oldlen, t->align);
	newlen = newoff + t->len;
	rcu_read_unlock();

	alloc = max(newlen, NF_CT_EXT_PREALLOC);
	kmemleak_not_leak(old);
	new = __krealloc(old, alloc, gfp);//扩大内存或者申请内存
	if (!new)
		return NULL;

	if (!old) {
		//首次创建offset全置为０
		memset(new->offset, 0, sizeof(new->offset));
		ct->ext = new;
	} else if (new != old) {
		//需要释放旧扩展内存
		kfree_rcu(old, rcu);
		rcu_assign_pointer(ct->ext, new);
	}

	//记录自已的
	new->offset[id] = newoff;//记录id扩展的内存位置
	new->len = newlen;//记录扩展长度
	memset((void *)new + newoff, 0, newlen - newoff);//初始化id扩展内存
	return (void *)new + newoff;//返回id扩展内存
}
EXPORT_SYMBOL(nf_ct_ext_add);

/* This MUST be called in process context. */
//连接跟踪扩展注册
int nf_ct_extend_register(const struct nf_ct_ext_type *type)
{
	int ret = 0;

	mutex_lock(&nf_ct_ext_type_mutex);
	if (nf_ct_ext_types[type->id]) {
		//扩展已注册，报错
		ret = -EBUSY;
		goto out;
	}

	rcu_assign_pointer(nf_ct_ext_types[type->id], type);
out:
	mutex_unlock(&nf_ct_ext_type_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_extend_register);

/* This MUST be called in process context. */
//扩展解注册
void nf_ct_extend_unregister(const struct nf_ct_ext_type *type)
{
	mutex_lock(&nf_ct_ext_type_mutex);
	RCU_INIT_POINTER(nf_ct_ext_types[type->id], NULL);
	mutex_unlock(&nf_ct_ext_type_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_ct_extend_unregister);
