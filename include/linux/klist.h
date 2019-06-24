/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *	klist.h - Some generic list helpers, extending struct list_head a bit.
 *
 *	Implementations are found in lib/klist.c
 *
 *	Copyright (C) 2005 Patrick Mochel
 */

#ifndef _LINUX_KLIST_H
#define _LINUX_KLIST_H

#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/list.h>

struct klist_node;
//通过list_head来产现klist,与list_head相同，此实现仅为一个链表
//与list_head不同，存放在list中的元素通过get,put函数会增加减少每个
//元素的引用计数，不会出现被误删除的情况
struct klist {
	spinlock_t		k_lock;
	struct list_head	k_list;
	//增加元素引用
	void			(*get)(struct klist_node *);
	//释放元素引用
	void			(*put)(struct klist_node *);
} __attribute__ ((aligned (sizeof(void *))));

#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)

extern void klist_init(struct klist *k, void (*get)(struct klist_node *),
		       void (*put)(struct klist_node *));

struct klist_node {
	void			*n_klist;	/* never access directly */
	struct list_head	n_node;
	struct kref		n_ref;
};

extern void klist_add_tail(struct klist_node *n, struct klist *k);
extern void klist_add_head(struct klist_node *n, struct klist *k);
extern void klist_add_behind(struct klist_node *n, struct klist_node *pos);
extern void klist_add_before(struct klist_node *n, struct klist_node *pos);

extern void klist_del(struct klist_node *n);
extern void klist_remove(struct klist_node *n);

extern int klist_node_attached(struct klist_node *n);


struct klist_iter {
	struct klist		*i_klist;//遍历的链表
	struct klist_node	*i_cur;//当前指向哪个位置
};


extern void klist_iter_init(struct klist *k, struct klist_iter *i);
extern void klist_iter_init_node(struct klist *k, struct klist_iter *i,
				 struct klist_node *n);
extern void klist_iter_exit(struct klist_iter *i);
extern struct klist_node *klist_prev(struct klist_iter *i);
extern struct klist_node *klist_next(struct klist_iter *i);

#endif
