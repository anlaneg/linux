/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMER_TYPES_H
#define _LINUX_TIMER_TYPES_H

#include <linux/lockdep_types.h>
#include <linux/types.h>

struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct hlist_node	entry;//用于挂在list上（双链表）
	unsigned long		expires;//过期时间
	void			(*function)(struct timer_list *);//timer回调函数
	u32			flags;/*指出timer标记，及所在cpu(低位包含timer初始化是对应的cpu id)*/

#ifdef CONFIG_LOCKDEP
	struct lockdep_map	lockdep_map;
#endif
};

#endif /* _LINUX_TIMER_TYPES_H */
