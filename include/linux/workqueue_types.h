/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WORKQUEUE_TYPES_H
#define _LINUX_WORKQUEUE_TYPES_H

#include <linux/atomic.h>
#include <linux/lockdep_types.h>
#include <linux/timer_types.h>
#include <linux/types.h>

struct workqueue_struct;

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
void delayed_work_timer_fn(struct timer_list *t);

struct work_struct {
	atomic_long_t data;//work函数func的参数（也包含标记位）
	struct list_head entry;//用于将work串起来
	work_func_t func;//work函数
#ifdef CONFIG_LOCKDEP
	struct lockdep_map lockdep_map;
#endif
};

#endif /* _LINUX_WORKQUEUE_TYPES_H */
