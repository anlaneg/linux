/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMER_H
#define _LINUX_TIMER_H

#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/stddef.h>
#include <linux/debugobjects.h>
#include <linux/stringify.h>
#include <linux/timer_types.h>

#ifdef CONFIG_LOCKDEP
/*
 * NB: because we have to copy the lockdep_map, setting the lockdep_map key
 * (second argument) here is required, otherwise it could be initialised to
 * the copy of the lockdep_map later! We use the pointer to and the string
 * "<file>:<line>" as the key resp. the name of the lockdep_map.
 */
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#else
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)
#endif

/**
 * @TIMER_DEFERRABLE: A deferrable timer will work normally when the
 * system is busy, but will not cause a CPU to come out of idle just
 * to service it; instead, the timer will be serviced when the CPU
 * eventually wakes up with a subsequent non-deferrable timer.
 *
 * @TIMER_IRQSAFE: An irqsafe timer is executed with IRQ disabled and
 * it's safe to wait for the completion of the running instance from
 * IRQ handlers, for example, by calling del_timer_sync().
 *
 * Note: The irq disabled callback execution is a special case for
 * workqueue locking issues. It's not meant for executing random crap
 * with interrupts disabled. Abuse is monitored!
 *
 * @TIMER_PINNED: A pinned timer will not be affected by any timer
 * placement heuristics (like, NOHZ) and will always expire on the CPU
 * on which the timer was enqueued.
 *
 * Note: Because enqueuing of timers can migrate the timer from one
 * CPU to another, pinned timers are not guaranteed to stay on the
 * initialy selected CPU.  They move to the CPU on which the enqueue
 * function is invoked via mod_timer() or add_timer().  If the timer
 * should be placed on a particular CPU, then add_timer_on() has to be
 * used.
 */
#define TIMER_CPUMASK		0x0003FFFF /*timer flags利用低18位来表示cpu id*/
/*标记此timer正在迁移（被修改为在cpu间移动）*/
#define TIMER_MIGRATING		0x00040000
#define TIMER_BASEMASK		(TIMER_CPUMASK | TIMER_MIGRATING)
#define TIMER_DEFERRABLE	0x00080000
#define TIMER_PINNED		0x00100000
#define TIMER_IRQSAFE		0x00200000
#define TIMER_INIT_FLAGS	(TIMER_DEFERRABLE | TIMER_PINNED | TIMER_IRQSAFE)
/*timer flags利用高位标记指明自已所处的timer base index,
 * arrayshift即定义此数值在flags上的起始标记位*/
#define TIMER_ARRAYSHIFT	22
/*从TIMER_ARRAYSHIFT位开始，当前共有10位来表示timer base index
 * 由此可知WHEEL_SIZE不能超过 ((1<<11) -1)*/
#define TIMER_ARRAYMASK		0xFFC00000

#define TIMER_TRACE_FLAGMASK	(TIMER_MIGRATING | TIMER_DEFERRABLE | TIMER_PINNED | TIMER_IRQSAFE)

/*timer结构体初始化，设置timer flags及触发函数回调*/
#define __TIMER_INITIALIZER(_function, _flags) {		\
		.entry = { .next = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.flags = (_flags),				\
		__TIMER_LOCKDEP_MAP_INITIALIZER(FILE_LINE)	\
	}

/*定义名称为_name的timer，并设置其对应的触发函数*/
#define DEFINE_TIMER(_name, _function)				\
	struct timer_list _name =				\
		__TIMER_INITIALIZER(_function, 0)

/*
 * LOCKDEP and DEBUG timer interfaces.
 */
void init_timer_key(struct timer_list *timer,
		    void (*func)(struct timer_list *), unsigned int flags,
		    const char *name, struct lock_class_key *key);

#ifdef CONFIG_DEBUG_OBJECTS_TIMERS
extern void init_timer_on_stack_key(struct timer_list *timer,
				    void (*func)(struct timer_list *),
				    unsigned int flags, const char *name,
				    struct lock_class_key *key);
#else
static inline void init_timer_on_stack_key(struct timer_list *timer,
					   void (*func)(struct timer_list *),
					   unsigned int flags,
					   const char *name,
					   struct lock_class_key *key)
{
	init_timer_key(timer, func, flags, name, key);
}
#endif

#ifdef CONFIG_LOCKDEP
#define __init_timer(_timer, _fn, _flags)				\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_key((_timer), (_fn), (_flags), #_timer, &__key);\
	} while (0)

#define __init_timer_on_stack(_timer, _fn, _flags)			\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_on_stack_key((_timer), (_fn), (_flags),	\
					#_timer, &__key);		 \
	} while (0)
#else
#define __init_timer(_timer, _fn, _flags)				\
	init_timer_key((_timer), (_fn/*超时回调*/), (_flags), NULL, NULL)
#define __init_timer_on_stack(_timer, _fn, _flags)			\
	init_timer_on_stack_key((_timer), (_fn), (_flags), NULL, NULL)
#endif

/**
 * timer_setup - prepare a timer for first use
 * @timer: the timer in question
 * @callback: the function to call when timer expires
 * @flags: any TIMER_* flags
 *
 * Regular timer initialization should use either DEFINE_TIMER() above,
 * or timer_setup(). For timers on the stack, timer_setup_on_stack() must
 * be used and must be balanced with a call to destroy_timer_on_stack().
 */
//初始化一个timer
#define timer_setup(timer, callback/*超时回调*/, flags)			\
	__init_timer((timer), (callback), (flags))

#define timer_setup_on_stack(timer, callback, flags)		\
	__init_timer_on_stack((timer), (callback), (flags))

#ifdef CONFIG_DEBUG_OBJECTS_TIMERS
extern void destroy_timer_on_stack(struct timer_list *timer);
#else
static inline void destroy_timer_on_stack(struct timer_list *timer) { }
#endif

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

/**
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static inline int timer_pending(const struct timer_list * timer)
{
	/*如果此timer entry不为空，则其已被加入到系统*/
	return !hlist_unhashed_lockless(&timer->entry);
}

extern void add_timer_on(struct timer_list *timer, int cpu);
extern int mod_timer(struct timer_list *timer, unsigned long expires);
extern int mod_timer_pending(struct timer_list *timer, unsigned long expires);
extern int timer_reduce(struct timer_list *timer, unsigned long expires);

/*
 * The jiffies value which is added to now, when there is no timer
 * in the timer wheel:
 */
#define NEXT_TIMER_MAX_DELTA	((1UL << 30) - 1)

extern void add_timer(struct timer_list *timer);

extern int try_to_del_timer_sync(struct timer_list *timer);
extern int timer_delete_sync(struct timer_list *timer);
extern int timer_delete(struct timer_list *timer);
extern int timer_shutdown_sync(struct timer_list *timer);
extern int timer_shutdown(struct timer_list *timer);

/**
 * del_timer_sync - Delete a pending timer and wait for a running callback
 * @timer:	The timer to be deleted
 *
 * See timer_delete_sync() for detailed explanation.
 *
 * Do not use in new code. Use timer_delete_sync() instead.
 */
static inline int del_timer_sync(struct timer_list *timer)
{
	return timer_delete_sync(timer);
}

/**
 * del_timer - Delete a pending timer
 * @timer:	The timer to be deleted
 *
 * See timer_delete() for detailed explanation.
 *
 * Do not use in new code. Use timer_delete() instead.
 */
static inline int del_timer(struct timer_list *timer)
{
	return timer_delete(timer);
}

extern void init_timers(void);
struct hrtimer;
extern enum hrtimer_restart it_real_fn(struct hrtimer *);

unsigned long __round_jiffies(unsigned long j, int cpu);
unsigned long __round_jiffies_relative(unsigned long j, int cpu);
unsigned long round_jiffies(unsigned long j);
unsigned long round_jiffies_relative(unsigned long j);

unsigned long __round_jiffies_up(unsigned long j, int cpu);
unsigned long __round_jiffies_up_relative(unsigned long j, int cpu);
unsigned long round_jiffies_up(unsigned long j);
unsigned long round_jiffies_up_relative(unsigned long j);

#ifdef CONFIG_HOTPLUG_CPU
int timers_prepare_cpu(unsigned int cpu);
int timers_dead_cpu(unsigned int cpu);
#else
#define timers_prepare_cpu	NULL
#define timers_dead_cpu		NULL
#endif

#endif
