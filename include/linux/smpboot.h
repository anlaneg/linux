/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SMPBOOT_H
#define _LINUX_SMPBOOT_H

#include <linux/types.h>

struct task_struct;
/* Cookie handed to the thread_fn*/
struct smpboot_thread_data;

/**
 * struct smp_hotplug_thread - CPU hotplug related thread descriptor
 * @store:		Pointer to per cpu storage for the task pointers
 * @list:		List head for core management
 * @thread_should_run:	Check whether the thread should run or not. Called with
 *			preemption disabled.
 * @thread_fn:		The associated thread function
 * @create:		Optional setup function, called when the thread gets
 *			created (Not called from the thread context)
 * @setup:		Optional setup function, called when the thread gets
 *			operational the first time
 * @cleanup:		Optional cleanup function, called when the thread
 *			should stop (module exit)
 * @park:		Optional park function, called when the thread is
 *			parked (cpu offline)
 * @unpark:		Optional unpark function, called when the thread is
 *			unparked (cpu online)
 * @selfparking:	Thread is not parked by the park function.
 * @thread_comm:	The base name of the thread
 */
struct smp_hotplug_thread {
	struct task_struct		* __percpu *store;
	struct list_head		list;
	//检查thread在cpu上是否可运行
	int				(*thread_should_run)(unsigned int cpu);
	//thread在此cpu上可运行时，通过此回调完成工作
	void				(*thread_fn)(unsigned int cpu);
	/*kthread创建完成后，通过此回调完成创建*/
	void				(*create)(unsigned int cpu);
	//通过状态由none切换到active时，调用setup
	void				(*setup)(unsigned int cpu);
	//thread退出前执行
	void				(*cleanup)(unsigned int cpu, bool online);
	//thread需要到达park状态时，通过此回调后，进入park状态
	void				(*park)(unsigned int cpu);
	//由park状态切换到active关态时，调用unpark
	void				(*unpark)(unsigned int cpu);
	bool				selfparking;
	const char			*thread_comm;
};

int smpboot_register_percpu_thread(struct smp_hotplug_thread *plug_thread);

void smpboot_unregister_percpu_thread(struct smp_hotplug_thread *plug_thread);

#endif
