// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include "rxe.h"

/*rxe_task运行，直到遇到非0返回*/
int __rxe_do_task(struct rxe_task *task)

{
	int ret;

	while ((ret = task->func(task->arg)) == 0)
		;

	task->ret = ret;

	return ret;
}

/*
 * this locking is due to a potential race where
 * a second caller finds the task already running
 * but looks just after the last call to func
 */
static void do_task(struct tasklet_struct *t)
{
    /*softirq会依据中断触发此函数执行task*/
	int cont;
	int ret;
	/*取tasklet对应的rxe_task*/
	struct rxe_task *task = from_tasklet(task, t, tasklet);
	struct rxe_qp *qp = (struct rxe_qp *)task->arg;
	unsigned int iterations = RXE_MAX_ITERATIONS;

	spin_lock_bh(&task->lock);
	switch (task->state) {
	case TASK_STATE_START:
	    /*start转busy状态*/
		task->state = TASK_STATE_BUSY;
		spin_unlock_bh(&task->lock);
		break;

	case TASK_STATE_BUSY:
	    /*状态：busy->armed*/
		task->state = TASK_STATE_ARMED;
		fallthrough;
	case TASK_STATE_ARMED:
	    	/*armed状态情况，函数返回*/
		spin_unlock_bh(&task->lock);
		return;

	default:
		spin_unlock_bh(&task->lock);
		rxe_dbg_qp(qp, "failed with bad state %d\n", task->state);
		return;
	}

	do {
		cont = 0;
		/*执行此task任务*/
		ret = task->func(task->arg);

		spin_lock_bh(&task->lock);
		switch (task->state) {
		case TASK_STATE_BUSY:
			if (ret) {
				/*func返回非0，状态由busy->start*/
				task->state = TASK_STATE_START;
			} else if (iterations--) {
				cont = 1;
			} else {
				/* reschedule the tasklet and exit
				 * the loop to give up the cpu
				 */
				tasklet_schedule(&task->tasklet);
				task->state = TASK_STATE_START;
			}
			break;

		/* someone tried to run the task since the last time we called
		 * func, so we will call one more time regardless of the
		 * return value
		 */
		case TASK_STATE_ARMED:
			task->state = TASK_STATE_BUSY;
			cont = 1;
			break;

		default:
			rxe_dbg_qp(qp, "failed with bad state %d\n",
					task->state);
		}
		spin_unlock_bh(&task->lock);
	} while (cont);

	task->ret = ret;/*使用func回调返回值*/
}

int rxe_init_task(struct rxe_task *task, void *arg, int (*func)(void *))
{
	task->arg	= arg;
	/*设置此task对应的工作函数*/
	task->func	= func;
	task->destroyed	= false;

	tasklet_setup(&task->tasklet, do_task);

	task->state = TASK_STATE_START;
	spin_lock_init(&task->lock);

	return 0;
}

void rxe_cleanup_task(struct rxe_task *task)
{
	bool idle;

	/*
	 * Mark the task, then wait for it to finish. It might be
	 * running in a non-tasklet (direct call) context.
	 */
	task->destroyed = true;

	do {
		spin_lock_bh(&task->lock);
		idle = (task->state == TASK_STATE_START);
		spin_unlock_bh(&task->lock);
	} while (!idle);

	tasklet_kill(&task->tasklet);
}

void rxe_run_task(struct rxe_task *task)
{
	if (task->destroyed)
		return;

	do_task(&task->tasklet);
}

void rxe_sched_task(struct rxe_task *task)
{
	if (task->destroyed)
		return;

	tasklet_schedule(&task->tasklet);
}

void rxe_disable_task(struct rxe_task *task)
{
	tasklet_disable(&task->tasklet);
}

void rxe_enable_task(struct rxe_task *task)
{
	tasklet_enable(&task->tasklet);
}
