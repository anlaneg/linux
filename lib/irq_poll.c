// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to interrupt-poll handling in the block layer. This
 * is similar to NAPI for network devices.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/irq_poll.h>
#include <linux/delay.h>

static unsigned int irq_poll_budget __read_mostly = 256;

static DEFINE_PER_CPU(struct list_head, blk_cpu_iopoll);

/**
 * irq_poll_sched - Schedule a run of the iopoll handler
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     Add this irq_poll structure to the pending poll list and trigger the
 *     raise of the blk iopoll softirq.
 **/
void irq_poll_sched(struct irq_poll *iop)
{
	unsigned long flags;

	if (test_bit(IRQ_POLL_F_DISABLE, &iop->state))
		return;
	if (test_and_set_bit(IRQ_POLL_F_SCHED, &iop->state))
		return;

	local_irq_save(flags);
	/*添加此iop到链表，并触发irq_poll软中断*/
	list_add_tail(&iop->list, this_cpu_ptr(&blk_cpu_iopoll));
	raise_softirq_irqoff(IRQ_POLL_SOFTIRQ);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(irq_poll_sched);

/**
 * __irq_poll_complete - Mark this @iop as un-polled again
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     See irq_poll_complete(). This function must be called with interrupts
 *     disabled.
 **/
static void __irq_poll_complete(struct irq_poll *iop)
{
	list_del(&iop->list);/*将自已自链表上移除*/
	smp_mb__before_atomic();
	/*指明无sched标记*/
	clear_bit_unlock(IRQ_POLL_F_SCHED, &iop->state);
}

/**
 * irq_poll_complete - Mark this @iop as un-polled again
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     If a driver consumes less than the assigned budget in its run of the
 *     iopoll handler, it'll end the polled mode by calling this function. The
 *     iopoll handler will not be invoked again before irq_poll_sched()
 *     is called.
 **/
void irq_poll_complete(struct irq_poll *iop)
{
	unsigned long flags;

	local_irq_save(flags);
	__irq_poll_complete(iop);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(irq_poll_complete);

static void __latent_entropy irq_poll_softirq(struct softirq_action *h)
{
	/*取当前cpu上的所有irq_poll*/
	struct list_head *list = this_cpu_ptr(&blk_cpu_iopoll);
	int rearm = 0, budget = irq_poll_budget;
	unsigned long start_time = jiffies;/*软中断开启执行时间*/

	local_irq_disable();

	/*遍历挂接在此list上所有irq_poll*/
	while (!list_empty(list)) {
		struct irq_poll *iop;
		int work, weight;

		/*
		 * If softirq window is exhausted then punt.
		 */
		if (budget <= 0 || time_after(jiffies, start_time)) {
			/*budget用法或者处理时间片用完，仍有数据，需要再次触发*/
			rearm = 1;
			break;
		}

		local_irq_enable();

		/* Even though interrupts have been re-enabled, this
		 * access is safe because interrupts can only add new
		 * entries to the tail of this list, and only ->poll()
		 * calls can remove this head entry from the list.
		 */
		iop = list_entry(list->next, struct irq_poll, list);

		weight = iop->weight;
		work = 0;
		if (test_bit(IRQ_POLL_F_SCHED, &iop->state))
			work = iop->poll(iop, weight);/*触发poll回调*/

		budget -= work;/*budget减少*/

		local_irq_disable();

		/*
		 * Drivers must not modify the iopoll state, if they
		 * consume their assigned weight (or more, some drivers can't
		 * easily just stop processing, they have to complete an
		 * entire mask of commands).In such cases this code
		 * still "owns" the iopoll instance and therefore can
		 * move the instance around on the list at-will.
		 */
		if (work >= weight) {
			if (test_bit(IRQ_POLL_F_DISABLE, &iop->state))
				/*iop被移除*/
				__irq_poll_complete(iop);
			else
				/*重新加入iop*/
				list_move_tail(&iop->list, list);
		}
	}

	if (rearm)
		/*再次触发irq poll*/
		__raise_softirq_irqoff(IRQ_POLL_SOFTIRQ);

	local_irq_enable();
}

/**
 * irq_poll_disable - Disable iopoll on this @iop
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     Disable io polling and wait for any pending callbacks to have completed.
 **/
void irq_poll_disable(struct irq_poll *iop)
{
	set_bit(IRQ_POLL_F_DISABLE, &iop->state);
	while (test_and_set_bit(IRQ_POLL_F_SCHED, &iop->state))
		msleep(1);
	clear_bit(IRQ_POLL_F_DISABLE, &iop->state);
}
EXPORT_SYMBOL(irq_poll_disable);

/**
 * irq_poll_enable - Enable iopoll on this @iop
 * @iop:      The parent iopoll structure
 *
 * Description:
 *     Enable iopoll on this @iop. Note that the handler run will not be
 *     scheduled, it will only mark it as active.
 **/
void irq_poll_enable(struct irq_poll *iop)
{
	BUG_ON(!test_bit(IRQ_POLL_F_SCHED, &iop->state));
	smp_mb__before_atomic();
	clear_bit_unlock(IRQ_POLL_F_SCHED, &iop->state);
}
EXPORT_SYMBOL(irq_poll_enable);

/**
 * irq_poll_init - Initialize this @iop
 * @iop:      The parent iopoll structure
 * @weight:   The default weight (or command completion budget)
 * @poll_fn:  The handler to invoke
 *
 * Description:
 *     Initialize and enable this irq_poll structure.
 **/
void irq_poll_init(struct irq_poll *iop, int weight, irq_poll_fn *poll_fn)
{
	memset(iop, 0, sizeof(*iop));
	INIT_LIST_HEAD(&iop->list);
	iop->weight = weight;
	iop->poll = poll_fn;/*设置poll回调*/
}
EXPORT_SYMBOL(irq_poll_init);

static int irq_poll_cpu_dead(unsigned int cpu)
{
	/*
	 * If a CPU goes away, splice its entries to the current CPU and
	 * set the POLL softirq bit. The local_bh_disable()/enable() pair
	 * ensures that it is handled. Otherwise the current CPU could
	 * reach idle with the POLL softirq pending.
	 */
	local_bh_disable();
	local_irq_disable();
	list_splice_init(&per_cpu(blk_cpu_iopoll, cpu),
			 this_cpu_ptr(&blk_cpu_iopoll));
	__raise_softirq_irqoff(IRQ_POLL_SOFTIRQ);
	local_irq_enable();
	local_bh_enable();

	return 0;
}

static __init int irq_poll_setup(void)
{
	int i;

	/*每个cpu均初始化blk_cpu_iopoll list*/
	for_each_possible_cpu(i)
		INIT_LIST_HEAD(&per_cpu(blk_cpu_iopoll, i));

	/*设置iro-poll软中断处理函数*/
	open_softirq(IRQ_POLL_SOFTIRQ, irq_poll_softirq);
	cpuhp_setup_state_nocalls(CPUHP_IRQ_POLL_DEAD, "irq_poll:dead", NULL,
				  irq_poll_cpu_dead);
	return 0;
}
subsys_initcall(irq_poll_setup);
