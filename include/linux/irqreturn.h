/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQRETURN_H
#define _LINUX_IRQRETURN_H

/**
 * enum irqreturn - irqreturn type values
 * @IRQ_NONE:		interrupt was not from this device or was not handled
 * @IRQ_HANDLED:	interrupt was handled by this device
 * @IRQ_WAKE_THREAD:	handler requests to wake the handler thread
 */
enum irqreturn {
	IRQ_NONE		= (0 << 0),
	IRQ_HANDLED		= (1 << 0),
	/*返回此值，将唤醒中断处理进程的从进程*/
	IRQ_WAKE_THREAD		= (1 << 1),
};

/*中断处理函数返回值*/
typedef enum irqreturn irqreturn_t;
#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)

#endif
