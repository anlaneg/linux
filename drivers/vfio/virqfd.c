// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO generic eventfd code for IRQFD support.
 * Derived from drivers/vfio/pci/vfio_pci_intrs.c
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 */

#include <linux/vfio.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "vfio.h"

static struct workqueue_struct *vfio_irqfd_cleanup_wq;
static DEFINE_SPINLOCK(virqfd_lock);

int __init vfio_virqfd_init(void)
{
    //创建vfio-irqfd-cleanup工作队列
	vfio_irqfd_cleanup_wq =
		create_singlethread_workqueue("vfio-irqfd-cleanup");
	if (!vfio_irqfd_cleanup_wq)
		return -ENOMEM;

	return 0;
}

void vfio_virqfd_exit(void)
{
	destroy_workqueue(vfio_irqfd_cleanup_wq);
}

static void virqfd_deactivate(struct virqfd *virqfd)
{
    //virqfd入队
	queue_work(vfio_irqfd_cleanup_wq, &virqfd->shutdown);
}

static int virqfd_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	struct virqfd *virqfd = container_of(wait, struct virqfd, wait);
	__poll_t flags = key_to_poll(key);

	if (flags & EPOLLIN) {
		u64 cnt;
		eventfd_ctx_do_read(virqfd->eventfd, &cnt);

		/* An event has been signaled, call function */
		if ((!virqfd->handler ||
		     virqfd->handler(virqfd->opaque, virqfd->data)) &&
		    virqfd->thread)
			schedule_work(&virqfd->inject);
	}

	if (flags & EPOLLHUP) {
		unsigned long flags;
		spin_lock_irqsave(&virqfd_lock, flags);

		/*
		 * The eventfd is closing, if the virqfd has not yet been
		 * queued for release, as determined by testing whether the
		 * virqfd pointer to it is still valid, queue it now.  As
		 * with kvm irqfds, we know we won't race against the virqfd
		 * going away because we hold the lock to get here.
		 */
		if (*(virqfd->pvirqfd) == virqfd) {
			*(virqfd->pvirqfd) = NULL;
			/*将virqfd加入等待队列*/
			virqfd_deactivate(virqfd);
		}

		spin_unlock_irqrestore(&virqfd_lock, flags);
	}

	return 0;
}

static void virqfd_ptable_queue_proc(struct file *file,
				     wait_queue_head_t *wqh, poll_table *pt)
{
    //由pt获得virqfd,并将其加入到wqh的队列
	struct virqfd *virqfd = container_of(pt, struct virqfd, pt);
	add_wait_queue(wqh, &virqfd->wait);
}

static void virqfd_shutdown(struct work_struct *work)
{
    //由work获得virqfd
	struct virqfd *virqfd = container_of(work, struct virqfd, shutdown);
	u64 cnt;

	eventfd_ctx_remove_wait_queue(virqfd->eventfd, &virqfd->wait, &cnt);
	flush_work(&virqfd->inject);
	eventfd_ctx_put(virqfd->eventfd);

	kfree(virqfd);
}

static void virqfd_inject(struct work_struct *work)
{
    //由work获得virqfd,并调用thread回调
	struct virqfd *virqfd = container_of(work, struct virqfd, inject);
	if (virqfd->thread)
		virqfd->thread(virqfd->opaque, virqfd->data);
}

int vfio_virqfd_enable(void *opaque,
		       int (*handler)(void *, void *),
		       void (*thread)(void *, void *),
		       void *data, struct virqfd **pvirqfd, int fd/*eventfd对应的文件fd*/)
{
	struct fd irqfd;
	struct eventfd_ctx *ctx;
	struct virqfd *virqfd;
	int ret = 0;
	__poll_t events;

	/*创建virqfd*/
	virqfd = kzalloc(sizeof(*virqfd), GFP_KERNEL_ACCOUNT);
	if (!virqfd)
		return -ENOMEM;

	virqfd->pvirqfd = pvirqfd;
	virqfd->opaque = opaque;
	virqfd->handler = handler;
	virqfd->thread = thread;/*指定thread回调*/
	virqfd->data = data;

	INIT_WORK(&virqfd->shutdown, virqfd_shutdown);
	INIT_WORK(&virqfd->inject, virqfd_inject);/*如果有thread回调，则调用，否则nothing to do*/

	//取中断对应的eventfd
	irqfd = fdget(fd);
	if (!irqfd.file) {
		ret = -EBADF;
		goto err_fd;
	}

	//取eventfd对应的私有数据
	ctx = eventfd_ctx_fileget(irqfd.file);
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		goto err_ctx;
	}

	virqfd->eventfd = ctx;

	/*
	 * virqfds can be released by closing the eventfd or directly
	 * through ioctl.  These are both done through a workqueue, so
	 * we update the pointer to the virqfd under lock to avoid
	 * pushing multiple jobs to release the same virqfd.
	 */
	spin_lock_irq(&virqfd_lock);

	if (*pvirqfd) {
		spin_unlock_irq(&virqfd_lock);
		ret = -EBUSY;
		goto err_busy;
	}
	*pvirqfd = virqfd;

	spin_unlock_irq(&virqfd_lock);

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd.
	 */
	init_waitqueue_func_entry(&virqfd->wait, virqfd_wakeup);
	init_poll_funcptr(&virqfd->pt, virqfd_ptable_queue_proc);

	/*触发eventfd的poll回调，等待事件发生*/
	events = vfs_poll(irqfd.file, &virqfd->pt);

	/*
	 * Check if there was an event already pending on the eventfd
	 * before we registered and trigger it as if we didn't miss it.
	 */
	if (events & EPOLLIN) {
	    /*eventfd可读，如果有handle,则通过handle处理此事件，否则如果有thread回调，则
	     * 执行inject work，使之触发thread回调*/
		if ((!handler || handler(opaque, data)) && thread)
			schedule_work(&virqfd->inject);
	}

	/*
	 * Do not drop the file until the irqfd is fully initialized,
	 * otherwise we might race against the EPOLLHUP.
	 */
	fdput(irqfd);

	return 0;
err_busy:
	eventfd_ctx_put(ctx);
err_ctx:
	fdput(irqfd);
err_fd:
	kfree(virqfd);

	return ret;
}
EXPORT_SYMBOL_GPL(vfio_virqfd_enable);

void vfio_virqfd_disable(struct virqfd **pvirqfd)
{
	unsigned long flags;

	spin_lock_irqsave(&virqfd_lock, flags);

	if (*pvirqfd) {
		virqfd_deactivate(*pvirqfd);
		*pvirqfd = NULL;
	}

	spin_unlock_irqrestore(&virqfd_lock, flags);

	/*
	 * Block until we know all outstanding shutdown jobs have completed.
	 * Even if we don't queue the job, flush the wq to be sure it's
	 * been released.
	 */
	flush_workqueue(vfio_irqfd_cleanup_wq);
}
EXPORT_SYMBOL_GPL(vfio_virqfd_disable);
