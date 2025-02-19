// SPDX-License-Identifier: GPL-2.0-only
/*
 *  fs/eventfd.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/anon_inodes.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/kref.h>
#include <linux/eventfd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/idr.h>
#include <linux/uio.h>

//负责context id号分配
static DEFINE_IDA(eventfd_ida);

struct eventfd_ctx {
	struct kref kref;
	wait_queue_head_t wqh;
	/*
	 * Every time that a write(2) is performed on an eventfd, the
	 * value of the __u64 being written is added to "count" and a
	 * wakeup is performed on "wqh". If EFD_SEMAPHORE flag was not
	 * specified, a read(2) will return the "count" value to userspace,
	 * and will reset "count" to zero. The kernel side eventfd_signal()
	 * also, adds to the "count" counter and issue a wakeup.
	 */
	__u64 count;
	unsigned int flags;
	int id;//ctx编号
};

/**
 * eventfd_signal_mask - Increment the event counter
 * @ctx: [in] Pointer to the eventfd context.
 * @mask: [in] poll mask
 *
 * This function is supposed to be called by the kernel in paths that do not
 * allow sleeping. In this function we allow the counter to reach the ULLONG_MAX
 * value, and we signal this as overflow condition by returning a EPOLLERR
 * to poll(2).
 */
void eventfd_signal_mask(struct eventfd_ctx *ctx, __poll_t mask)
{
	unsigned long flags;

	/*
	 * Deadlock or stack overflow issues can happen if we recurse here
	 * through waitqueue wakeup handlers. If the caller users potentially
	 * nested waitqueues with custom wakeup handlers, then it should
	 * check eventfd_signal_allowed() before calling this function. If
	 * it returns false, the eventfd_signal() call should be deferred to a
	 * safe context.
	 */
	if (WARN_ON_ONCE(current->in_eventfd))
		/*防止在执行下列函数时被中断了，这里直接返回（故不能保证信号数量）*/
		return;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	current->in_eventfd = 1;
	if (ctx->count < ULLONG_MAX)
		ctx->count++;/*增加事件数*/
	if (waitqueue_active(&ctx->wqh))
	    /*等待队列中有wait,采用pollin事件将其唤醒*/
		wake_up_locked_poll(&ctx->wqh, EPOLLIN | mask);
	current->in_eventfd = 0;
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);
}
EXPORT_SYMBOL_GPL(eventfd_signal_mask);

static void eventfd_free_ctx(struct eventfd_ctx *ctx)
{
	if (ctx->id >= 0)
		ida_free(&eventfd_ida, ctx->id);
	kfree(ctx);
}

static void eventfd_free(struct kref *kref)
{
	struct eventfd_ctx *ctx = container_of(kref, struct eventfd_ctx, kref);

	eventfd_free_ctx(ctx);
}

/**
 * eventfd_ctx_put - Releases a reference to the internal eventfd context.
 * @ctx: [in] Pointer to eventfd context.
 *
 * The eventfd context reference must have been previously acquired either
 * with eventfd_ctx_fdget() or eventfd_ctx_fileget().
 */
void eventfd_ctx_put(struct eventfd_ctx *ctx)
{
	kref_put(&ctx->kref, eventfd_free);
}
EXPORT_SYMBOL_GPL(eventfd_ctx_put);

static int eventfd_release(struct inode *inode, struct file *file)
{
	struct eventfd_ctx *ctx = file->private_data;

	wake_up_poll(&ctx->wqh, EPOLLHUP);
	eventfd_ctx_put(ctx);
	return 0;
}

static __poll_t eventfd_poll(struct file *file, poll_table *wait)
{
	struct eventfd_ctx *ctx = file->private_data;
	__poll_t events = 0;
	u64 count;

	/*poll等待*/
	poll_wait(file, &ctx->wqh, wait);

	/*
	 * All writes to ctx->count occur within ctx->wqh.lock.  This read
	 * can be done outside ctx->wqh.lock because we know that poll_wait
	 * takes that lock (through add_wait_queue) if our caller will sleep.
	 *
	 * The read _can_ therefore seep into add_wait_queue's critical
	 * section, but cannot move above it!  add_wait_queue's spin_lock acts
	 * as an acquire barrier and ensures that the read be ordered properly
	 * against the writes.  The following CAN happen and is safe:
	 *
	 *     poll                               write
	 *     -----------------                  ------------
	 *     lock ctx->wqh.lock (in poll_wait)
	 *     count = ctx->count
	 *     __add_wait_queue
	 *     unlock ctx->wqh.lock
	 *                                        lock ctx->qwh.lock
	 *                                        ctx->count += n
	 *                                        if (waitqueue_active)
	 *                                          wake_up_locked_poll
	 *                                        unlock ctx->qwh.lock
	 *     eventfd_poll returns 0
	 *
	 * but the following, which would miss a wakeup, cannot happen:
	 *
	 *     poll                               write
	 *     -----------------                  ------------
	 *     count = ctx->count (INVALID!)
	 *                                        lock ctx->qwh.lock
	 *                                        ctx->count += n
	 *                                        **waitqueue_active is false**
	 *                                        **no wake_up_locked_poll!**
	 *                                        unlock ctx->qwh.lock
	 *     lock ctx->wqh.lock (in poll_wait)
	 *     __add_wait_queue
	 *     unlock ctx->wqh.lock
	 *     eventfd_poll returns 0
	 */
	count = READ_ONCE(ctx->count);

	if (count > 0)
	    //event量大于0，可读
		events |= EPOLLIN;
	if (count == ULLONG_MAX)
	    //event量过大，报错
		events |= EPOLLERR;
	if (ULLONG_MAX - 1 > count)
	    //event量可写
		events |= EPOLLOUT;

	return events;
}

void eventfd_ctx_do_read(struct eventfd_ctx *ctx, __u64 *cnt)
{
	lockdep_assert_held(&ctx->wqh.lock);

    /*如果是信号量，则每一个event触发一次；否则容许多个event合并成一次触发*/
	*cnt = ((ctx->flags & EFD_SEMAPHORE) && ctx->count) ? 1 : ctx->count;
	ctx->count -= *cnt;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_do_read);

/**
 * eventfd_ctx_remove_wait_queue - Read the current counter and removes wait queue.
 * @ctx: [in] Pointer to eventfd context.
 * @wait: [in] Wait queue to be removed.
 * @cnt: [out] Pointer to the 64-bit counter value.
 *
 * Returns %0 if successful, or the following error codes:
 *
 * -EAGAIN      : The operation would have blocked.
 *
 * This is used to atomically remove a wait queue entry from the eventfd wait
 * queue head, and read/reset the counter value.
 */
int eventfd_ctx_remove_wait_queue(struct eventfd_ctx *ctx, wait_queue_entry_t *wait,
				  __u64 *cnt)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	eventfd_ctx_do_read(ctx, cnt);
	__remove_wait_queue(&ctx->wqh, wait);
	if (*cnt != 0 && waitqueue_active(&ctx->wqh))
		wake_up_locked_poll(&ctx->wqh, EPOLLOUT);
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return *cnt != 0 ? 0 : -EAGAIN;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_remove_wait_queue);

//eventfd读操作处理
static ssize_t eventfd_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	/*取得context*/
	struct eventfd_ctx *ctx = file->private_data;
	__u64 ucnt = 0;

	if (iov_iter_count(to) < sizeof(ucnt))
		/*读的长度不得小于sizeof(u64)*/
		return -EINVAL;
	spin_lock_irq(&ctx->wqh.lock);
	if (!ctx->count) {
		if ((file->f_flags & O_NONBLOCK) ||
		    (iocb->ki_flags & IOCB_NOWAIT)) {
			/*指明了不阻塞，直接返回*/
			spin_unlock_irq(&ctx->wqh.lock);
			return -EAGAIN;
		}

		/*等待直到ctx->count不为零*/
		if (wait_event_interruptible_locked_irq(ctx->wqh, ctx->count)) {
			spin_unlock_irq(&ctx->wqh.lock);
			return -ERESTARTSYS;
		}
	}
	eventfd_ctx_do_read(ctx, &ucnt);/*读取count*/
	current->in_eventfd = 1;
	if (waitqueue_active(&ctx->wqh))
		/*唤醒等待者*/
		wake_up_locked_poll(&ctx->wqh, EPOLLOUT);
	current->in_eventfd = 0;
	spin_unlock_irq(&ctx->wqh.lock);
	/*写入count*/
	if (unlikely(copy_to_iter(&ucnt, sizeof(ucnt), to) != sizeof(ucnt)))
		return -EFAULT;

	return sizeof(ucnt);
}

static ssize_t eventfd_write(struct file *file, const char __user *buf, size_t count,
			     loff_t *ppos)
{
	struct eventfd_ctx *ctx = file->private_data;
	ssize_t res;
	__u64 ucnt;

	if (count < sizeof(ucnt))
		return -EINVAL;
	if (copy_from_user(&ucnt, buf, sizeof(ucnt)))
		return -EFAULT;
	if (ucnt == ULLONG_MAX)
		return -EINVAL;
	spin_lock_irq(&ctx->wqh.lock);
	res = -EAGAIN;
	if (ULLONG_MAX - ctx->count > ucnt)
		/*没有绕圈，可写入*/
		res = sizeof(ucnt);
	else if (!(file->f_flags & O_NONBLOCK)) {
		/*等待count消费一部分后满足不绕圈后再写入*/
		res = wait_event_interruptible_locked_irq(ctx->wqh,
				ULLONG_MAX - ctx->count > ucnt);
		if (!res)
			res = sizeof(ucnt);
	}
	if (likely(res > 0)) {
	    /*增加事件触发次数*/
		ctx->count += ucnt;
		current->in_eventfd = 1;
		if (waitqueue_active(&ctx->wqh))
			/*唤醒等待者*/
			wake_up_locked_poll(&ctx->wqh, EPOLLIN);
		current->in_eventfd = 0;
	}
	spin_unlock_irq(&ctx->wqh.lock);

	return res;
}

#ifdef CONFIG_PROC_FS
static void eventfd_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct eventfd_ctx *ctx = f->private_data;

	spin_lock_irq(&ctx->wqh.lock);
	seq_printf(m, "eventfd-count: %16llx\n",
		   (unsigned long long)ctx->count);/*显示event数*/
	spin_unlock_irq(&ctx->wqh.lock);
	seq_printf(m, "eventfd-id: %d\n", ctx->id);
	seq_printf(m, "eventfd-semaphore: %d\n",
		   !!(ctx->flags & EFD_SEMAPHORE));
}
#endif

//eventfd对应的fops
static const struct file_operations eventfd_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= eventfd_show_fdinfo,
#endif
	.release	= eventfd_release,
	.poll		= eventfd_poll,/*count大于零，可读；等于ULLONG_MAX，出错；小于ULLONG_MAX，可写*/
	.read_iter	= eventfd_read,/*消费count*/
	.write		= eventfd_write,/*生产count*/
	.llseek		= noop_llseek,
};

/**
 * eventfd_fget - Acquire a reference of an eventfd file descriptor.
 * @fd: [in] Eventfd file descriptor.
 *
 * Returns a pointer to the eventfd file structure in case of success, or the
 * following error pointer:
 *
 * -EBADF    : Invalid @fd file descriptor.
 * -EINVAL   : The @fd file descriptor is not an eventfd file.
 */
struct file *eventfd_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	/*fd指定的必须为eventfd*/
	if (file->f_op != &eventfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file;
}
EXPORT_SYMBOL_GPL(eventfd_fget);

/**
 * eventfd_ctx_fdget - Acquires a reference to the internal eventfd context.
 * @fd: [in] Eventfd file descriptor.
 *
 * Returns a pointer to the internal eventfd context, otherwise the error
 * pointers returned by the following functions:
 *
 * eventfd_fget
 */
struct eventfd_ctx *eventfd_ctx_fdget(int fd)
{
    /*通过fd找到其对应的eventfd_ctx*/
	struct eventfd_ctx *ctx;
	struct fd f = fdget(fd);
	if (!f.file)
		return ERR_PTR(-EBADF);
	//取文件私有数据，即eventfd_ctx
	ctx = eventfd_ctx_fileget(f.file);
	fdput(f);
	return ctx;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_fdget);

/**
 * eventfd_ctx_fileget - Acquires a reference to the internal eventfd context.
 * @file: [in] Eventfd file pointer.
 *
 * Returns a pointer to the internal eventfd context, otherwise the error
 * pointer:
 *
 * -EINVAL   : The @fd file descriptor is not an eventfd file.
 */
struct eventfd_ctx *eventfd_ctx_fileget(struct file *file)
{
    /*取eventfd file对应的私有数据，即eventfd_ctx*/
	struct eventfd_ctx *ctx;

	if (file->f_op != &eventfd_fops)
		return ERR_PTR(-EINVAL);

	ctx = file->private_data;
	kref_get(&ctx->kref);
	return ctx;
}
EXPORT_SYMBOL_GPL(eventfd_ctx_fileget);

//实现eventfd,eventfd2系统调用,申请fd创建eventfd对应的file
static int do_eventfd(unsigned int count, int flags)
{
	struct eventfd_ctx *ctx;
	struct file *file;
	int fd;

	/* Check the EFD_* constants for consistency.  */
	BUILD_BUG_ON(EFD_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(EFD_NONBLOCK != O_NONBLOCK);

	/*有效flags检查*/
	if (flags & ~EFD_FLAGS_SET)
		return -EINVAL;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	kref_init(&ctx->kref);
	init_waitqueue_head(&ctx->wqh);
	ctx->count = count;/*指定初始事件数*/
	ctx->flags = flags;
	/*分配一个编号*/
	ctx->id = ida_alloc(&eventfd_ida, GFP_KERNEL);

	flags &= EFD_SHARED_FCNTL_FLAGS;
	flags |= O_RDWR;
	/*映射fd*/
	fd = get_unused_fd_flags(flags);
	if (fd < 0)
		goto err;

	/*申请一个匿名文件，指明eventfd文件对应的fops*/
	file = anon_inode_getfile("[eventfd]", &eventfd_fops, ctx, flags);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		fd = PTR_ERR(file);
		goto err;
	}

	file->f_mode |= FMODE_NOWAIT;
	fd_install(fd, file);/*fd与文件关联*/
	return fd;
err:
	eventfd_free_ctx(ctx);
	return fd;
}

/*定义系统调用eventfd2*/
SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
{
	return do_eventfd(count, flags);
}

/*定义系统调用eventfd*/
SYSCALL_DEFINE1(eventfd, unsigned int, count)
{
	return do_eventfd(count, 0);
}

