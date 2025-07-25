// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/file.c
 *
 *  Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes
 *
 *  Manage the dynamic fd arrays in the process files_struct.
 */

#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/close_range.h>
#include <net/sock.h>

#include "internal.h"

unsigned int sysctl_nr_open __read_mostly = 1024*1024;
unsigned int sysctl_nr_open_min = BITS_PER_LONG;
/* our min() is unusable in constant expressions ;-/ */
#define __const_min(x, y) ((x) < (y) ? (x) : (y))
unsigned int sysctl_nr_open_max =
	__const_min(INT_MAX, ~(size_t)0/sizeof(void *)) & -BITS_PER_LONG;

static void __free_fdtable(struct fdtable *fdt)
{
	kvfree(fdt->fd);
	kvfree(fdt->open_fds);
	kfree(fdt);
}

static void free_fdtable_rcu(struct rcu_head *rcu)
{
	__free_fdtable(container_of(rcu, struct fdtable, rcu));
}

#define BITBIT_NR(nr)	BITS_TO_LONGS(BITS_TO_LONGS(nr))
#define BITBIT_SIZE(nr)	(BITBIT_NR(nr) * sizeof(long))

/*
 * Copy 'count' fd bits from the old table to the new table and clear the extra
 * space if any.  This does not copy the file pointers.  Called with the files
 * spinlock held for write.
 */
static void copy_fd_bitmaps(struct fdtable *nfdt, struct fdtable *ofdt,
			    unsigned int count)
{
	unsigned int cpy, set;

	cpy = count / BITS_PER_BYTE;
	set = (nfdt->max_fds - count) / BITS_PER_BYTE;
	memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
	memset((char *)nfdt->open_fds + cpy, 0, set);
	memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
	memset((char *)nfdt->close_on_exec + cpy, 0, set);

	cpy = BITBIT_SIZE(count);
	set = BITBIT_SIZE(nfdt->max_fds) - cpy;
	memcpy(nfdt->full_fds_bits, ofdt->full_fds_bits, cpy);
	memset((char *)nfdt->full_fds_bits + cpy, 0, set);
}

/*
 * Copy all file descriptors from the old table to the new, expanded table and
 * clear the extra space.  Called with the files spinlock held for write.
 */
static void copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
	size_t cpy, set;

	BUG_ON(nfdt->max_fds < ofdt->max_fds);

	cpy = ofdt->max_fds * sizeof(struct file *);
	set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
	memcpy(nfdt->fd, ofdt->fd, cpy);
	memset((char *)nfdt->fd + cpy, 0, set);

	copy_fd_bitmaps(nfdt, ofdt, ofdt->max_fds);
}

/*
 * Note how the fdtable bitmap allocations very much have to be a multiple of
 * BITS_PER_LONG. This is not only because we walk those things in chunks of
 * 'unsigned long' in some places, but simply because that is how the Linux
 * kernel bitmaps are defined to work: they are not "bits in an array of bytes",
 * they are very much "bits in an array of unsigned long".
 *
 * The ALIGN(nr, BITS_PER_LONG) here is for clarity: since we just multiplied
 * by that "1024/sizeof(ptr)" before, we already know there are sufficient
 * clear low bits. Clang seems to realize that, gcc ends up being confused.
 *
 * On a 128-bit machine, the ALIGN() would actually matter. In the meantime,
 * let's consider it documentation (and maybe a test-case for gcc to improve
 * its code generation ;)
 */
//申请大小为nr的fdtable
static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	void *data;

	/*
	 * Figure out how many fds we actually want to support in this fdtable.
	 * Allocation steps are keyed to the size of the fdarray, since it
	 * grows far faster than any of the other dynamic data. We try to fit
	 * the fdarray into comfortable page-tuned chunks: starting at 1024B
	 * and growing in powers of two from there on.
	 */
	//保证至少有1024B会用于存放struct file*,64位时，可支持128个项
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));
	nr = ALIGN(nr, BITS_PER_LONG);
	/*
	 * Note that this can drive nr *below* what we had passed if sysctl_nr_open
	 * had been set lower between the check in expand_files() and here.  Deal
	 * with that in caller, it's cheaper that way.
	 *
	 * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
	 * bitmaps handling below becomes unpleasant, to put it mildly...
	 */
	if (unlikely(nr > sysctl_nr_open))
		nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

	//申请新的fdt
	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
	if (!fdt)
		goto out;
	//设置最大fds,申请相应的fd数组
	fdt->max_fds = nr;
	/*申请nr个struct file指针*/
	data = kvmalloc_array(nr, sizeof(struct file *), GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_fdt;
	fdt->fd = data;

	//申请相应的open fd bitmap内存（close_on_exec + full_fds_bits + open_fds )
	data = kvmalloc(max_t(size_t,
				 2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES),
				 GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_arr;
	//指向open的fds bitmap
	fdt->open_fds = data;
	data += nr / BITS_PER_BYTE;
	//指向close_on_exec的fds bitmap
	fdt->close_on_exec = data;
	data += nr / BITS_PER_BYTE;
	//指向full_fds的bitmaps
	fdt->full_fds_bits = data;

	return fdt;

out_arr:
	kvfree(fdt->fd);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}

/*
 * Expand the file descriptor table.
 * This function will allocate a new fdtable and both fd array and fdset, of
 * the given size.
 * Return <0 error code on error; 1 on successful completion.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
//将files大小扩展到nr个，更新files->fdtab
static int expand_fdtable(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *new_fdt, *cur_fdt;

	//开始扩展files大小，释放掉锁
	spin_unlock(&files->file_lock);

	//申请一个nr大小的fdtable
	new_fdt = alloc_fdtable(nr);

	/* make sure all fd_install() have seen resize_in_progress
	 * or have finished their rcu_read_lock_sched() section.
	 */
	if (atomic_read(&files->count) > 1)
		synchronize_rcu();

	spin_lock(&files->file_lock);
	if (!new_fdt)
		/*返回前需要持有锁，申请内存失败*/
		return -ENOMEM;
	/*
	 * extremely unlikely race - sysctl_nr_open decreased between the check in
	 * caller and alloc_fdtable().  Cheaper to catch it here...
	 */
	if (unlikely(new_fdt->max_fds <= nr)) {
		//未申请到所需要的nr大小
		__free_fdtable(new_fdt);
		return -EMFILE;
	}

	//取当前fdtable
	cur_fdt = files_fdtable(files);
	BUG_ON(nr < cur_fdt->max_fds);
	//将旧的数据填充copy到新申请的表里
	copy_fdtable(new_fdt, cur_fdt);

	//原子的完成fdtable的切换
	rcu_assign_pointer(files->fdt, new_fdt);

	//旧的fdt不是file->fdtab，则调用rcu对旧数据进行施放
	if (cur_fdt != &files->fdtab)
		call_rcu(&cur_fdt->rcu, free_fdtable_rcu);
	/* coupled with smp_rmb() in fd_install() */
	smp_wmb();
	return 1;
}

/*
 * Expand files.
 * This function will expand the file structures, if the requested size exceeds
 * the current capacity and there is room for expansion.
 * Return <0 error code on error; 0 when nothing done; 1 when files were
 * expanded and execution may have blocked.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int expand_files(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *fdt;
	int expanded = 0;

repeat:
	fdt = files_fdtable(files);

	/* Do we need to expand? */
	if (nr < fdt->max_fds)
		//nr未超过max_fds,不需要再进行扩展
		return expanded;

	/* Can we expand? */
	if (nr >= sysctl_nr_open)
		//超过sysctl_nr_open,总数量超系统限制
		return -EMFILE;

	if (unlikely(files->resize_in_progress)) {
		//已有线程在扩展，等待其完成后重试
		spin_unlock(&files->file_lock);
		expanded = 1;
		//将自身挂起，等待其它线程完成扩展
		wait_event(files->resize_wait, !files->resize_in_progress);

		//被唤醒，需要重新加锁再取fdtable再检查一次。
		spin_lock(&files->file_lock);
		goto repeat;
	}

	/* All good, so we try */
	//指明我们现在开始扩展
	files->resize_in_progress = true;
	expanded = expand_fdtable(files, nr);
	//执行我们已完成size扩展
	files->resize_in_progress = false;

	//防止存在等待者，将其唤醒
	wake_up_all(&files->resize_wait);
	return expanded;
}

//指明fd对应的文件设置了close_exec标记
static inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->close_on_exec);
}

//指明fd对应的文件没有设置close_exec标记
static inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
	if (test_bit(fd, fdt->close_on_exec))
		__clear_bit(fd, fdt->close_on_exec);
}

static inline void __set_open_fd(unsigned int fd, struct fdtable *fdt)
{
	//设置fd对应的文件struct file*已占用
	__set_bit(fd, fdt->open_fds);
	fd /= BITS_PER_LONG;
	/*检查open_fds[fd]位置处向后sizeof(long)*8个fd是否均已分配
	 *若均已分配，则置fd索引已满*/
	if (!~fdt->open_fds[fd])
		//无指针时，置full_fds_bits占用
		__set_bit(fd, fdt->full_fds_bits);
}

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
	__clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

static unsigned int count_open_files(struct fdtable *fdt)
{
	unsigned int size = fdt->max_fds;
	unsigned int i;

	/* Find the last open fd */
	for (i = size / BITS_PER_LONG; i > 0; ) {
		if (fdt->open_fds[--i])
			break;
	}
	i = (i + 1) * BITS_PER_LONG;
	return i;
}

/*
 * Note that a sane fdtable size always has to be a multiple of
 * BITS_PER_LONG, since we have bitmaps that are sized by this.
 *
 * 'max_fds' will normally already be properly aligned, but it
 * turns out that in the close_range() -> __close_range() ->
 * unshare_fd() -> dup_fd() -> sane_fdtable_size() we can end
 * up having a 'max_fds' value that isn't already aligned.
 *
 * Rather than make close_range() have to worry about this,
 * just make that BITS_PER_LONG alignment be part of a sane
 * fdtable size. Becuase that's really what it is.
 */
static unsigned int sane_fdtable_size(struct fdtable *fdt, unsigned int max_fds)
{
	unsigned int count;

	count = count_open_files(fdt);
	if (max_fds < NR_OPEN_DEFAULT)
		max_fds = NR_OPEN_DEFAULT;
	return ALIGN(min(count, max_fds), BITS_PER_LONG);
}

/*
 * Allocate a new files structure and copy contents from the
 * passed in files structure.
 * errorp will be valid only when the returned files_struct is NULL.
 */
struct files_struct *dup_fd(struct files_struct *oldf, unsigned int max_fds, int *errorp)
{
	struct files_struct *newf;
	struct file **old_fds, **new_fds;
	unsigned int open_files, i;
	struct fdtable *old_fdt, *new_fdt;

	*errorp = -ENOMEM;
	newf = kmem_cache_alloc(files_cachep, GFP_KERNEL);
	if (!newf)
		goto out;

	atomic_set(&newf->count, 1);

	spin_lock_init(&newf->file_lock);
	newf->resize_in_progress = false;
	init_waitqueue_head(&newf->resize_wait);
	newf->next_fd = 0;
	new_fdt = &newf->fdtab;
	new_fdt->max_fds = NR_OPEN_DEFAULT;
	new_fdt->close_on_exec = newf->close_on_exec_init;
	new_fdt->open_fds = newf->open_fds_init;
	new_fdt->full_fds_bits = newf->full_fds_bits_init;
	new_fdt->fd = &newf->fd_array[0];

	spin_lock(&oldf->file_lock);
	old_fdt = files_fdtable(oldf);
	open_files = sane_fdtable_size(old_fdt, max_fds);

	/*
	 * Check whether we need to allocate a larger fd array and fd set.
	 */
	while (unlikely(open_files > new_fdt->max_fds)) {
		spin_unlock(&oldf->file_lock);

		if (new_fdt != &newf->fdtab)
			__free_fdtable(new_fdt);

		new_fdt = alloc_fdtable(open_files - 1);
		if (!new_fdt) {
			*errorp = -ENOMEM;
			goto out_release;
		}

		/* beyond sysctl_nr_open; nothing to do */
		if (unlikely(new_fdt->max_fds < open_files)) {
			__free_fdtable(new_fdt);
			*errorp = -EMFILE;
			goto out_release;
		}

		/*
		 * Reacquire the oldf lock and a pointer to its fd table
		 * who knows it may have a new bigger fd table. We need
		 * the latest pointer.
		 */
		spin_lock(&oldf->file_lock);
		old_fdt = files_fdtable(oldf);
		open_files = sane_fdtable_size(old_fdt, max_fds);
	}

	copy_fd_bitmaps(new_fdt, old_fdt, open_files);

	old_fds = old_fdt->fd;
	new_fds = new_fdt->fd;

	for (i = open_files; i != 0; i--) {
		struct file *f = *old_fds++;
		if (f) {
			get_file(f);
		} else {
			/*
			 * The fd may be claimed in the fd bitmap but not yet
			 * instantiated in the files array if a sibling thread
			 * is partway through open().  So make sure that this
			 * fd is available to the new process.
			 */
			__clear_open_fd(open_files - i, new_fdt);
		}
		rcu_assign_pointer(*new_fds++, f);
	}
	spin_unlock(&oldf->file_lock);

	/* clear the remainder */
	memset(new_fds, 0, (new_fdt->max_fds - open_files) * sizeof(struct file *));

	rcu_assign_pointer(newf->fdt, new_fdt);

	return newf;

out_release:
	kmem_cache_free(files_cachep, newf);
out:
	return NULL;
}

static struct fdtable *close_files(struct files_struct * files)
{
	/*
	 * It is safe to dereference the fd table without RCU or
	 * ->file_lock because this is the last reference to the
	 * files structure.
	 */
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	unsigned int i, j = 0;

	for (;;) {
		unsigned long set;
		i = j * BITS_PER_LONG;
		if (i >= fdt->max_fds)
			break;
		set = fdt->open_fds[j++];
		while (set) {
			if (set & 1) {
				struct file * file = xchg(&fdt->fd[i], NULL);
				if (file) {
					filp_close(file, files);
					cond_resched();
				}
			}
			i++;
			set >>= 1;
		}
	}

	return fdt;
}

void put_files_struct(struct files_struct *files)
{
	if (atomic_dec_and_test(&files->count)) {
		struct fdtable *fdt = close_files(files);

		/* free the arrays if they are not embedded */
		if (fdt != &files->fdtab)
			__free_fdtable(fdt);
		kmem_cache_free(files_cachep, files);
	}
}

void exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}

struct files_struct init_files = {
	.count		= ATOMIC_INIT(1),
	.fdt		= &init_files.fdtab,
	.fdtab		= {
		.max_fds	= NR_OPEN_DEFAULT,
		.fd		= &init_files.fd_array[0],
		.close_on_exec	= init_files.close_on_exec_init,
		.open_fds	= init_files.open_fds_init,
		.full_fds_bits	= init_files.full_fds_bits_init,
	},
	.file_lock	= __SPIN_LOCK_UNLOCKED(init_files.file_lock),
	.resize_wait	= __WAIT_QUEUE_HEAD_INITIALIZER(init_files.resize_wait),
};

//找一个未占用的fd
static unsigned int find_next_fd(struct fdtable *fdt, unsigned int start)
{
	unsigned int maxfd = fdt->max_fds;
	unsigned int maxbit = maxfd / BITS_PER_LONG;//将bit索引换算为long类型索引
	unsigned int bitbit = start / BITS_PER_LONG;

	//自full_fds_bits中找出一个有空闲fd的区段，计算结果，并换算区间开始的fd编号
	bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
	if (bitbit > maxfd)
		return maxfd;//规范为maxfd
	if (bitbit > start)
		start = bitbit;
	//在open_fds的start,maxfd位置找一个未打开的fd空间
	return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

/*
 * allocate a file descriptor, mark it busy.
 */
//申请一个文件描述符
static int alloc_fd(unsigned start, unsigned end, unsigned flags)
{
	struct files_struct *files = current->files;
	unsigned int fd;
	int error;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
repeat:
	//取fdt
	fdt = files_fdtable(files);
	fd = start;/*从start位置开始申请（例如从0号fd开始）*/

	/*如果start较小，则更新为next_fd*/
	if (fd < files->next_fd)
		fd = files->next_fd;

	if (fd < fdt->max_fds)
		fd = find_next_fd(fdt, fd);

	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	error = -EMFILE;
	if (fd >= end)
		goto out;//超限，申请失败

	//扩大files的fdtable
	error = expand_files(files, fd);
	if (error < 0)
		goto out;//expand失败

	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	if (error)
		/*在我们执行扩展时，我们被其它线程阻塞过了，
		 * 此时fdtble地址，next_fd可能已发生变换，重新执行一次*/
		goto repeat;

	if (start <= files->next_fd)
		files->next_fd = fd + 1;//下次优先尝试fd+1

	//占用对应的fd
	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		//有exec时close标记，则加入到close_fd_exec
		__set_close_on_exec(fd, fdt);
	else
		//清除相应位标记
		__clear_close_on_exec(fd, fdt);
	error = fd;
#if 1
	/* Sanity check */
	//fd对应的空间必须为空，如果不为空，告警，并置为空
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	/*返回分配的fd*/
	return error;
}

int __get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
	//申请一个未用的fd
	return alloc_fd(0/*从0开始申请*/, nofile, flags);
}

//申请一个未用的fd(自0开始）
int get_unused_fd_flags(unsigned flags)
{
	return __get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE)/*此进程配置的最大fd数目*/);
}
EXPORT_SYMBOL(get_unused_fd_flags);

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__clear_open_fd(fd, fdt);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

void put_unused_fd(unsigned int fd)
{
	struct files_struct *files = current->files;
	spin_lock(&files->file_lock);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
}

EXPORT_SYMBOL(put_unused_fd);

/*
 * Install a file pointer in the fd array.
 *
 * The VFS is full of places where we drop the files lock between
 * setting the open_fds bitmap and installing the file in the file
 * array.  At any such point, we are vulnerable to a dup2() race
 * installing a file in the array before us.  We need to detect this and
 * fput() the struct file we are about to overwrite in this case.
 *
 * It should never happen - if we allow dup2() do it, _really_ bad things
 * will follow.
 *
 * This consumes the "file" refcount, so callers should treat it
 * as if they had called fput(file).
 */

//为fd关联其对应的file
void fd_install(unsigned int fd, struct file *file)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;

	if (WARN_ON_ONCE(unlikely(file->f_mode & FMODE_BACKING)))
		return;

	rcu_read_lock_sched();

	if (unlikely(files->resize_in_progress)) {
		//有其它线程正在resize fdtable,取files->file_lock锁
		//如果拿到锁，则通过fdt->fd[fd]=file要么写在旧的数据结构上
		//resize的线程将其copy到新的fdtable,要么直接写在新的数据结构上
		rcu_read_unlock_sched();
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		BUG_ON(fdt->fd[fd] != NULL);
		rcu_assign_pointer(fdt->fd[fd], file);
		spin_unlock(&files->file_lock);
		return;
	}
	/* coupled with smp_wmb() in expand_fdtable() */
	smp_rmb();
	fdt = rcu_dereference_sched(files->fdt);
	BUG_ON(fdt->fd[fd] != NULL);
	//设置fd对应的file
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
}

EXPORT_SYMBOL(fd_install);

/**
 * file_close_fd_locked - return file associated with fd
 * @files: file struct to retrieve file from
 * @fd: file descriptor to retrieve file for
 *
 * Doesn't take a separate reference count.
 *
 * Context: files_lock must be held.
 *
 * Returns: The file associated with @fd (NULL if @fd is not open)
 */
struct file *file_close_fd_locked(struct files_struct *files, unsigned fd)
{
	struct fdtable *fdt = files_fdtable(files);
	struct file *file;

	lockdep_assert_held(&files->file_lock);

	if (fd >= fdt->max_fds)
		return NULL;

	fd = array_index_nospec(fd, fdt->max_fds);
	file = fdt->fd[fd];
	if (file) {
		rcu_assign_pointer(fdt->fd[fd], NULL);
		__put_unused_fd(files, fd);
	}
	return file;
}

//通过fd找到file,解除fd与file之间的映射，并对其调用filp_close
int close_fd(unsigned fd)
{
	struct files_struct *files = current->files;
	struct file *file;

	spin_lock(&files->file_lock);
	file = file_close_fd_locked(files, fd);
	spin_unlock(&files->file_lock);
	if (!file)
		return -EBADF;

	return filp_close(file, files);
}
EXPORT_SYMBOL(close_fd); /* for ksys_close() */

/**
 * last_fd - return last valid index into fd table
 * @fdt: File descriptor table.
 *
 * Context: Either rcu read lock or files_lock must be held.
 *
 * Returns: Last valid index into fdtable.
 */
static inline unsigned last_fd(struct fdtable *fdt)
{
	return fdt->max_fds - 1;
}

static inline void __range_cloexec(struct files_struct *cur_fds,
				   unsigned int fd, unsigned int max_fd)
{
	struct fdtable *fdt;

	/* make sure we're using the correct maximum value */
	spin_lock(&cur_fds->file_lock);
	fdt = files_fdtable(cur_fds);
	max_fd = min(last_fd(fdt), max_fd);
	if (fd <= max_fd)
		bitmap_set(fdt->close_on_exec, fd, max_fd - fd + 1);
	spin_unlock(&cur_fds->file_lock);
}

static inline void __range_close(struct files_struct *files, unsigned int fd,
				 unsigned int max_fd)
{
	struct file *file;
	unsigned n;

	spin_lock(&files->file_lock);
	n = last_fd(files_fdtable(files));
	max_fd = min(max_fd, n);

	for (; fd <= max_fd; fd++) {
		file = file_close_fd_locked(files, fd);
		if (file) {
			spin_unlock(&files->file_lock);
			filp_close(file, files);
			cond_resched();
			spin_lock(&files->file_lock);
		} else if (need_resched()) {
			spin_unlock(&files->file_lock);
			cond_resched();
			spin_lock(&files->file_lock);
		}
	}
	spin_unlock(&files->file_lock);
}

/**
 * __close_range() - Close all file descriptors in a given range.
 *
 * @fd:     starting file descriptor to close
 * @max_fd: last file descriptor to close
 * @flags:  CLOSE_RANGE flags.
 *
 * This closes a range of file descriptors. All file descriptors
 * from @fd up to and including @max_fd are closed.
 */
int __close_range(unsigned fd, unsigned max_fd, unsigned int flags)
{
	struct task_struct *me = current;
	struct files_struct *cur_fds = me->files, *fds = NULL;

	if (flags & ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC))
		return -EINVAL;

	if (fd > max_fd)
		return -EINVAL;

	if (flags & CLOSE_RANGE_UNSHARE) {
		int ret;
		unsigned int max_unshare_fds = NR_OPEN_MAX;

		/*
		 * If the caller requested all fds to be made cloexec we always
		 * copy all of the file descriptors since they still want to
		 * use them.
		 */
		if (!(flags & CLOSE_RANGE_CLOEXEC)) {
			/*
			 * If the requested range is greater than the current
			 * maximum, we're closing everything so only copy all
			 * file descriptors beneath the lowest file descriptor.
			 */
			rcu_read_lock();
			if (max_fd >= last_fd(files_fdtable(cur_fds)))
				max_unshare_fds = fd;
			rcu_read_unlock();
		}

		ret = unshare_fd(CLONE_FILES, max_unshare_fds, &fds);
		if (ret)
			return ret;

		/*
		 * We used to share our file descriptor table, and have now
		 * created a private one, make sure we're using it below.
		 */
		if (fds)
			swap(cur_fds, fds);
	}

	if (flags & CLOSE_RANGE_CLOEXEC)
		__range_cloexec(cur_fds, fd, max_fd);
	else
		__range_close(cur_fds, fd, max_fd);

	if (fds) {
		/*
		 * We're done closing the files we were supposed to. Time to install
		 * the new file descriptor table and drop the old one.
		 */
		task_lock(me);
		me->files = cur_fds;
		task_unlock(me);
		put_files_struct(fds);
	}

	return 0;
}

/**
 * file_close_fd - return file associated with fd
 * @fd: file descriptor to retrieve file for
 *
 * Doesn't take a separate reference count.
 *
 * Returns: The file associated with @fd (NULL if @fd is not open)
 */
struct file *file_close_fd(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct file *file;

	spin_lock(&files->file_lock);
	file = file_close_fd_locked(files, fd);
	spin_unlock(&files->file_lock);

	return file;
}

void do_close_on_exec(struct files_struct *files)
{
	unsigned i;
	struct fdtable *fdt;

	/* exec unshares first */
	spin_lock(&files->file_lock);
	for (i = 0; ; i++) {
		unsigned long set;
		unsigned fd = i * BITS_PER_LONG;
		fdt = files_fdtable(files);
		if (fd >= fdt->max_fds)
			break;
		set = fdt->close_on_exec[i];
		if (!set)
			continue;
		fdt->close_on_exec[i] = 0;
		for ( ; set ; fd++, set >>= 1) {
			struct file *file;
			if (!(set & 1))
				continue;
			file = fdt->fd[fd];
			if (!file)
				continue;
			rcu_assign_pointer(fdt->fd[fd], NULL);
			__put_unused_fd(files, fd);
			spin_unlock(&files->file_lock);
			filp_close(file, files);
			cond_resched();
			spin_lock(&files->file_lock);
		}

	}
	spin_unlock(&files->file_lock);
}

static struct file *__get_file_rcu(struct file __rcu **f)
{
	struct file __rcu *file;
	struct file __rcu *file_reloaded;
	struct file __rcu *file_reloaded_cmp;

	file = rcu_dereference_raw(*f);
	if (!file)
		return NULL;

	if (unlikely(!atomic_long_inc_not_zero(&file->f_count)))
		return ERR_PTR(-EAGAIN);

	file_reloaded = rcu_dereference_raw(*f);

	/*
	 * Ensure that all accesses have a dependency on the load from
	 * rcu_dereference_raw() above so we get correct ordering
	 * between reuse/allocation and the pointer check below.
	 */
	file_reloaded_cmp = file_reloaded;
	OPTIMIZER_HIDE_VAR(file_reloaded_cmp);

	/*
	 * atomic_long_inc_not_zero() above provided a full memory
	 * barrier when we acquired a reference.
	 *
	 * This is paired with the write barrier from assigning to the
	 * __rcu protected file pointer so that if that pointer still
	 * matches the current file, we know we have successfully
	 * acquired a reference to the right file.
	 *
	 * If the pointers don't match the file has been reallocated by
	 * SLAB_TYPESAFE_BY_RCU.
	 */
	if (file == file_reloaded_cmp)
		return file_reloaded;

	fput(file);
	return ERR_PTR(-EAGAIN);
}

/**
 * get_file_rcu - try go get a reference to a file under rcu
 * @f: the file to get a reference on
 *
 * This function tries to get a reference on @f carefully verifying that
 * @f hasn't been reused.
 *
 * This function should rarely have to be used and only by users who
 * understand the implications of SLAB_TYPESAFE_BY_RCU. Try to avoid it.
 *
 * Return: Returns @f with the reference count increased or NULL.
 */
struct file *get_file_rcu(struct file __rcu **f)
{
	for (;;) {
		struct file __rcu *file;

		file = __get_file_rcu(f);
		if (unlikely(!file))
			return NULL;

		if (unlikely(IS_ERR(file)))
			continue;

		return file;
	}
}
EXPORT_SYMBOL_GPL(get_file_rcu);

/**
 * get_file_active - try go get a reference to a file
 * @f: the file to get a reference on
 *
 * In contast to get_file_rcu() the pointer itself isn't part of the
 * reference counting.
 *
 * This function should rarely have to be used and only by users who
 * understand the implications of SLAB_TYPESAFE_BY_RCU. Try to avoid it.
 *
 * Return: Returns @f with the reference count increased or NULL.
 */
struct file *get_file_active(struct file **f)
{
	struct file __rcu *file;

	rcu_read_lock();
	file = __get_file_rcu(f);
	rcu_read_unlock();
	if (IS_ERR(file))
		file = NULL;
	return file;
}
EXPORT_SYMBOL_GPL(get_file_active);

static inline struct file *__fget_files_rcu(struct files_struct *files,
       unsigned int fd, fmode_t mask)
{
	for (;;) {
		struct file *file;
		struct fdtable *fdt = rcu_dereference_raw(files->fdt);
		struct file __rcu **fdentry;
		unsigned long nospec_mask;

		/* Mask is a 0 for invalid fd's, ~0 for valid ones */
		nospec_mask = array_index_mask_nospec(fd, fdt->max_fds);

		/*
		 * fdentry points to the 'fd' offset, or fdt->fd[0].
		 * Loading from fdt->fd[0] is always safe, because the
		 * array always exists.
		 */
		fdentry = fdt->fd + (fd & nospec_mask);

		/* Do the load, then mask any invalid result */
		file = rcu_dereference_raw(*fdentry);
		file = (void *)(nospec_mask & (unsigned long)file);
		if (unlikely(!file))
			return NULL;

		/*
		 * Ok, we have a file pointer that was valid at
		 * some point, but it might have become stale since.
		 *
		 * We need to confirm it by incrementing the refcount
		 * and then check the lookup again.
		 *
		 * atomic_long_inc_not_zero() gives us a full memory
		 * barrier. We only really need an 'acquire' one to
		 * protect the loads below, but we don't have that.
		 */
		if (unlikely(!atomic_long_inc_not_zero(&file->f_count)))
			continue;

		/*
		 * Such a race can take two forms:
		 *
		 *  (a) the file ref already went down to zero and the
		 *      file hasn't been reused yet or the file count
		 *      isn't zero but the file has already been reused.
		 *
		 *  (b) the file table entry has changed under us.
		 *       Note that we don't need to re-check the 'fdt->fd'
		 *       pointer having changed, because it always goes
		 *       hand-in-hand with 'fdt'.
		 *
		 * If so, we need to put our ref and try again.
		 */
		if (unlikely(file != rcu_dereference_raw(*fdentry)) ||
		    unlikely(rcu_dereference_raw(files->fdt) != fdt)) {
			fput(file);
			continue;
		}

		/*
		 * This isn't the file we're looking for or we're not
		 * allowed to get a reference to it.
		 */
		if (unlikely(file->f_mode & mask)) {
			fput(file);
			return NULL;
		}

		/*
		 * Ok, we have a ref to the file, and checked that it
		 * still exists.
		 */
		return file;
	}
}

//通过fd，mask查找对应的file
static struct file *__fget_files(struct files_struct *files, unsigned int fd,
				 fmode_t mask)
{
	struct file *file;

	rcu_read_lock();
	//查找fd对应的file
	file = __fget_files_rcu(files, fd, mask);
	rcu_read_unlock();

	return file;
}

static inline struct file *__fget(unsigned int fd, fmode_t mask)
{
	return __fget_files(current->files, fd, mask);
}

struct file *fget(unsigned int fd)
{
	//返回fd对应的文件，此文件不能是O_PATH方式打开的
	return __fget(fd, FMODE_PATH);
}
EXPORT_SYMBOL(fget);

struct file *fget_raw(unsigned int fd)
{
	/*通过fd获得其对应的file*/
	return __fget(fd, 0);
}
EXPORT_SYMBOL(fget_raw);

struct file *fget_task(struct task_struct *task, unsigned int fd)
{
	struct file *file = NULL;

	task_lock(task);
	if (task->files)
		file = __fget_files(task->files, fd, 0);
	task_unlock(task);

	return file;
}

struct file *lookup_fdget_rcu(unsigned int fd)
{
	return __fget_files_rcu(current->files, fd, 0);

}
EXPORT_SYMBOL_GPL(lookup_fdget_rcu);

struct file *task_lookup_fdget_rcu(struct task_struct *task, unsigned int fd)
{
	/* Must be called with rcu_read_lock held */
	struct files_struct *files;
	struct file *file = NULL;

	task_lock(task);
	files = task->files;
	if (files)
		file = __fget_files_rcu(files, fd, 0);
	task_unlock(task);

	return file;
}

struct file *task_lookup_next_fdget_rcu(struct task_struct *task, unsigned int *ret_fd)
{
	/* Must be called with rcu_read_lock held */
	struct files_struct *files;
	unsigned int fd = *ret_fd;
	struct file *file = NULL;

	task_lock(task);
	files = task->files;
	if (files) {
		for (; fd < files_fdtable(files)->max_fds; fd++) {
			file = __fget_files_rcu(files, fd, 0);
			if (file)
				break;
		}
	}
	task_unlock(task);
	*ret_fd = fd;
	return file;
}
EXPORT_SYMBOL(task_lookup_next_fdget_rcu);

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared.
 *
 * You can use this instead of fget if you satisfy all of the following
 * conditions:
 * 1) You must call fput_light before exiting the syscall and returning control
 *    to userspace (i.e. you cannot remember the returned struct file * after
 *    returning to userspace).
 * 2) You must not call filp_close on the returned struct file * in between
 *    calls to fget_light and fput_light.
 * 3) You must not clone the current task in between the calls to fget_light
 *    and fput_light.
 *
 * The fput_needed flag returned by fget_light should be passed to the
 * corresponding fput_light.
 */
static unsigned long __fget_light(unsigned int fd, fmode_t mask)
{
	//取当前进程打开的文件列表
	struct files_struct *files = current->files;
	struct file *file;

	/*
	 * If another thread is concurrently calling close_fd() followed
	 * by put_files_struct(), we must not observe the old table
	 * entry combined with the new refcount - otherwise we could
	 * return a file that is concurrently being freed.
	 *
	 * atomic_read_acquire() pairs with atomic_dec_and_test() in
	 * put_files_struct().
	 */
	if (likely(atomic_read_acquire(&files->count) == 1)) {
		file = files_lookup_fd_raw(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		//查找fd对应的file
		file = __fget_files(files, fd, mask);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}
unsigned long __fdget(unsigned int fd)
{
	return __fget_light(fd, FMODE_PATH);
}
EXPORT_SYMBOL(__fdget);

unsigned long __fdget_raw(unsigned int fd)
{
	return __fget_light(fd, 0);
}

/*
 * Try to avoid f_pos locking. We only need it if the
 * file is marked for FMODE_ATOMIC_POS, and it can be
 * accessed multiple ways.
 *
 * Always do it for directories, because pidfd_getfd()
 * can make a file accessible even if it otherwise would
 * not be, and for directories this is a correctness
 * issue, not a "POSIX requirement".
 */
static inline bool file_needs_f_pos_lock(struct file *file)
{
	return (file->f_mode & FMODE_ATOMIC_POS) &&
		(file_count(file) > 1 || file->f_op->iterate_shared);
}

unsigned long __fdget_pos(unsigned int fd)
{
	unsigned long v = __fdget(fd);
	struct file *file = (struct file *)(v & ~3);

	if (file && file_needs_f_pos_lock(file)) {
		v |= FDPUT_POS_UNLOCK;
		mutex_lock(&file->f_pos_lock);
	}
	return v;
}

void __f_unlock_pos(struct file *f)
{
	mutex_unlock(&f->f_pos_lock);
}

/*
 * We only lock f_pos if we have threads or if the file might be
 * shared with another process. In both cases we'll have an elevated
 * file count (done either by fdget() or by fork()).
 */

void set_close_on_exec(unsigned int fd, int flag)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (flag)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);
}

bool get_close_on_exec(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	bool res;
	rcu_read_lock();
	fdt = files_fdtable(files);
	res = close_on_exec(fd, fdt);
	rcu_read_unlock();
	return res;
}

static int do_dup2(struct files_struct *files,
	struct file *file, unsigned fd, unsigned flags)
__releases(&files->file_lock)
{
	struct file *tofree;
	struct fdtable *fdt;

	/*
	 * We need to detect attempts to do dup2() over allocated but still
	 * not finished descriptor.  NB: OpenBSD avoids that at the price of
	 * extra work in their equivalent of fget() - they insert struct
	 * file immediately after grabbing descriptor, mark it larval if
	 * more work (e.g. actual opening) is needed and make sure that
	 * fget() treats larval files as absent.  Potentially interesting,
	 * but while extra work in fget() is trivial, locking implications
	 * and amount of surgery on open()-related paths in VFS are not.
	 * FreeBSD fails with -EBADF in the same situation, NetBSD "solution"
	 * deadlocks in rather amusing ways, AFAICS.  All of that is out of
	 * scope of POSIX or SUS, since neither considers shared descriptor
	 * tables and this condition does not arise without those.
	 */
	fdt = files_fdtable(files);
	tofree = fdt->fd[fd];
	if (!tofree && fd_is_open(fd, fdt))
		goto Ebusy;
	get_file(file);
	rcu_assign_pointer(fdt->fd[fd], file);
	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);

	if (tofree)
		filp_close(tofree, files);

	return fd;

Ebusy:
	spin_unlock(&files->file_lock);
	return -EBUSY;
}

int replace_fd(unsigned fd, struct file *file, unsigned flags)
{
	int err;
	struct files_struct *files = current->files;

	if (!file)
		return close_fd(fd);

	if (fd >= rlimit(RLIMIT_NOFILE))
		/*fd超过此进程的最大数*/
		return -EBADF;

	spin_lock(&files->file_lock);
	err = expand_files(files, fd);
	if (unlikely(err < 0))
		goto out_unlock;
	return do_dup2(files, file, fd, flags);

out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

/**
 * receive_fd() - Install received file into file descriptor table
 * @file: struct file that was received from another process
 * @ufd: __user pointer to write new fd number to
 * @o_flags: the O_* flags to apply to the new fd entry
 *
 * Installs a received file into the file descriptor table, with appropriate
 * checks and count updates. Optionally writes the fd number to userspace, if
 * @ufd is non-NULL.
 *
 * This helper handles its own reference counting of the incoming
 * struct file.
 *
 * Returns newly install fd or -ve on error.
 */
int receive_fd(struct file *file, int __user *ufd, unsigned int o_flags)
{
	int new_fd;
	int error;

	error = security_file_receive(file);
	if (error)
		return error;

	new_fd = get_unused_fd_flags(o_flags);/*取得一个新的fd*/
	if (new_fd < 0)
		return new_fd;

	if (ufd) {
		error = put_user(new_fd, ufd);
		if (error) {
			put_unused_fd(new_fd);
			return error;
		}
	}

	fd_install(new_fd, get_file(file));/*此fd与file关联*/
	__receive_sock(file);
	return new_fd;
}
EXPORT_SYMBOL_GPL(receive_fd);

int receive_fd_replace(int new_fd, struct file *file, unsigned int o_flags)
{
	int error;

	error = security_file_receive(file);
	if (error)
		return error;
	error = replace_fd(new_fd, file, o_flags);
	if (error)
		return error;
	__receive_sock(file);
	return new_fd;
}

static int ksys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	int err = -EBADF;
	struct file *file;
	struct files_struct *files = current->files;

	if ((flags & ~O_CLOEXEC) != 0)
		return -EINVAL;

	if (unlikely(oldfd == newfd))
		return -EINVAL;

	if (newfd >= rlimit(RLIMIT_NOFILE))
		/*新的fd超过此进程设置的最大数*/
		return -EBADF;

	spin_lock(&files->file_lock);
	err = expand_files(files, newfd);
	file = files_lookup_fd_locked(files, oldfd);
	if (unlikely(!file))
		goto Ebadf;
	if (unlikely(err < 0)) {
		if (err == -EMFILE)
			goto Ebadf;
		goto out_unlock;
	}
	return do_dup2(files, file, newfd, flags);

Ebadf:
	err = -EBADF;
out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
{
	return ksys_dup3(oldfd, newfd, flags);
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	if (unlikely(newfd == oldfd)) { /* corner case */
		struct files_struct *files = current->files;
		struct file *f;
		int retval = oldfd;

		rcu_read_lock();
		f = __fget_files_rcu(files, oldfd, 0);
		if (!f)
			retval = -EBADF;
		rcu_read_unlock();
		if (f)
			fput(f);
		return retval;
	}
	return ksys_dup3(oldfd, newfd, 0);
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	int ret = -EBADF;
	struct file *file = fget_raw(fildes);

	if (file) {
		ret = get_unused_fd_flags(0);
		if (ret >= 0)
			fd_install(ret, file);
		else
			fput(file);
	}
	return ret;
}

int f_dupfd(unsigned int from, struct file *file, unsigned flags)
{
	unsigned long nofile = rlimit(RLIMIT_NOFILE);/*此进程支持的最大file数目*/
	int err;
	if (from >= nofile)
		return -EINVAL;
	err = alloc_fd(from, nofile, flags);
	if (err >= 0) {
		get_file(file);
		fd_install(err, file);
	}
	return err;
}

//通过f函数遍历files
int iterate_fd(struct files_struct *files, unsigned n,
		int (*f)(const void *, struct file *, unsigned),
		const void *p)
{
	struct fdtable *fdt;
	int res = 0;
	if (!files)
		return 0;
	spin_lock(&files->file_lock);
	//遍历所有fds,逐个得到file,并调用f函数
	for (fdt = files_fdtable(files); n < fdt->max_fds; n++) {
		struct file *file;
		file = rcu_dereference_check_fdtable(files, fdt->fd[n]);
		if (!file)
			continue;
		//调用函数f
		res = f(p, file, n);
		if (res)
			break;
	}
	spin_unlock(&files->file_lock);
	return res;
}
EXPORT_SYMBOL(iterate_fd);
