/* SPDX-License-Identifier: GPL-2.0 */
/*
 * descriptor table internals; you almost certainly want file.h instead.
 */

#ifndef __LINUX_FDTABLE_H
#define __LINUX_FDTABLE_H

#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/nospec.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <linux/atomic.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

struct fdtable {
	//最大fd数目（也是当前fd数组的大小）
	unsigned int max_fds;
	//记录struct file*的fd数组(每个fd对应一个struct file)
	struct file __rcu **fd;      /* current fd array */
	//指向close_on_exec的fds bitmap
	unsigned long *close_on_exec;
	//记录已经open的fd(bitmap形式,仅需要释放open_fds即可完成close_on_exec,full_fds_bits的释放）
	unsigned long *open_fds;
	//指向full_fds的bitmaps（用于表示open_fds[i]开始的sizeof(long)*8个fd均已分配出去）
	//即[i*sizeof(long)*8,(i+1)*sizeof(long)*8]范围内的fd均已分配出去
	unsigned long *full_fds_bits;
	struct rcu_head rcu;
};

/*
 * Open file table structure
 */
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	//指明当前正在执行fdtable的size调整
	bool resize_in_progress;
	//等待队列，用于等待其它线程的resize过程完成
	wait_queue_head_t resize_wait;

	//fdtable,提供通过fd编号查找struct file指针
	struct fdtable __rcu *fdt;
	struct fdtable fdtab;//提供静态大小的默认fdtable,但fdt仍可指向一个动态申请的内存
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	unsigned int next_fd;//需要优先尝试的fd，此fd之前的均已分配出去了
	unsigned long close_on_exec_init[1];
	unsigned long open_fds_init[1];
	unsigned long full_fds_bits_init[1];
	struct file __rcu * fd_array[NR_OPEN_DEFAULT];
};

struct file_operations;
struct vfsmount;
struct dentry;

//取当前files对应的fdtable
#define rcu_dereference_check_fdtable(files, fdtfd) \
	rcu_dereference_check((fdtfd), lockdep_is_held(&(files)->file_lock))

#define files_fdtable(files) \
	rcu_dereference_check_fdtable((files), (files)->fdt)

/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *files_lookup_fd_raw(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	unsigned long mask = array_index_mask_nospec(fd, fdt->max_fds);
	struct file *needs_masking;

	/*
	 * 'mask' is zero for an out-of-bounds fd, all ones for ok.
	 * 'fd&mask' is 'fd' for ok, or 0 for out of bounds.
	 *
	 * Accessing fdt->fd[0] is ok, but needs masking of the result.
	 */
	needs_masking = rcu_dereference_raw(fdt->fd[fd&mask]);
	return (struct file *)(mask & (unsigned long)needs_masking);
}

//获取fd对应的files
static inline struct file *files_lookup_fd_locked(struct files_struct *files, unsigned int fd)
{
	RCU_LOCKDEP_WARN(!lockdep_is_held(&files->file_lock),
			   "suspicious rcu_dereference_check() usage");
	return files_lookup_fd_raw(files, fd);
}

static inline bool close_on_exec(unsigned int fd, const struct files_struct *files)
{
	return test_bit(fd, files_fdtable(files)->close_on_exec);
}

struct task_struct;

void put_files_struct(struct files_struct *fs);
int unshare_files(void);
struct fd_range {
	unsigned int from, to;
};
struct files_struct *dup_fd(struct files_struct *, struct fd_range *) __latent_entropy;
void do_close_on_exec(struct files_struct *);
int iterate_fd(struct files_struct *, unsigned,
		int (*)(const void *, struct file *, unsigned),
		const void *);

extern int close_fd(unsigned int fd);
extern struct file *file_close_fd(unsigned int fd);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FDTABLE_H */
