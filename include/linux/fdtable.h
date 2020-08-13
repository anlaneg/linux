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
#define NR_OPEN_MAX ~0U

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

static inline bool close_on_exec(unsigned int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->close_on_exec);
}

static inline bool fd_is_open(unsigned int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->open_fds);
}

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
static inline struct file *__fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);

	if (fd < fdt->max_fds) {
		//提取fd对应的file
		fd = array_index_nospec(fd, fdt->max_fds);
		return rcu_dereference_raw(fdt->fd[fd]);
	}
	//给出的fd过大，返回NULL
	return NULL;
}

//获取fd对应的files
static inline struct file *fcheck_files(struct files_struct *files, unsigned int fd)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_held() &&
			   !lockdep_is_held(&files->file_lock),
			   "suspicious rcu_dereference_check() usage");
	return __fcheck_files(files, fd);
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void put_files_struct(struct files_struct *fs);
void reset_files_struct(struct files_struct *);
int unshare_files(struct files_struct **);
struct files_struct *dup_fd(struct files_struct *, unsigned, int *) __latent_entropy;
void do_close_on_exec(struct files_struct *);
int iterate_fd(struct files_struct *, unsigned,
		int (*)(const void *, struct file *, unsigned),
		const void *);

extern int __alloc_fd(struct files_struct *files,
		      unsigned start, unsigned end, unsigned flags);
extern void __fd_install(struct files_struct *files,
		      unsigned int fd, struct file *file);
extern int __close_fd(struct files_struct *files,
		      unsigned int fd);
extern int __close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);
extern int __close_fd_get_file(unsigned int fd, struct file **res);
extern int unshare_fd(unsigned long unshare_flags, unsigned int max_fds,
		      struct files_struct **new_fdp);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FDTABLE_H */
