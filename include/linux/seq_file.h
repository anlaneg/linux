/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SEQ_FILE_H
#define _LINUX_SEQ_FILE_H

#include <linux/types.h>
#include <linux/string.h>
#include <linux/string_helpers.h>
#include <linux/bug.h>
#include <linux/mutex.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>
#include <linux/fs.h>
#include <linux/cred.h>

struct seq_operations;

struct seq_file {
	char *buf;//用于缓存文件内容
	size_t size;//用于记录buf的长度
	size_t from;//buf中有效数据起点
	size_t count;//buf中自from有效数据数量
	size_t pad_until;
	loff_t index;
	loff_t read_pos;//读取的偏移量
	struct mutex lock;
	const struct seq_operations *op;//操作集
	int poll_event;
	const struct file *file;//指向file,file的private_data指向seq_file,实现互指
	void *private;//指向struct kernfs_open_file
};

struct seq_operations {
    //创建一个迭代器
	void * (*start) (struct seq_file *m, loff_t *pos);
	//当迭代完成时被调用，用于执行清理工作
	void (*stop) (struct seq_file *m, void *v);
	//移动迭代器到下一个序号位置
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	//格式化迭代器指向的对象完成格式化
	int (*show) (struct seq_file *m, void *v);
};

#define SEQ_SKIP 1

/**
 * seq_has_overflowed - check if the buffer has overflowed
 * @m: the seq_file handle
 *
 * seq_files have a buffer which may overflow. When this happens a larger
 * buffer is reallocated and all the data will be printed again.
 * The overflow state is true when m->count == m->size.
 *
 * Returns true if the buffer received more than it can hold.
 */
static inline bool seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}

/**
 * seq_get_buf - get buffer to write arbitrary data to
 * @m: the seq_file handle
 * @bufp: the beginning of the buffer is stored here
 *
 * Return the number of bytes available in the buffer, or zero if
 * there's no space.
 */
//获取seq_file中可写书的buf长度，可书写的buf起始位置
static inline size_t seq_get_buf(struct seq_file *m, char **bufp)
{
	//seq_file中的已读取的数据长度一定小于缓冲区可提供的数据长度
	BUG_ON(m->count > m->size);
	if (m->count < m->size)
		*bufp = m->buf + m->count;//可以填充的区域
	else
		*bufp = NULL;//ｍ->count=m->size时

	return m->size - m->count;//可以填充的区域的大小
}

/**
 * seq_commit - commit data to the buffer
 * @m: the seq_file handle
 * @num: the number of bytes to commit
 *
 * Commit @num bytes of data written to a buffer previously acquired
 * by seq_buf_get.  To signal an error condition, or that the data
 * didn't fit in the available space, pass a negative @num value.
 */
static inline void seq_commit(struct seq_file *m, int num)
{
	if (num < 0) {
		m->count = m->size;//如果num小于0，将有效数据变更为m->size,即页的整数倍
	} else {
		BUG_ON(m->count + num > m->size);
		m->count += num;//如果num大于0，则有效数据增加m字节
	}
}

/**
 * seq_setwidth - set padding width
 * @m: the seq_file handle
 * @size: the max number of bytes to pad.
 *
 * Call seq_setwidth() for setting max width, then call seq_printf() etc. and
 * finally call seq_pad() to pad the remaining bytes.
 */
static inline void seq_setwidth(struct seq_file *m, size_t size)
{
	m->pad_until = m->count + size;
}
void seq_pad(struct seq_file *m, char c);

char *mangle_path(char *s, const char *p, const char *esc);
int seq_open(struct file *, const struct seq_operations *);
ssize_t seq_read(struct file *, char __user *, size_t, loff_t *);
ssize_t seq_read_iter(struct kiocb *iocb, struct iov_iter *iter);
loff_t seq_lseek(struct file *, loff_t, int);
int seq_release(struct inode *, struct file *);
int seq_write(struct seq_file *seq, const void *data, size_t len);

__printf(2, 0)
void seq_vprintf(struct seq_file *m, const char *fmt, va_list args);
__printf(2, 3)
void seq_printf(struct seq_file *m, const char *fmt, ...);
void seq_putc(struct seq_file *m, char c);
void seq_puts(struct seq_file *m, const char *s);
void seq_put_decimal_ull_width(struct seq_file *m, const char *delimiter,
			       unsigned long long num, unsigned int width);
void seq_put_decimal_ull(struct seq_file *m, const char *delimiter,
			 unsigned long long num);
void seq_put_decimal_ll(struct seq_file *m, const char *delimiter, long long num);
void seq_put_hex_ll(struct seq_file *m, const char *delimiter,
		    unsigned long long v, unsigned int width);

void seq_escape_mem(struct seq_file *m, const char *src, size_t len,
		    unsigned int flags, const char *esc);

static inline void seq_escape_str(struct seq_file *m, const char *src,
				  unsigned int flags, const char *esc)
{
	seq_escape_mem(m, src, strlen(src)/*字符串长度*/, flags, esc);
}

/**
 * seq_escape - print string into buffer, escaping some characters
 * @m: target buffer
 * @s: NULL-terminated string
 * @esc: set of characters that need escaping
 *
 * Puts string into buffer, replacing each occurrence of character from
 * @esc with usual octal escape.
 *
 * Use seq_has_overflowed() to check for errors.
 */
static inline void seq_escape(struct seq_file *m, const char *s, const char *esc)
{
	seq_escape_str(m, s, ESCAPE_OCTAL, esc);
}

void seq_hex_dump(struct seq_file *m, const char *prefix_str, int prefix_type,
		  int rowsize, int groupsize, const void *buf, size_t len,
		  bool ascii);

int seq_path(struct seq_file *, const struct path *, const char *);
int seq_file_path(struct seq_file *, struct file *, const char *);
int seq_dentry(struct seq_file *, struct dentry *, const char *);
int seq_path_root(struct seq_file *m, const struct path *path,
		  const struct path *root, const char *esc);

void *single_start(struct seq_file *, loff_t *);
int single_open(struct file *, int (*)(struct seq_file *, void *), void *);
int single_open_size(struct file *, int (*)(struct seq_file *, void *), void *, size_t);
int single_release(struct inode *, struct file *);
void *__seq_open_private(struct file *, const struct seq_operations *, int);
int seq_open_private(struct file *, const struct seq_operations *, int);
int seq_release_private(struct inode *, struct file *);

#ifdef CONFIG_BINARY_PRINTF
void seq_bprintf(struct seq_file *m, const char *f, const u32 *binary);
#endif

#define DEFINE_SEQ_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	int ret = seq_open(file, &__name ## _sops);			\
	if (!ret && inode->i_private) {					\
		struct seq_file *seq_f = file->private_data;		\
		seq_f->private = inode->i_private;			\
	}								\
	return ret;							\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= seq_release,					\
}

#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}

#define DEFINE_SHOW_STORE_ATTRIBUTE(__name)				\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.write		= __name ## _write,				\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}

#define DEFINE_PROC_SHOW_ATTRIBUTE(__name)				\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, pde_data(inode));	\
}									\
									\
static const struct proc_ops __name ## _proc_ops = {			\
	.proc_open	= __name ## _open,				\
	.proc_read	= seq_read,					\
	.proc_lseek	= seq_lseek,					\
	.proc_release	= single_release,				\
}

static inline struct user_namespace *seq_user_ns(struct seq_file *seq)
{
#ifdef CONFIG_USER_NS
	return seq->file->f_cred->user_ns;
#else
	extern struct user_namespace init_user_ns;
	return &init_user_ns;
#endif
}

/**
 * seq_show_options - display mount options with appropriate escapes.
 * @m: the seq_file handle
 * @name: the mount option name
 * @value: the mount option name's value, can be NULL
 */
static inline void seq_show_option(struct seq_file *m, const char *name/*选项名称*/,
				   const char *value)
{
	seq_putc(m, ',');
	seq_escape(m, name, ",= \t\n\\");
	if (value) {
		seq_putc(m, '=');
		seq_escape(m, value, ", \t\n\\");
	}
}

/**
 * seq_show_option_n - display mount options with appropriate escapes
 *		       where @value must be a specific length (i.e.
 *		       not NUL-terminated).
 * @m: the seq_file handle
 * @name: the mount option name
 * @value: the mount option name's value, cannot be NULL
 * @length: the exact length of @value to display, must be constant expression
 *
 * This is a macro since this uses "length" to define the size of the
 * stack buffer.
 */
#define seq_show_option_n(m, name, value, length) {	\
	char val_buf[length + 1];			\
	memcpy(val_buf, value, length);			\
	val_buf[length] = '\0';				\
	seq_show_option(m, name, val_buf);		\
}

#define SEQ_START_TOKEN ((void *)1)
/*
 * Helpers for iteration over list_head-s in seq_files
 */

extern struct list_head *seq_list_start(struct list_head *head,
		loff_t pos);
extern struct list_head *seq_list_start_head(struct list_head *head,
		loff_t pos);
extern struct list_head *seq_list_next(void *v, struct list_head *head,
		loff_t *ppos);

extern struct list_head *seq_list_start_rcu(struct list_head *head, loff_t pos);
extern struct list_head *seq_list_start_head_rcu(struct list_head *head, loff_t pos);
extern struct list_head *seq_list_next_rcu(void *v, struct list_head *head, loff_t *ppos);

/*
 * Helpers for iteration over hlist_head-s in seq_files
 */

extern struct hlist_node *seq_hlist_start(struct hlist_head *head,
					  loff_t pos);
extern struct hlist_node *seq_hlist_start_head(struct hlist_head *head,
					       loff_t pos);
extern struct hlist_node *seq_hlist_next(void *v, struct hlist_head *head,
					 loff_t *ppos);

extern struct hlist_node *seq_hlist_start_rcu(struct hlist_head *head,
					      loff_t pos);
extern struct hlist_node *seq_hlist_start_head_rcu(struct hlist_head *head,
						   loff_t pos);
extern struct hlist_node *seq_hlist_next_rcu(void *v,
						   struct hlist_head *head,
						   loff_t *ppos);

/* Helpers for iterating over per-cpu hlist_head-s in seq_files */
extern struct hlist_node *seq_hlist_start_percpu(struct hlist_head __percpu *head, int *cpu, loff_t pos);

extern struct hlist_node *seq_hlist_next_percpu(void *v, struct hlist_head __percpu *head, int *cpu, loff_t *pos);

void seq_file_init(void);
#endif
