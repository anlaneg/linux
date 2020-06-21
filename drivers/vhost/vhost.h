/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _VHOST_H
#define _VHOST_H

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/atomic.h>
#include <linux/vhost_iotlb.h>

struct vhost_work;
typedef void (*vhost_work_fn_t)(struct vhost_work *work);

#define VHOST_WORK_QUEUED 1
struct vhost_work {
	struct llist_node	  node;
	vhost_work_fn_t		  fn;
	unsigned long		  flags;
};

/* Poll a file (eventfd or socket) */
/* Note: there's nothing vhost specific about this structure. */
struct vhost_poll {
	poll_table                table;
	wait_queue_head_t        *wqh;
	wait_queue_entry_t              wait;
	struct vhost_work	  work;
	__poll_t		  mask;
	struct vhost_dev	 *dev;
};

void vhost_work_init(struct vhost_work *work, vhost_work_fn_t fn);
void vhost_work_queue(struct vhost_dev *dev, struct vhost_work *work);
bool vhost_has_work(struct vhost_dev *dev);

void vhost_poll_init(struct vhost_poll *poll, vhost_work_fn_t fn,
		     __poll_t mask, struct vhost_dev *dev);
int vhost_poll_start(struct vhost_poll *poll, struct file *file);
void vhost_poll_stop(struct vhost_poll *poll);
void vhost_poll_flush(struct vhost_poll *poll);
void vhost_poll_queue(struct vhost_poll *poll);
void vhost_work_flush(struct vhost_dev *dev, struct vhost_work *work);
long vhost_vring_ioctl(struct vhost_dev *d, unsigned int ioctl, void __user *argp);

struct vhost_log {
	u64 addr;
	u64 len;
};

enum vhost_uaddr_type {
	VHOST_ADDR_DESC = 0,
	VHOST_ADDR_AVAIL = 1,
	VHOST_ADDR_USED = 2,
	VHOST_NUM_ADDRS = 3,
};

/* The virtqueue structure describes a queue attached to a device. */
struct vhost_virtqueue {
	struct vhost_dev *dev;

	/* The actual ring of buffers. */
	struct mutex mutex;
	unsigned int num;//队列长度
	struct vring_desc __user *desc;/*用户态指定的desc表起始地址*/
	//avail表中存放的是可用的描述符（desc）索引，其长度与vq一致
	struct vring_avail __user *avail;/*用户态指定的avail表起始地址*/
	struct vring_used __user *used;/*用户态指定的use表起始地址*/
	const struct vhost_iotlb_map *meta_iotlb[VHOST_NUM_ADDRS];
	struct file *kick;/*用户态通过VHOST_SET_VRING_KICK传入的eventfd*/
	struct eventfd_ctx *call_ctx;//通过此eventfd告知guest，有数据到达
	struct eventfd_ctx *error_ctx;
	struct eventfd_ctx *log_ctx;

	struct vhost_poll poll;

	/* The routine to call when the Guest pings us, or timeout. */
	//guest与我们相互ping时通过rx,tx队列的handle_kick进行
	vhost_work_fn_t handle_kick;

	/* Last available index we saw. */
	u16 last_avail_idx;/*记录我们读取到的avail表位置*/

	/* Caches available index value from user. */
	u16 avail_idx;/*记录当前我们可读取的avail表最大位置*/

	/* Last index we used. */
	u16 last_used_idx;//指出可存放used的起始索引

	/* Used flags */
	u16 used_flags;

	/* Last used index value we have signalled on */
	u16 signalled_used;

	/* Last used index value we have signalled on */
	bool signalled_used_valid;

	/* Log writes to used structure. */
	bool log_used;/*是否支持VHOST_VRING_F_LOG*/
	u64 log_addr;/*用户态指定的log起始地址*/

	struct iovec iov[UIO_MAXIOV];
	struct iovec iotlb_iov[64];
	struct iovec *indirect;
	struct vring_used_elem *heads;
	/* Protected by virtqueue mutex. */
	struct vhost_iotlb *umem;/*用户态指定的memory region情况*/
	struct vhost_iotlb *iotlb;
	void *private_data;/*vq的后端，例如vsock*/
	u64 acked_features;/*通过VHOST_SET_FEATURES开启的功能*/
	u64 acked_backend_features;/*通过VHOST_SET_BACKEND_FEATURES开启的backend功能*/
	/* Log write descriptors */
	void __user *log_base;/*用户态指定的log base*/
	struct vhost_log *log;

	/* Ring endianness. Defaults to legacy native endianness.
	 * Set to true when starting a modern virtio device. */
	bool is_le;/*是否使用小端*/
#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
	/* Ring endianness requested by userspace for cross-endian support. */
	bool user_be;
#endif
	u32 busyloop_timeout;
};

struct vhost_msg_node {
  union {
	  struct vhost_msg msg;
	  struct vhost_msg_v2 msg_v2;
  };
  struct vhost_virtqueue *vq;
  struct list_head node;
};

struct vhost_dev {
	struct mm_struct *mm;
	struct mutex mutex;
	struct vhost_virtqueue **vqs;/*设备虚拟队列*/
	int nvqs;/*虚队列数目*/
	struct eventfd_ctx *log_ctx;/*用户态通过VHOST_SET_LOG_FD指定的eventfd_ctx*/
	/*内核线程vhost-$(owner-pid)将执行挂接在此链表上的所有work*/
	struct llist_head work_list;
	//内核线程，用于处理work_list上所有的vhost_work的回调
	struct task_struct *worker;
	struct vhost_iotlb *umem;/*用户态指定的mem region*/
	struct vhost_iotlb *iotlb;
	spinlock_t iotlb_lock;
	struct list_head read_list;
	struct list_head pending_list;
	wait_queue_head_t wait;
	int iov_limit;
	int weight;
	int byte_weight;
	u64 kcov_handle;
	/*消息处理回调（由vhost_dev_init设置）*/
	int (*msg_handler)(struct vhost_dev *dev,
			   struct vhost_iotlb_msg *msg);
};

bool vhost_exceeds_weight(struct vhost_virtqueue *vq, int pkts, int total_len);
void vhost_dev_init(struct vhost_dev *, struct vhost_virtqueue **vqs,
		    int nvqs, int iov_limit, int weight, int byte_weight,
		    int (*msg_handler)(struct vhost_dev *dev,
				       struct vhost_iotlb_msg *msg));
long vhost_dev_set_owner(struct vhost_dev *dev);
bool vhost_dev_has_owner(struct vhost_dev *dev);
long vhost_dev_check_owner(struct vhost_dev *);
struct vhost_iotlb *vhost_dev_reset_owner_prepare(void);
void vhost_dev_reset_owner(struct vhost_dev *dev, struct vhost_iotlb *iotlb);
void vhost_dev_cleanup(struct vhost_dev *);
void vhost_dev_stop(struct vhost_dev *);
long vhost_dev_ioctl(struct vhost_dev *, unsigned int ioctl, void __user *argp);
long vhost_vring_ioctl(struct vhost_dev *d, unsigned int ioctl, void __user *argp);
bool vhost_vq_access_ok(struct vhost_virtqueue *vq);
bool vhost_log_access_ok(struct vhost_dev *);

int vhost_get_vq_desc(struct vhost_virtqueue *,
		      struct iovec iov[], unsigned int iov_count,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num);
void vhost_discard_vq_desc(struct vhost_virtqueue *, int n);

int vhost_vq_init_access(struct vhost_virtqueue *);
int vhost_add_used(struct vhost_virtqueue *, unsigned int head, int len);
int vhost_add_used_n(struct vhost_virtqueue *, struct vring_used_elem *heads,
		     unsigned count);
void vhost_add_used_and_signal(struct vhost_dev *, struct vhost_virtqueue *,
			       unsigned int id, int len);
void vhost_add_used_and_signal_n(struct vhost_dev *, struct vhost_virtqueue *,
			       struct vring_used_elem *heads, unsigned count);
void vhost_signal(struct vhost_dev *, struct vhost_virtqueue *);
void vhost_disable_notify(struct vhost_dev *, struct vhost_virtqueue *);
bool vhost_vq_avail_empty(struct vhost_dev *, struct vhost_virtqueue *);
bool vhost_enable_notify(struct vhost_dev *, struct vhost_virtqueue *);

int vhost_log_write(struct vhost_virtqueue *vq, struct vhost_log *log,
		    unsigned int log_num, u64 len,
		    struct iovec *iov, int count);
int vq_meta_prefetch(struct vhost_virtqueue *vq);

struct vhost_msg_node *vhost_new_msg(struct vhost_virtqueue *vq, int type);
void vhost_enqueue_msg(struct vhost_dev *dev,
		       struct list_head *head,
		       struct vhost_msg_node *node);
struct vhost_msg_node *vhost_dequeue_msg(struct vhost_dev *dev,
					 struct list_head *head);
__poll_t vhost_chr_poll(struct file *file, struct vhost_dev *dev,
			    poll_table *wait);
ssize_t vhost_chr_read_iter(struct vhost_dev *dev, struct iov_iter *to,
			    int noblock);
ssize_t vhost_chr_write_iter(struct vhost_dev *dev,
			     struct iov_iter *from);
int vhost_init_device_iotlb(struct vhost_dev *d, bool enabled);

void vhost_iotlb_map_free(struct vhost_iotlb *iotlb,
			  struct vhost_iotlb_map *map);

#define vq_err(vq, fmt, ...) do {                                  \
		pr_debug(pr_fmt(fmt), ##__VA_ARGS__);       \
		if ((vq)->error_ctx)                               \
		        /*向error_ctx触发eventfd事件*/\
				eventfd_signal((vq)->error_ctx, 1);\
	} while (0)

enum {
	VHOST_FEATURES = (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) |
			 (1ULL << VIRTIO_RING_F_INDIRECT_DESC) |
			 (1ULL << VIRTIO_RING_F_EVENT_IDX) |
			 (1ULL << VHOST_F_LOG_ALL) |
			 (1ULL << VIRTIO_F_ANY_LAYOUT) |
			 (1ULL << VIRTIO_F_VERSION_1)
};

/**
 * vhost_vq_set_backend - Set backend.
 *
 * @vq            Virtqueue.
 * @private_data  The private data.
 *
 * Context: Need to call with vq->mutex acquired.
 */
static inline void vhost_vq_set_backend(struct vhost_virtqueue *vq,
					void *private_data)
{
    /*设置vq的后端*/
	vq->private_data = private_data;
}

/**
 * vhost_vq_get_backend - Get backend.
 *
 * @vq            Virtqueue.
 *
 * Context: Need to call with vq->mutex acquired.
 * Return: Private data previously set with vhost_vq_set_backend.
 */
static inline void *vhost_vq_get_backend(struct vhost_virtqueue *vq)
{
    /*取vq的后端*/
	return vq->private_data;
}

static inline bool vhost_has_feature(struct vhost_virtqueue *vq, int bit)
{
	return vq->acked_features & (1ULL << bit);
}

static inline bool vhost_backend_has_feature(struct vhost_virtqueue *vq, int bit)
{
	return vq->acked_backend_features & (1ULL << bit);
}

#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
static inline bool vhost_is_little_endian(struct vhost_virtqueue *vq)
{
	return vq->is_le;
}
#else
static inline bool vhost_is_little_endian(struct vhost_virtqueue *vq)
{
    /*检查vq是否使用小端字节序*/
	return virtio_legacy_is_little_endian() || vq->is_le;
}
#endif

/* Memory accessors */
static inline u16 vhost16_to_cpu(struct vhost_virtqueue *vq, __virtio16 val)
{
    //将u16 val由vhost字节序转换为cpu序
	return __virtio16_to_cpu(vhost_is_little_endian(vq), val);
}

static inline __virtio16 cpu_to_vhost16(struct vhost_virtqueue *vq, u16 val)
{
    //将u16 val由cpu序转换为vhost字节序
	return __cpu_to_virtio16(vhost_is_little_endian(vq), val);
}

static inline u32 vhost32_to_cpu(struct vhost_virtqueue *vq, __virtio32 val)
{
    //将u32 val由vhost字节序转换为cpu序
	return __virtio32_to_cpu(vhost_is_little_endian(vq), val);
}

static inline __virtio32 cpu_to_vhost32(struct vhost_virtqueue *vq, u32 val)
{
    //将u32 val由cpu序转换为vhost字节序
	return __cpu_to_virtio32(vhost_is_little_endian(vq), val);
}

static inline u64 vhost64_to_cpu(struct vhost_virtqueue *vq, __virtio64 val)
{
    //将u64 val由vhost字节序转换为cpu序
	return __virtio64_to_cpu(vhost_is_little_endian(vq), val);
}

static inline __virtio64 cpu_to_vhost64(struct vhost_virtqueue *vq, u64 val)
{
    //将u64 val由cpu序转换为vhost字节序
	return __cpu_to_virtio64(vhost_is_little_endian(vq), val);
}
#endif
