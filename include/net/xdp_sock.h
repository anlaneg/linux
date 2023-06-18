/* SPDX-License-Identifier: GPL-2.0 */
/* AF_XDP internal functions
 * Copyright(c) 2018 Intel Corporation.
 */

#ifndef _LINUX_XDP_SOCK_H
#define _LINUX_XDP_SOCK_H

#include <linux/bpf.h>
#include <linux/workqueue.h>
#include <linux/if_xdp.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <net/sock.h>

struct net_device;
struct xsk_queue;
struct xdp_buff;

struct xdp_umem {
	void *addrs;/*用户态注册的内存起始地址*/
	u64 size;/*用户态注册的内存大小*/
	u32 headroom;/*用户态指明的报文headroom大小*/
	u32 chunk_size;/*用户态指明的chunk_size*/
	u32 chunks;/*用户态注册的内存可划分成多少个chunk*/
	u32 npgs;/*用户态注册的内存实际占用的页数*/
	struct user_struct *user;
	refcount_t users;
	u8 flags;/*用户态注册内存时指明的flags*/
	bool zc;/*指明zero copy是否被使能*/
	struct page **pgs;/*pin住用户态注册的内存，所对应的页指针数组，大小为npgs*/
	int id;/*唯一标识umem*/
	struct list_head xsk_dma_list;/*用于挂接所有dma_map*/
	struct work_struct work;
};

struct xsk_map {
	struct bpf_map map;/*bpf_map结构*/
	spinlock_t lock; /* Synchronize map updates */
	struct xdp_sock __rcu *xsk_map[];
};

struct xdp_sock {
	/* struct sock must be the first member of struct xdp_sock */
	struct sock sk;
	//socket对应的rx队列
	struct xsk_queue *rx ____cacheline_aligned_in_smp;
	struct net_device *dev;/*关联的底层设备*/
	struct xdp_umem *umem;/*指向用户态注册的memory*/
	struct list_head flush_node;
	struct xsk_buff_pool *pool;/*收包用的buffer pool*/
	u16 queue_id;
	bool zc;/*是否支持零copy*/
	enum {
		XSK_READY = 0,
		XSK_BOUND,
		XSK_UNBOUND,
	} state;

	//socket对应的tx队列
	struct xsk_queue *tx ____cacheline_aligned_in_smp;
	struct list_head tx_list;
	/* Protects generic receive. */
	spinlock_t rx_lock;

	/* Statistics */
	u64 rx_dropped;/*收方向丢包统计*/
	u64 rx_queue_full;/*统计收方向队列满的次数*/

	struct list_head map_list;
	/* Protects map_list */
	spinlock_t map_list_lock;
	/* Protects multiple processes in the control path */
	struct mutex mutex;
	struct xsk_queue *fq_tmp; /* Only as tmp storage before bind */
	struct xsk_queue *cq_tmp; /* Only as tmp storage before bind */
};

#ifdef CONFIG_XDP_SOCKETS

int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp);
int __xsk_map_redirect(struct xdp_sock *xs, struct xdp_buff *xdp);
void __xsk_map_flush(void);

#else

static inline int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	return -ENOTSUPP;
}

static inline int __xsk_map_redirect(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	return -EOPNOTSUPP;
}

static inline void __xsk_map_flush(void)
{
}

#endif /* CONFIG_XDP_SOCKETS */

#endif /* _LINUX_XDP_SOCK_H */
