/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_VERBS_H
#define RXE_VERBS_H

#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <rdma/rdma_user_rxe.h>
#include "rxe_pool.h"
#include "rxe_task.h"
#include "rxe_hw_counters.h"

static inline int pkey_match(u16 key1, u16 key2)
{
	return (((key1 & 0x7fff) != 0) &&
		((key1 & 0x7fff) == (key2 & 0x7fff)) &&
		((key1 & 0x8000) || (key2 & 0x8000))) ? 1 : 0;
}

/* Return >0 if psn_a > psn_b
 *	   0 if psn_a == psn_b
 *	  <0 if psn_a < psn_b
 */
static inline int psn_compare(u32 psn_a, u32 psn_b)
{
	s32 diff;

	diff = (psn_a - psn_b) << 8;
	return diff;
}

struct rxe_ucontext {
	struct ib_ucontext ibuc;
	struct rxe_pool_entry	pelem;
};

struct rxe_pd {
	struct ib_pd            ibpd;
	struct rxe_pool_entry	pelem;
};

struct rxe_ah {
	struct ib_ah		ibah;
	struct rxe_pool_entry	pelem;
	struct rxe_av		av;
	bool			is_user;
	int			ah_num;
};

struct rxe_cqe {
	union {
		struct ib_wc		ibwc;
		struct ib_uverbs_wc	uibwc;
	};
};

struct rxe_cq {
	struct ib_cq		ibcq;
	struct rxe_pool_entry	pelem;
	/*cq队列*/
	struct rxe_queue	*queue;
	spinlock_t		cq_lock;
	u8			notify;
	bool			is_dying;
	bool			is_user;
	/*complete对应的task*/
	struct tasklet_struct	comp_task;
};

enum wqe_state {
	wqe_state_posted,
	wqe_state_processing,
	wqe_state_pending,
	wqe_state_done,
	wqe_state_error,
};

struct rxe_sq {
	int			max_wr;/*seq最大wr数目*/
	int			max_sge;
	int			max_inline;
	spinlock_t		sq_lock; /* guard queue */
	struct rxe_queue	*queue;/*sq队列*/
};

struct rxe_rq {
	int			max_wr;
	int			max_sge;
	spinlock_t		producer_lock; /* guard queue producer */
	spinlock_t		consumer_lock; /* guard queue consumer */
	struct rxe_queue	*queue;
};

struct rxe_srq {
	struct ib_srq		ibsrq;
	struct rxe_pool_entry	pelem;
	struct rxe_pd		*pd;
	struct rxe_rq		rq;
	u32			srq_num;

	int			limit;
	int			error;
};

enum rxe_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */
	QP_STATE_DRAINED,	/* req only */
	QP_STATE_ERROR
};

struct rxe_req_info {
	enum rxe_qp_state	state;
	int			wqe_index;/*生产者指针*/
	u32			psn;
	int			opcode;
	atomic_t		rd_atomic;
	int			wait_fence;
	int			need_rd_atomic;
	int			wait_psn;
	int			need_retry;
	int			noack_pkts;
	struct rxe_task		task;
};

struct rxe_comp_info {
	u32			psn;
	int			opcode;
	int			timeout;
	int			timeout_retry;
	int			started_retry;
	u32			retry_cnt;
	u32			rnr_retry;
	struct rxe_task		task;
};

enum rdatm_res_state {
	rdatm_res_state_next,
	rdatm_res_state_new,
	rdatm_res_state_replay,
};

struct resp_res {
	int			type;
	int			replay;
	u32			first_psn;
	u32			last_psn;
	u32			cur_psn;
	enum rdatm_res_state	state;

	union {
		struct {
			struct sk_buff	*skb;
		} atomic;
		struct {
			struct rxe_mr	*mr;
			u64		va_org;
			u32		rkey;
			u32		length;
			u64		va;
			u32		resid;
		} read;
	};
};

struct rxe_resp_info {
	enum rxe_qp_state	state;
	u32			msn;
	u32			psn;
	u32			ack_psn;
	int			opcode;
	int			drop_msg;
	int			goto_error;
	int			sent_psn_nak;
	enum ib_wc_status	status;
	u8			aeth_syndrome;

	/* Receive only */
	/*指向可使用的下一个recv wqe*/
	struct rxe_recv_wqe	*wqe;

	/* RDMA read / atomic only */
	u64			va;
	u64			offset;
	struct rxe_mr		*mr;
	u32			resid;
	u32			rkey;
	u32			length;
	u64			atomic_orig;

	/* SRQ only */
	struct {
		struct rxe_recv_wqe	wqe;
		struct ib_sge		sge[RXE_MAX_SGE];
	} srq_wqe;

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 */
	struct resp_res		*resources;
	unsigned int		res_head;
	unsigned int		res_tail;
	struct resp_res		*res;
	struct rxe_task		task;
};

struct rxe_qp {
	struct ib_qp		ibqp;
	struct rxe_pool_entry	pelem;
	struct ib_qp_attr	attr;
	/*标记qp是否有效*/
	unsigned int		valid;
	unsigned int		mtu;
	bool			is_user;

	/*所属的pd*/
	struct rxe_pd		*pd;
	struct rxe_srq		*srq;
	/*send对应的cq*/
	struct rxe_cq		*scq;
	/*recv对应的cq*/
	struct rxe_cq		*rcq;

	enum ib_sig_type	sq_sig_type;

	/*发送q*/
	struct rxe_sq		sq;
	/*接收q*/
	struct rxe_rq		rq;

	/*对应的udp socket*/
	struct socket		*sk;
	u32			dst_cookie;
	u16			src_port;

	/*rc,uc两种模式情况下，使用此av*/
	struct rxe_av		pri_av;
	struct rxe_av		alt_av;

	/* list of mcast groups qp has joined (for cleanup) */
	struct list_head	grp_list;
	spinlock_t		grp_lock; /* guard grp_list */

	/*rxe_resp_queue_pkt函数负责向其中添加skb，这些skb是roce收到的报文，后续会用它填充wr*/
	struct sk_buff_head	req_pkts;
	/*rxe_comp_queue_pkt函数负责向其中添加skb*/
	struct sk_buff_head	resp_pkts;

	/*处理发送请求，处理req_pkts*/
	struct rxe_req_info	req;
	/*对接收内容进行响应*/
	struct rxe_comp_info	comp;
	/*处理接收请求,处理resp_pkts*/
	struct rxe_resp_info	resp;

	atomic_t		ssn;
	atomic_t		skb_out;
	int			need_req_skb;

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct timer_list retrans_timer;
	u64 qp_timeout_jiffies;

	/* Timer for handling RNR NAKS. */
	struct timer_list rnr_nak_timer;

	spinlock_t		state_lock; /* guard requester and completer */

	struct execute_work	cleanup_work;
};

enum rxe_mr_state {
	RXE_MR_STATE_INVALID,
	RXE_MR_STATE_FREE,
	RXE_MR_STATE_VALID,
};

enum rxe_mr_copy_dir {
	RXE_TO_MR_OBJ,
	RXE_FROM_MR_OBJ,
};

enum rxe_mr_lookup_type {
	RXE_LOOKUP_LOCAL,
	RXE_LOOKUP_REMOTE,
};

/*一页中可以存放多少rxe_phys_buf*/
#define RXE_BUF_PER_MAP		(PAGE_SIZE / sizeof(struct rxe_phys_buf))

struct rxe_phys_buf {
	u64      addr;/*虚地址*/
	u64      size;/*内存大小*/
};

struct rxe_map {
    /*buffer地址及大小信息*/
	struct rxe_phys_buf	buf[RXE_BUF_PER_MAP];
};

struct rxe_map_set {
    /*指针数组，每个成员指向一个struct rxe_map*/
	struct rxe_map		**map;
	/*虚地址*/
	u64			va;
	u64			iova;
	/*内存长度*/
	size_t			length;
	u32			offset;
	u32			nbuf;
	/*页大小的左移位数*/
	int			page_shift;
	/*页的掩码*/
	int			page_mask;
};

static inline int rkey_is_mw(u32 rkey)
{
	u32 index = rkey >> 8;

	return (index >= RXE_MIN_MW_INDEX) && (index <= RXE_MAX_MW_INDEX);
}

struct rxe_mr {
	struct rxe_pool_entry	pelem;
	struct ib_mr		ibmr;

	/*对应的umem信息*/
	struct ib_umem		*umem;

	/*本端key*/
	u32			lkey;
	/*远端key*/
	u32			rkey;
	/*mr状态*/
	enum rxe_mr_state	state;
	enum ib_mr_type		type;
	int			access;

	int			map_shift;
	int			map_mask;

	/*内存总页数*/
	u32			num_buf;

	u32			max_buf;
	/*rxe_map_set的大小*/
	u32			num_map;

	atomic_t		num_mw;

	struct rxe_map_set	*cur_map_set;
	struct rxe_map_set	*next_map_set;
};

enum rxe_mw_state {
	RXE_MW_STATE_INVALID	= RXE_MR_STATE_INVALID,
	RXE_MW_STATE_FREE	= RXE_MR_STATE_FREE,
	RXE_MW_STATE_VALID	= RXE_MR_STATE_VALID,
};

struct rxe_mw {
	struct ib_mw		ibmw;
	struct rxe_pool_entry	pelem;
	spinlock_t		lock;
	enum rxe_mw_state	state;
	struct rxe_qp		*qp; /* Type 2 only */
	struct rxe_mr		*mr;
	u32			rkey;
	int			access;
	u64			addr;
	u64			length;
};

struct rxe_mc_grp {
	struct rxe_pool_entry	pelem;
	spinlock_t		mcg_lock; /* guard group */
	struct rxe_dev		*rxe;
	struct list_head	qp_list;
	union ib_gid		mgid;
	int			num_qp;
	u32			qkey;
	u16			pkey;
};

struct rxe_mc_elem {
	struct rxe_pool_entry	pelem;
	struct list_head	qp_list;
	struct list_head	grp_list;
	struct rxe_qp		*qp;
	struct rxe_mc_grp	*grp;
};

struct rxe_port {
    /*port属性*/
	struct ib_port_attr	attr;
	__be64			port_guid;
	__be64			subnet_prefix;
	spinlock_t		port_lock; /* guard port */
	unsigned int		mtu_cap;
	/* special QPs */
	u32			qp_smi_index;
	u32			qp_gsi_index;
};

struct rxe_dev {
	struct ib_device	ib_dev;
	/*设备属性*/
	struct ib_device_attr	attr;
	int			max_ucontext;
	int			max_inline_data;
	struct mutex	usdev_lock;

	/*所属的netdev设备*/
	struct net_device	*ndev;

	int			xmit_errors;

	struct rxe_pool		uc_pool;
	struct rxe_pool		pd_pool;
	struct rxe_pool		ah_pool;
	struct rxe_pool		srq_pool;
	struct rxe_pool		qp_pool;
	struct rxe_pool		cq_pool;
	struct rxe_pool		mr_pool;
	struct rxe_pool		mw_pool;
	struct rxe_pool		mc_grp_pool;
	struct rxe_pool		mc_elem_pool;

	spinlock_t		pending_lock; /* guard pending_mmaps */
	struct list_head	pending_mmaps;

	spinlock_t		mmap_offset_lock; /* guard mmap_offset */
	u64			mmap_offset;

	/*统计信息*/
	atomic64_t		stats_counters[RXE_NUM_OF_COUNTERS];

	struct rxe_port		port;
	struct crypto_shash	*tfm;
};

static inline void rxe_counter_inc(struct rxe_dev *rxe, enum rxe_counters index)
{
	atomic64_inc(&rxe->stats_counters[index]);
}

static inline struct rxe_dev *to_rdev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct rxe_dev, ib_dev) : NULL;
}

static inline struct rxe_ucontext *to_ruc(struct ib_ucontext *uc)
{
	return uc ? container_of(uc, struct rxe_ucontext, ibuc) : NULL;
}

/*转pd对应的rxe_pd*/
static inline struct rxe_pd *to_rpd(struct ib_pd *pd)
{
	return pd ? container_of(pd, struct rxe_pd, ibpd) : NULL;
}

/*由ib_ah转rxe_ah*/
static inline struct rxe_ah *to_rah(struct ib_ah *ah)
{
	return ah ? container_of(ah, struct rxe_ah, ibah) : NULL;
}

static inline struct rxe_srq *to_rsrq(struct ib_srq *srq)
{
	return srq ? container_of(srq, struct rxe_srq, ibsrq) : NULL;
}

static inline struct rxe_qp *to_rqp(struct ib_qp *qp)
{
	return qp ? container_of(qp, struct rxe_qp, ibqp) : NULL;
}

static inline struct rxe_cq *to_rcq(struct ib_cq *cq)
{
	return cq ? container_of(cq, struct rxe_cq, ibcq) : NULL;
}

static inline struct rxe_mr *to_rmr(struct ib_mr *mr)
{
	return mr ? container_of(mr, struct rxe_mr, ibmr) : NULL;
}

static inline struct rxe_mw *to_rmw(struct ib_mw *mw)
{
	return mw ? container_of(mw, struct rxe_mw, ibmw) : NULL;
}

static inline struct rxe_pd *rxe_ah_pd(struct rxe_ah *ah)
{
	return to_rpd(ah->ibah.pd);
}

static inline struct rxe_pd *mr_pd(struct rxe_mr *mr)
{
	return to_rpd(mr->ibmr.pd);
}

static inline struct rxe_pd *rxe_mw_pd(struct rxe_mw *mw)
{
	return to_rpd(mw->ibmw.pd);
}

int rxe_register_device(struct rxe_dev *rxe, const char *ibdev_name);

void rxe_mc_cleanup(struct rxe_pool_entry *arg);

#endif /* RXE_VERBS_H */
