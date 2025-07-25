/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef RDMA_USER_RXE_H
#define RDMA_USER_RXE_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

enum {
	RXE_NETWORK_TYPE_IPV4 = 1,
	RXE_NETWORK_TYPE_IPV6 = 2,
};

union rxe_gid {
	__u8	raw[16];
	struct {
		__be64	subnet_prefix;
		__be64	interface_id;
	} global;
};

struct rxe_global_route {
	union rxe_gid	dgid;
	__u32		flow_label;/*ipv6 flow label*/
	__u8		sgid_index;/*对应的源gid索引号，通过此索引可以找到netdev*/
	__u8		hop_limit;/*ttl填充*/
	__u8		traffic_class;/*ipv6 traffic class*/
};

struct rxe_av {
    /*port编号*/
	__u8			port_num;
	/* From RXE_NETWORK_TYPE_* */
	__u8			network_type;/*网络层类型ipv4/ipv6*/
	__u8			dmac[6];/*目的Mac*/
	struct rxe_global_route	grh;
	union {
		struct sockaddr_in	_sockaddr_in;/*ipv4地址*/
		struct sockaddr_in6	_sockaddr_in6;
	} sgid_addr/*源地址*/, dgid_addr;/*目的地址*/
};

struct rxe_send_wr {
	__aligned_u64		wr_id;/*wr编号*/
	__u32			reserved;
	__u32			opcode;/*操作码，见enum ib_wr_opcode*/
	__u32			send_flags;
	union {
		__be32		imm_data;/*包含的立即数*/
		__u32		invalidate_rkey;
	} ex;
	union {
		struct {
			__aligned_u64 remote_addr;
			__u32	length;
			__u32	rkey;
			__u8	type;
			__u8	level;
		} flush;
		struct {
			__aligned_u64 remote_addr;
			__u32	rkey;
			__u32	reserved;
		} rdma;
		struct {
			__aligned_u64 remote_addr;
			__aligned_u64 compare_add;
			__aligned_u64 swap;
			__u32	rkey;
			__u32	reserved;
		} atomic;
		struct {
			__u32	remote_qpn;/*远端qpn*/
			__u32	remote_qkey;/*远端qkey*/
			__u16	pkey_index;
			__u16	reserved;
			__u32	ah_num;/*ah编号*/
			__u32	pad[4];
			struct rxe_av av;/* only old user provider for UD sends*/
		} ud;/*ud类型qp*/
		struct {
			__aligned_u64	addr;
			__aligned_u64	length;
			__u32		mr_lkey;
			__u32		mw_rkey;
			__u32		rkey;
			__u32		access;
		} mw;
		/* reg is only used by the kernel and is not part of the uapi */
#ifdef __KERNEL__
		struct {
			union {
				struct ib_mr *mr;
				__aligned_u64 reserved;
			};
			__u32	     key;
			__u32	     access;
		} reg;
#endif
	} wr;
};

struct rxe_sge {
	__aligned_u64 addr;
	__u32	length;/*sge长度*/
	__u32	lkey;/*sge对应mr*/
};

struct mminfo {
	__aligned_u64		offset;/*偏移起始位置*/
	__u32			size;/*内存大小*/
	__u32			pad;
};

struct rxe_dma_info {
    /*数据总长度*/
	__u32			length;
	__u32			resid;/*数据剩余长度*/
	__u32			cur_sge;/*当前遍历到哪个sge数组成员（成员索引）*/
	/*seg数组长度*/
	__u32			num_sge;
	__u32			sge_offset;
	__u32			reserved;
	union {
	    /*记录inline数据（有IB_SEND_INLINE标记时有效）*/
		__DECLARE_FLEX_ARRAY(__u8, inline_data);
		__DECLARE_FLEX_ARRAY(__u8, atomic_wr);
		/*sge数组,记录非inline的要执行dma的数据段*/
		__DECLARE_FLEX_ARRAY(struct rxe_sge, sge);
	};
};

struct rxe_send_wqe {
	struct rxe_send_wr	wr;
	__u32			status;
	__u32			state;
	__aligned_u64		iova;
	__u32			mask;
	__u32			first_psn;/*首包psn(packet send number)*/
	__u32			last_psn;/*属包psn*/
	__u32			ack_length;
	__u32			ssn;/*此send wqe关联的全局唯一number*/
	__u32			has_rd_atomic;
	struct rxe_dma_info	dma;/*数据*/
};

struct rxe_recv_wqe {
	__aligned_u64		wr_id;
	__u32			reserved;
	__u32			padding;
	struct rxe_dma_info	dma;
};

struct rxe_create_ah_resp {
	__u32 ah_num;
	__u32 reserved;
};

struct rxe_create_cq_resp {
	struct mminfo mi;
};

struct rxe_resize_cq_resp {
	struct mminfo mi;
};

struct rxe_create_qp_resp {
	struct mminfo rq_mi;
	struct mminfo sq_mi;
};

struct rxe_create_srq_resp {
	struct mminfo mi;
	__u32 srq_num;
	__u32 reserved;
};

struct rxe_modify_srq_cmd {
	__aligned_u64 mmap_info_addr;
};

/* This data structure is stored at the base of work and
 * completion queues shared between user space and kernel space.
 * It contains the producer and consumer indices. Is also
 * contains a copy of the queue size parameters for user space
 * to use but the kernel must use the parameters in the
 * rxe_queue struct. For performance reasons arrange to have
 * producer and consumer indices in separate cache lines
 * the kernel should always mask the indices to avoid accessing
 * memory outside of the data area
 */
struct rxe_queue_buf {
	__u32			log2_elem_size;/*队列元素大小针对log2的对数，1<<log2_elem_size即为元素大小*/
	__u32			index_mask;/*队列长度是2的N次方的整数，index_mask是其对应的掩码*/
	__u32			pad_1[30];
	__u32			producer_index;/*生产者指针*/
	__u32			pad_2[31];
	__u32			consumer_index;/*消费者指针*/
	__u32			pad_3[31];
	__u8			data[];/*指向队列元素*/
};

#endif /* RDMA_USER_RXE_H */
