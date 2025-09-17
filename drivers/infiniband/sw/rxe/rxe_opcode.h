/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_OPCODE_H
#define RXE_OPCODE_H

/*
 * contains header bit mask definitions and header lengths
 * declaration of the rxe_opcode_info struct and
 * rxe_wr_opcode_info struct
 */

enum rxe_wr_mask {
	WR_INLINE_MASK			= BIT(0),
	WR_ATOMIC_MASK			= BIT(1),
	WR_SEND_MASK			= BIT(2),/*指明为send操作*/
	WR_READ_MASK			= BIT(3),
	WR_WRITE_MASK			= BIT(4),
	WR_LOCAL_OP_MASK		= BIT(5),/*指明本地操作*/
	WR_FLUSH_MASK			= BIT(6),
	WR_ATOMIC_WRITE_MASK		= BIT(7),

	WR_READ_OR_WRITE_MASK		= WR_READ_MASK | WR_WRITE_MASK,/*标记为读或写操作*/
	WR_WRITE_OR_SEND_MASK		= WR_WRITE_MASK | WR_SEND_MASK,/*标记为write或send操作*/
	WR_ATOMIC_OR_READ_MASK		= WR_ATOMIC_MASK | WR_READ_MASK,
};

#define WR_MAX_QPT		(8)

struct rxe_wr_opcode_info {
	char			*name;
	enum rxe_wr_mask	mask[WR_MAX_QPT];
};

extern struct rxe_wr_opcode_info rxe_wr_opcode_info[];

enum rxe_hdr_type {
	RXE_LRH,
	RXE_GRH,
	RXE_BTH,
	RXE_RETH,
	RXE_AETH,
	RXE_ATMETH,
	RXE_ATMACK,
	RXE_IETH,
	RXE_RDETH,
	RXE_DETH,
	RXE_IMMDT,
	RXE_FETH,
	RXE_PAYLOAD,
	NUM_HDR_TYPES
};

enum rxe_hdr_mask {
	RXE_LRH_MASK		= BIT(RXE_LRH),
	RXE_GRH_MASK		= BIT(RXE_GRH),
	RXE_BTH_MASK		= BIT(RXE_BTH),
	RXE_IMMDT_MASK		= BIT(RXE_IMMDT),/*标记报文中包含rxe_immdt头*/
	RXE_RETH_MASK		= BIT(RXE_RETH),/*标明报文中包含rxe_reth头*/
	RXE_AETH_MASK		= BIT(RXE_AETH),/*标明报文中包含rxe_aeth头*/
	RXE_ATMETH_MASK		= BIT(RXE_ATMETH),/*标明报文中包含rxe_atmeth头*/
	RXE_ATMACK_MASK		= BIT(RXE_ATMACK),/*标明报文中包含rxe_atmack头*/
	RXE_IETH_MASK		= BIT(RXE_IETH),/*标明报文中包含rxe_ieth头*/
	RXE_RDETH_MASK		= BIT(RXE_RDETH),
	RXE_DETH_MASK		= BIT(RXE_DETH),/*标明报文中包含rxe_deth头*/
	RXE_FETH_MASK		= BIT(RXE_FETH),
	RXE_PAYLOAD_MASK	= BIT(RXE_PAYLOAD),/*标记包括payload*/

	/*标记为request类，如无此标记，则为response报文*/
	RXE_REQ_MASK		= BIT(NUM_HDR_TYPES + 0),
	RXE_ACK_MASK		= BIT(NUM_HDR_TYPES + 1),
	RXE_SEND_MASK		= BIT(NUM_HDR_TYPES + 2),/*指明为send类操作，这种调用send_data_in*/
	RXE_WRITE_MASK		= BIT(NUM_HDR_TYPES + 3),/*写标记，这种调用write_data_in*/
	RXE_READ_MASK		= BIT(NUM_HDR_TYPES + 4),/*读标记*/
	RXE_ATOMIC_MASK		= BIT(NUM_HDR_TYPES + 5),/*原子操作标记*/
	RXE_FLUSH_MASK		= BIT(NUM_HDR_TYPES + 6),/*flush标记，有此标记时，报文中包含RXE_FETH头*/

	RXE_RWR_MASK		= BIT(NUM_HDR_TYPES + 7),
	RXE_COMP_MASK		= BIT(NUM_HDR_TYPES + 8),/*有此标记时，execute执行成功后，跳RESPST_COMPLETE*/

	RXE_START_MASK		= BIT(NUM_HDR_TYPES + 9),/*opcode中首个（first)*/
	RXE_MIDDLE_MASK		= BIT(NUM_HDR_TYPES + 10),/*opcode中中间的*/
	RXE_END_MASK		= BIT(NUM_HDR_TYPES + 11),/*opcode中最后一个(last)*/

	/*标记为loopback类型报文*/
	RXE_LOOPBACK_MASK	= BIT(NUM_HDR_TYPES + 12),

	/*标记原子写*/
	RXE_ATOMIC_WRITE_MASK   = BIT(NUM_HDR_TYPES + 14),

	/*有读或者原子标记*/
	RXE_READ_OR_ATOMIC_MASK	= (RXE_READ_MASK | RXE_ATOMIC_MASK),
	RXE_WRITE_OR_SEND_MASK	= (RXE_WRITE_MASK | RXE_SEND_MASK),
	/*读操作或写操作*/
	RXE_READ_OR_WRITE_MASK	= (RXE_READ_MASK | RXE_WRITE_MASK),
	/*标记包含rdma操作：读，写，原子写，flush,原子操作*/
	RXE_RDMA_OP_MASK	= (RXE_READ_MASK | RXE_WRITE_MASK |
				   RXE_ATOMIC_WRITE_MASK | RXE_FLUSH_MASK |
				   RXE_ATOMIC_MASK),
};

#define OPCODE_NONE		(-1)
#define RXE_NUM_OPCODE		256

struct rxe_opcode_info {
    /*opcode名称*/
	char			*name;
	/*opcode对应的mask*/
	enum rxe_hdr_mask	mask;
	/*此op对应的消息header长度*/
	int			length;
	/*此op对应的消息到指定消息标签起始位置的offset*/
	int			offset[NUM_HDR_TYPES];
};

extern struct rxe_opcode_info rxe_opcode[RXE_NUM_OPCODE];

#endif /* RXE_OPCODE_H */
