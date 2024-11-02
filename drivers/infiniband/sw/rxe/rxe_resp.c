// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"

static char *resp_state_name[] = {
	[RESPST_NONE]				= "NONE",
	[RESPST_GET_REQ]			= "GET_REQ",
	[RESPST_CHK_PSN]			= "CHK_PSN",
	[RESPST_CHK_OP_SEQ]			= "CHK_OP_SEQ",
	[RESPST_CHK_OP_VALID]			= "CHK_OP_VALID",
	[RESPST_CHK_RESOURCE]			= "CHK_RESOURCE",
	[RESPST_CHK_LENGTH]			= "CHK_LENGTH",
	[RESPST_CHK_RKEY]			= "CHK_RKEY",
	[RESPST_EXECUTE]			= "EXECUTE",
	[RESPST_READ_REPLY]			= "READ_REPLY",
	[RESPST_ATOMIC_REPLY]			= "ATOMIC_REPLY",
	[RESPST_ATOMIC_WRITE_REPLY]		= "ATOMIC_WRITE_REPLY",
	[RESPST_PROCESS_FLUSH]			= "PROCESS_FLUSH",
	[RESPST_COMPLETE]			= "COMPLETE",
	[RESPST_ACKNOWLEDGE]			= "ACKNOWLEDGE",
	[RESPST_CLEANUP]			= "CLEANUP",
	[RESPST_DUPLICATE_REQUEST]		= "DUPLICATE_REQUEST",
	[RESPST_ERR_MALFORMED_WQE]		= "ERR_MALFORMED_WQE",
	[RESPST_ERR_UNSUPPORTED_OPCODE]		= "ERR_UNSUPPORTED_OPCODE",
	[RESPST_ERR_MISALIGNED_ATOMIC]		= "ERR_MISALIGNED_ATOMIC",
	[RESPST_ERR_PSN_OUT_OF_SEQ]		= "ERR_PSN_OUT_OF_SEQ",
	[RESPST_ERR_MISSING_OPCODE_FIRST]	= "ERR_MISSING_OPCODE_FIRST",
	[RESPST_ERR_MISSING_OPCODE_LAST_C]	= "ERR_MISSING_OPCODE_LAST_C",
	[RESPST_ERR_MISSING_OPCODE_LAST_D1E]	= "ERR_MISSING_OPCODE_LAST_D1E",
	[RESPST_ERR_TOO_MANY_RDMA_ATM_REQ]	= "ERR_TOO_MANY_RDMA_ATM_REQ",
	[RESPST_ERR_RNR]			= "ERR_RNR",
	[RESPST_ERR_RKEY_VIOLATION]		= "ERR_RKEY_VIOLATION",
	[RESPST_ERR_INVALIDATE_RKEY]		= "ERR_INVALIDATE_RKEY_VIOLATION",
	[RESPST_ERR_LENGTH]			= "ERR_LENGTH",
	[RESPST_ERR_CQ_OVERFLOW]		= "ERR_CQ_OVERFLOW",
	[RESPST_ERROR]				= "ERROR",
	[RESPST_DONE]				= "DONE",
	[RESPST_EXIT]				= "EXIT",
};

/* rxe_recv calls here to add a request packet to the input queue */
void rxe_resp_queue_pkt(struct rxe_qp *qp, struct sk_buff *skb)
{
	int must_sched;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);

	/*将skb添加到qp->req_pkts队列*/
	skb_queue_tail(&qp->req_pkts, skb);

	/*检查是否需要调度（队列长度大于1，则需要调度，先保证前面的报文处理；rc rdma操作必调度）*/
	must_sched = (pkt->opcode == IB_OPCODE_RC_RDMA_READ_REQUEST) ||
			(skb_queue_len(&qp->req_pkts) > 1);

	/*触发task,使其开始处理收到的报文*/
	if (must_sched)
		/*触发调度*/
		rxe_sched_task(&qp->resp.task);
	else
		/*无论等待调度，直接运行此task*/
		rxe_run_task(&qp->resp.task);
}

/*rxe_resp_queue_pkt函数将报文填充到qp->req_pkts中，此函数负责自队列peek首个报文*/
static inline enum resp_states get_req(struct rxe_qp *qp,
				       struct rxe_pkt_info **pkt_p/*出参，首个qp->req_pkts的pkt_info*/)
{
	struct sk_buff *skb;

	/*peek首个报文*/
	skb = skb_peek(&qp->req_pkts);
	if (!skb)
	    /*队列为空，直接退出*/
		return RESPST_EXIT;

	*pkt_p = SKB_TO_PKT(skb);

	return (qp->resp.res) ? RESPST_READ_REPLY : RESPST_CHK_PSN;
}

/*检查psn,正常情况下走：RESPST_CHK_OP_SEQ，其它为异常状态*/
static enum resp_states check_psn(struct rxe_qp *qp,
				  struct rxe_pkt_info *pkt)
{
	/*此报文psn与qp中响应psn之间的差值*/
	int diff = psn_compare(pkt->psn, qp->resp.psn);
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (diff > 0) {
			/*收到的包大于预期的psn（即收到乱序的包）*/
			if (qp->resp.sent_psn_nak)
				/*之前已收到过乱序的包，走RESPST_CLEANUP*/
				return RESPST_CLEANUP;

			/*首次收到乱序的包，标记需要发送nack*/
			qp->resp.sent_psn_nak = 1;
			/*乱序计数增加*/
			rxe_counter_inc(rxe, RXE_CNT_OUT_OF_SEQ_REQ);

			/*走乱序状态*/
			return RESPST_ERR_PSN_OUT_OF_SEQ;

		} else if (diff < 0) {
			/*此psn已存认，收到重复的请求，重复计数增加*/
			rxe_counter_inc(rxe, RXE_CNT_DUP_REQ);

			/*走收到重复请求状态*/
			return RESPST_DUPLICATE_REQUEST;
		}

		/*diff=0,如果之前收到过乱序的包，此处则置为0*/
		if (qp->resp.sent_psn_nak)
			qp->resp.sent_psn_nak = 0;

		break;

	case IB_QPT_UC:
		if (qp->resp.drop_msg || diff != 0) {
			if (pkt->mask & RXE_START_MASK) {
				qp->resp.drop_msg = 0;
				return RESPST_CHK_OP_SEQ;
			}

			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}
		break;
	default:
		break;
	}

	/*默认走check op seq*/
	return RESPST_CHK_OP_SEQ;
}

static enum resp_states check_op_seq(struct rxe_qp *qp,
				     struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
		switch (qp->resp.opcode/*上次执行时的opcode*/) {
		case IB_OPCODE_RC_SEND_FIRST:
		case IB_OPCODE_RC_SEND_MIDDLE:
			switch (pkt->opcode/*当次报文的opcode*/) {
			case IB_OPCODE_RC_SEND_MIDDLE:
			case IB_OPCODE_RC_SEND_LAST:
			case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
				return RESPST_CHK_OP_VALID;/*有效的opt*/
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_C;/*缺少last opt*/
			}

		case IB_OPCODE_RC_RDMA_WRITE_FIRST:
		case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_RC_RDMA_WRITE_LAST:
			case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;/*有效opt*/
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_C;/*缺少last opt*/
			}

		default:
			switch (pkt->opcode) {
			/*此时上次收到的是非first,middle,本次收到middle,last，则报错缺first*/
			case IB_OPCODE_RC_SEND_MIDDLE:
			case IB_OPCODE_RC_SEND_LAST:
			case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
			case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_RC_RDMA_WRITE_LAST:
			case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_ERR_MISSING_OPCODE_FIRST;/*qp未设置first就遇到了middle opt*/
			default:
				return RESPST_CHK_OP_VALID;/*有效opt*/
			}
		}
		break;

	case IB_QPT_UC:
		switch (qp->resp.opcode) {
		case IB_OPCODE_UC_SEND_FIRST:
		case IB_OPCODE_UC_SEND_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_SEND_MIDDLE:
			case IB_OPCODE_UC_SEND_LAST:
			case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_D1E;/*未遇到last opt*/
			}

		case IB_OPCODE_UC_RDMA_WRITE_FIRST:
		case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_UC_RDMA_WRITE_LAST:
			case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
			}

		default:
			switch (pkt->opcode) {
			/*此时上次收到的是非first,middle,本次收到middle,last，则跳RESPST_CLEANUP*/
			case IB_OPCODE_UC_SEND_MIDDLE:
			case IB_OPCODE_UC_SEND_LAST:
			case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_UC_RDMA_WRITE_LAST:
			case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				qp->resp.drop_msg = 1;
				return RESPST_CLEANUP;
			default:
				return RESPST_CHK_OP_VALID;
			}
		}
		break;

	default:
		return RESPST_CHK_OP_VALID;
	}
}

/*检查报文指明的opcode是否与qp属性匹配*/
static bool check_qp_attr_access(struct rxe_qp *qp,
				 struct rxe_pkt_info *pkt)
{
	if (((pkt->mask & RXE_READ_MASK) &&
	     !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_READ)/*报文要求读，但qp不容许远程读*/) ||
	    ((pkt->mask & (RXE_WRITE_MASK | RXE_ATOMIC_WRITE_MASK)) &&
	     !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_WRITE)/*报文要求写，但qp不容许远程写*/) ||
	    ((pkt->mask & RXE_ATOMIC_MASK) &&
	     !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_ATOMIC/*报文要求原子操作，但qp不支持远程原子操作*/)))
		/*比如报文opcode对应需要read权限，但qp不容许remote read，则检查失败*/
		return false;

	if (pkt->mask & RXE_FLUSH_MASK) {
		u32 flush_type = feth_plt(pkt);

		if ((flush_type & IB_FLUSH_GLOBAL &&
		     !(qp->attr.qp_access_flags & IB_ACCESS_FLUSH_GLOBAL)) ||
		    (flush_type & IB_FLUSH_PERSISTENT &&
		     !(qp->attr.qp_access_flags & IB_ACCESS_FLUSH_PERSISTENT)))
			return false;
	}

	return true;
}

static enum resp_states check_op_valid(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (!check_qp_attr_access(qp, pkt))
			/*opcode隐含要求的访问方式与qp支持的访问方式不一致*/
			return RESPST_ERR_UNSUPPORTED_OPCODE;

		break;

	case IB_QPT_UC:
		if ((pkt->mask & RXE_WRITE_MASK) &&
		    !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_WRITE)) {
			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}

		break;

	case IB_QPT_UD:
	case IB_QPT_GSI:
		break;

	default:
		WARN_ON_ONCE(1);
		break;
	}

	return RESPST_CHK_RESOURCE;
}

static enum resp_states get_srq_wqe(struct rxe_qp *qp)
{
	struct rxe_srq *srq = qp->srq;
	struct rxe_queue *q = srq->rq.queue;
	struct rxe_recv_wqe *wqe;
	struct ib_event ev;
	unsigned int count;
	size_t size;
	unsigned long flags;

	if (srq->error)
		/*srq有误，跳err*/
		return RESPST_ERR_RNR;

	spin_lock_irqsave(&srq->rq.consumer_lock, flags);

	wqe = queue_head(q, QUEUE_TYPE_FROM_CLIENT);
	if (!wqe) {
		/*无法取得wqe*/
		spin_unlock_irqrestore(&srq->rq.consumer_lock, flags);
		return RESPST_ERR_RNR;
	}

	/* don't trust user space data */
	if (unlikely(wqe->dma.num_sge > srq->rq.max_sge)) {
		/*wqe中指明num_sge超过srq的最大sge*/
		spin_unlock_irqrestore(&srq->rq.consumer_lock, flags);
		rxe_dbg_qp(qp, "invalid num_sge in SRQ entry\n");
		return RESPST_ERR_MALFORMED_WQE;
	}
	size = sizeof(*wqe) + wqe->dma.num_sge*sizeof(struct rxe_sge);
	memcpy(&qp->resp.srq_wqe, wqe, size);

	qp->resp.wqe = &qp->resp.srq_wqe.wqe;
	queue_advance_consumer(q, QUEUE_TYPE_FROM_CLIENT);
	count = queue_count(q, QUEUE_TYPE_FROM_CLIENT);

	if (srq->limit && srq->ibsrq.event_handler && (count < srq->limit)) {
		srq->limit = 0;
		goto event;
	}

	spin_unlock_irqrestore(&srq->rq.consumer_lock, flags);
	return RESPST_CHK_LENGTH;

event:
	spin_unlock_irqrestore(&srq->rq.consumer_lock, flags);
	ev.device = qp->ibqp.device;
	ev.element.srq = qp->ibqp.srq;
	ev.event = IB_EVENT_SRQ_LIMIT_REACHED;
	srq->ibsrq.event_handler(&ev, srq->ibsrq.srq_context);
	return RESPST_CHK_LENGTH;
}

static enum resp_states check_resource(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	struct rxe_srq *srq = qp->srq;

	if (pkt->mask & (RXE_READ_OR_ATOMIC_MASK | RXE_ATOMIC_WRITE_MASK)) {
		/* it is the requesters job to not send
		 * too many read/atomic ops, we just
		 * recycle the responder resource queue
		 */
		if (likely(qp->attr.max_dest_rd_atomic > 0))
			return RESPST_CHK_LENGTH;
		else
			/*达到max_dest_rd_atomic上限*/
			return RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
	}

	if (pkt->mask & RXE_RWR_MASK) {
		if (srq)
			return get_srq_wqe(qp);

		/*自rq中取可使用的wqe,并设置qp->resp.weq*/
		qp->resp.wqe = queue_head(qp->rq.queue,
				QUEUE_TYPE_FROM_CLIENT);
		/*如果无法获取到wqe,则跳RESPST_ERR_RNR*/
		return (qp->resp.wqe) ? RESPST_CHK_LENGTH : RESPST_ERR_RNR;
	}

	return RESPST_CHK_LENGTH;
}

static enum resp_states rxe_resp_check_length(struct rxe_qp *qp,
					      struct rxe_pkt_info *pkt)
{
	/*
	 * See IBA C9-92
	 * For UD QPs we only check if the packet will fit in the
	 * receive buffer later. For rmda operations additional
	 * length checks are performed in check_rkey.
	 */
	if (pkt->mask & RXE_PAYLOAD_MASK && ((qp_type(qp) == IB_QPT_RC) ||
					     (qp_type(qp) == IB_QPT_UC))) {
		/*报文中有payload,且qp为rc/uc时进入*/
		unsigned int mtu = qp->mtu;/*qp的mtu*/
		unsigned int payload = payload_size(pkt);/*报文中的payload长度*/

		if ((pkt->mask & RXE_START_MASK) &&
		    (pkt->mask & RXE_END_MASK)) {
			if (unlikely(payload > mtu)) {
				/*报文的opcode(首或尾）提供的payload大于mtu*/
				rxe_dbg_qp(qp, "only packet too long");
				return RESPST_ERR_LENGTH;
			}
		} else if ((pkt->mask & RXE_START_MASK) ||
			   (pkt->mask & RXE_MIDDLE_MASK)) {
			/*报文的opcode(首或中间的）报文的payload必须与mtu相等*/
			if (unlikely(payload != mtu)) {
				rxe_dbg_qp(qp, "first or middle packet not mtu");
				return RESPST_ERR_LENGTH;
			}
		} else if (pkt->mask & RXE_END_MASK) {
			/*end报文的payload不得为0，不得大于mtu*/
			if (unlikely((payload == 0) || (payload > mtu))) {
				rxe_dbg_qp(qp, "last packet zero or too long");
				return RESPST_ERR_LENGTH;
			}
		}
	}

	/* See IBA C9-94 */
	if (pkt->mask & RXE_RETH_MASK) {
		if (reth_len(pkt) > (1U << 31)) {
			/*指明的dma长度有误*/
			rxe_dbg_qp(qp, "dma length too long");
			return RESPST_ERR_LENGTH;
		}
	}

	if (pkt->mask & RXE_RDMA_OP_MASK)
		/*opcode属于读写等语义，需要执行pkey检查*/
		return RESPST_CHK_RKEY;
	else
		return RESPST_EXECUTE;
}

/* if the reth length field is zero we can assume nothing
 * about the rkey value and should not validate or use it.
 * Instead set qp->resp.rkey to 0 which is an invalid rkey
 * value since the minimum index part is 1.
 */
static void qp_resp_from_reth(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	unsigned int length = reth_len(pkt);

	qp->resp.va = reth_va(pkt);/*取报文指明的va*/
	qp->resp.offset = 0;/*指偏移量*/
	qp->resp.resid = length;
	qp->resp.length = length;/*报文指明dma地址*/
	if (pkt->mask & RXE_READ_OR_WRITE_MASK && length == 0)
		qp->resp.rkey = 0;/*长度为零时，rkey定为0*/
	else
		/*提取reth中指明的rkey*/
		qp->resp.rkey = reth_rkey(pkt);/*取报文指明的rkey*/
}

static void qp_resp_from_atmeth(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	qp->resp.va = atmeth_va(pkt);
	qp->resp.offset = 0;
	qp->resp.rkey = atmeth_rkey(pkt);
	qp->resp.resid = sizeof(u64);/*dma长度为8个字节*/
}

/* resolve the packet rkey to qp->resp.mr or set qp->resp.mr to NULL
 * if an invalid rkey is received or the rdma length is zero. For middle
 * or last packets use the stored value of mr.
 */
static enum resp_states check_rkey(struct rxe_qp *qp,
				   struct rxe_pkt_info *pkt)
{
	/*进入此流程的这些opcode均有RXE_RDMA_OP_MASK标记*/
	struct rxe_mr *mr = NULL;
	struct rxe_mw *mw = NULL;
	u64 va;
	u32 rkey;
	u32 resid;
	u32 pktlen;
	int mtu = qp->mtu;
	enum resp_states state;
	int access = 0;

	/* parse RETH or ATMETH header for first/only packets
	 * for va, length, rkey, etc. or use current value for
	 * middle/last packets.
	 */
	if (pkt->mask & (RXE_READ_OR_WRITE_MASK | RXE_ATOMIC_WRITE_MASK)) {
		/*遇到读，写，原子写*/
		if (pkt->mask & RXE_RETH_MASK)
			/*报文包括reth头，自reth中提取va,offset等*/
			qp_resp_from_reth(qp, pkt);

		/*报文要求的访问权限*/
		access = (pkt->mask & RXE_READ_MASK) ? IB_ACCESS_REMOTE_READ
						     : IB_ACCESS_REMOTE_WRITE;
	} else if (pkt->mask & RXE_FLUSH_MASK) {
		u32 flush_type = feth_plt(pkt);

		if (pkt->mask & RXE_RETH_MASK)
			/*报文包含reth头，自reth中提取va,offset等*/
			qp_resp_from_reth(qp, pkt);

		if (flush_type & IB_FLUSH_GLOBAL)
			access |= IB_ACCESS_FLUSH_GLOBAL;
		if (flush_type & IB_FLUSH_PERSISTENT)
			access |= IB_ACCESS_FLUSH_PERSISTENT;
	} else if (pkt->mask & RXE_ATOMIC_MASK) {
		/*原子标记，报文含atmeth头，自atmeth中提取va,offset等*/
		qp_resp_from_atmeth(qp, pkt);
		access = IB_ACCESS_REMOTE_ATOMIC;
	} else {
		/* shouldn't happen */
		WARN_ON(1);
	}

	/* A zero-byte read or write op is not required to
	 * set an addr or rkey. See C9-88
	 */
	if ((pkt->mask & RXE_READ_OR_WRITE_MASK) &&
	    (pkt->mask & RXE_RETH_MASK) && reth_len(pkt) == 0) {
		/*reth长度指明为0时，mr为NULL*/
		qp->resp.mr = NULL;
		return RESPST_EXECUTE;
	}

	va	= qp->resp.va;
	rkey	= qp->resp.rkey;
	resid	= qp->resp.resid;
	pktlen	= payload_size(pkt);/*取当前报文中包含的pktlen*/

	if (rkey_is_mw(rkey)) {
		/*这个rkey为mw,查询mw*/
		mw = rxe_lookup_mw(qp, access, rkey);
		if (!mw) {
			rxe_dbg_qp(qp, "no MW matches rkey %#x\n", rkey);
			state = RESPST_ERR_RKEY_VIOLATION;
			goto err;
		}

		mr = mw->mr;
		if (!mr) {
			rxe_dbg_qp(qp, "MW doesn't have an MR\n");
			state = RESPST_ERR_RKEY_VIOLATION;
			goto err;
		}

		if (mw->access & IB_ZERO_BASED)
			qp->resp.offset = mw->addr;

		rxe_get(mr);
		rxe_put(mw);
		mw = NULL;
	} else {
		/*这种rkey是mr,通过rkey,access查询mr*/
		mr = lookup_mr(qp->pd, access, rkey, RXE_LOOKUP_REMOTE);
		if (!mr) {
			/*没有找到对应的mr。*/
			rxe_dbg_qp(qp, "no MR matches rkey %#x\n", rkey);
			state = RESPST_ERR_RKEY_VIOLATION;
			goto err;
		}
	}

	if (pkt->mask & RXE_FLUSH_MASK) {
		/* FLUSH MR may not set va or resid
		 * no need to check range since we will flush whole mr
		 */
		if (feth_sel(pkt) == IB_FLUSH_MR)
			goto skip_check_range;
	}

	/*检查mr是否能处理范围(va+qp->resp.offset, va+qp->resp.offset + resid)*/
	if (mr_check_range(mr, va + qp->resp.offset, resid)) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

skip_check_range:
	if (pkt->mask & (RXE_WRITE_MASK | RXE_ATOMIC_WRITE_MASK)) {
		if (resid > mtu) {
			/*要操作的长度超过了mtu*/
			if (pktlen != mtu || bth_pad(pkt)) {
				/*报文长度与mtu不一致，且pad不为零*/
				state = RESPST_ERR_LENGTH;
				goto err;
			}
		} else {
			if (pktlen != resid) {
				/*要操作的长度与报文长度不一致*/
				state = RESPST_ERR_LENGTH;
				goto err;
			}
			if ((bth_pad(pkt) != (0x3 & (-resid)))) {
				/*两者pad不一致*/
				/* This case may not be exactly that
				 * but nothing else fits.
				 */
				state = RESPST_ERR_LENGTH;
				goto err;
			}
		}
	}

	WARN_ON_ONCE(qp->resp.mr);

	qp->resp.mr = mr;
	return RESPST_EXECUTE;/*跳execute*/

err:
	qp->resp.mr = NULL;
	if (mr)
		rxe_put(mr);
	if (mw)
		rxe_put(mw);

	return state;
}

/*利用(data_addr,data_len)填充qp响应对应的wqe*/
static enum resp_states send_data_in(struct rxe_qp *qp, void *data_addr,
				     int data_len)
{
	int err;

	/*利用data_addr填充qp->resp.wqe*/
	err = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE/*本地写*/, &qp->resp.wqe->dma/*wqe对应的起始地址*/,
			data_addr/*源数据地址*/, data_len/*源数据长度*/, RXE_TO_MR_OBJ/*复制数据到mr*/);
	if (unlikely(err))
		/*复制出错*/
		return (err == -ENOSPC) ? RESPST_ERR_LENGTH
					: RESPST_ERR_MALFORMED_WQE;

	return RESPST_NONE;
}

static enum resp_states write_data_in(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt)
{
	enum resp_states rc = RESPST_NONE;
	int	err;
	int data_len = payload_size(pkt);

	/*将pkt payload内容填充到qp->resp.mr*/
	err = rxe_mr_copy(qp->resp.mr, qp->resp.va + qp->resp.offset,
			  payload_addr(pkt), data_len, RXE_TO_MR_OBJ);
	if (err) {
		rc = RESPST_ERR_RKEY_VIOLATION;
		goto out;
	}

	qp->resp.va += data_len;
	qp->resp.resid -= data_len;

out:
	return rc;
}

static struct resp_res *rxe_prepare_res(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					int type)
{
	struct resp_res *res;
	u32 pkts;

	/*指向head对应的struct resp_res*/
	res = &qp->resp.resources[qp->resp.res_head];
	rxe_advance_resp_resource(qp);
	free_rd_atomic_resource(res);

	res->type = type;
	res->replay = 0;

	switch (type) {
	case RXE_READ_MASK:
		res->read.va = qp->resp.va + qp->resp.offset;
		res->read.va_org = qp->resp.va + qp->resp.offset;
		res->read.resid = qp->resp.resid;
		res->read.length = qp->resp.resid;
		res->read.rkey = qp->resp.rkey;

		pkts = max_t(u32, (reth_len(pkt) + qp->mtu - 1)/qp->mtu, 1);
		res->first_psn = pkt->psn;
		res->cur_psn = pkt->psn;
		res->last_psn = (pkt->psn + pkts - 1) & BTH_PSN_MASK;

		res->state = rdatm_res_state_new;
		break;
	case RXE_ATOMIC_MASK:
	case RXE_ATOMIC_WRITE_MASK:
		res->first_psn = pkt->psn;
		res->last_psn = pkt->psn;
		res->cur_psn = pkt->psn;
		break;
	case RXE_FLUSH_MASK:
		res->flush.va = qp->resp.va + qp->resp.offset;
		res->flush.length = qp->resp.length;
		res->flush.type = feth_plt(pkt);
		res->flush.level = feth_sel(pkt);
	}

	return res;
}

static enum resp_states process_flush(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	u64 length, start;
	struct rxe_mr *mr = qp->resp.mr;
	struct resp_res *res = qp->resp.res;

	/* oA19-14, oA19-15 */
	if (res && res->replay)
		return RESPST_ACKNOWLEDGE;
	else if (!res) {
		res = rxe_prepare_res(qp, pkt, RXE_FLUSH_MASK);
		qp->resp.res = res;
	}

	if (res->flush.level == IB_FLUSH_RANGE) {
		start = res->flush.va;
		length = res->flush.length;
	} else { /* level == IB_FLUSH_MR */
		start = mr->ibmr.iova;
		length = mr->ibmr.length;
	}

	if (res->flush.type & IB_FLUSH_PERSISTENT) {
		if (rxe_flush_pmem_iova(mr, start, length))
			return RESPST_ERR_RKEY_VIOLATION;
		/* Make data persistent. */
		wmb();
	} else if (res->flush.type & IB_FLUSH_GLOBAL) {
		/* Make data global visibility. */
		wmb();
	}

	qp->resp.msn++;

	/* next expected psn, read handles this separately */
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;

	qp->resp.opcode = pkt->opcode;
	qp->resp.status = IB_WC_SUCCESS;

	return RESPST_ACKNOWLEDGE;
}

static enum resp_states atomic_reply(struct rxe_qp *qp,
				     struct rxe_pkt_info *pkt)
{
	struct rxe_mr *mr = qp->resp.mr;
	struct resp_res *res = qp->resp.res;
	int err;

	if (!res) {
		res = rxe_prepare_res(qp, pkt, RXE_ATOMIC_MASK);
		qp->resp.res = res;
	}

	if (!res->replay) {
		u64 iova = qp->resp.va + qp->resp.offset;

		err = rxe_mr_do_atomic_op(mr, iova, pkt->opcode,
					  atmeth_comp(pkt),
					  atmeth_swap_add(pkt),
					  &res->atomic.orig_val);
		if (err)
			return err;

		qp->resp.msn++;

		/* next expected psn, read handles this separately */
		qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;
		qp->resp.ack_psn = qp->resp.psn;

		qp->resp.opcode = pkt->opcode;
		qp->resp.status = IB_WC_SUCCESS;
	}

	return RESPST_ACKNOWLEDGE;
}

static enum resp_states atomic_write_reply(struct rxe_qp *qp,
					   struct rxe_pkt_info *pkt)
{
	struct resp_res *res = qp->resp.res;
	struct rxe_mr *mr;
	u64 value;
	u64 iova;
	int err;

	if (!res) {
		res = rxe_prepare_res(qp, pkt, RXE_ATOMIC_WRITE_MASK);
		qp->resp.res = res;
	}

	if (res->replay)
		return RESPST_ACKNOWLEDGE;

	mr = qp->resp.mr;
	value = *(u64 *)payload_addr(pkt);
	iova = qp->resp.va + qp->resp.offset;

	err = rxe_mr_do_atomic_write(mr, iova, value);
	if (err)
		return err;

	qp->resp.resid = 0;
	qp->resp.msn++;

	/* next expected psn, read handles this separately */
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;

	qp->resp.opcode = pkt->opcode;
	qp->resp.status = IB_WC_SUCCESS;

	return RESPST_ACKNOWLEDGE;
}

static struct sk_buff *prepare_ack_packet(struct rxe_qp *qp,
					  struct rxe_pkt_info *ack,
					  int opcode/*要发送的ack消息opcode*/,
					  int payload/*payload长度*/,
					  u32 psn/*包的squence number*/,
					  u8 syndrome/*ack消息错误原因*/)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct sk_buff *skb;
	int paylen;
	int pad;
	int err;

	/*
	 * allocate packet
	 */
	pad = (-payload) & 0x3;/*payload对齐需要的pad长度*/
	/*ack报文总长度*/
	paylen = rxe_opcode[opcode].length/*header总长度*/ + payload + pad + RXE_ICRC_SIZE;

	/*申请skb,设置skb关联的netdev*/
	skb = rxe_init_packet(rxe, &qp->pri_av, paylen, ack);
	if (!skb)
		return NULL;

	/*设置skb报文关联的一组信息*/
	ack->qp = qp;
	ack->opcode = opcode;
	ack->mask = rxe_opcode[opcode].mask;
	ack->paylen = paylen;
	ack->psn = psn;

	/*构造ack的bth报文*/
	bth_init(ack, opcode, 0, 0, pad, IB_DEFAULT_PKEY_FULL/*指明pkey*/,
		 qp->attr.dest_qp_num/*设置目标qp*/, 0/*不要求响应ack*/, psn);

	/*此ack需要包含aeth头时*/
	if (ack->mask & RXE_AETH_MASK) {
		aeth_set_syn(ack, syndrome);/*设置syndrome*/
		aeth_set_msn(ack, qp->resp.msn);/*响应msn*/
	}

	/*此ack需要包含atmack头时*/
	if (ack->mask & RXE_ATMACK_MASK)
		atmack_set_orig(ack, qp->resp.res->atomic.orig_val);

	/*填充ip,udp header*/
	err = rxe_prepare(&qp->pri_av, ack, skb);
	if (err) {
		kfree_skb(skb);
		return NULL;
	}

	/*返回构造好的报文*/
	return skb;
}

/**
 * rxe_recheck_mr - revalidate MR from rkey and get a reference
 * @qp: the qp
 * @rkey: the rkey
 *
 * This code allows the MR to be invalidated or deregistered or
 * the MW if one was used to be invalidated or deallocated.
 * It is assumed that the access permissions if originally good
 * are OK and the mappings to be unchanged.
 *
 * TODO: If someone reregisters an MR to change its size or
 * access permissions during the processing of an RDMA read
 * we should kill the responder resource and complete the
 * operation with an error.
 *
 * Return: mr on success else NULL
 */
static struct rxe_mr *rxe_recheck_mr(struct rxe_qp *qp, u32 rkey)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_mr *mr;
	struct rxe_mw *mw;

	if (rkey_is_mw(rkey)) {
		mw = rxe_pool_get_index(&rxe->mw_pool, rkey >> 8);
		if (!mw)
			return NULL;

		mr = mw->mr;
		if (mw->rkey != rkey || mw->state != RXE_MW_STATE_VALID ||
		    !mr || mr->state != RXE_MR_STATE_VALID) {
			rxe_put(mw);
			return NULL;
		}

		rxe_get(mr);
		rxe_put(mw);

		return mr;
	}

	/*通过rkey获取mr*/
	mr = rxe_pool_get_index(&rxe->mr_pool, rkey >> 8);
	if (!mr)
		return NULL;

	if (mr->rkey != rkey || mr->state != RXE_MR_STATE_VALID) {
		rxe_put(mr);
		return NULL;
	}

	return mr;
}

/* RDMA read response. If res is not NULL, then we have a current RDMA request
 * being processed or replayed.
 */
static enum resp_states read_reply(struct rxe_qp *qp,
				   struct rxe_pkt_info *req_pkt)
{
	struct rxe_pkt_info ack_pkt;
	struct sk_buff *skb;
	int mtu = qp->mtu;
	enum resp_states state;
	int payload;
	int opcode;
	int err;
	struct resp_res *res = qp->resp.res;
	struct rxe_mr *mr;

	if (!res) {
		/*没有设置res*/
		res = rxe_prepare_res(qp, req_pkt, RXE_READ_MASK);
		qp->resp.res = res;
	}

	if (res->state == rdatm_res_state_new) {
		if (!res->replay || qp->resp.length == 0) {
			/* if length == 0 mr will be NULL (is ok)
			 * otherwise qp->resp.mr holds a ref on mr
			 * which we transfer to mr and drop below.
			 */
			mr = qp->resp.mr;
			qp->resp.mr = NULL;
		} else {
			mr = rxe_recheck_mr(qp, res->read.rkey);
			if (!mr)
				return RESPST_ERR_RKEY_VIOLATION;
		}

		/*报文中指明要读取的内容小于mtu，则opcode采用read_response_only,否则用read_response_first*/
		if (res->read.resid <= mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
	} else {
		/* re-lookup mr from rkey on all later packets.
		 * length will be non-zero. This can fail if someone
		 * modifies or destroys the mr since the first packet.
		 */
		mr = rxe_recheck_mr(qp, res->read.rkey);
		if (!mr)
			return RESPST_ERR_RKEY_VIOLATION;

		if (res->read.resid > mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST;
	}

	res->state = rdatm_res_state_next;

	/*确定payload长度*/
	payload = min_t(int, res->read.resid, mtu);

	/*构造opcode对应的skb*/
	skb = prepare_ack_packet(qp, &ack_pkt, opcode, payload,
				 res->cur_psn, AETH_ACK_UNLIMITED);
	if (!skb) {
		state = RESPST_ERR_RNR;
		goto err_out;
	}

	/*将va中的内容填充到ack_pkt中*/
	err = rxe_mr_copy(mr, res->read.va, payload_addr(&ack_pkt),
			  payload, RXE_FROM_MR_OBJ);
	if (err) {
		kfree_skb(skb);
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err_out;
	}

	/*pad添加*/
	if (bth_pad(&ack_pkt)) {
		u8 *pad = payload_addr(&ack_pkt) + payload;

		memset(pad, 0, bth_pad(&ack_pkt));
	}

	/*向外发送此报文*/
	/* rxe_xmit_packet always consumes the skb */
	err = rxe_xmit_packet(qp, &ack_pkt, skb);
	if (err) {
		state = RESPST_ERR_RNR;
		goto err_out;
	}

	res->read.va += payload;
	res->read.resid -= payload;
	res->cur_psn = (res->cur_psn + 1) & BTH_PSN_MASK;

	if (res->read.resid > 0) {
		state = RESPST_DONE;
	} else {
		qp->resp.res = NULL;
		if (!res->replay)
			qp->resp.opcode = -1;
		if (psn_compare(res->cur_psn, qp->resp.psn) >= 0)
			qp->resp.psn = res->cur_psn;
		state = RESPST_CLEANUP;
	}

err_out:
	if (mr)
		rxe_put(mr);
	return state;
}

static int invalidate_rkey(struct rxe_qp *qp, u32 rkey)
{
	if (rkey_is_mw(rkey))
		return rxe_invalidate_mw(qp, rkey);
	else
		/*按照rkey来无效普通注册的mr*/
		return rxe_invalidate_mr(qp, rkey);
}

/* Executes a new request. A retried request never reach that function (send
 * and writes are discarded, and reads and atomics are retried elsewhere.
 */
static enum resp_states execute(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	enum resp_states err;
	struct sk_buff *skb = PKT_TO_SKB(pkt);
	union rdma_network_hdr hdr;

	if (pkt->mask & RXE_SEND_MASK) {
		if (qp_type(qp) == IB_QPT_UD ||
		    qp_type(qp) == IB_QPT_GSI) {
			/*只处理ud,gsi类型的send类操作（这两种需要将ip header复制上去）*/
			if (skb->protocol == htons(ETH_P_IP)) {
				/*将ipv4 hdr填充到qp->resp.wqe->dma中*/
				memset(&hdr.reserved, 0,
						sizeof(hdr.reserved));
				memcpy(&hdr.roce4grh, ip_hdr(skb),
						sizeof(hdr.roce4grh));/*复制skb内容到roce4grh*/
				/*复制roce4grh到qp->resp.wqe->dma*/
				err = send_data_in(qp, &hdr, sizeof(hdr));
			} else {
				/*复制ipv6 header到qp->resp.wqe->dma中*/
				err = send_data_in(qp, ipv6_hdr(skb),
						sizeof(hdr));
			}
			if (err)
				return err;/*复制出错，直接返回下一步状态*/
		}

		/*再将payload填充到qp->resp.wqe->dma中*/
		err = send_data_in(qp, payload_addr(pkt), payload_size(pkt));
		if (err)
			return err;
	} else if (pkt->mask & RXE_WRITE_MASK) {
		/*将pkt payload内容填充到qp->resp.mr*/
		err = write_data_in(qp, pkt);
		if (err)
			return err;
	} else if (pkt->mask & RXE_READ_MASK) {
		/* For RDMA Read we can increment the msn now. See C9-148. */
		qp->resp.msn++;/*收到read操作，我们增加msn编号，跳RESPST_READ_REPLY*/
		return RESPST_READ_REPLY;
	} else if (pkt->mask & RXE_ATOMIC_MASK) {
		return RESPST_ATOMIC_REPLY;
	} else if (pkt->mask & RXE_ATOMIC_WRITE_MASK) {
		return RESPST_ATOMIC_WRITE_REPLY;
	} else if (pkt->mask & RXE_FLUSH_MASK) {
		return RESPST_PROCESS_FLUSH;
	} else {
		/*没有其它标记了。*/
		/* Unreachable */
		WARN_ON_ONCE(1);
	}

	/*如上示，只有write,send执行成功后可以进入下面流程*/

	if (pkt->mask & RXE_IETH_MASK) {
		u32 rkey = ieth_rkey(pkt);

		/*无效ieth中包含的rkey*/
		err = invalidate_rkey(qp, rkey);
		if (err)
			return RESPST_ERR_INVALIDATE_RKEY;
	}

	if (pkt->mask & RXE_END_MASK)
		/* We successfully processed this new request. */
		qp->resp.msn++;/*当前为此系列opcode最后一个op，故msg增加*/

	/* next expected psn, read handles this separately */
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;/*增加psn*/
	qp->resp.ack_psn = qp->resp.psn;/*预期的下一个psn*/

	qp->resp.opcode = pkt->opcode;/*记录响应的opcode*/
	qp->resp.status = IB_WC_SUCCESS;/*opcde执行成功*/

	if (pkt->mask & RXE_COMP_MASK)
		return RESPST_COMPLETE;
	else if (qp_type(qp) == IB_QPT_RC)
		/*针对rc需要进行ack*/
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}

static enum resp_states do_complete(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt)
{
	struct rxe_cqe cqe;
	struct ib_wc *wc = &cqe.ibwc;
	struct ib_uverbs_wc *uwc = &cqe.uibwc;
	struct rxe_recv_wqe *wqe = qp->resp.wqe;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	unsigned long flags;

	if (!wqe)
		goto finish;

	memset(&cqe, 0, sizeof(cqe));

	if (qp->rcq->is_user) {
		uwc->status		= qp->resp.status;
		uwc->qp_num		= qp->ibqp.qp_num;
		uwc->wr_id		= wqe->wr_id;
	} else {
		wc->status		= qp->resp.status;
		wc->qp			= &qp->ibqp;
		wc->wr_id		= wqe->wr_id;
	}

	if (wc->status == IB_WC_SUCCESS) {
		/*执行成功*/
		rxe_counter_inc(rxe, RXE_CNT_RDMA_RECV);
		wc->opcode = (pkt->mask & RXE_IMMDT_MASK &&
				pkt->mask & RXE_WRITE_MASK) ?
					IB_WC_RECV_RDMA_WITH_IMM : IB_WC_RECV;
		wc->byte_len = (pkt->mask & RXE_IMMDT_MASK &&
				pkt->mask & RXE_WRITE_MASK) ?
					qp->resp.length : wqe->dma.length - wqe->dma.resid;

		/* fields after byte_len are different between kernel and user
		 * space
		 */
		if (qp->rcq->is_user) {
			uwc->wc_flags = IB_WC_GRH;

			if (pkt->mask & RXE_IMMDT_MASK) {
				uwc->wc_flags |= IB_WC_WITH_IMM;
				uwc->ex.imm_data = immdt_imm(pkt);
			}

			if (pkt->mask & RXE_IETH_MASK) {
				uwc->wc_flags |= IB_WC_WITH_INVALIDATE;
				uwc->ex.invalidate_rkey = ieth_rkey(pkt);
			}

			if (pkt->mask & RXE_DETH_MASK)
				uwc->src_qp = deth_sqp(pkt);

			uwc->port_num		= qp->attr.port_num;
		} else {
			struct sk_buff *skb = PKT_TO_SKB(pkt);

			wc->wc_flags = IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE;
			if (skb->protocol == htons(ETH_P_IP))
				wc->network_hdr_type = RDMA_NETWORK_IPV4;
			else
				wc->network_hdr_type = RDMA_NETWORK_IPV6;

			if (is_vlan_dev(skb->dev)) {
				wc->wc_flags |= IB_WC_WITH_VLAN;
				wc->vlan_id = vlan_dev_vlan_id(skb->dev);
			}

			if (pkt->mask & RXE_IMMDT_MASK) {
				wc->wc_flags |= IB_WC_WITH_IMM;
				wc->ex.imm_data = immdt_imm(pkt);
			}

			if (pkt->mask & RXE_IETH_MASK) {
				wc->wc_flags |= IB_WC_WITH_INVALIDATE;
				wc->ex.invalidate_rkey = ieth_rkey(pkt);
			}

			if (pkt->mask & RXE_DETH_MASK)
				wc->src_qp = deth_sqp(pkt);

			wc->port_num		= qp->attr.port_num;
		}
	} else {
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			rxe_err_qp(qp, "non-flush error status = %d",
				wc->status);
	}

	/* have copy for srq and reference for !srq */
	if (!qp->srq)
		queue_advance_consumer(qp->rq.queue, QUEUE_TYPE_FROM_CLIENT);

	/*wqe填充完成，将此设置NULL*/
	qp->resp.wqe = NULL;

	/*填充cqe*/
	if (rxe_cq_post(qp->rcq, &cqe, pkt ? bth_se(pkt)/*报文是否有se标记*/ : 1))
		return RESPST_ERR_CQ_OVERFLOW;

finish:
	spin_lock_irqsave(&qp->state_lock, flags);
	if (unlikely(qp_state(qp) == IB_QPS_ERR)) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		return RESPST_CHK_RESOURCE;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	if (unlikely(!pkt))
		return RESPST_DONE;
	if (qp_type(qp) == IB_QPT_RC)
		/*针对rc跳ack状态*/
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}


static int send_common_ack(struct rxe_qp *qp, u8 syndrome/*错误原因*/, u32 psn/*响应对应的报文psn*/,
				  int opcode/*ack对应的opcode*/, const char *msg/*响应对应的日志内容*/)
{
	int err;
	struct rxe_pkt_info ack_pkt;
	struct sk_buff *skb;

	/*构造ack报文*/
	skb = prepare_ack_packet(qp, &ack_pkt, opcode, 0/*payload长度为零*/, psn, syndrome);
	if (!skb)
		return -ENOMEM;

	/*ack报文发送*/
	err = rxe_xmit_packet(qp, &ack_pkt, skb);
	if (err)
		rxe_dbg_qp(qp, "Failed sending %s\n", msg);

	return err;
}

/*向指定qp发送ack报文，确认psn报文已收到，并指明错误原因*/
static int send_ack(struct rxe_qp *qp, u8 syndrome/*错误原因*/, u32 psn/*响应对应的psn*/)
{
	return send_common_ack(qp, syndrome, psn,
			IB_OPCODE_RC_ACKNOWLEDGE, "ACK");
}

/*向指定qp发送atomic ack报文，确认psn报文已收到，并指明错误原因*/
static int send_atomic_ack(struct rxe_qp *qp, u8 syndrome, u32 psn)
{
	int ret = send_common_ack(qp, syndrome, psn,
			IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE, "ATOMIC ACK");

	/* have to clear this since it is used to trigger
	 * long read replies
	 */
	qp->resp.res = NULL;
	return ret;
}

/*向指定qp发送read response ack报文，确认psn报文已收到，并指明错误原因*/
static int send_read_response_ack(struct rxe_qp *qp, u8 syndrome, u32 psn)
{
	int ret = send_common_ack(qp, syndrome, psn,
			IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY,
			"RDMA READ response of length zero ACK");

	/* have to clear this since it is used to trigger
	 * long read replies
	 */
	qp->resp.res = NULL;
	return ret;
}

static enum resp_states acknowledge(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt)
{
	if (qp_type(qp) != IB_QPT_RC)
		/*只有rc可以进入此流程，否则走cleanup*/
		return RESPST_CLEANUP;

	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED)
		/*非默认值，即发生了错误，则走此回应*/
		send_ack(qp, qp->resp.aeth_syndrome, pkt->psn/*用于响应的报文psn*/);
	else if (pkt->mask & RXE_ATOMIC_MASK)
		/*如果有atomic标记，则响应AETH_ACK_UNLIMITED*/
		send_atomic_ack(qp, AETH_ACK_UNLIMITED, pkt->psn);
	else if (pkt->mask & (RXE_FLUSH_MASK | RXE_ATOMIC_WRITE_MASK))
		/*flush操作，或者atomic write操作，响应ack*/
		send_read_response_ack(qp, AETH_ACK_UNLIMITED, pkt->psn);
	else if (bth_ack(pkt))
		/*按报文要求，响应ack报文，并发送*/
		send_ack(qp, AETH_ACK_UNLIMITED, pkt->psn);

	return RESPST_CLEANUP;
}

static enum resp_states cleanup(struct rxe_qp *qp,
				struct rxe_pkt_info *pkt)
{
	struct sk_buff *skb;

	if (pkt) {
		/*丢弃掉req上的报文(前述处理均在peek情况下执行）故这里需要出队*/
		skb = skb_dequeue(&qp->req_pkts);
		rxe_put(qp);
		kfree_skb(skb);
		ib_device_put(qp->ibqp.device);
	}

	if (qp->resp.mr) {
		/*如果查询了mr，则put回mr*/
		rxe_put(qp->resp.mr);
		qp->resp.mr = NULL;
	}

	return RESPST_DONE;
}

static struct resp_res *find_resource(struct rxe_qp *qp, u32 psn)
{
	int i;

	for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
		struct resp_res *res = &qp->resp.resources[i];

		if (res->type == 0)
			continue;

		if (psn_compare(psn, res->first_psn) >= 0 &&
		    psn_compare(psn, res->last_psn) <= 0) {
			return res;
		}
	}

	return NULL;
}

static enum resp_states duplicate_request(struct rxe_qp *qp,
					  struct rxe_pkt_info *pkt)
{
	enum resp_states rc;
	u32 prev_psn = (qp->resp.ack_psn - 1) & BTH_PSN_MASK;

	if (pkt->mask & RXE_SEND_MASK ||
	    pkt->mask & RXE_WRITE_MASK) {
		/* SEND. Ack again and cleanup. C9-105. */
		send_ack(qp, AETH_ACK_UNLIMITED, prev_psn);
		return RESPST_CLEANUP;
	} else if (pkt->mask & RXE_FLUSH_MASK) {
		struct resp_res *res;

		/* Find the operation in our list of responder resources. */
		res = find_resource(qp, pkt->psn);
		if (res) {
			res->replay = 1;
			res->cur_psn = pkt->psn;
			qp->resp.res = res;
			rc = RESPST_PROCESS_FLUSH;
			goto out;
		}

		/* Resource not found. Class D error. Drop the request. */
		rc = RESPST_CLEANUP;
		goto out;
	} else if (pkt->mask & RXE_READ_MASK) {
		struct resp_res *res;

		res = find_resource(qp, pkt->psn);
		if (!res) {
			/* Resource not found. Class D error.  Drop the
			 * request.
			 */
			rc = RESPST_CLEANUP;
			goto out;
		} else {
			/* Ensure this new request is the same as the previous
			 * one or a subset of it.
			 */
			u64 iova = reth_va(pkt);
			u32 resid = reth_len(pkt);

			if (iova < res->read.va_org ||
			    resid > res->read.length ||
			    (iova + resid) > (res->read.va_org +
					      res->read.length)) {
				rc = RESPST_CLEANUP;
				goto out;
			}

			if (reth_rkey(pkt) != res->read.rkey) {
				rc = RESPST_CLEANUP;
				goto out;
			}

			res->cur_psn = pkt->psn;
			res->state = (pkt->psn == res->first_psn) ?
					rdatm_res_state_new :
					rdatm_res_state_replay;
			res->replay = 1;

			/* Reset the resource, except length. */
			res->read.va_org = iova;
			res->read.va = iova;
			res->read.resid = resid;

			/* Replay the RDMA read reply. */
			qp->resp.res = res;
			rc = RESPST_READ_REPLY;
			goto out;
		}
	} else {
		struct resp_res *res;

		/* Find the operation in our list of responder resources. */
		res = find_resource(qp, pkt->psn);
		if (res) {
			res->replay = 1;
			res->cur_psn = pkt->psn;
			qp->resp.res = res;
			rc = pkt->mask & RXE_ATOMIC_MASK ?
					RESPST_ATOMIC_REPLY :
					RESPST_ATOMIC_WRITE_REPLY;
			goto out;
		}

		/* Resource not found. Class D error. Drop the request. */
		rc = RESPST_CLEANUP;
		goto out;
	}
out:
	return rc;
}

/* Process a class A or C. Both are treated the same in this implementation. */
static void do_class_ac_error(struct rxe_qp *qp, u8 syndrome,
			      enum ib_wc_status status)
{
	qp->resp.aeth_syndrome	= syndrome;
	qp->resp.status		= status;

	/* indicate that we should go through the ERROR state */
	qp->resp.goto_error	= 1;
}

static enum resp_states do_class_d1e_error(struct rxe_qp *qp)
{
	/* UC */
	if (qp->srq) {
		/* Class E */
		qp->resp.drop_msg = 1;
		if (qp->resp.wqe) {
			qp->resp.status = IB_WC_REM_INV_REQ_ERR;
			return RESPST_COMPLETE;
		} else {
			return RESPST_CLEANUP;
		}
	} else {
		/* Class D1. This packet may be the start of a
		 * new message and could be valid. The previous
		 * message is invalid and ignored. reset the
		 * recv wr to its original state
		 */
		if (qp->resp.wqe) {
			qp->resp.wqe->dma.resid = qp->resp.wqe->dma.length;
			qp->resp.wqe->dma.cur_sge = 0;
			qp->resp.wqe->dma.sge_offset = 0;
			qp->resp.opcode = -1;
		}

		if (qp->resp.mr) {
			rxe_put(qp->resp.mr);
			qp->resp.mr = NULL;
		}

		return RESPST_CLEANUP;
	}
}

/* drain incoming request packet queue */
static void drain_req_pkts(struct rxe_qp *qp)
{
	struct sk_buff *skb;

	/*将qp->req_pkts上所有报文均释放*/
	while ((skb = skb_dequeue(&qp->req_pkts))) {
		rxe_put(qp);
		kfree_skb(skb);
		ib_device_put(qp->ibqp.device);
	}
}

/* complete receive wqe with flush error */
static int flush_recv_wqe(struct rxe_qp *qp, struct rxe_recv_wqe *wqe)
{
	struct rxe_cqe cqe = {};
	struct ib_wc *wc = &cqe.ibwc;
	struct ib_uverbs_wc *uwc = &cqe.uibwc;
	int err;

	if (qp->rcq->is_user) {
		uwc->wr_id = wqe->wr_id;
		uwc->status = IB_WC_WR_FLUSH_ERR;
		uwc->qp_num = qp_num(qp);
	} else {
		wc->wr_id = wqe->wr_id;
		wc->status = IB_WC_WR_FLUSH_ERR;/*状态为flush err*/
		wc->qp = &qp->ibqp;
	}

	err = rxe_cq_post(qp->rcq, &cqe, 0);
	if (err)
		rxe_dbg_cq(qp->rcq, "post cq failed err = %d", err);

	return err;
}

/* drain and optionally complete the recive queue
 * if unable to complete a wqe stop completing and
 * just flush the remaining wqes
 */
static void flush_recv_queue(struct rxe_qp *qp, bool notify)
{
	struct rxe_queue *q = qp->rq.queue;
	struct rxe_recv_wqe *wqe;
	int err;

	if (qp->srq) {
		if (notify && qp->ibqp.event_handler) {
			struct ib_event ev;

			ev.device = qp->ibqp.device;
			ev.element.qp = &qp->ibqp;
			ev.event = IB_EVENT_QP_LAST_WQE_REACHED;
			qp->ibqp.event_handler(&ev, qp->ibqp.qp_context);
		}
		return;
	}

	/* recv queue not created. nothing to do. */
	if (!qp->rq.queue)
		return;

	while ((wqe = queue_head(q, q->type))) {
		if (notify) {
			err = flush_recv_wqe(qp, wqe);
			if (err)
				notify = 0;
		}
		queue_advance_consumer(q, q->type);
	}

	qp->resp.wqe = NULL;
}

/*处理收到的请求类报文（已串到qp->req_pkts链表）并进行响应,
 * （包括将报文内容填充到用户态指明的recv_wr)*/
int rxe_responder(struct rxe_qp *qp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);/*关联的rxe设备*/
	enum resp_states state;
	struct rxe_pkt_info *pkt = NULL;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&qp->state_lock, flags);
	/*qp无效或者状态为ERR,RESET*/
	if (!qp->valid || qp_state(qp) == IB_QPS_ERR ||
			  qp_state(qp) == IB_QPS_RESET) {
		/*有效，但状态变更为err,则需要通知*/
		bool notify = qp->valid && (qp_state(qp) == IB_QPS_ERR);

		drain_req_pkts(qp);/*移除此qp上缓存的所有报文*/
		flush_recv_queue(qp, notify);
		spin_unlock_irqrestore(&qp->state_lock, flags);
		/*qp状态已无效，put后退出*/
		goto exit;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;/*初始化默认出错原因*/

	/*初始化状态为RESPST_GET_REQ*/
	state = RESPST_GET_REQ;

	while (1) {
		/*显示当前state*/
		rxe_dbg_qp(qp, "state = %s\n", resp_state_name[state]);
		switch (state) {
		case RESPST_GET_REQ:
		    /*取接收到的req类报文,并得到下一步state（预期走：RESPST_CHK_PSN）*/
			state = get_req(qp, &pkt/*出参，收到的报文*/);
			break;
		case RESPST_CHK_PSN:
			/*比较psn，并得到下一步state(预期走：RESPST_CHK_OP_SEQ，ps.后面预期均是下个）*/
			state = check_psn(qp, pkt);
			break;
		case RESPST_CHK_OP_SEQ:
			/*检查opcode的顺序是否有效（预期走：RESPST_CHK_OP_VALID）*/
			state = check_op_seq(qp, pkt);
			break;
		case RESPST_CHK_OP_VALID:
			/*检查opcode是否与qp权限匹配。是否有效（预期走：RESPST_CHK_RESOURCE）*/
			state = check_op_valid(qp, pkt);
			break;
		case RESPST_CHK_RESOURCE:
			/*设置待填充buffer到qp->resp.wqe （预期走：RESPST_CHK_LENGTH）*/
			state = check_resource(qp, pkt);
			break;
		case RESPST_CHK_LENGTH:
			/*检查报文长度，reth dma长度，分辨是否需要pkey检查，否则跳execute*/
			state = rxe_resp_check_length(qp, pkt);
			break;
		case RESPST_CHK_RKEY:
			/*通过rkey查找mr*/
			state = check_rkey(qp, pkt);
			break;
		case RESPST_EXECUTE:
		    /*填充数据到qp->resp.wqe*/
			state = execute(qp, pkt);
			break;
		case RESPST_COMPLETE:
			/*收到了一批中最后一个opcode,设置cqe*/
			state = do_complete(qp, pkt);
			break;
		case RESPST_READ_REPLY:
			/*收到read请求，按read查求取对应mr并填写read_response进行响应*/
			state = read_reply(qp, pkt);
			break;
		case RESPST_ATOMIC_REPLY:
			state = atomic_reply(qp, pkt);
			break;
		case RESPST_ATOMIC_WRITE_REPLY:
			state = atomic_write_reply(qp, pkt);
			break;
		case RESPST_PROCESS_FLUSH:
			state = process_flush(qp, pkt);
			break;
		case RESPST_ACKNOWLEDGE:
			/*rc操作完成（可能成功或者失败），执行ack响应*/
			state = acknowledge(qp, pkt);
			break;
		case RESPST_CLEANUP:
			/*前述采用peek方式处理报文，此时执行dequeue，并释放报文*/
			state = cleanup(qp, pkt);
			break;
		case RESPST_DUPLICATE_REQUEST:
			/*收到重复的request*/
			state = duplicate_request(qp, pkt);
			break;
		case RESPST_ERR_PSN_OUT_OF_SEQ:
			/*收到乱序报文，丢掉此报文，向对端重复确认qp->resp.psn,暗示丢包*/
			/* RC only - Class B. Drop packet. */
			send_ack(qp, AETH_NAK_PSN_SEQ_ERROR/*psn编号有误*/, qp->resp.psn);
			state = RESPST_CLEANUP;/*转cleanup*/
			break;

		case RESPST_ERR_TOO_MANY_RDMA_ATM_REQ:
		case RESPST_ERR_MISSING_OPCODE_FIRST:
		case RESPST_ERR_MISSING_OPCODE_LAST_C:
		case RESPST_ERR_UNSUPPORTED_OPCODE:
		case RESPST_ERR_MISALIGNED_ATOMIC:
			/* RC Only - Class C. */
			do_class_ac_error(qp, AETH_NAK_INVALID_REQ,
					  IB_WC_REM_INV_REQ_ERR);
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_MISSING_OPCODE_LAST_D1E:
			state = do_class_d1e_error(qp);
			break;
		case RESPST_ERR_RNR:
			if (qp_type(qp) == IB_QPT_RC) {
				rxe_counter_inc(rxe, RXE_CNT_SND_RNR);
				/* RC - class B */
				send_ack(qp, AETH_RNR_NAK |
					 (~AETH_TYPE_MASK &
					 qp->attr.min_rnr_timer),
					 pkt->psn);
			} else {
				/* UD/UC - class D */
				qp->resp.drop_msg = 1;
			}
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_RKEY_VIOLATION:
			if (qp_type(qp) == IB_QPT_RC) {
				/* Class C */
				do_class_ac_error(qp, AETH_NAK_REM_ACC_ERR,
						  IB_WC_REM_ACCESS_ERR);
				state = RESPST_COMPLETE;
			} else {
				qp->resp.drop_msg = 1;
				if (qp->srq) {
					/* UC/SRQ Class D */
					qp->resp.status = IB_WC_REM_ACCESS_ERR;
					state = RESPST_COMPLETE;
				} else {
					/* UC/non-SRQ Class E. */
					state = RESPST_CLEANUP;
				}
			}
			break;

		case RESPST_ERR_INVALIDATE_RKEY:
			/* RC - Class J. */
			qp->resp.goto_error = 1;
			qp->resp.status = IB_WC_REM_INV_REQ_ERR;
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_LENGTH:
			if (qp_type(qp) == IB_QPT_RC) {
				/* Class C */
				do_class_ac_error(qp, AETH_NAK_INVALID_REQ,
						  IB_WC_REM_INV_REQ_ERR);
				state = RESPST_COMPLETE;
			} else if (qp->srq) {
				/* UC/UD - class E */
				qp->resp.status = IB_WC_REM_INV_REQ_ERR;
				state = RESPST_COMPLETE;
			} else {
				/* UC/UD - class D */
				qp->resp.drop_msg = 1;
				state = RESPST_CLEANUP;
			}
			break;

		case RESPST_ERR_MALFORMED_WQE:
			/* All, Class A. */
			do_class_ac_error(qp, AETH_NAK_REM_OP_ERR,
					  IB_WC_LOC_QP_OP_ERR);
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_CQ_OVERFLOW:
			/* All - Class G */
			state = RESPST_ERROR;
			break;

		case RESPST_DONE:
			/*处理完成，如果需要goto error,则更新为error状态*/
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			/*正常处理完成，走done*/
			goto done;

		case RESPST_EXIT:
		    /*处理结束，退出*/
			if (qp->resp.goto_error) {
			    /*遇到错误，更改state,要求下一步*/
				state = RESPST_ERROR;
				break;
			}

			goto exit;

		case RESPST_ERROR:
		    /*达到错误状态*/
			qp->resp.goto_error = 0;
			rxe_dbg_qp(qp, "moved to error state\n");
			rxe_qp_error(qp);
			goto exit;

		default:
			WARN_ON_ONCE(1);
		}
	}

	/* A non-zero return value will cause rxe_do_task to
	 * exit its loop and end the work item. A zero return
	 * will continue looping and return to rxe_responder
	 */
done:
	ret = 0;
	goto out;
exit:
	ret = -EAGAIN;
out:
	return ret;
}
