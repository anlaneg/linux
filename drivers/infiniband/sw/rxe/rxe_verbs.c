// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <net/addrconf.h>
#include <rdma/uverbs_ioctl.h>

#include "rxe.h"
#include "rxe_queue.h"
#include "rxe_hw_counters.h"

static int post_one_recv(struct rxe_rq *rq, const struct ib_recv_wr *ibwr);

/* dev */
/*查询ib设备属性*/
static int rxe_query_device(struct ib_device *ibdev,
			    struct ib_device_attr *attr/*出参，设备属性*/,
			    struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	int err;

	if (udata->inlen || udata->outlen) {
		rxe_dbg_dev(rxe, "malformed udata");
	    	/*此接口要求两者为0*/
		err = -EINVAL;
		goto err_out;
	}

	memcpy(attr, &rxe->attr, sizeof(*attr));

	return 0;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

/*查询指定port的属性*/
static int rxe_query_port(struct ib_device *ibdev,
			  u32 port_num, struct ib_port_attr *attr)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	int err, ret;

	if (port_num != 1) {
		err = -EINVAL;
		rxe_dbg_dev(rxe, "bad port_num = %d", port_num);
		goto err_out;
	}

	/*填充port属性*/
	memcpy(attr, &rxe->port.attr, sizeof(*attr));

	mutex_lock(&rxe->usdev_lock);
	/*取port的speed,width*/
	ret = ib_get_eth_speed(ibdev, port_num, &attr->active_speed,
			       &attr->active_width);

	if (attr->state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else if (dev_get_flags(rxe->ndev) & IFF_UP)
	    /*如果底层网络设备为up,则变更为polling*/
		attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	mutex_unlock(&rxe->usdev_lock);

	return ret;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

/*rxe获取index指明的pkey*/
static int rxe_query_pkey(struct ib_device *ibdev,
			  u32 port_num, u16 index, u16 *pkey)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	int err;

	if (index != 0) {
		/*仅支持index为0*/
		err = -EINVAL;
		rxe_dbg_dev(rxe, "bad pkey index = %d", index);
		goto err_out;
	}

	*pkey = IB_DEFAULT_PKEY_FULL;
	return 0;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

static int rxe_modify_device(struct ib_device *ibdev,
			     int mask, struct ib_device_modify *attr)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	int err;

	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID |
		     IB_DEVICE_MODIFY_NODE_DESC)) {
		err = -EOPNOTSUPP;
		rxe_dbg_dev(rxe, "unsupported mask = 0x%x", mask);
		goto err_out;
	}

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		rxe->attr.sys_image_guid = cpu_to_be64(attr->sys_image_guid);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		memcpy(rxe->ib_dev.node_desc,
		       attr->node_desc, sizeof(rxe->ib_dev.node_desc));
	}

	return 0;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

static int rxe_modify_port(struct ib_device *ibdev, u32 port_num,
			   int mask, struct ib_port_modify *attr)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	struct rxe_port *port;
	int err;

	if (port_num != 1) {
		err = -EINVAL;
		rxe_dbg_dev(rxe, "bad port_num = %d", port_num);
		goto err_out;
	}

	//TODO is shutdown useful
	if (mask & ~(IB_PORT_RESET_QKEY_CNTR)) {
		err = -EOPNOTSUPP;
		rxe_dbg_dev(rxe, "unsupported mask = 0x%x", mask);
		goto err_out;
	}

	port = &rxe->port;
	port->attr.port_cap_flags |= attr->set_port_cap_mask;
	port->attr.port_cap_flags &= ~attr->clr_port_cap_mask;

	if (mask & IB_PORT_RESET_QKEY_CNTR)
		port->attr.qkey_viol_cntr = 0;

	return 0;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

/*取ib设备对应的底层链路层类别（以太，IB)*/
static enum rdma_link_layer rxe_get_link_layer(struct ib_device *ibdev,
					       u32 port_num)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	int err;

	if (port_num != 1) {
		err = -EINVAL;
		rxe_dbg_dev(rxe, "bad port_num = %d", port_num);
		goto err_out;
	}

	return IB_LINK_LAYER_ETHERNET;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

static int rxe_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	struct rxe_dev *rxe = to_rdev(ibdev);
	struct ib_port_attr attr = {};
	int err;

	if (port_num != 1) {
		err = -EINVAL;
		rxe_dbg_dev(rxe, "bad port_num = %d", port_num);
		goto err_out;
	}

	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		goto err_out;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	/*利用port属性填充此值*/
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

/* uc */
static int rxe_alloc_ucontext(struct ib_ucontext *ibuc, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibuc->device);
	struct rxe_ucontext *uc = to_ruc(ibuc);
	int err;

	err = rxe_add_to_pool(&rxe->uc_pool, uc);
	if (err)
		rxe_err_dev(rxe, "unable to create uc");

	return err;
}

static void rxe_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	struct rxe_ucontext *uc = to_ruc(ibuc);
	int err;

	err = rxe_cleanup(uc);
	if (err)
		rxe_err_uc(uc, "cleanup failed, err = %d", err);
}

/* pd */
/*并不直接申请rxe_pd,而直接将ib_pd转换为rxe_pd（上层流程已申请了此结构体）*/
static int rxe_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	int err;

	/*初始化pd所属的pool*/
	err = rxe_add_to_pool(&rxe->pd_pool, pd);
	if (err) {
		rxe_dbg_dev(rxe, "unable to alloc pd");
		goto err_out;
	}

	return 0;

err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

static int rxe_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct rxe_pd *pd = to_rpd(ibpd);
	int err;

	err = rxe_cleanup(pd);
	if (err)
		rxe_err_pd(pd, "cleanup failed, err = %d", err);

	return 0;
}

/* ah */
/*创建ah*/
static int rxe_create_ah(struct ib_ah *ibah,
			 struct rdma_ah_init_attr *init_attr,
			 struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibah->device);
	struct rxe_ah *ah = to_rah(ibah);
	struct rxe_create_ah_resp __user *uresp = NULL;
	int err, cleanup_err;

	if (udata) {
		/* test if new user provider */
		if (udata->outlen >= sizeof(*uresp))
			uresp = udata->outbuf;
		ah->is_user = true;
	} else {
		ah->is_user = false;
	}

	/*添加ah到ah_pool*/
	err = rxe_add_to_pool_ah(&rxe->ah_pool, ah,
			init_attr->flags & RDMA_CREATE_AH_SLEEPABLE);
	if (err) {
		rxe_dbg_dev(rxe, "unable to create ah");
		goto err_out;
	}

	/* create index > 0 */
	ah->ah_num = ah->elem.index;

	err = rxe_ah_chk_attr(ah, init_attr->ah_attr);
	if (err) {
		rxe_dbg_ah(ah, "bad attr");
		goto err_cleanup;
	}

	if (uresp) {
		/* only if new user provider */
		err = copy_to_user(&uresp->ah_num, &ah->ah_num,
					 sizeof(uresp->ah_num));
		if (err) {
			err = -EFAULT;
			rxe_dbg_ah(ah, "unable to copy to user");
			goto err_cleanup;
		}
	} else if (ah->is_user) {
		/* only if old user provider */
		ah->ah_num = 0;
	}

	rxe_init_av(init_attr->ah_attr, &ah->av);
	rxe_finalize(ah);

	return 0;

err_cleanup:
	cleanup_err = rxe_cleanup(ah);
	if (cleanup_err)
		rxe_err_ah(ah, "cleanup failed, err = %d", cleanup_err);
err_out:
	rxe_err_ah(ah, "returned err = %d", err);
	return err;
}

static int rxe_modify_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
{
	struct rxe_ah *ah = to_rah(ibah);
	int err;

	err = rxe_ah_chk_attr(ah, attr);
	if (err) {
		rxe_dbg_ah(ah, "bad attr");
		goto err_out;
	}

	rxe_init_av(attr, &ah->av);

	return 0;

err_out:
	rxe_err_ah(ah, "returned err = %d", err);
	return err;
}

static int rxe_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
{
	struct rxe_ah *ah = to_rah(ibah);

	memset(attr, 0, sizeof(*attr));
	attr->type = ibah->type;
	rxe_av_to_attr(&ah->av, attr);

	return 0;
}

static int rxe_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	struct rxe_ah *ah = to_rah(ibah);
	int err;

	err = rxe_cleanup_ah(ah, flags & RDMA_DESTROY_AH_SLEEPABLE);
	if (err)
		rxe_err_ah(ah, "cleanup failed, err = %d", err);

	return 0;
}

/* srq */
/*创建srq*/
static int rxe_create_srq(struct ib_srq *ibsrq, struct ib_srq_init_attr *init,
			  struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibsrq->device);
	struct rxe_pd *pd = to_rpd(ibsrq->pd);
	struct rxe_srq *srq = to_rsrq(ibsrq);
	struct rxe_create_srq_resp __user *uresp = NULL;
	int err, cleanup_err;

	if (udata) {
		if (udata->outlen < sizeof(*uresp)) {
			err = -EINVAL;
			rxe_err_dev(rxe, "malformed udata");
			goto err_out;
		}
		uresp = udata->outbuf;
	}

	if (init->srq_type != IB_SRQT_BASIC) {
		err = -EOPNOTSUPP;
		rxe_dbg_dev(rxe, "srq type = %d, not supported",
				init->srq_type);
		goto err_out;
	}

	err = rxe_srq_chk_init(rxe, init);
	if (err) {
		rxe_dbg_dev(rxe, "invalid init attributes");
		goto err_out;
	}

	/*将srq加入到pool*/
	err = rxe_add_to_pool(&rxe->srq_pool, srq);
	if (err) {
		rxe_dbg_dev(rxe, "unable to create srq, err = %d", err);
		goto err_out;
	}

	rxe_get(pd);
	srq->pd = pd;

	/*初始化srq*/
	err = rxe_srq_from_init(rxe, srq, init, udata, uresp);
	if (err) {
		rxe_dbg_srq(srq, "create srq failed, err = %d", err);
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	cleanup_err = rxe_cleanup(srq);
	if (cleanup_err)
		rxe_err_srq(srq, "cleanup failed, err = %d", cleanup_err);
err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

static int rxe_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask mask,
			  struct ib_udata *udata)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);
	struct rxe_dev *rxe = to_rdev(ibsrq->device);
	struct rxe_modify_srq_cmd cmd = {};
	int err;

	if (udata) {
		if (udata->inlen < sizeof(cmd)) {
			err = -EINVAL;
			rxe_dbg_srq(srq, "malformed udata");
			goto err_out;
		}

		err = ib_copy_from_udata(&cmd, udata, sizeof(cmd));
		if (err) {
			err = -EFAULT;
			rxe_dbg_srq(srq, "unable to read udata");
			goto err_out;
		}
	}

	err = rxe_srq_chk_attr(rxe, srq, attr, mask);
	if (err) {
		rxe_dbg_srq(srq, "bad init attributes");
		goto err_out;
	}

	err = rxe_srq_from_attr(rxe, srq, attr, mask, &cmd, udata);
	if (err) {
		rxe_dbg_srq(srq, "bad attr");
		goto err_out;
	}

	return 0;

err_out:
	rxe_err_srq(srq, "returned err = %d", err);
	return err;
}

static int rxe_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);
	int err;

	if (srq->error) {
		err = -EINVAL;
		rxe_dbg_srq(srq, "srq in error state");
		goto err_out;
	}

	attr->max_wr = srq->rq.queue->buf->index_mask;
	attr->max_sge = srq->rq.max_sge;
	attr->srq_limit = srq->limit;
	return 0;

err_out:
	rxe_err_srq(srq, "returned err = %d", err);
	return err;
}

static int rxe_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
			     const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct rxe_srq *srq = to_rsrq(ibsrq);
	unsigned long flags;

	spin_lock_irqsave(&srq->rq.producer_lock, flags);

	while (wr) {
		err = post_one_recv(&srq->rq, wr);
		if (unlikely(err))
			break;
		wr = wr->next;
	}

	spin_unlock_irqrestore(&srq->rq.producer_lock, flags);

	if (err) {
		*bad_wr = wr;
		rxe_err_srq(srq, "returned err = %d", err);
	}

	return err;
}

static int rxe_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);
	int err;

	err = rxe_cleanup(srq);
	if (err)
		rxe_err_srq(srq, "cleanup failed, err = %d", err);

	return 0;
}

/* qp */
/*初始化qp*/
static int rxe_create_qp(struct ib_qp *ibqp/*要初始化的qp*/, struct ib_qp_init_attr *init/*qp初始化属性*/,
			 struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_pd *pd = to_rpd(ibqp->pd);
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_create_qp_resp __user *uresp = NULL;
	int err, cleanup_err;

	if (udata) {
		if (udata->inlen) {
			err = -EINVAL;
			rxe_dbg_dev(rxe, "malformed udata, err = %d", err);
			goto err_out;
		}

		if (udata->outlen < sizeof(*uresp)) {
			err = -EINVAL;
			rxe_dbg_dev(rxe, "malformed udata, err = %d", err);
			goto err_out;
		}

		/*包含udata,指明用户态qp*/
		qp->is_user = true;
		uresp = udata->outbuf;
	} else {
	    /*非用户态qp*/
		qp->is_user = false;
	}

	if (init->create_flags) {
		err = -EOPNOTSUPP;
		rxe_dbg_dev(rxe, "unsupported create_flags, err = %d", err);
		goto err_out;
	}

	err = rxe_qp_chk_init(rxe, init);
	if (err) {
		rxe_dbg_dev(rxe, "bad init attr, err = %d", err);
		goto err_out;
	}

	/*将qp加入到pool*/
	err = rxe_add_to_pool(&rxe->qp_pool, qp);
	if (err) {
		rxe_dbg_dev(rxe, "unable to create qp, err = %d", err);
		goto err_out;
	}

	/*初始化此qp*/
	err = rxe_qp_from_init(rxe, qp, pd, init, uresp, ibqp->pd, udata);
	if (err) {
		rxe_dbg_qp(qp, "create qp failed, err = %d", err);
		goto err_cleanup;
	}

	rxe_finalize(qp);
	return 0;

err_cleanup:
	cleanup_err = rxe_cleanup(qp);
	if (cleanup_err)
		rxe_err_qp(qp, "cleanup failed, err = %d", cleanup_err);
err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

/*更新qp*/
static int rxe_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int mask, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);
	int err;

	if (mask & ~IB_QP_ATTR_STANDARD_BITS) {
		err = -EOPNOTSUPP;
		rxe_dbg_qp(qp, "unsupported mask = 0x%x, err = %d",
			   mask, err);
		goto err_out;
	}

	err = rxe_qp_chk_attr(rxe, qp, attr, mask);
	if (err) {
		rxe_dbg_qp(qp, "bad mask/attr, err = %d", err);
		goto err_out;
	}

	err = rxe_qp_from_attr(qp, attr, mask, udata);
	if (err) {
		rxe_dbg_qp(qp, "modify qp failed, err = %d", err);
		goto err_out;
	}

	if ((mask & IB_QP_AV) && (attr->ah_attr.ah_flags & IB_AH_GRH))
		qp->src_port = rdma_get_udp_sport(attr->ah_attr.grh.flow_label,
						  qp->ibqp.qp_num,
						  qp->attr.dest_qp_num);

	return 0;

err_out:
	rxe_err_qp(qp, "returned err = %d", err);
	return err;
}

/*查询qp*/
static int rxe_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int mask, struct ib_qp_init_attr *init)
{
	struct rxe_qp *qp = to_rqp(ibqp);

	/*qp填充init*/
	rxe_qp_to_init(qp, init);
	/*qp填充attr*/
	rxe_qp_to_attr(qp, attr, mask);

	return 0;
}

static int rxe_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct rxe_qp *qp = to_rqp(ibqp);
	int err;

	err = rxe_qp_chk_destroy(qp);
	if (err) {
		rxe_dbg_qp(qp, "unable to destroy qp, err = %d", err);
		goto err_out;
	}

	err = rxe_cleanup(qp);
	if (err)
		rxe_err_qp(qp, "cleanup failed, err = %d", err);

	return 0;

err_out:
	rxe_err_qp(qp, "returned err = %d", err);
	return err;
}

/* send wr */

/* sanity check incoming send work request */
static int validate_send_wr(struct rxe_qp *qp, const struct ib_send_wr *ibwr,
			    unsigned int *maskp, unsigned int *lengthp)
{
	int num_sge = ibwr->num_sge;
	struct rxe_sq *sq = &qp->sq;
	unsigned int mask = 0;
	unsigned long length = 0;
	int err = -EINVAL;
	int i;

	do {
		/*此操作对应的mask,例如send_write对应的WR_INLINE_MASK | WR_SEND_MASK*/
		mask = wr_opcode_mask(ibwr->opcode, qp);
		if (!mask) {
			/*无效操作*/
			rxe_err_qp(qp, "bad wr opcode for qp type");
			break;
		}

		if (num_sge > sq->max_sge) {
			/*sge超限*/
			rxe_err_qp(qp, "num_sge > max_sge");
			break;
		}

		length = 0;
		for (i = 0; i < ibwr->num_sge; i++)
			length += ibwr->sg_list[i].length;

		if (length > (1UL << 31)) {
			/*指明了inline,但提供的数据超过sq inline限制*/
			rxe_err_qp(qp, "message length too long");
			break;
		}

		if (mask & WR_ATOMIC_MASK) {
			if (length != 8) {
				rxe_err_qp(qp, "atomic length != 8");
				break;
			}
			if (atomic_wr(ibwr)->remote_addr & 0x7) {
				rxe_err_qp(qp, "misaligned atomic address");
				break;
			}
		}
		if (ibwr->send_flags & IB_SEND_INLINE) {
			if (!(mask & WR_INLINE_MASK)) {
				/*此操作不容许inline发送，但用户指定有inline发送标记*/
				rxe_err_qp(qp, "opcode doesn't support inline data");
				break;
			}
			if (length > sq->max_inline) {
				rxe_err_qp(qp, "inline length too big");
				break;
			}
		}

		err = 0;
	} while (0);

	*maskp = mask;
	*lengthp = (int)length;

	return err;
}

static int init_send_wr(struct rxe_qp *qp, struct rxe_send_wr *wr,
			 const struct ib_send_wr *ibwr)
{
	wr->wr_id = ibwr->wr_id;
	wr->opcode = ibwr->opcode;
	wr->send_flags = ibwr->send_flags;

	if (qp_type(qp) == IB_QPT_UD ||
	    qp_type(qp) == IB_QPT_GSI) {
		struct ib_ah *ibah = ud_wr(ibwr)->ah;

		wr->wr.ud.remote_qpn = ud_wr(ibwr)->remote_qpn;
		wr->wr.ud.remote_qkey = ud_wr(ibwr)->remote_qkey;
		wr->wr.ud.ah_num = to_rah(ibah)->ah_num;
		if (qp_type(qp) == IB_QPT_GSI)
			wr->wr.ud.pkey_index = ud_wr(ibwr)->pkey_index;

		switch (wr->opcode) {
		case IB_WR_SEND_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			break;
		case IB_WR_SEND:
			break;
		default:
			rxe_err_qp(qp, "bad wr opcode %d for UD/GSI QP",
					wr->opcode);
			return -EINVAL;
		}
	} else {
		switch (wr->opcode) {
		case IB_WR_RDMA_WRITE_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			fallthrough;
		case IB_WR_RDMA_READ:
		case IB_WR_RDMA_WRITE:
			wr->wr.rdma.remote_addr = rdma_wr(ibwr)->remote_addr;
			wr->wr.rdma.rkey	= rdma_wr(ibwr)->rkey;
			break;
		case IB_WR_SEND_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			break;
		case IB_WR_SEND_WITH_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
			break;
		case IB_WR_RDMA_READ_WITH_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
			wr->wr.rdma.remote_addr = rdma_wr(ibwr)->remote_addr;
			wr->wr.rdma.rkey	= rdma_wr(ibwr)->rkey;
			break;
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			wr->wr.atomic.remote_addr =
				atomic_wr(ibwr)->remote_addr;
			wr->wr.atomic.compare_add =
				atomic_wr(ibwr)->compare_add;
			wr->wr.atomic.swap = atomic_wr(ibwr)->swap;
			wr->wr.atomic.rkey = atomic_wr(ibwr)->rkey;
			break;
		case IB_WR_LOCAL_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
			break;
		case IB_WR_REG_MR:
			wr->wr.reg.mr = reg_wr(ibwr)->mr;
			wr->wr.reg.key = reg_wr(ibwr)->key;
			wr->wr.reg.access = reg_wr(ibwr)->access;
			break;
		case IB_WR_SEND:
		case IB_WR_BIND_MW:
		case IB_WR_FLUSH:
		case IB_WR_ATOMIC_WRITE:
			break;
		default:
			rxe_err_qp(qp, "unsupported wr opcode %d",
					wr->opcode);
			return -EINVAL;
		}
	}

	return 0;
}

/*支持数据inline，将ibwr中的数据写入到inline中*/
static void copy_inline_data_to_wqe(struct rxe_send_wqe *wqe,
				    const struct ib_send_wr *ibwr)
{
	struct ib_sge *sge = ibwr->sg_list;
	u8 *p = wqe->dma.inline_data;
	int i;

	for (i = 0; i < ibwr->num_sge; i++, sge++) {
		memcpy(p, ib_virt_dma_to_page(sge->addr), sge->length);
		p += sge->length;
	}
}

/*初始化send wqe*/
static int init_send_wqe(struct rxe_qp *qp, const struct ib_send_wr *ibwr,
			 unsigned int mask, unsigned int length,
			 struct rxe_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;
	int err;

	/*利用ibwr初始化rxe_send_wqe*/
	err = init_send_wr(qp, &wqe->wr, ibwr);
	if (err)
		return err;

	/* local operation */
	if (unlikely(mask & WR_LOCAL_OP_MASK)) {
		wqe->mask = mask;
		wqe->state = wqe_state_posted;
		return 0;
	}

	if (unlikely(ibwr->send_flags & IB_SEND_INLINE))
		/*支持数据inline，将ibwr中的数据写入到inline中*/
		copy_inline_data_to_wqe(wqe, ibwr);
	else
		/*非inline数据，将sge元数据写入到dma.sge*/
		memcpy(wqe->dma.sge, ibwr->sg_list,
		       num_sge * sizeof(struct ib_sge));

	wqe->iova = mask & WR_ATOMIC_MASK ? atomic_wr(ibwr)->remote_addr :
		mask & WR_READ_OR_WRITE_MASK ? rdma_wr(ibwr)->remote_addr : 0;
	wqe->mask		= mask;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= wqe_state_posted;/*初始状态为posted*/
	wqe->ssn		= atomic_add_return(1, &qp->ssn);/*为此wqe提供唯一编号*/

	return 0;
}

static int post_one_send(struct rxe_qp *qp, const struct ib_send_wr *ibwr)
{
	int err;
	struct rxe_sq *sq = &qp->sq;
	struct rxe_send_wqe *send_wqe;
	unsigned int mask;
	unsigned int length;
	int full;

	/*校验wr*/
	err = validate_send_wr(qp, ibwr, &mask, &length);
	if (err)
		return err;

	/*检查队列是否已满*/
	full = queue_full(sq->queue, QUEUE_TYPE_FROM_ULP);
	if (unlikely(full)) {
		rxe_err_qp(qp, "send queue full");
		return -ENOMEM;
	}

	/*取生产者索引对应的wqe*/
	send_wqe = queue_producer_addr(sq->queue, QUEUE_TYPE_FROM_ULP);
	/*利用ibwr初始化send_wqe*/
	err = init_send_wqe(qp, ibwr, mask, length, send_wqe);
	if (!err)
		/*更新新产者指针*/
		queue_advance_producer(sq->queue, QUEUE_TYPE_FROM_ULP);

	return err;
}

static int rxe_post_send_kernel(struct rxe_qp *qp,
				const struct ib_send_wr *ibwr,
				const struct ib_send_wr **bad_wr)
{
	int err = 0;
	unsigned long flags;

	spin_lock_irqsave(&qp->sq.sq_lock, flags);
	while (ibwr) {
		/*针对每一个send_wr调用post_one_send*/
		err = post_one_send(qp, ibwr);
		if (err) {
			*bad_wr = ibwr;
			break;
		}
		/*切换到下一个wr*/
		ibwr = ibwr->next;
	}
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);

	if (!err)
		/*队列准备完成，调度task 向外发送*/
		rxe_sched_task(&qp->req.task);

	spin_lock_irqsave(&qp->state_lock, flags);
	if (qp_state(qp) == IB_QPS_ERR)
		rxe_sched_task(&qp->comp.task);
	spin_unlock_irqrestore(&qp->state_lock, flags);

	return err;
}

/*rxe实现post_send,用于知会数据已准备完成*/
static int rxe_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	struct rxe_qp *qp = to_rqp(ibqp);
	int err;
	unsigned long flags;

	spin_lock_irqsave(&qp->state_lock, flags);
	/* caller has already called destroy_qp */
	if (WARN_ON_ONCE(!qp->valid)) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		rxe_err_qp(qp, "qp has been destroyed");
		return -EINVAL;
	}

	if (unlikely(qp_state(qp) < IB_QPS_RTS)) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		*bad_wr = wr;
		rxe_err_qp(qp, "qp not ready to send");
		return -EINVAL;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	if (qp->is_user) {
		/* Utilize process context to do protocol processing */
		rxe_run_task(&qp->req.task);
	} else {
		err = rxe_post_send_kernel(qp, wr, bad_wr);
		if (err)
			return err;
	}

	return 0;
}

/* recv wr */
static int post_one_recv(struct rxe_rq *rq, const struct ib_recv_wr *ibwr)
{
	int i;
	unsigned long length;
	struct rxe_recv_wqe *recv_wqe;
	int num_sge = ibwr->num_sge;
	int full;
	int err;

	/*检查队列是否为满*/
	full = queue_full(rq->queue, QUEUE_TYPE_FROM_ULP);
	if (unlikely(full)) {
		err = -ENOMEM;
		rxe_dbg("queue full");
		goto err_out;
	}

	/*num_sge过大，接收失败*/
	if (unlikely(num_sge > rq->max_sge)) {
		err = -EINVAL;
		rxe_dbg("bad num_sge > max_sge");
		goto err_out;
	}

	/*取接收buffer总长度*/
	length = 0;
	for (i = 0; i < num_sge; i++)
		length += ibwr->sg_list[i].length;

	/* IBA max message size is 2^31 */
	if (length >= (1UL<<31)) {
		/*长度过大*/
		err = -EINVAL;
		rxe_dbg("message length too long");
		goto err_out;
	}

	/*自rq->queue中取一项recv_wqe*/
	recv_wqe = queue_producer_addr(rq->queue, QUEUE_TYPE_FROM_ULP);

	/*填充recv_wqe*/
	recv_wqe->wr_id = ibwr->wr_id;
	recv_wqe->dma.length = length;
	recv_wqe->dma.resid = length;
	recv_wqe->dma.num_sge = num_sge;
	recv_wqe->dma.cur_sge = 0;
	recv_wqe->dma.sge_offset = 0;
	/*复制ib_sge指针到ibwr->sg_list*/
	memcpy(recv_wqe->dma.sge, ibwr->sg_list,
	       num_sge * sizeof(struct ib_sge));

	/*更新生产者指针*/
	queue_advance_producer(rq->queue, QUEUE_TYPE_FROM_ULP);

	return 0;

err_out:
	rxe_dbg("returned err = %d", err);
	return err;
}

/*qp收取wr*/
static int rxe_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_rq *rq = &qp->rq;
	unsigned long flags;

	spin_lock_irqsave(&qp->state_lock, flags);
	/* caller has already called destroy_qp */
	if (WARN_ON_ONCE(!qp->valid)) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		rxe_err_qp(qp, "qp has been destroyed");
		return -EINVAL;
	}

	/* see C10-97.2.1 */
	if (unlikely((qp_state(qp) < IB_QPS_INIT))) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		*bad_wr = wr;
		rxe_dbg_qp(qp, "qp not ready to post recv");
		return -EINVAL;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	/*srq不为空，报错*/
	if (unlikely(qp->srq)) {
		*bad_wr = wr;
		rxe_dbg_qp(qp, "qp has srq, use post_srq_recv instead");
		return -EINVAL;
	}

	spin_lock_irqsave(&rq->producer_lock, flags);

	/*针对每个wr执行一次post_one_recv*/
	while (wr) {
		err = post_one_recv(rq, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}

	spin_unlock_irqrestore(&rq->producer_lock, flags);

	spin_lock_irqsave(&qp->state_lock, flags);
	if (qp_state(qp) == IB_QPS_ERR)
		rxe_sched_task(&qp->resp.task);
	spin_unlock_irqrestore(&qp->state_lock, flags);

	return err;
}

/* cq */
/*rxe 创建cq*/
static int rxe_create_cq(struct ib_cq *ibcq/*要初始化的cq*/, const struct ib_cq_init_attr *attr,
			 struct ib_udata *udata)
{
	struct ib_device *dev = ibcq->device;
	struct rxe_dev *rxe = to_rdev(dev);/*cq对应的rxe设备*/
	struct rxe_cq *cq = to_rcq(ibcq);/*结构体转为rxe_cq*/
	struct rxe_create_cq_resp __user *uresp = NULL;
	int err, cleanup_err;

	if (udata) {
		if (udata->outlen < sizeof(*uresp)) {
			err = -EINVAL;
			rxe_dbg_dev(rxe, "malformed udata, err = %d", err);
			goto err_out;
		}
		uresp = udata->outbuf;
	}

	if (attr->flags) {
		err = -EOPNOTSUPP;
		rxe_dbg_dev(rxe, "bad attr->flags, err = %d", err);
		goto err_out;
	}

	/*cqe数目检查*/
	err = rxe_cq_chk_attr(rxe, NULL, attr->cqe, attr->comp_vector);
	if (err) {
		rxe_dbg_dev(rxe, "bad init attributes, err = %d", err);
		goto err_out;
	}

	/*将此cq加入到此rxe设备的cq_pool*/
	err = rxe_add_to_pool(&rxe->cq_pool, cq);
	if (err) {
		rxe_dbg_dev(rxe, "unable to create cq, err = %d", err);
		goto err_out;
	}

	err = rxe_cq_from_init(rxe, cq, attr->cqe, attr->comp_vector, udata,
			       uresp);
	if (err) {
		rxe_dbg_cq(cq, "create cq failed, err = %d", err);
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	cleanup_err = rxe_cleanup(cq);
	if (cleanup_err)
		rxe_err_cq(cq, "cleanup failed, err = %d", cleanup_err);
err_out:
	rxe_err_dev(rxe, "returned err = %d", err);
	return err;
}

static int rxe_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_dev *rxe = to_rdev(ibcq->device);
	struct rxe_resize_cq_resp __user *uresp = NULL;
	int err;

	if (udata) {
		if (udata->outlen < sizeof(*uresp)) {
			err = -EINVAL;
			rxe_dbg_cq(cq, "malformed udata");
			goto err_out;
		}
		uresp = udata->outbuf;
	}

	err = rxe_cq_chk_attr(rxe, cq, cqe, 0);
	if (err) {
		rxe_dbg_cq(cq, "bad attr, err = %d", err);
		goto err_out;
	}

	err = rxe_cq_resize_queue(cq, cqe, uresp, udata);
	if (err) {
		rxe_dbg_cq(cq, "resize cq failed, err = %d", err);
		goto err_out;
	}

	return 0;

err_out:
	rxe_err_cq(cq, "returned err = %d", err);
	return err;
}

/*自cq中最多出num_entries个ib_wc*/
static int rxe_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	int i;
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	/*尝试自cq queue中最多出num_entries个cqe,并将结果填充到wc中*/
	for (i = 0; i < num_entries; i++) {
		cqe = queue_head(cq->queue, QUEUE_TYPE_TO_ULP);
		if (!cqe)
			break;	/* queue empty */

		memcpy(wc++, &cqe->ibwc, sizeof(*wc));/*将cqe->ibwc中内容复制到wc中*/
		queue_advance_consumer(cq->queue, QUEUE_TYPE_TO_ULP);/*消费指针移动*/
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	return i;
}

/*检查cq队列中是否有wc_cnt个元素，如果元素数大于wc_cnt，则返回wc_cnt,否则返回实际count*/
static int rxe_peek_cq(struct ib_cq *ibcq, int wc_cnt)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	int count;

	count = queue_count(cq->queue, QUEUE_TYPE_TO_ULP);

	return (count > wc_cnt) ? wc_cnt : count;
}

static int rxe_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	int ret = 0;
	int empty;
	unsigned long irq_flags;

	spin_lock_irqsave(&cq->cq_lock, irq_flags);
	cq->notify |= flags & IB_CQ_SOLICITED_MASK;
	empty = queue_empty(cq->queue, QUEUE_TYPE_TO_ULP);

	if ((flags & IB_CQ_REPORT_MISSED_EVENTS) && !empty/*队列不为空*/)
		ret = 1;

	spin_unlock_irqrestore(&cq->cq_lock, irq_flags);

	return ret;
}

static int rxe_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	int err;

	/* See IBA C11-17: The CI shall return an error if this Verb is
	 * invoked while a Work Queue is still associated with the CQ.
	 */
	if (atomic_read(&cq->num_wq)) {
		err = -EINVAL;
		rxe_dbg_cq(cq, "still in use");
		goto err_out;
	}

	err = rxe_cleanup(cq);
	if (err)
		rxe_err_cq(cq, "cleanup failed, err = %d", err);

	return 0;

err_out:
	rxe_err_cq(cq, "returned err = %d", err);
	return err;
}

/* mr */
static struct ib_mr *rxe_get_dma_mr(struct ib_pd *ibpd, int access)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mr *mr;
	int err;

	/*申请mr*/
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	/*将此mr添加进mr_pool*/
	err = rxe_add_to_pool(&rxe->mr_pool, mr);
	if (err) {
		rxe_dbg_dev(rxe, "unable to create mr");
		goto err_free;
	}

	/*pd引用增加*/
	rxe_get(pd);
	/*加入到pool中*/
	mr->ibmr.pd = ibpd;
	mr->ibmr.device = ibpd->device;

	rxe_mr_init_dma(access, mr);
	rxe_finalize(mr);
	return &mr->ibmr;

err_free:
	kfree(mr);
	rxe_err_pd(pd, "returned err = %d", err);
	return ERR_PTR(err);
}

/*rxe设备注册mr*/
static struct ib_mr *rxe_reg_user_mr(struct ib_pd *ibpd, u64 start/*内存起始地址*/,
				     u64 length/*内存长度*/, u64 iova, int access/*访问标记*/,
				     struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mr *mr;
	int err, cleanup_err;

	if (access & ~RXE_ACCESS_SUPPORTED_MR) {
		rxe_err_pd(pd, "access = %#x not supported (%#x)", access,
				RXE_ACCESS_SUPPORTED_MR);
		return ERR_PTR(-EOPNOTSUPP);
	}

	/*申请一个rxe_mr*/
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	/*此mr信息添加进mr pool*/
	err = rxe_add_to_pool(&rxe->mr_pool, mr);
	if (err) {
		rxe_dbg_pd(pd, "unable to create mr");
		goto err_free;
	}

	rxe_get(pd);
	mr->ibmr.pd = ibpd;
	mr->ibmr.device = ibpd->device;

	/*初始化mr，pin住相应的内存页*/
	err = rxe_mr_init_user(rxe, start, length, iova, access, mr);
	if (err) {
		rxe_dbg_mr(mr, "reg_user_mr failed, err = %d", err);
		goto err_cleanup;
	}

	rxe_finalize(mr);
	return &mr->ibmr;

err_cleanup:
	cleanup_err = rxe_cleanup(mr);
	if (cleanup_err)
		rxe_err_mr(mr, "cleanup failed, err = %d", cleanup_err);
err_free:
	kfree(mr);
	rxe_err_pd(pd, "returned err = %d", err);
	return ERR_PTR(err);
}

static struct ib_mr *rxe_rereg_user_mr(struct ib_mr *ibmr, int flags,
                                      u64 start, u64 length, u64 iova,
                                      int access, struct ib_pd *ibpd,
                                      struct ib_udata *udata)
{
       struct rxe_mr *mr = to_rmr(ibmr);
       struct rxe_pd *old_pd = to_rpd(ibmr->pd);
       struct rxe_pd *pd = to_rpd(ibpd);

       /* for now only support the two easy cases:
        * rereg_pd and rereg_access
        */
       if (flags & ~RXE_MR_REREG_SUPPORTED) {
               rxe_err_mr(mr, "flags = %#x not supported", flags);
               return ERR_PTR(-EOPNOTSUPP);
       }

       if (flags & IB_MR_REREG_PD) {
               rxe_put(old_pd);
               rxe_get(pd);
               mr->ibmr.pd = ibpd;
       }

       if (flags & IB_MR_REREG_ACCESS) {
               if (access & ~RXE_ACCESS_SUPPORTED_MR) {
                       rxe_err_mr(mr, "access = %#x not supported", access);
                       return ERR_PTR(-EOPNOTSUPP);
               }
               mr->access = access;
       }

       return NULL;
}

/*申请ib_mr*/
static struct ib_mr *rxe_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type/*memory region类型*/,
				  u32 max_num_sg)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mr *mr;
	int err, cleanup_err;

	/*当前仅支持ib_mr_type_mem_reg类型*/
	if (mr_type != IB_MR_TYPE_MEM_REG) {
		err = -EINVAL;
		rxe_dbg_pd(pd, "mr type %d not supported, err = %d",
			   mr_type, err);
		goto err_out;
	}

	/*申请mr结构体*/
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	/*将申请的mr添加入memory region pool中*/
	err = rxe_add_to_pool(&rxe->mr_pool, mr);
	if (err)
		goto err_free;

	/*pd引用数增加*/
	rxe_get(pd);
	mr->ibmr.pd = ibpd;
	mr->ibmr.device = ibpd->device;

	/*初始化mr(并不真正的申请它）*/
	err = rxe_mr_init_fast(max_num_sg, mr);
	if (err) {
		rxe_dbg_mr(mr, "alloc_mr failed, err = %d", err);
		goto err_cleanup;
	}

	rxe_finalize(mr);
	return &mr->ibmr;

err_cleanup:
	cleanup_err = rxe_cleanup(mr);
	if (cleanup_err)
		rxe_err_mr(mr, "cleanup failed, err = %d", err);
err_free:
	kfree(mr);
err_out:
	rxe_err_pd(pd, "returned err = %d", err);
	return ERR_PTR(err);
}

static int rxe_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct rxe_mr *mr = to_rmr(ibmr);
	int err, cleanup_err;

	/* See IBA 10.6.7.2.6 */
	if (atomic_read(&mr->num_mw) > 0) {
		err = -EINVAL;
		rxe_dbg_mr(mr, "mr has mw's bound");
		goto err_out;
	}

	cleanup_err = rxe_cleanup(mr);
	if (cleanup_err)
		rxe_err_mr(mr, "cleanup failed, err = %d", cleanup_err);

	kfree_rcu_mightsleep(mr);
	return 0;

err_out:
	rxe_err_mr(mr, "returned err = %d", err);
	return err;
}

/*rxe设备父设备名称（及网络接口名称）*/
static ssize_t parent_show(struct device *device,
			   struct device_attribute *attr, char *buf)
{
	struct rxe_dev *rxe =
		rdma_device_to_drv_device(device, struct rxe_dev, ib_dev);

	return sysfs_emit(buf, "%s\n", rxe_parent_name(rxe, 1));
}

static DEVICE_ATTR_RO(parent);

static struct attribute *rxe_dev_attributes[] = {
	&dev_attr_parent.attr,
	NULL
};

static const struct attribute_group rxe_attr_group = {
	.attrs = rxe_dev_attributes,
};

/*驱动使能此设备*/
static int rxe_enable_driver(struct ib_device *ib_dev)
{
	struct rxe_dev *rxe = container_of(ib_dev, struct rxe_dev, ib_dev);

	rxe_set_port_state(rxe);
	dev_info(&rxe->ib_dev.dev, "added %s\n", netdev_name(rxe->ndev));
	return 0;
}

static const struct ib_device_ops rxe_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_RXE,
	.uverbs_abi_ver = RXE_UVERBS_ABI_VERSION,
	/*申请rdma_hw_stats结构体*/
	.alloc_hw_port_stats = rxe_ib_alloc_hw_port_stats,
	.alloc_mr = rxe_alloc_mr,/*申请指定类型的mr*/
	.alloc_mw = rxe_alloc_mw,
	.alloc_pd = rxe_alloc_pd,/*申请pd*/
	.alloc_ucontext = rxe_alloc_ucontext,
	.attach_mcast = rxe_attach_mcast,
	.create_ah = rxe_create_ah,
	.create_cq = rxe_create_cq,/*初始化cq*/
	.create_qp = rxe_create_qp,/*创建并初始化qp*/
	.create_srq = rxe_create_srq,
	.create_user_ah = rxe_create_ah,
	.dealloc_driver = rxe_dealloc,
	.dealloc_mw = rxe_dealloc_mw,
	.dealloc_pd = rxe_dealloc_pd,
	.dealloc_ucontext = rxe_dealloc_ucontext,
	.dereg_mr = rxe_dereg_mr,
	.destroy_ah = rxe_destroy_ah,
	.destroy_cq = rxe_destroy_cq,
	.destroy_qp = rxe_destroy_qp,
	.destroy_srq = rxe_destroy_srq,
	.detach_mcast = rxe_detach_mcast,
	.device_group = &rxe_attr_group,
	.enable_driver = rxe_enable_driver,
	.get_dma_mr = rxe_get_dma_mr,
	.get_hw_stats = rxe_ib_get_hw_stats,
	.get_link_layer = rxe_get_link_layer,
	.get_port_immutable = rxe_port_immutable,
	.map_mr_sg = rxe_map_mr_sg,
	.mmap = rxe_mmap,/*响应mmap*/
	/*更新ah*/
	.modify_ah = rxe_modify_ah,
	/*更新ib_device*/
	.modify_device = rxe_modify_device,
	/*port属性修改*/
	.modify_port = rxe_modify_port,
	.modify_qp = rxe_modify_qp,
	.modify_srq = rxe_modify_srq,
	.peek_cq = rxe_peek_cq,/*自cq中检查是否有count个元素，如果没有返回实际元素数，否则返回count*/
	.poll_cq = rxe_poll_cq,/*自cq中最多出num_entries个ib_wc*/
	.post_recv = rxe_post_recv,/*将参数传入的待填充的buffer,存入到rq中，以便接收时填充用*/
	.post_send = rxe_post_send,/*将参数传入的待发送的buffer，存入到sq中，以便发送时使用*/
	.post_srq_recv = rxe_post_srq_recv,
	.query_ah = rxe_query_ah,
	.query_device = rxe_query_device,/*针对设备进行属性查询*/
	.query_pkey = rxe_query_pkey,/*给定index查询pkey*/
	.query_port = rxe_query_port,/*查询port属性*/
	.query_qp = rxe_query_qp,
	.query_srq = rxe_query_srq,
	.reg_user_mr = rxe_reg_user_mr,/*rxe注册mr*/
	.req_notify_cq = rxe_req_notify_cq,
	.rereg_user_mr = rxe_rereg_user_mr,
	.resize_cq = rxe_resize_cq,

	INIT_RDMA_OBJ_SIZE(ib_ah, rxe_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, rxe_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, rxe_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_qp, rxe_qp, ibqp),
	INIT_RDMA_OBJ_SIZE(ib_srq, rxe_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, rxe_ucontext, ibuc),
	INIT_RDMA_OBJ_SIZE(ib_mw, rxe_mw, ibmw),
};

/*rxe设备注册*/
int rxe_register_device(struct rxe_dev *rxe/*要注册的rxe设备*/, const char *ibdev_name/*ib设备名称*/)
{
	int err;
	struct ib_device *dev = &rxe->ib_dev;

	strscpy(dev->node_desc, "rxe", sizeof(dev->node_desc));

	dev->node_type = RDMA_NODE_IB_CA;
	/*支持一个port*/
	dev->phys_port_cnt = 1;
	dev->num_comp_vectors = num_possible_cpus();
	dev->local_dma_lkey = 0;
	/*利用底层设备的mac做node的全局唯一id*/
	addrconf_addr_eui48((unsigned char *)&dev->node_guid,
			    rxe->ndev->dev_addr);

	dev->uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
				BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ);

	/*设置ib设备对应的操作集为rxe_dev_ops*/
	ib_set_device_ops(dev, &rxe_dev_ops);

	/*为rxe设备的1号port关联底层设备rxe->ndev*/
	err = ib_device_set_netdev(&rxe->ib_dev, rxe->ndev, 1);
	if (err)
		return err;

	err = rxe_icrc_init(rxe);
	if (err)
		return err;

	/*注册此ib设备*/
	err = ib_register_device(dev, ibdev_name, NULL/*dma设备为空*/);
	if (err)
		rxe_dbg_dev(rxe, "failed with error %d\n", err);

	/*
	 * Note that rxe may be invalid at this point if another thread
	 * unregistered it.
	 */
	return err;
}
