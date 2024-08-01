// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"

/* check that QP matches packet opcode type and is in a valid state */
static int check_type_state(struct rxe_dev *rxe, struct rxe_pkt_info *pkt,
			    struct rxe_qp *qp)
{
	unsigned int pkt_type;
	unsigned long flags;

	if (unlikely(!qp->valid))
		/*qp无效,直接返回*/
		return -EINVAL;

	/*报文中高3位为pkt_type,取pkt_type*/
	pkt_type = pkt->opcode & 0xe0;

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		/*rc时，pkt_type必须为rc*/
		if (unlikely(pkt_type != IB_OPCODE_RC))
			return -EINVAL;
		break;
	case IB_QPT_UC:
		/*uc时，pkt_type必须为uc*/
		if (unlikely(pkt_type != IB_OPCODE_UC))
			return -EINVAL;
		break;
	case IB_QPT_UD:
	case IB_QPT_GSI:
		/*ud/gsi时，pkt_type必须为ud*/
		if (unlikely(pkt_type != IB_OPCODE_UD))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	spin_lock_irqsave(&qp->state_lock, flags);
	/*qp状态检查*/
	if (pkt->mask & RXE_REQ_MASK) {
		if (unlikely(qp_state(qp) < IB_QPS_RTR)) {
			spin_unlock_irqrestore(&qp->state_lock, flags);
			return -EINVAL;
		}
	} else {
		if (unlikely(qp_state(qp) < IB_QPS_RTS)) {
			spin_unlock_irqrestore(&qp->state_lock, flags);
			return -EINVAL;
		}
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	return 0;
}

static void set_bad_pkey_cntr(struct rxe_port *port)
{
	spin_lock_bh(&port->port_lock);
	port->attr.bad_pkey_cntr = min((u32)0xffff,
				       port->attr.bad_pkey_cntr + 1);
	spin_unlock_bh(&port->port_lock);
}

static void set_qkey_viol_cntr(struct rxe_port *port)
{
	spin_lock_bh(&port->port_lock);
	port->attr.qkey_viol_cntr = min((u32)0xffff,
					port->attr.qkey_viol_cntr + 1);
	spin_unlock_bh(&port->port_lock);
}

static int check_keys(struct rxe_dev *rxe, struct rxe_pkt_info *pkt,
		      u32 qpn, struct rxe_qp *qp)
{
	struct rxe_port *port = &rxe->port;
	u16 pkey = bth_pkey(pkt);/*取报文中使用的pkey*/

	pkt->pkey_index = 0;

	/*pkey的最低15位不为0x7fff时，报错*/
	if (!pkey_match(pkey, IB_DEFAULT_PKEY_FULL)) {
		set_bad_pkey_cntr(port);
		return -EINVAL;
	}

	if (qp_type(qp) == IB_QPT_UD || qp_type(qp) == IB_QPT_GSI) {
		/*ud,gsi情况下，取qkey*/
		u32 qkey = (qpn == 1) ? GSI_QKEY : qp->attr.qkey;

		/*deth头部中提供的qkey与qp不一致，报错*/
		if (unlikely(deth_qkey(pkt) != qkey)) {
			set_qkey_viol_cntr(port);
			return -EINVAL;
		}
	}

	return 0;
}

static int check_addr(struct rxe_dev *rxe, struct rxe_pkt_info *pkt,
		      struct rxe_qp *qp)
{
	struct sk_buff *skb = PKT_TO_SKB(pkt);

	/*非rc,uc的不检查addr*/
	if (qp_type(qp) != IB_QPT_RC && qp_type(qp) != IB_QPT_UC)
		return 0;

	/*设备Port number 校验*/
	if (unlikely(pkt->port_num != qp->attr.port_num))
		return -EINVAL;

	if (skb->protocol == htons(ETH_P_IP)) {
	    /*ipv4端目的ip校验*/
		struct in_addr *saddr =
			&qp->pri_av.sgid_addr._sockaddr_in.sin_addr;
		struct in_addr *daddr =
			&qp->pri_av.dgid_addr._sockaddr_in.sin_addr;

		/*报文中与qp中保存的地址不同，报错*/
		if ((ip_hdr(skb)->daddr != saddr->s_addr) ||
		    (ip_hdr(skb)->saddr != daddr->s_addr))
			return -EINVAL;

	} else if (skb->protocol == htons(ETH_P_IPV6)) {
	    /*ipv6源目的ip校验*/
		struct in6_addr *saddr =
			&qp->pri_av.sgid_addr._sockaddr_in6.sin6_addr;
		struct in6_addr *daddr =
			&qp->pri_av.dgid_addr._sockaddr_in6.sin6_addr;

		if (memcmp(&ipv6_hdr(skb)->daddr, saddr, sizeof(*saddr)) ||
		    memcmp(&ipv6_hdr(skb)->saddr, daddr, sizeof(*daddr)))
			return -EINVAL;
	}

	return 0;
}

/*header检查，设置qp*/
static int hdr_check(struct rxe_pkt_info *pkt)
{
	struct rxe_dev *rxe = pkt->rxe;
	struct rxe_port *port = &rxe->port;
	struct rxe_qp *qp = NULL;
	u32 qpn = bth_qpn(pkt);/*取报文中提明的qpn*/
	int index;
	int err;

	/*transport版本号不符合，报错*/
	if (unlikely(bth_tver(pkt) != BTH_TVER))
		goto err1;

	/*不支持qpn为0的情况*/
	if (unlikely(qpn == 0))
		goto err1;

	/*非组播qpn情况处理*/
	if (qpn != IB_MULTICAST_QPN) {
		/*qpn为1情况下，采用port->qp_gsi_index做为qpn,否则采用原始qpn*/
		index = (qpn == 1) ? port->qp_gsi_index : qpn;

		/*通过index查询对应的qp*/
		qp = rxe_pool_get_index(&rxe->qp_pool, index);
		if (unlikely(!qp))
			goto err1;

		/*报文pkt_type字段检查，qp状态与pkt匹配检查*/
		err = check_type_state(rxe, pkt, qp);
		if (unlikely(err))
			goto err2;

		/*源地址与目的地址校验*/
		err = check_addr(rxe, pkt, qp);
		if (unlikely(err))
			goto err2;

		/*pkey及qkey检验*/
		err = check_keys(rxe, pkt, qpn, qp);
		if (unlikely(err))
			goto err2;
	} else {
		/*qpn为IB_MULTICAST_QPN时，报文mask必须有RXE_GRH_MASK标记*/
		if (unlikely((pkt->mask & RXE_GRH_MASK) == 0))
			goto err1;

		/*注意此时qp为NULL*/
	}

	/*设置pkt对应的qp*/
	pkt->qp = qp;
	return 0;

err2:
	rxe_put(qp);
err1:
	return -EINVAL;
}

/*基本校验通过后，此函数用于收取roce报文*/
static inline void rxe_rcv_pkt(struct rxe_pkt_info *pkt, struct sk_buff *skb)
{
	if (pkt->mask & RXE_REQ_MASK)
	    /*收到request类报文，添加报文至qp->req_pkts，
	     * 触发qp->resp.task，即rxe_responder函数
	     **/
		rxe_resp_queue_pkt(pkt->qp, skb);
	else
	    /*收到response类报文，添加报文至qp->resp_pkts，
	     * 触发qp->comp.task，即rxe_completer函数*/
		rxe_comp_queue_pkt(pkt->qp, skb);
}

static void rxe_rcv_mcast_pkt(struct rxe_dev *rxe, struct sk_buff *skb)
{
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct rxe_mcg *mcg;
	struct rxe_mca *mca;
	struct rxe_qp *qp;
	union ib_gid dgid;
	int err;

	if (skb->protocol == htons(ETH_P_IP))
		ipv6_addr_set_v4mapped(ip_hdr(skb)->daddr,
				       (struct in6_addr *)&dgid);
	else if (skb->protocol == htons(ETH_P_IPV6))
		memcpy(&dgid, &ipv6_hdr(skb)->daddr, sizeof(dgid));

	/* lookup mcast group corresponding to mgid, takes a ref */
	mcg = rxe_lookup_mcg(rxe, &dgid);
	if (!mcg)
		goto drop;	/* mcast group not registered */

	spin_lock_bh(&rxe->mcg_lock);

	/* this is unreliable datagram service so we let
	 * failures to deliver a multicast packet to a
	 * single QP happen and just move on and try
	 * the rest of them on the list
	 */
	list_for_each_entry(mca, &mcg->qp_list, qp_list) {
		qp = mca->qp;

		/* validate qp for incoming packet */
		err = check_type_state(rxe, pkt, qp);
		if (err)
			continue;

		err = check_keys(rxe, pkt, bth_qpn(pkt), qp);
		if (err)
			continue;

		/* for all but the last QP create a new clone of the
		 * skb and pass to the QP. Pass the original skb to
		 * the last QP in the list.
		 */
		if (mca->qp_list.next != &mcg->qp_list) {
			struct sk_buff *cskb;
			struct rxe_pkt_info *cpkt;

			cskb = skb_clone(skb, GFP_ATOMIC);
			if (unlikely(!cskb))
				continue;

			if (WARN_ON(!ib_device_try_get(&rxe->ib_dev))) {
				kfree_skb(cskb);
				break;
			}

			cpkt = SKB_TO_PKT(cskb);
			cpkt->qp = qp;
			rxe_get(qp);
			rxe_rcv_pkt(cpkt, cskb);
		} else {
			pkt->qp = qp;
			rxe_get(qp);
			rxe_rcv_pkt(pkt, skb);
			skb = NULL;	/* mark consumed */
		}
	}

	spin_unlock_bh(&rxe->mcg_lock);

	kref_put(&mcg->ref_cnt, rxe_cleanup_mcg);

	if (likely(!skb))
		return;

	/* This only occurs if one of the checks fails on the last
	 * QP in the list above
	 */

drop:
	kfree_skb(skb);
	ib_device_put(&rxe->ib_dev);
}

/**
 * rxe_chk_dgid - validate destination IP address
 * @rxe: rxe device that received packet
 * @skb: the received packet buffer
 *
 * Accept any loopback packets
 * Extract IP address from packet and
 * Accept if multicast packet
 * Accept if matches an SGID table entry
 */
static int rxe_chk_dgid(struct rxe_dev *rxe, struct sk_buff *skb)
{
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	const struct ib_gid_attr *gid_attr;
	union ib_gid dgid;
	union ib_gid *pdgid;

	if (pkt->mask & RXE_LOOPBACK_MASK)
		/*有loopback标记，返回0*/
		return 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		/*将目的地址映射为v6地址，后以目的地址做为pdgid*/
		ipv6_addr_set_v4mapped(ip_hdr(skb)->daddr,
				       (struct in6_addr *)&dgid);
		pdgid = &dgid;
	} else {
		/*以目的地址做为pdgid*/
		pdgid = (union ib_gid *)&ipv6_hdr(skb)->daddr;
	}

	/*pdgid为组播，返回0*/
	if (rdma_is_multicast_addr((struct in6_addr *)pdgid))
		return 0;

	gid_attr = rdma_find_gid_by_port(&rxe->ib_dev, pdgid,
					 IB_GID_TYPE_ROCE_UDP_ENCAP,
					 1, skb->dev);
	if (IS_ERR(gid_attr))
		return PTR_ERR(gid_attr);

	rdma_put_gid_attr(gid_attr);
	return 0;
}

/* rxe_rcv is called from the interface driver */
void rxe_rcv(struct sk_buff *skb)
{
	int err;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct rxe_dev *rxe = pkt->rxe;

	if (unlikely(skb->len < RXE_BTH_BYTES))
		/*报文长度不足*/
		goto drop;

	if (rxe_chk_dgid(rxe, skb) < 0)
		goto drop;

	pkt->opcode = bth_opcode(pkt);/*取opcode*/
	pkt->psn = bth_psn(pkt);/*取psn*/
	pkt->qp = NULL;/*初始化此pkt对应的qp*/
	pkt->mask |= rxe_opcode[pkt->opcode].mask;/*按opcode合入mask*/

	if (unlikely(skb->len < header_size(pkt)))
	    /*报文长度不足header*/
		goto drop;

	/*检查header*/
	err = hdr_check(pkt);
	if (unlikely(err))
		goto drop;

	/*icrc校验*/
	err = rxe_icrc_check(skb, pkt);
	if (unlikely(err))
		goto drop;

	/*统计收到的报文数*/
	rxe_counter_inc(rxe, RXE_CNT_RCVD_PKTS);

	if (unlikely(bth_qpn(pkt) == IB_MULTICAST_QPN))
	    /*multicast_qpn类型，收取组播报文*/
		rxe_rcv_mcast_pkt(rxe, skb);
	else
		/*单播性qp报文收取报文*/
		rxe_rcv_pkt(pkt, skb);

	return;

drop:
	if (pkt->qp)
		rxe_put(pkt->qp);

	kfree_skb(skb);
	ib_device_put(&rxe->ib_dev);
}
