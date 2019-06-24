// SPDX-License-Identifier: GPL-2.0-only
/*
 *	STP SAP demux
 *
 *	Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 */
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/llc.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <net/llc.h>
#include <net/llc_pdu.h>
#include <net/stp.h>

/* 01:80:c2:00:00:20 - 01:80:c2:00:00:2F */
#define GARP_ADDR_MIN	0x20
#define GARP_ADDR_MAX	0x2F
#define GARP_ADDR_RANGE	(GARP_ADDR_MAX - GARP_ADDR_MIN)

//注册二层link local 协议的处理函数
static const struct stp_proto __rcu *garp_protos[GARP_ADDR_RANGE + 1] __read_mostly;

//注册stp协议的收包函数
static const struct stp_proto __rcu *stp_proto __read_mostly;

static struct llc_sap *sap __read_mostly;
static unsigned int sap_registered;
static DEFINE_MUTEX(stp_proto_mutex);

/* Called under rcu_read_lock from LLC */
//检查2层报文，通过检查将其送给stp或者2层link local协议钩子处理
static int stp_pdu_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev)
{
	const struct ethhdr *eh = eth_hdr(skb);
	const struct llc_pdu_un *pdu = llc_pdu_un_hdr(skb);
	const struct stp_proto *proto;

	if (pdu->ssap != LLC_SAP_BSPAN ||
	    pdu->dsap != LLC_SAP_BSPAN ||
	    pdu->ctrl_1 != LLC_PDU_TYPE_U)
		goto err;

	if (eh->h_dest[5] >= GARP_ADDR_MIN && eh->h_dest[5] <= GARP_ADDR_MAX) {
		proto = rcu_dereference(garp_protos[eh->h_dest[5] -
						    GARP_ADDR_MIN]);
		//检查这些地址是否为link local地址，如果是，取对应协议
		if (proto &&
		    !ether_addr_equal(eh->h_dest, proto->group_address))
			goto err;
	} else
		//如果不是，则认为是stp协议
		proto = rcu_dereference(stp_proto);

	if (!proto)
		goto err;

	//使对应协议处理此报文
	proto->rcv(proto, skb, dev);
	return 0;

err:
	kfree_skb(skb);
	return 0;
}

int stp_proto_register(const struct stp_proto *proto)
{
	int err = 0;

	mutex_lock(&stp_proto_mutex);
	if (sap_registered++ == 0) {
		//首次注册时，进行初始化（注册llc协议对应的stp报文号）
		//从而保证llc_rcv到报文后，依据sap可以送给stp进行解析
		sap = llc_sap_open(LLC_SAP_BSPAN, stp_pdu_rcv);
		if (!sap) {
			err = -ENOMEM;
			goto out;
		}
	}
	//如果组mac为0，则直接将proto赋给stp_proto
	if (is_zero_ether_addr(proto->group_address))
		rcu_assign_pointer(stp_proto, proto);
	else
		//否则将地址赋给对应的garp_protos(link local protocols)
		rcu_assign_pointer(garp_protos[proto->group_address[5] -
					       GARP_ADDR_MIN], proto);
out:
	mutex_unlock(&stp_proto_mutex);
	return err;
}
EXPORT_SYMBOL_GPL(stp_proto_register);

//解注册
void stp_proto_unregister(const struct stp_proto *proto)
{
	mutex_lock(&stp_proto_mutex);
	if (is_zero_ether_addr(proto->group_address))
		RCU_INIT_POINTER(stp_proto, NULL);
	else
		RCU_INIT_POINTER(garp_protos[proto->group_address[5] -
					       GARP_ADDR_MIN], NULL);
	synchronize_rcu();

	if (--sap_registered == 0)
		llc_sap_put(sap);
	mutex_unlock(&stp_proto_mutex);
}
EXPORT_SYMBOL_GPL(stp_proto_unregister);

MODULE_LICENSE("GPL");
