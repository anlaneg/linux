// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/llc.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/openvswitch.h>
#include <linux/export.h>

#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "vport.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

static struct vport_ops ovs_netdev_vport_ops;

/* Must be called with rcu_read_lock. */
//ovs报文入口
static void netdev_port_receive(struct sk_buff *skb)
{
	struct vport *vport;

	vport = ovs_netdev_get_vport(skb->dev);
	if (unlikely(!vport))
		goto error;

	if (unlikely(skb_warn_if_lro(skb)))
		goto error;

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	if (skb->dev->type == ARPHRD_ETHER)
		skb_push_rcsum(skb, ETH_HLEN);

	ovs_vport_receive(vport, skb, skb_tunnel_info(skb));
	return;
error:
	kfree_skb(skb);
}

/* Called with rcu_read_lock and bottom-halves disabled. */
//netdev收包入口
static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	netdev_port_receive(skb);
	//知会kernel协议栈，报文已被消耗
	return RX_HANDLER_CONSUMED;
}

//取ovs的local接口
static struct net_device *get_dpdev(const struct datapath *dp)
{
	struct vport *local;

	local = ovs_vport_ovsl(dp, OVSP_LOCAL);
	return local->dev;
}

//将vport对应的名称为$name的netdev收包修改为netdev_frame_hook
struct vport *ovs_netdev_link(struct vport *vport, const char *name)
{
	int err;

	//从vport所属datapath所属network中查找名称为name的dev
	vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), name);
	if (!vport->dev) {
		//如果name对应的netdev不存在，则报错
		err = -ENODEV;
		goto error_free_vport;
	}
	netdev_tracker_alloc(vport->dev, &vport->dev_tracker, GFP_KERNEL);
	if (vport->dev->flags & IFF_LOOPBACK ||
	    (vport->dev->type != ARPHRD_ETHER &&
	     vport->dev->type != ARPHRD_NONE) ||
	    ovs_is_internal_dev(vport->dev)) {
		//不容许internal,loopback口以及非以太类网接口
		err = -EINVAL;
		goto error_put;
	}

	rtnl_lock();
	err = netdev_master_upper_dev_link(vport->dev,
					   get_dpdev(vport->dp),
					   NULL, NULL, NULL);
	if (err)
		goto error_unlock;

	//为设备注册收包回调（bridge也采用相一致的机制）
	//修改加入datapath的vport->dev设备的收包函数变更为netdev_frame_hook)
	err = netdev_rx_handler_register(vport->dev, netdev_frame_hook,
					 vport/*指明rx_handler_data为vport*/);
	if (err)
		goto error_master_upper_dev_unlink;

	//禁止dev上的lro
	dev_disable_lro(vport->dev);
	dev_set_promiscuity(vport->dev, 1);
	vport->dev->priv_flags |= IFF_OVS_DATAPATH;
	rtnl_unlock();

	return vport;

error_master_upper_dev_unlink:
	netdev_upper_dev_unlink(vport->dev, get_dpdev(vport->dp));
error_unlock:
	rtnl_unlock();
error_put:
	netdev_put(vport->dev, &vport->dev_tracker);
error_free_vport:
	ovs_vport_free(vport);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(ovs_netdev_link);

//netdev port创建
static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ovs_vport_alloc(0, &ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static void vport_netdev_free(struct rcu_head *rcu)
{
	struct vport *vport = container_of(rcu, struct vport, rcu);

	//释放对dev的引用
	netdev_put(vport->dev, &vport->dev_tracker);
	ovs_vport_free(vport);
}

void ovs_netdev_detach_dev(struct vport *vport)
{
	ASSERT_RTNL();
	vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(vport->dev);
	netdev_upper_dev_unlink(vport->dev,
				netdev_master_upper_dev_get(vport->dev));
	dev_set_promiscuity(vport->dev, -1);
}

static void netdev_destroy(struct vport *vport)
{
	rtnl_lock();
	if (netif_is_ovs_port(vport->dev))
		ovs_netdev_detach_dev(vport);
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}

void ovs_netdev_tunnel_destroy(struct vport *vport)
{
	rtnl_lock();
	if (netif_is_ovs_port(vport->dev))
		ovs_netdev_detach_dev(vport);

	/* We can be invoked by both explicit vport deletion and
	 * underlying netdev deregistration; delete the link only
	 * if it's not already shutting down.
	 */
	if (vport->dev->reg_state == NETREG_REGISTERED)
		rtnl_delete_link(vport->dev, 0, NULL);
	netdev_put(vport->dev, &vport->dev_tracker);
	vport->dev = NULL;
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}
EXPORT_SYMBOL_GPL(ovs_netdev_tunnel_destroy);

/* Returns null if this device is not attached to a datapath. */
struct vport *ovs_netdev_get_vport(struct net_device *dev)
{
	//由dev获得vport
	if (likely(netif_is_ovs_port(dev)))
		return (struct vport *)
			rcu_dereference_rtnl(dev->rx_handler_data);
	else
		return NULL;
}

static struct vport_ops ovs_netdev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,
	//接口创建
	.create		= netdev_create,
	//接口销毁
	.destroy	= netdev_destroy,
	//针对netdev类型的报文，其自ovs向外发送时，其将投递给vport->dev对应的那个口
	.send		= dev_queue_xmit,
};

//添加netdev vport ops
int __init ovs_netdev_init(void)
{
	//注册类型为ovs_vport_type_netdev的ops
	return ovs_vport_ops_register(&ovs_netdev_vport_ops);
}

//移除netdev vport ops
void ovs_netdev_exit(void)
{
	//netdev ops移除
	ovs_vport_ops_unregister(&ovs_netdev_vport_ops);
}
