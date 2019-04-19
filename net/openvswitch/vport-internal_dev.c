/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>

#include <net/dst.h>
#include <net/xfrm.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

struct internal_dev {
	struct vport *vport;
};

static struct vport_ops ovs_internal_vport_ops;

//通过netdev获取对应的vport
static struct internal_dev *internal_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

/* Called with rcu_read_lock_bh. */
//kernel将自internal_dev发出报文时，nod的xmit函数将促使其进入此函数，
//并将报文送给datapath处理
static netdev_tx_t
internal_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	int len, err;

	len = skb->len;
	rcu_read_lock();
	//进入datapath进行处理
	err = ovs_vport_receive(internal_dev_priv(netdev)->vport, skb, NULL);
	rcu_read_unlock();

	if (likely(!err)) {
		struct pcpu_sw_netstats *tstats = this_cpu_ptr(netdev->tstats);

		u64_stats_update_begin(&tstats->syncp);
		//记录报文的传输字节数及包数
		tstats->tx_bytes += len;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
	} else {
		netdev->stats.tx_errors++;
	}
	return NETDEV_TX_OK;
}

static int internal_dev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int internal_dev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

static void internal_dev_getinfo(struct net_device *netdev,
				 struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, "openvswitch", sizeof(info->driver));
}

static const struct ethtool_ops internal_dev_ethtool_ops = {
	.get_drvinfo	= internal_dev_getinfo,
	.get_link	= ethtool_op_get_link,
};

static void internal_dev_destructor(struct net_device *dev)
{
	struct vport *vport = ovs_internal_dev_get_vport(dev);

	ovs_vport_free(vport);
}

static void
internal_get_stats(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	int i;

	memset(stats, 0, sizeof(*stats));
	stats->rx_errors  = dev->stats.rx_errors;
	stats->tx_errors  = dev->stats.tx_errors;
	stats->tx_dropped = dev->stats.tx_dropped;
	stats->rx_dropped = dev->stats.rx_dropped;

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *percpu_stats;
		struct pcpu_sw_netstats local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(dev->tstats, i);

		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->rx_bytes         += local_stats.rx_bytes;
		stats->rx_packets       += local_stats.rx_packets;
		stats->tx_bytes         += local_stats.tx_bytes;
		stats->tx_packets       += local_stats.tx_packets;
	}
}

static const struct net_device_ops internal_dev_netdev_ops = {
	.ndo_open = internal_dev_open,
	.ndo_stop = internal_dev_stop,
	//ovs internal设备发包函数，实现为当kernel针对此接口向外发包时，
	//使报文进入其所属的datapath，再进行转发
	.ndo_start_xmit = internal_dev_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	//返回报文的统计信息
	.ndo_get_stats64 = internal_get_stats,
};

static struct rtnl_link_ops internal_dev_link_ops __read_mostly = {
	.kind = "openvswitch",
};

static void do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

	netdev->max_mtu = ETH_MAX_MTU;

	//置netdev的ops
	netdev->netdev_ops = &internal_dev_netdev_ops;

	netdev->priv_flags &= ~IFF_TX_SKB_SHARING;
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_OPENVSWITCH |
			      IFF_NO_QUEUE;
	netdev->needs_free_netdev = true;
	netdev->priv_destructor = internal_dev_destructor;
	netdev->ethtool_ops = &internal_dev_ethtool_ops;
	netdev->rtnl_link_ops = &internal_dev_link_ops;

	netdev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |
			   NETIF_F_HIGHDMA | NETIF_F_HW_CSUM |
			   NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL;

	netdev->vlan_features = netdev->features;
	netdev->hw_enc_features = netdev->features;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
	netdev->hw_features = netdev->features & ~NETIF_F_LLTX;

	//为此设备生成随机mac地址
	eth_hw_addr_random(netdev);
}

//internal-dev设备创建，其需要创建为一个link接口
static struct vport *internal_dev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct internal_dev *internal_dev;
	int err;

	vport = ovs_vport_alloc(0, &ovs_internal_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	//申请名称为parms->name的netdev,并通过do_setup初始化它
	vport->dev = alloc_netdev(sizeof(struct internal_dev),
				  parms->name, NET_NAME_USER, do_setup);
	if (!vport->dev) {
		err = -ENOMEM;
		goto error_free_vport;
	}
	vport->dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!vport->dev->tstats) {
		err = -ENOMEM;
		goto error_free_netdev;
	}

	dev_net_set(vport->dev, ovs_dp_get_net(vport->dp));
	//设置private,使vport->dev可以找到vport结构
	internal_dev = internal_dev_priv(vport->dev);
	internal_dev->vport = vport;

	/* Restrict bridge port to current netns. */
	if (vport->port_no == OVSP_LOCAL)
		vport->dev->features |= NETIF_F_NETNS_LOCAL;

	rtnl_lock();
	//网络设备注册
	err = register_netdevice(vport->dev);
	if (err)
		goto error_unlock;

	dev_set_promiscuity(vport->dev, 1);
	rtnl_unlock();
	netif_start_queue(vport->dev);

	return vport;

error_unlock:
	rtnl_unlock();
	free_percpu(vport->dev->tstats);
error_free_netdev:
	free_netdev(vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void internal_dev_destroy(struct vport *vport)
{
	netif_stop_queue(vport->dev);
	rtnl_lock();
	dev_set_promiscuity(vport->dev, -1);

	/* unregister_netdevice() waits for an RCU grace period. */
	unregister_netdevice(vport->dev);
	free_percpu(vport->dev->tstats);
	rtnl_unlock();
}

//自internal_dev向外发送报文时，送给kernel协议栈
static netdev_tx_t internal_dev_recv(struct sk_buff *skb)
{
	struct net_device *netdev = skb->dev;
	struct pcpu_sw_netstats *stats;

	//接口未up,直接丢包
	if (unlikely(!(netdev->flags & IFF_UP))) {
		kfree_skb(skb);
		netdev->stats.rx_dropped++;
		return NETDEV_TX_OK;
	}

	skb_dst_drop(skb);
	nf_reset(skb);
	secpath_reset(skb);

	//指明报文去往本机
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

	stats = this_cpu_ptr(netdev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	//将报文扔给kernel协议栈
	netif_rx(skb);
	return NETDEV_TX_OK;
}

static struct vport_ops ovs_internal_vport_ops = {
	.type		= OVS_VPORT_TYPE_INTERNAL,
	.create		= internal_dev_create,//创建对应的netdev
	.destroy	= internal_dev_destroy,
	//针对internal设备的报文，其自ovs向外发送时，会被丢给kernel,其入接口变更为vport->dev对应的设备
	.send		= internal_dev_recv,
};

//检查所给netdev是否为internal_dev
int ovs_is_internal_dev(const struct net_device *netdev)
{
	return netdev->netdev_ops == &internal_dev_netdev_ops;
}

//获取vport
struct vport *ovs_internal_dev_get_vport(struct net_device *netdev)
{
	if (!ovs_is_internal_dev(netdev))
		return NULL;

	return internal_dev_priv(netdev)->vport;
}

int ovs_internal_dev_rtnl_link_register(void)
{
	int err;

	//注册link类型
	err = rtnl_link_register(&internal_dev_link_ops);
	if (err < 0)
		return err;

	//注册internal_vport的ops
	err = ovs_vport_ops_register(&ovs_internal_vport_ops);
	if (err < 0)
		rtnl_link_unregister(&internal_dev_link_ops);

	return err;
}

void ovs_internal_dev_rtnl_link_unregister(void)
{
	ovs_vport_ops_unregister(&ovs_internal_vport_ops);
	rtnl_link_unregister(&internal_dev_link_ops);
}
