/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NETDEV_RX_QUEUE_H
#define _LINUX_NETDEV_RX_QUEUE_H

#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/sysfs.h>
#include <net/xdp.h>

/* This structure contains an instance of an RX queue. */
struct netdev_rx_queue {
	struct xdp_rxq_info		xdp_rxq;
#ifdef CONFIG_RPS
    	//指明可接收此rx队列的cpu map （来源于queueu/rx-%d/rps_cpus配置）
	struct rps_map __rcu		*rps_map;
	/*指明具体的一条flow由哪个cpu处理（来源于？？？）*/
	struct rps_dev_flow_table __rcu	*rps_flow_table;
#endif
	struct kobject			kobj;
	struct net_device		*dev;
	netdevice_tracker		dev_tracker;

#ifdef CONFIG_XDP_SOCKETS
	/*对应的xdp pool*/
	struct xsk_buff_pool            *pool;
#endif
	/* NAPI instance for the queue
	 * Readers and writers must hold RTNL
	 */
	struct napi_struct		*napi;
} ____cacheline_aligned_in_smp;

/*
 * RX queue sysfs structures and functions.
 */
struct rx_queue_attribute {
	struct attribute attr;
	ssize_t (*show)(struct netdev_rx_queue *queue, char *buf);
	ssize_t (*store)(struct netdev_rx_queue *queue,
			 const char *buf, size_t len);
};

static inline struct netdev_rx_queue *
__netif_get_rx_queue(struct net_device *dev, unsigned int rxq)
{
	return dev->_rx + rxq;
}

#ifdef CONFIG_SYSFS
static inline unsigned int
get_netdev_rx_queue_index(struct netdev_rx_queue *queue)
{
	struct net_device *dev = queue->dev;
	int index = queue - dev->_rx;

	BUG_ON(index >= dev->num_rx_queues);
	return index;
}
#endif
#endif
