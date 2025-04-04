/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018, Intel Corporation. */

#ifndef _FAILOVER_H
#define _FAILOVER_H

#include <linux/netdevice.h>

struct failover_ops {
    //slave_dev注册时触发(pre)
	int (*slave_pre_register)(struct net_device *slave_dev,
				  struct net_device *failover_dev);
	//slave_dev注册时触发(post)
	int (*slave_register)(struct net_device *slave_dev,
			      struct net_device *failover_dev);
	//slave_dev解注册时触发（pre)
	int (*slave_pre_unregister)(struct net_device *slave_dev,
				    struct net_device *failover_dev);
	//slave_dev解注册时触发（post)
	int (*slave_unregister)(struct net_device *slave_dev,
				struct net_device *failover_dev);
	//slave_dev link发生变更时触发
	int (*slave_link_change)(struct net_device *slave_dev,
				 struct net_device *failover_dev);
	//slave_name发生变更时触发
	int (*slave_name_change)(struct net_device *slave_dev,
				 struct net_device *failover_dev);
	/*提供slave设备的rx_handle回调*/
	rx_handler_result_t (*slave_handle_frame)(struct sk_buff **pskb);
};

struct failover {
	struct list_head list;
	struct net_device __rcu *failover_dev;
	netdevice_tracker	dev_tracker;
	struct failover_ops __rcu *ops;
};

struct failover *failover_register(struct net_device *dev,
				   struct failover_ops *ops);
void failover_unregister(struct failover *failover);
int failover_slave_unregister(struct net_device *slave_dev);

#endif /* _FAILOVER_H */
