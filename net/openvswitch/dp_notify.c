// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 */

#include <linux/netdevice.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

//实现vport与netdev的detach
static void dp_detach_port_notify(struct vport *vport)
{
	struct sk_buff *notify;
	struct datapath *dp;

	dp = vport->dp;
	notify = ovs_vport_cmd_build_info(vport, ovs_dp_get_net(dp),
					  0, 0, OVS_VPORT_CMD_DEL);
	//实现vport删除
	ovs_dp_detach_port(vport);
	if (IS_ERR(notify)) {
		genl_set_err(&dp_vport_genl_family, ovs_dp_get_net(dp), 0,
			     0, PTR_ERR(notify));
		return;
	}

	//向上通知vport删除
	genlmsg_multicast_netns(&dp_vport_genl_family,
				ovs_dp_get_net(dp), notify, 0,
				0, GFP_KERNEL);
}

//具体的kernel work
void ovs_dp_notify_wq(struct work_struct *work)
{
	struct ovs_net *ovs_net = container_of(work, struct ovs_net, dp_notify_work);
	struct datapath *dp;

	ovs_lock();
	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		int i;

		for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
			struct vport *vport;
			struct hlist_node *n;

			hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node) {
				if (vport->ops->type == OVS_VPORT_TYPE_INTERNAL)
					//跳过internal设备
					continue;

				if (!(vport->dev->priv_flags & IFF_OVS_DATAPATH))
					dp_detach_port_notify(vport);
			}
		}
	}
	ovs_unlock();
}

//处理vport的netdev移除事件，完成vport与其的detach
static int dp_device_event(struct notifier_block *unused, unsigned long event,
			   void *ptr)
{
	struct ovs_net *ovs_net;
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct vport *vport = NULL;

	//非internal设备，取vport
	if (!ovs_is_internal_dev(dev))
		vport = ovs_netdev_get_vport(dev);

	if (!vport)
		return NOTIFY_DONE;

	//收到设备被移除事件，
	if (event == NETDEV_UNREGISTER) {
		/* upper_dev_unlink and decrement promisc immediately */
		ovs_netdev_detach_dev(vport);

		/* schedule vport destroy, dev_put and genl notification */
		ovs_net = net_generic(dev_net(dev), ovs_net_id);
		queue_work(system_wq, &ovs_net->dp_notify_work);
	}

	return NOTIFY_DONE;
}

struct notifier_block ovs_dp_device_notifier = {
	.notifier_call = dp_device_event
};
