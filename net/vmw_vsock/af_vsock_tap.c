// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Tap functions for AF_VSOCK sockets.
 *
 * Code based on net/netlink/af_netlink.c tap functions.
 */

#include <linux/module.h>
#include <net/sock.h>
#include <net/af_vsock.h>
#include <linux/if_arp.h>

static DEFINE_SPINLOCK(vsock_tap_lock);
static struct list_head vsock_tap_all __read_mostly =
				LIST_HEAD_INIT(vsock_tap_all);

int vsock_add_tap(struct vsock_tap *vt)
{
	if (unlikely(vt->dev->type != ARPHRD_VSOCKMON))
		return -EINVAL;

	__module_get(vt->module);

	spin_lock(&vsock_tap_lock);
	list_add_rcu(&vt->list, &vsock_tap_all);
	spin_unlock(&vsock_tap_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(vsock_add_tap);

int vsock_remove_tap(struct vsock_tap *vt)
{
	struct vsock_tap *tmp;
	bool found = false;

	spin_lock(&vsock_tap_lock);

	list_for_each_entry(tmp, &vsock_tap_all, list) {
		if (vt == tmp) {
			list_del_rcu(&vt->list);
			found = true;
			goto out;
		}
	}

	pr_warn("vsock_remove_tap: %p not found\n", vt);
out:
	spin_unlock(&vsock_tap_lock);

	synchronize_net();

	if (found)
		module_put(vt->module);

	return found ? 0 : -ENODEV;
}
EXPORT_SYMBOL_GPL(vsock_remove_tap);

static int __vsock_deliver_tap_skb(struct sk_buff *skb,
				   struct net_device *dev)
{
	int ret = 0;
	struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);

	if (nskb) {
		dev_hold(dev);

		nskb->dev = dev;
		ret = dev_queue_xmit(nskb);
		if (unlikely(ret > 0))
			ret = net_xmit_errno(ret);

		dev_put(dev);
	}

	return ret;
}

static void __vsock_deliver_tap(struct sk_buff *skb)
{
	int ret;
	struct vsock_tap *tmp;

	//遍历vsock_tap_all链表，送一份skb副本给相应的设备
	list_for_each_entry_rcu(tmp, &vsock_tap_all, list) {
		ret = __vsock_deliver_tap_skb(skb, tmp->dev);
		if (unlikely(ret))
			break;
	}
}

//如果vsock_tap_all不为空，则复制报文给链上所有设备一份
void vsock_deliver_tap(struct sk_buff *build_skb(void *opaque), void *opaque)
{
	struct sk_buff *skb;

	rcu_read_lock();

	//如果队列为空，则不处理
	if (likely(list_empty(&vsock_tap_all)))
		goto out;

	//按opaque完成报文构造
	skb = build_skb(opaque);
	if (skb) {
	    //复制报文给vsock_tap_all上所有设备
		__vsock_deliver_tap(skb);
		//释放原报文
		consume_skb(skb);
	}

out:
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(vsock_deliver_tap);
