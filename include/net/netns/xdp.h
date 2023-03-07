/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_XDP_H__
#define __NETNS_XDP_H__

#include <linux/mutex.h>
#include <linux/types.h>

struct netns_xdp {
	struct mutex		lock;
	//负责挂接所有xdp socket
	struct hlist_head	list;
};

#endif /* __NETNS_XDP_H__ */
