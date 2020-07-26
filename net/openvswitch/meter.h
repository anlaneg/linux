/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017 Nicira, Inc.
 */

#ifndef METER_H
#define METER_H 1

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/genetlink.h>
#include <linux/skbuff.h>
#include <linux/bits.h>

#include "flow.h"
struct datapath;

#define DP_MAX_BANDS		1
#define DP_METER_ARRAY_SIZE_MIN	BIT_ULL(10)
#define DP_METER_NUM_MAX	(200000UL)

struct dp_meter_band {
	u32 type;
	u32 rate;//容许的最大速率 kbps
	u32 burst_size;//容许的burst流量 kbps
	u64 bucket; /* 1/1000 packets, or in bits */
	struct ovs_flow_stats stats;
};

struct dp_meter {
	spinlock_t lock;    /* Per meter lock */
	struct rcu_head rcu;
	u32 id;
	u16 kbps:1/*单位是否为kbps或者包数每秒*/, keep_stats:1;
	u16 n_bands;/*band的数目*/
	u32 max_delta_t;
	u64 used;
	//定义此meter被命中的包数及字节数
	struct ovs_flow_stats stats;
	//记录配置的bands
	struct dp_meter_band bands[];
};

struct dp_meter_instance {
	struct rcu_head rcu;
	u32 n_meters;//dp_meter的数目
	struct dp_meter __rcu *dp_meters[];
};

struct dp_meter_table {
	struct dp_meter_instance __rcu *ti;
	u32 count;
	u32 max_meters_allowed;/*容许的最大meter*/
};

extern struct genl_family dp_meter_genl_family;
int ovs_meters_init(struct datapath *dp);
void ovs_meters_exit(struct datapath *dp);
bool ovs_meter_execute(struct datapath *dp, struct sk_buff *skb,
		       struct sw_flow_key *key, u32 meter_id);

#endif /* meter.h */
