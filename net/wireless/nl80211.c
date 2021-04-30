// SPDX-License-Identifier: GPL-2.0-only
/*
 * This is the new netlink-based wireless configuration interface.
 * 基于netlink的无线配置接口
 *
 * Copyright 2006-2010	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014  Intel Mobile Communications GmbH
 * Copyright 2015-2017	Intel Deutschland GmbH
 * Copyright (C) 2018-2021 Intel Corporation
 */

#include <linux/if.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/nospec.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>
#include <net/cfg80211.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include "core.h"
#include "nl80211.h"
#include "reg.h"
#include "rdev-ops.h"

static int nl80211_crypto_settings(struct cfg80211_registered_device *rdev,
				   struct genl_info *info,
				   struct cfg80211_crypto_settings *settings,
				   int cipher_limit);

/* the netlink family */
static struct genl_family nl80211_fam;

/* multicast groups */
enum nl80211_multicast_groups {
	NL80211_MCGRP_CONFIG,
	NL80211_MCGRP_SCAN,
	NL80211_MCGRP_REGULATORY,
	NL80211_MCGRP_MLME,
	NL80211_MCGRP_VENDOR,
	NL80211_MCGRP_NAN,
	NL80211_MCGRP_TESTMODE /* keep last - ifdef! */
};

static const struct genl_multicast_group nl80211_mcgrps[] = {
	[NL80211_MCGRP_CONFIG] = { .name = NL80211_MULTICAST_GROUP_CONFIG },
	[NL80211_MCGRP_SCAN] = { .name = NL80211_MULTICAST_GROUP_SCAN },
	[NL80211_MCGRP_REGULATORY] = { .name = NL80211_MULTICAST_GROUP_REG },
	[NL80211_MCGRP_MLME] = { .name = NL80211_MULTICAST_GROUP_MLME },
	[NL80211_MCGRP_VENDOR] = { .name = NL80211_MULTICAST_GROUP_VENDOR },
	[NL80211_MCGRP_NAN] = { .name = NL80211_MULTICAST_GROUP_NAN },
#ifdef CONFIG_NL80211_TESTMODE
	[NL80211_MCGRP_TESTMODE] = { .name = NL80211_MULTICAST_GROUP_TESTMODE }
#endif
};

/* returns ERR_PTR values */
static struct wireless_dev *
__cfg80211_wdev_from_attrs(struct cfg80211_registered_device *rdev,
			   struct net *netns, struct nlattr **attrs)
{
	struct wireless_dev *result = NULL;
	bool have_ifidx = attrs[NL80211_ATTR_IFINDEX];
	bool have_wdev_id = attrs[NL80211_ATTR_WDEV];
	u64 wdev_id = 0;
	int wiphy_idx = -1;
	int ifidx = -1;

	if (info->user_ptr[0] &&
	    !(ops->internal_flags & NL80211_FLAG_NO_WIPHY_MTX)) {
		struct cfg80211_registered_device *rdev = info->user_ptr[0];

		/* we kept the mutex locked since pre_doit */
		__acquire(&rdev->wiphy.mtx);
		wiphy_unlock(&rdev->wiphy);
	}

	//加锁了，这里解锁
	if (ops->internal_flags & NL80211_FLAG_NEED_RTNL)
		rtnl_unlock();

	/* If needed, clear the netlink message payload from the SKB
	 * as it might contain key data that shouldn't stick around on
	 * the heap after the SKB is freed. The netlink message header
	 * is still needed for further processing, so leave it intact.
	 */
	if (ops->internal_flags & NL80211_FLAG_CLEAR_SKB) {
		struct nlmsghdr *nlh = nlmsg_hdr(skb);

		memset(nlmsg_data(nlh), 0, nlmsg_len(nlh));
	}
}

static int nl80211_set_sar_sub_specs(struct cfg80211_registered_device *rdev,
				     struct cfg80211_sar_specs *sar_specs,
				     struct nlattr *spec[], int index)
{
	u32 range_index, i;

	if (!sar_specs || !spec)
		return -EINVAL;

	if (!spec[NL80211_SAR_ATTR_SPECS_POWER] ||
	    !spec[NL80211_SAR_ATTR_SPECS_RANGE_INDEX])
		return -EINVAL;

	range_index = nla_get_u32(spec[NL80211_SAR_ATTR_SPECS_RANGE_INDEX]);

	/* check if range_index exceeds num_freq_ranges */
	if (range_index >= rdev->wiphy.sar_capa->num_freq_ranges)
		return -EINVAL;

	/* check if range_index duplicates */
	for (i = 0; i < index; i++) {
		if (sar_specs->sub_specs[i].freq_range_index == range_index)
			return -EINVAL;
	}

	sar_specs->sub_specs[index].power =
		nla_get_s32(spec[NL80211_SAR_ATTR_SPECS_POWER]);

	sar_specs->sub_specs[index].freq_range_index = range_index;

	return 0;
}

static int nl80211_set_sar_specs(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg80211_registered_device *rdev = info->user_ptr[0];
	struct nlattr *spec[NL80211_SAR_ATTR_SPECS_MAX + 1];
	struct nlattr *tb[NL80211_SAR_ATTR_MAX + 1];
	struct cfg80211_sar_specs *sar_spec;
	enum nl80211_sar_type type;
	struct nlattr *spec_list;
	u32 specs;
	int rem, err;

	if (!rdev->wiphy.sar_capa || !rdev->ops->set_sar_specs)
		return -EOPNOTSUPP;

	if (!info->attrs[NL80211_ATTR_SAR_SPEC])
		return -EINVAL;

	nla_parse_nested(tb, NL80211_SAR_ATTR_MAX,
			 info->attrs[NL80211_ATTR_SAR_SPEC],
			 NULL, NULL);

	if (!tb[NL80211_SAR_ATTR_TYPE] || !tb[NL80211_SAR_ATTR_SPECS])
		return -EINVAL;

	type = nla_get_u32(tb[NL80211_SAR_ATTR_TYPE]);
	if (type != rdev->wiphy.sar_capa->type)
		return -EINVAL;

	specs = 0;
	nla_for_each_nested(spec_list, tb[NL80211_SAR_ATTR_SPECS], rem)
		specs++;

	if (specs > rdev->wiphy.sar_capa->num_freq_ranges)
		return -EINVAL;

	sar_spec = kzalloc(sizeof(*sar_spec) +
			   specs * sizeof(struct cfg80211_sar_sub_specs),
			   GFP_KERNEL);
	if (!sar_spec)
		return -ENOMEM;

	sar_spec->type = type;
	specs = 0;
	nla_for_each_nested(spec_list, tb[NL80211_SAR_ATTR_SPECS], rem) {
		nla_parse_nested(spec, NL80211_SAR_ATTR_SPECS_MAX,
				 spec_list, NULL, NULL);

		switch (type) {
		case NL80211_SAR_TYPE_POWER:
			if (nl80211_set_sar_sub_specs(rdev, sar_spec,
						      spec, specs)) {
				err = -EINVAL;
				goto error;
			}
			break;
		default:
			err = -EINVAL;
			goto error;
		}
		specs++;
	}

	sar_spec->num_sub_specs = specs;

	rdev->cur_cmd_info = info;
	err = rdev_set_sar_specs(rdev, sar_spec);
	rdev->cur_cmd_info = NULL;
error:
	kfree(sar_spec);
	return err;
}

static const struct genl_ops nl80211_ops[] = {
	{
		.cmd = NL80211_CMD_GET_WIPHY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_wiphy,
		.dumpit = nl80211_dump_wiphy,
		.done = nl80211_dump_wiphy_done,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
};

static const struct genl_small_ops nl80211_small_ops[] = {
	{
		.cmd = NL80211_CMD_SET_WIPHY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_wiphy,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = NL80211_CMD_GET_INTERFACE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_interface,
		.dumpit = nl80211_dump_interface,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL80211_FLAG_NEED_WDEV,
	},
	{
		.cmd = NL80211_CMD_SET_INTERFACE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_interface,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_NEW_INTERFACE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_new_interface,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_DEL_INTERFACE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_del_interface,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_GET_KEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_key,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_KEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_key,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_NEW_KEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_new_key,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_DEL_KEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_del_key,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_BEACON,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_UNS_ADMIN_PERM,
		.doit = nl80211_set_beacon,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_START_AP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_UNS_ADMIN_PERM,
		.doit = nl80211_start_ap,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_STOP_AP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = GENL_UNS_ADMIN_PERM,
		.doit = nl80211_stop_ap,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_STATION,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_station,
		.dumpit = nl80211_dump_station,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_SET_STATION,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_station,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_NEW_STATION,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_new_station,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_DEL_STATION,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_del_station,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_MPATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_mpath,
		.dumpit = nl80211_dump_mpath,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_MPP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_mpp,
		.dumpit = nl80211_dump_mpp,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_MPATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_mpath,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_NEW_MPATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_new_mpath,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_DEL_MPATH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_del_mpath,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_BSS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_bss,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_REG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_reg_do,
		.dumpit = nl80211_get_reg_dump,
		.internal_flags = 0,
		/* can be retrieved by unprivileged users */
	},
#ifdef CONFIG_CFG80211_CRDA_SUPPORT
	{
		.cmd = NL80211_CMD_SET_REG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_reg,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = 0,
	},
#endif
	{
		.cmd = NL80211_CMD_REQ_SET_REG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_req_set_reg,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NL80211_CMD_RELOAD_REGDB,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_reload_regdb,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = NL80211_CMD_GET_MESH_CONFIG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_mesh_config,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_MESH_CONFIG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_update_mesh_config,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_TRIGGER_SCAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_trigger_scan,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_ABORT_SCAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_abort_scan,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_SCAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.dumpit = nl80211_dump_scan,
	},
	{
		.cmd = NL80211_CMD_START_SCHED_SCAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_start_sched_scan,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_STOP_SCHED_SCAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_stop_sched_scan,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_AUTHENTICATE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_authenticate,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_ASSOCIATE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_associate,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_DEAUTHENTICATE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_deauthenticate,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_DISASSOCIATE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_disassociate,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_JOIN_IBSS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_join_ibss,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_LEAVE_IBSS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_leave_ibss,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
#ifdef CONFIG_NL80211_TESTMODE
	{
		.cmd = NL80211_CMD_TESTMODE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_testmode_do,
		.dumpit = nl80211_testmode_dump,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
#endif
	{
		.cmd = NL80211_CMD_CONNECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_connect,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_UPDATE_CONNECT_PARAMS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_update_connect_params,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_DISCONNECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_disconnect,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_WIPHY_NETNS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_wiphy_netns,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY |
				  NL80211_FLAG_NEED_RTNL |
				  NL80211_FLAG_NO_WIPHY_MTX,
	},
	{
		.cmd = NL80211_CMD_GET_SURVEY,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.dumpit = nl80211_dump_survey,
	},
	{
		.cmd = NL80211_CMD_SET_PMKSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_setdel_pmksa,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_DEL_PMKSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_setdel_pmksa,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_FLUSH_PMKSA,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_flush_pmksa,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_REMAIN_ON_CHANNEL,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_remain_on_channel,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_cancel_remain_on_channel,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_TX_BITRATE_MASK,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_tx_bitrate_mask,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_REGISTER_FRAME,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_register_mgmt,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV,
	},
	{
		.cmd = NL80211_CMD_FRAME,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tx_mgmt,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_FRAME_WAIT_CANCEL,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tx_mgmt_cancel_wait,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_POWER_SAVE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_power_save,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_GET_POWER_SAVE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_power_save,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_SET_CQM,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_cqm,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_SET_CHANNEL,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_channel,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_JOIN_MESH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_join_mesh,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_LEAVE_MESH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_leave_mesh,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_JOIN_OCB,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_join_ocb,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_LEAVE_OCB,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_leave_ocb,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
#ifdef CONFIG_PM
	{
		.cmd = NL80211_CMD_GET_WOWLAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_wowlan,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
	{
		.cmd = NL80211_CMD_SET_WOWLAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_wowlan,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
#endif
	{
		.cmd = NL80211_CMD_SET_REKEY_OFFLOAD,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_rekey_data,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_TDLS_MGMT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tdls_mgmt,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_TDLS_OPER,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tdls_oper,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_UNEXPECTED_FRAME,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_register_unexpected_frame,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_PROBE_CLIENT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_probe_client,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_REGISTER_BEACONS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_register_beacons,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
	{
		.cmd = NL80211_CMD_SET_NOACK_MAP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_noack_map,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_START_P2P_DEVICE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_start_p2p_device,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_STOP_P2P_DEVICE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_stop_p2p_device,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_START_NAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_start_nan,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_STOP_NAN,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_stop_nan,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP |
				  NL80211_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL80211_CMD_ADD_NAN_FUNCTION,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_nan_add_func,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_DEL_NAN_FUNCTION,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_nan_del_func,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_CHANGE_NAN_CONFIG,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_nan_change_config,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_MCAST_RATE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_mcast_rate,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_SET_MAC_ACL,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_mac_acl,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_RADAR_DETECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_start_radar_detection,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_PROTOCOL_FEATURES,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_protocol_features,
	},
	{
		.cmd = NL80211_CMD_UPDATE_FT_IES,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_update_ft_ies,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_CRIT_PROTOCOL_START,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_crit_protocol_start,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_CRIT_PROTOCOL_STOP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_crit_protocol_stop,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_COALESCE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_coalesce,
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
	{
		.cmd = NL80211_CMD_SET_COALESCE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_coalesce,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY,
	},
	{
		.cmd = NL80211_CMD_CHANNEL_SWITCH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_channel_switch,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_VENDOR,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_vendor_cmd,
		.dumpit = nl80211_vendor_cmd_dump,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_SET_QOS_MAP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_qos_map,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_ADD_TX_TS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_add_tx_ts,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_DEL_TX_TS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_del_tx_ts,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_TDLS_CHANNEL_SWITCH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tdls_channel_switch,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tdls_cancel_channel_switch,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_MULTICAST_TO_UNICAST,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_multicast_to_unicast,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_SET_PMK,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_pmk,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP |
				  0 |
				  NL80211_FLAG_CLEAR_SKB,
	},
	{
		.cmd = NL80211_CMD_DEL_PMK,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_del_pmk,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_EXTERNAL_AUTH,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_external_auth,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_CONTROL_PORT_FRAME,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_tx_control_port,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_GET_FTM_RESPONDER_STATS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_get_ftm_responder_stats,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_PEER_MEASUREMENT_START,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_pmsr_start,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WDEV_UP,
	},
	{
		.cmd = NL80211_CMD_NOTIFY_RADAR,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_notify_radar_detection,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_UPDATE_OWE_INFO,
		.doit = nl80211_update_owe_info,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_PROBE_MESH_LINK,
		.doit = nl80211_probe_mesh_link,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV_UP,
	},
	{
		.cmd = NL80211_CMD_SET_TID_CONFIG,
		.doit = nl80211_set_tid_config,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_NETDEV,
	},
	{
		.cmd = NL80211_CMD_SET_SAR_SPECS,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = nl80211_set_sar_specs,
		.flags = GENL_UNS_ADMIN_PERM,
		.internal_flags = NL80211_FLAG_NEED_WIPHY |
				  NL80211_FLAG_NEED_RTNL,
	},
};

/*80211 family支持的情况*/
static struct genl_family nl80211_fam __ro_after_init = {
	.name = NL80211_GENL_NAME,	/* have users key off the name instead */
	.hdrsize = 0,			/* no private header */
	.version = 1,			/* no particular meaning now */
	.maxattr = NL80211_ATTR_MAX,
	.policy = nl80211_policy,
	.netnsok = true,
	//ops提供的netlink命令调用前，此函数总被调用
	.pre_doit = nl80211_pre_doit,
	.post_doit = nl80211_post_doit,
	.module = THIS_MODULE,
	//对外提供的netlink操作命令回调
	.ops = nl80211_ops,
	.n_ops = ARRAY_SIZE(nl80211_ops),
	.small_ops = nl80211_small_ops,
	.n_small_ops = ARRAY_SIZE(nl80211_small_ops),
	.mcgrps = nl80211_mcgrps,
	.n_mcgrps = ARRAY_SIZE(nl80211_mcgrps),
	.parallel_ops = true,
};

/* notification functions */

void nl80211_notify_wiphy(struct cfg80211_registered_device *rdev,
			  enum nl80211_commands cmd)
{
	struct sk_buff *msg;
	struct nl80211_dump_wiphy_state state = {};

	WARN_ON(cmd != NL80211_CMD_NEW_WIPHY &&
		cmd != NL80211_CMD_DEL_WIPHY);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	if (nl80211_send_wiphy(rdev, cmd, msg, 0, 0, 0, &state) < 0) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_CONFIG, GFP_KERNEL);
}

void nl80211_notify_iface(struct cfg80211_registered_device *rdev,
				struct wireless_dev *wdev,
				enum nl80211_commands cmd)
{
	struct sk_buff *msg;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	if (nl80211_send_iface(msg, 0, 0, 0, rdev, wdev, cmd) < 0) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_CONFIG, GFP_KERNEL);
}

static int nl80211_add_scan_req(struct sk_buff *msg,
				struct cfg80211_registered_device *rdev)
{
	struct cfg80211_scan_request *req = rdev->scan_req;
	struct nlattr *nest;
	int i;
	struct cfg80211_scan_info *info;

	if (WARN_ON(!req))
		return 0;

	nest = nla_nest_start_noflag(msg, NL80211_ATTR_SCAN_SSIDS);
	if (!nest)
		goto nla_put_failure;
	for (i = 0; i < req->n_ssids; i++) {
		if (nla_put(msg, i, req->ssids[i].ssid_len, req->ssids[i].ssid))
			goto nla_put_failure;
	}
	nla_nest_end(msg, nest);

	if (req->flags & NL80211_SCAN_FLAG_FREQ_KHZ) {
		nest = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQ_KHZ);
		if (!nest)
			goto nla_put_failure;
		for (i = 0; i < req->n_channels; i++) {
			if (nla_put_u32(msg, i,
				   ieee80211_channel_to_khz(req->channels[i])))
				goto nla_put_failure;
		}
		nla_nest_end(msg, nest);
	} else {
		nest = nla_nest_start_noflag(msg,
					     NL80211_ATTR_SCAN_FREQUENCIES);
		if (!nest)
			goto nla_put_failure;
		for (i = 0; i < req->n_channels; i++) {
			if (nla_put_u32(msg, i, req->channels[i]->center_freq))
				goto nla_put_failure;
		}
		nla_nest_end(msg, nest);
	}

	if (req->ie &&
	    nla_put(msg, NL80211_ATTR_IE, req->ie_len, req->ie))
		goto nla_put_failure;

	if (req->flags &&
	    nla_put_u32(msg, NL80211_ATTR_SCAN_FLAGS, req->flags))
		goto nla_put_failure;

	info = rdev->int_scan_req ? &rdev->int_scan_req->info :
		&rdev->scan_req->info;
	if (info->scan_start_tsf &&
	    (nla_put_u64_64bit(msg, NL80211_ATTR_SCAN_START_TIME_TSF,
			       info->scan_start_tsf, NL80211_BSS_PAD) ||
	     nla_put(msg, NL80211_ATTR_SCAN_START_TIME_TSF_BSSID, ETH_ALEN,
		     info->tsf_bssid)))
		goto nla_put_failure;

	return 0;
 nla_put_failure:
	return -ENOBUFS;
}

static int nl80211_prep_scan_msg(struct sk_buff *msg,
				 struct cfg80211_registered_device *rdev,
				 struct wireless_dev *wdev,
				 u32 portid, u32 seq, int flags,
				 u32 cmd)
{
	void *hdr;

	hdr = nl80211hdr_put(msg, portid, seq, flags, cmd);
	if (!hdr)
		return -1;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    (wdev->netdev && nla_put_u32(msg, NL80211_ATTR_IFINDEX,
					 wdev->netdev->ifindex)) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD))
		goto nla_put_failure;

	/* ignore errors and send incomplete event anyway */
	nl80211_add_scan_req(msg, rdev);

	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int
nl80211_prep_sched_scan_msg(struct sk_buff *msg,
			    struct cfg80211_sched_scan_request *req, u32 cmd)
{
	void *hdr;

	hdr = nl80211hdr_put(msg, 0, 0, 0, cmd);
	if (!hdr)
		return -1;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY,
			wiphy_to_rdev(req->wiphy)->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, req->dev->ifindex) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_COOKIE, req->reqid,
			      NL80211_ATTR_PAD))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

void nl80211_send_scan_start(struct cfg80211_registered_device *rdev,
			     struct wireless_dev *wdev)
{
	struct sk_buff *msg;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	if (nl80211_prep_scan_msg(msg, rdev, wdev, 0, 0, 0,
				  NL80211_CMD_TRIGGER_SCAN) < 0) {
		nlmsg_free(msg);
		return;
	}

	//知会开启扫描
	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_SCAN, GFP_KERNEL);
}

struct sk_buff *nl80211_build_scan_msg(struct cfg80211_registered_device *rdev,
				       struct wireless_dev *wdev, bool aborted)
{
	struct sk_buff *msg;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return NULL;

	if (nl80211_prep_scan_msg(msg, rdev, wdev, 0, 0, 0,
				  aborted ? NL80211_CMD_SCAN_ABORTED :
					    NL80211_CMD_NEW_SCAN_RESULTS) < 0) {
		nlmsg_free(msg);
		return NULL;
	}

	return msg;
}

/* send message created by nl80211_build_scan_msg() */
void nl80211_send_scan_msg(struct cfg80211_registered_device *rdev,
			   struct sk_buff *msg)
{
	if (!msg)
		return;

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_SCAN, GFP_KERNEL);
}

void nl80211_send_sched_scan(struct cfg80211_sched_scan_request *req, u32 cmd)
{
	struct sk_buff *msg;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	if (nl80211_prep_sched_scan_msg(msg, req, cmd) < 0) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(req->wiphy), msg, 0,
				NL80211_MCGRP_SCAN, GFP_KERNEL);
}

static bool nl80211_reg_change_event_fill(struct sk_buff *msg,
					  struct regulatory_request *request)
{
	/* Userspace can always count this one always being set */
	if (nla_put_u8(msg, NL80211_ATTR_REG_INITIATOR, request->initiator))
		goto nla_put_failure;

	if (request->alpha2[0] == '0' && request->alpha2[1] == '0') {
		if (nla_put_u8(msg, NL80211_ATTR_REG_TYPE,
			       NL80211_REGDOM_TYPE_WORLD))
			goto nla_put_failure;
	} else if (request->alpha2[0] == '9' && request->alpha2[1] == '9') {
		if (nla_put_u8(msg, NL80211_ATTR_REG_TYPE,
			       NL80211_REGDOM_TYPE_CUSTOM_WORLD))
			goto nla_put_failure;
	} else if ((request->alpha2[0] == '9' && request->alpha2[1] == '8') ||
		   request->intersect) {
		if (nla_put_u8(msg, NL80211_ATTR_REG_TYPE,
			       NL80211_REGDOM_TYPE_INTERSECTION))
			goto nla_put_failure;
	} else {
		if (nla_put_u8(msg, NL80211_ATTR_REG_TYPE,
			       NL80211_REGDOM_TYPE_COUNTRY) ||
		    nla_put_string(msg, NL80211_ATTR_REG_ALPHA2,
				   request->alpha2))
			goto nla_put_failure;
	}

	if (request->wiphy_idx != WIPHY_IDX_INVALID) {
		struct wiphy *wiphy = wiphy_idx_to_wiphy(request->wiphy_idx);

		if (wiphy &&
		    nla_put_u32(msg, NL80211_ATTR_WIPHY, request->wiphy_idx))
			goto nla_put_failure;

		if (wiphy &&
		    wiphy->regulatory_flags & REGULATORY_WIPHY_SELF_MANAGED &&
		    nla_put_flag(msg, NL80211_ATTR_WIPHY_SELF_MANAGED_REG))
			goto nla_put_failure;
	}

	return true;

nla_put_failure:
	return false;
}

/*
 * This can happen on global regulatory changes or device specific settings
 * based on custom regulatory domains.
 */
void nl80211_common_reg_change_event(enum nl80211_commands cmd_id,
				     struct regulatory_request *request)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, cmd_id);
	if (!hdr)
		goto nla_put_failure;

	if (!nl80211_reg_change_event_fill(msg, request))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	rcu_read_lock();
	genlmsg_multicast_allns(&nl80211_fam, msg, 0,
				NL80211_MCGRP_REGULATORY, GFP_ATOMIC);
	rcu_read_unlock();

	return;

nla_put_failure:
	nlmsg_free(msg);
}

static void nl80211_send_mlme_event(struct cfg80211_registered_device *rdev,
				    struct net_device *netdev,
				    const u8 *buf, size_t len,
				    enum nl80211_commands cmd, gfp_t gfp,
				    int uapsd_queues, const u8 *req_ies,
				    size_t req_ies_len, bool reconnect)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(100 + len + req_ies_len, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_FRAME, len, buf) ||
	    (req_ies &&
	     nla_put(msg, NL80211_ATTR_REQ_IE, req_ies_len, req_ies)))
		goto nla_put_failure;

	if (reconnect && nla_put_flag(msg, NL80211_ATTR_RECONNECT_REQUESTED))
		goto nla_put_failure;

	if (uapsd_queues >= 0) {
		struct nlattr *nla_wmm =
			nla_nest_start_noflag(msg, NL80211_ATTR_STA_WME);
		if (!nla_wmm)
			goto nla_put_failure;

		if (nla_put_u8(msg, NL80211_STA_WME_UAPSD_QUEUES,
			       uapsd_queues))
			goto nla_put_failure;

		nla_nest_end(msg, nla_wmm);
	}

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_rx_auth(struct cfg80211_registered_device *rdev,
			  struct net_device *netdev, const u8 *buf,
			  size_t len, gfp_t gfp)
{
	nl80211_send_mlme_event(rdev, netdev, buf, len,
				NL80211_CMD_AUTHENTICATE, gfp, -1, NULL, 0,
				false);
}

void nl80211_send_rx_assoc(struct cfg80211_registered_device *rdev,
			   struct net_device *netdev, const u8 *buf,
			   size_t len, gfp_t gfp, int uapsd_queues,
			   const u8 *req_ies, size_t req_ies_len)
{
	nl80211_send_mlme_event(rdev, netdev, buf, len,
				NL80211_CMD_ASSOCIATE, gfp, uapsd_queues,
				req_ies, req_ies_len, false);
}

void nl80211_send_deauth(struct cfg80211_registered_device *rdev,
			 struct net_device *netdev, const u8 *buf,
			 size_t len, bool reconnect, gfp_t gfp)
{
	nl80211_send_mlme_event(rdev, netdev, buf, len,
				NL80211_CMD_DEAUTHENTICATE, gfp, -1, NULL, 0,
				reconnect);
}

void nl80211_send_disassoc(struct cfg80211_registered_device *rdev,
			   struct net_device *netdev, const u8 *buf,
			   size_t len, bool reconnect, gfp_t gfp)
{
	nl80211_send_mlme_event(rdev, netdev, buf, len,
				NL80211_CMD_DISASSOCIATE, gfp, -1, NULL, 0,
				reconnect);
}

void cfg80211_rx_unprot_mlme_mgmt(struct net_device *dev, const u8 *buf,
				  size_t len)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	const struct ieee80211_mgmt *mgmt = (void *)buf;
	u32 cmd;

	if (WARN_ON(len < 2))
		return;

	if (ieee80211_is_deauth(mgmt->frame_control)) {
		cmd = NL80211_CMD_UNPROT_DEAUTHENTICATE;
	} else if (ieee80211_is_disassoc(mgmt->frame_control)) {
		cmd = NL80211_CMD_UNPROT_DISASSOCIATE;
	} else if (ieee80211_is_beacon(mgmt->frame_control)) {
		if (wdev->unprot_beacon_reported &&
		    elapsed_jiffies_msecs(wdev->unprot_beacon_reported) < 10000)
			return;
		cmd = NL80211_CMD_UNPROT_BEACON;
		wdev->unprot_beacon_reported = jiffies;
	} else {
		return;
	}

	trace_cfg80211_rx_unprot_mlme_mgmt(dev, buf, len);
	nl80211_send_mlme_event(rdev, dev, buf, len, cmd, GFP_ATOMIC, -1,
				NULL, 0, false);
}
EXPORT_SYMBOL(cfg80211_rx_unprot_mlme_mgmt);

static void nl80211_send_mlme_timeout(struct cfg80211_registered_device *rdev,
				      struct net_device *netdev, int cmd,
				      const u8 *addr, gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put_flag(msg, NL80211_ATTR_TIMED_OUT) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_auth_timeout(struct cfg80211_registered_device *rdev,
			       struct net_device *netdev, const u8 *addr,
			       gfp_t gfp)
{
	nl80211_send_mlme_timeout(rdev, netdev, NL80211_CMD_AUTHENTICATE,
				  addr, gfp);
}

void nl80211_send_assoc_timeout(struct cfg80211_registered_device *rdev,
				struct net_device *netdev, const u8 *addr,
				gfp_t gfp)
{
	nl80211_send_mlme_timeout(rdev, netdev, NL80211_CMD_ASSOCIATE,
				  addr, gfp);
}

void nl80211_send_connect_result(struct cfg80211_registered_device *rdev,
				 struct net_device *netdev,
				 struct cfg80211_connect_resp_params *cr,
				 gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(100 + cr->req_ie_len + cr->resp_ie_len +
			cr->fils.kek_len + cr->fils.pmk_len +
			(cr->fils.pmkid ? WLAN_PMKID_LEN : 0), gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_CONNECT);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    (cr->bssid &&
	     nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, cr->bssid)) ||
	    nla_put_u16(msg, NL80211_ATTR_STATUS_CODE,
			cr->status < 0 ? WLAN_STATUS_UNSPECIFIED_FAILURE :
			cr->status) ||
	    (cr->status < 0 &&
	     (nla_put_flag(msg, NL80211_ATTR_TIMED_OUT) ||
	      nla_put_u32(msg, NL80211_ATTR_TIMEOUT_REASON,
			  cr->timeout_reason))) ||
	    (cr->req_ie &&
	     nla_put(msg, NL80211_ATTR_REQ_IE, cr->req_ie_len, cr->req_ie)) ||
	    (cr->resp_ie &&
	     nla_put(msg, NL80211_ATTR_RESP_IE, cr->resp_ie_len,
		     cr->resp_ie)) ||
	    (cr->fils.update_erp_next_seq_num &&
	     nla_put_u16(msg, NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM,
			 cr->fils.erp_next_seq_num)) ||
	    (cr->status == WLAN_STATUS_SUCCESS &&
	     ((cr->fils.kek &&
	       nla_put(msg, NL80211_ATTR_FILS_KEK, cr->fils.kek_len,
		       cr->fils.kek)) ||
	      (cr->fils.pmk &&
	       nla_put(msg, NL80211_ATTR_PMK, cr->fils.pmk_len, cr->fils.pmk)) ||
	      (cr->fils.pmkid &&
	       nla_put(msg, NL80211_ATTR_PMKID, WLAN_PMKID_LEN, cr->fils.pmkid)))))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_roamed(struct cfg80211_registered_device *rdev,
			 struct net_device *netdev,
			 struct cfg80211_roam_info *info, gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;
	const u8 *bssid = info->bss ? info->bss->bssid : info->bssid;

	msg = nlmsg_new(100 + info->req_ie_len + info->resp_ie_len +
			info->fils.kek_len + info->fils.pmk_len +
			(info->fils.pmkid ? WLAN_PMKID_LEN : 0), gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_ROAM);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, bssid) ||
	    (info->req_ie &&
	     nla_put(msg, NL80211_ATTR_REQ_IE, info->req_ie_len,
		     info->req_ie)) ||
	    (info->resp_ie &&
	     nla_put(msg, NL80211_ATTR_RESP_IE, info->resp_ie_len,
		     info->resp_ie)) ||
	    (info->fils.update_erp_next_seq_num &&
	     nla_put_u16(msg, NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM,
			 info->fils.erp_next_seq_num)) ||
	    (info->fils.kek &&
	     nla_put(msg, NL80211_ATTR_FILS_KEK, info->fils.kek_len,
		     info->fils.kek)) ||
	    (info->fils.pmk &&
	     nla_put(msg, NL80211_ATTR_PMK, info->fils.pmk_len, info->fils.pmk)) ||
	    (info->fils.pmkid &&
	     nla_put(msg, NL80211_ATTR_PMKID, WLAN_PMKID_LEN, info->fils.pmkid)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_port_authorized(struct cfg80211_registered_device *rdev,
				  struct net_device *netdev, const u8 *bssid)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_PORT_AUTHORIZED);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, bssid))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, GFP_KERNEL);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_disconnected(struct cfg80211_registered_device *rdev,
			       struct net_device *netdev, u16 reason,
			       const u8 *ie, size_t ie_len, bool from_ap)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(100 + ie_len, GFP_KERNEL);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_DISCONNECT);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    (reason &&
	     nla_put_u16(msg, NL80211_ATTR_REASON_CODE, reason)) ||
	    (from_ap &&
	     nla_put_flag(msg, NL80211_ATTR_DISCONNECTED_BY_AP)) ||
	    (ie && nla_put(msg, NL80211_ATTR_IE, ie_len, ie)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, GFP_KERNEL);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_ibss_bssid(struct cfg80211_registered_device *rdev,
			     struct net_device *netdev, const u8 *bssid,
			     gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_JOIN_IBSS);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, bssid))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_notify_new_peer_candidate(struct net_device *dev, const u8 *addr,
					const u8 *ie, u8 ie_len,
					int sig_dbm, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg;
	void *hdr;

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_MESH_POINT))
		return;

	trace_cfg80211_notify_new_peer_candidate(dev, addr);

	msg = nlmsg_new(100 + ie_len, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_NEW_PEER_CANDIDATE);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) ||
	    (ie_len && ie &&
	     nla_put(msg, NL80211_ATTR_IE, ie_len, ie)) ||
	    (sig_dbm &&
	     nla_put_u32(msg, NL80211_ATTR_RX_SIGNAL_DBM, sig_dbm)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_notify_new_peer_candidate);

void nl80211_michael_mic_failure(struct cfg80211_registered_device *rdev,
				 struct net_device *netdev, const u8 *addr,
				 enum nl80211_key_type key_type, int key_id,
				 const u8 *tsc, gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_MICHAEL_MIC_FAILURE);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    (addr && nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr)) ||
	    nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, key_type) ||
	    (key_id != -1 &&
	     nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_id)) ||
	    (tsc && nla_put(msg, NL80211_ATTR_KEY_SEQ, 6, tsc)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void nl80211_send_beacon_hint_event(struct wiphy *wiphy,
				    struct ieee80211_channel *channel_before,
				    struct ieee80211_channel *channel_after)
{
	struct sk_buff *msg;
	void *hdr;
	struct nlattr *nl_freq;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_REG_BEACON_HINT);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	/*
	 * Since we are applying the beacon hint to a wiphy we know its
	 * wiphy_idx is valid
	 */
	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, get_wiphy_idx(wiphy)))
		goto nla_put_failure;

	/* Before */
	nl_freq = nla_nest_start_noflag(msg, NL80211_ATTR_FREQ_BEFORE);
	if (!nl_freq)
		goto nla_put_failure;

	if (nl80211_msg_put_channel(msg, wiphy, channel_before, false))
		goto nla_put_failure;
	nla_nest_end(msg, nl_freq);

	/* After */
	nl_freq = nla_nest_start_noflag(msg, NL80211_ATTR_FREQ_AFTER);
	if (!nl_freq)
		goto nla_put_failure;

	if (nl80211_msg_put_channel(msg, wiphy, channel_after, false))
		goto nla_put_failure;
	nla_nest_end(msg, nl_freq);

	genlmsg_end(msg, hdr);

	rcu_read_lock();
	genlmsg_multicast_allns(&nl80211_fam, msg, 0,
				NL80211_MCGRP_REGULATORY, GFP_ATOMIC);
	rcu_read_unlock();

	return;

nla_put_failure:
	nlmsg_free(msg);
}

static void nl80211_send_remain_on_chan_event(
	int cmd, struct cfg80211_registered_device *rdev,
	struct wireless_dev *wdev, u64 cookie,
	struct ieee80211_channel *chan,
	unsigned int duration, gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    (wdev->netdev && nla_put_u32(msg, NL80211_ATTR_IFINDEX,
					 wdev->netdev->ifindex)) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, chan->center_freq) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE,
			NL80211_CHAN_NO_HT) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_COOKIE, cookie,
			      NL80211_ATTR_PAD))
		goto nla_put_failure;

	if (cmd == NL80211_CMD_REMAIN_ON_CHANNEL &&
	    nla_put_u32(msg, NL80211_ATTR_DURATION, duration))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_ready_on_channel(struct wireless_dev *wdev, u64 cookie,
			       struct ieee80211_channel *chan,
			       unsigned int duration, gfp_t gfp)
{
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	trace_cfg80211_ready_on_channel(wdev, cookie, chan, duration);
	nl80211_send_remain_on_chan_event(NL80211_CMD_REMAIN_ON_CHANNEL,
					  rdev, wdev, cookie, chan,
					  duration, gfp);
}
EXPORT_SYMBOL(cfg80211_ready_on_channel);

void cfg80211_remain_on_channel_expired(struct wireless_dev *wdev, u64 cookie,
					struct ieee80211_channel *chan,
					gfp_t gfp)
{
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	trace_cfg80211_ready_on_channel_expired(wdev, cookie, chan);
	nl80211_send_remain_on_chan_event(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL,
					  rdev, wdev, cookie, chan, 0, gfp);
}
EXPORT_SYMBOL(cfg80211_remain_on_channel_expired);

void cfg80211_tx_mgmt_expired(struct wireless_dev *wdev, u64 cookie,
					struct ieee80211_channel *chan,
					gfp_t gfp)
{
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	trace_cfg80211_tx_mgmt_expired(wdev, cookie, chan);
	nl80211_send_remain_on_chan_event(NL80211_CMD_FRAME_WAIT_CANCEL,
					  rdev, wdev, cookie, chan, 0, gfp);
}
EXPORT_SYMBOL(cfg80211_tx_mgmt_expired);

void cfg80211_new_sta(struct net_device *dev, const u8 *mac_addr,
		      struct station_info *sinfo, gfp_t gfp)
{
	struct wiphy *wiphy = dev->ieee80211_ptr->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;

	trace_cfg80211_new_sta(dev, mac_addr, sinfo);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	if (nl80211_send_station(msg, NL80211_CMD_NEW_STATION, 0, 0, 0,
				 rdev, dev, mac_addr, sinfo) < 0) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
}
EXPORT_SYMBOL(cfg80211_new_sta);

void cfg80211_del_sta_sinfo(struct net_device *dev, const u8 *mac_addr,
			    struct station_info *sinfo, gfp_t gfp)
{
	struct wiphy *wiphy = dev->ieee80211_ptr->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;
	struct station_info empty_sinfo = {};

	if (!sinfo)
		sinfo = &empty_sinfo;

	trace_cfg80211_del_sta(dev, mac_addr);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg) {
		cfg80211_sinfo_release_content(sinfo);
		return;
	}

	if (nl80211_send_station(msg, NL80211_CMD_DEL_STATION, 0, 0, 0,
				 rdev, dev, mac_addr, sinfo) < 0) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
}
EXPORT_SYMBOL(cfg80211_del_sta_sinfo);

void cfg80211_conn_failed(struct net_device *dev, const u8 *mac_addr,
			  enum nl80211_connect_failed_reason reason,
			  gfp_t gfp)
{
	struct wiphy *wiphy = dev->ieee80211_ptr->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_GOODSIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_CONN_FAILED);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac_addr) ||
	    nla_put_u32(msg, NL80211_ATTR_CONN_FAILED_REASON, reason))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_conn_failed);

static bool __nl80211_unexpected_frame(struct net_device *dev, u8 cmd,
				       const u8 *addr, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg;
	void *hdr;
	u32 nlportid = READ_ONCE(wdev->ap_unexpected_nlportid);

	if (!nlportid)
		return false;

	msg = nlmsg_new(100, gfp);
	if (!msg)
		return true;

	hdr = nl80211hdr_put(msg, 0, 0, 0, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		return true;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	genlmsg_unicast(wiphy_net(&rdev->wiphy), msg, nlportid);
	return true;

 nla_put_failure:
	nlmsg_free(msg);
	return true;
}

bool cfg80211_rx_spurious_frame(struct net_device *dev,
				const u8 *addr, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	bool ret;

	trace_cfg80211_rx_spurious_frame(dev, addr);

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_AP &&
		    wdev->iftype != NL80211_IFTYPE_P2P_GO)) {
		trace_cfg80211_return_bool(false);
		return false;
	}
	ret = __nl80211_unexpected_frame(dev, NL80211_CMD_UNEXPECTED_FRAME,
					 addr, gfp);
	trace_cfg80211_return_bool(ret);
	return ret;
}
EXPORT_SYMBOL(cfg80211_rx_spurious_frame);

bool cfg80211_rx_unexpected_4addr_frame(struct net_device *dev,
					const u8 *addr, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	bool ret;

	trace_cfg80211_rx_unexpected_4addr_frame(dev, addr);

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_AP &&
		    wdev->iftype != NL80211_IFTYPE_P2P_GO &&
		    wdev->iftype != NL80211_IFTYPE_AP_VLAN)) {
		trace_cfg80211_return_bool(false);
		return false;
	}
	ret = __nl80211_unexpected_frame(dev,
					 NL80211_CMD_UNEXPECTED_4ADDR_FRAME,
					 addr, gfp);
	trace_cfg80211_return_bool(ret);
	return ret;
}
EXPORT_SYMBOL(cfg80211_rx_unexpected_4addr_frame);

int nl80211_send_mgmt(struct cfg80211_registered_device *rdev,
		      struct wireless_dev *wdev, u32 nlportid,
		      int freq, int sig_dbm,
		      const u8 *buf, size_t len, u32 flags, gfp_t gfp)
{
	struct net_device *netdev = wdev->netdev;
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(100 + len, gfp);
	if (!msg)
		return -ENOMEM;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_FRAME);
	if (!hdr) {
		nlmsg_free(msg);
		return -ENOMEM;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    (netdev && nla_put_u32(msg, NL80211_ATTR_IFINDEX,
					netdev->ifindex)) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, KHZ_TO_MHZ(freq)) ||
	    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ_OFFSET, freq % 1000) ||
	    (sig_dbm &&
	     nla_put_u32(msg, NL80211_ATTR_RX_SIGNAL_DBM, sig_dbm)) ||
	    nla_put(msg, NL80211_ATTR_FRAME, len, buf) ||
	    (flags &&
	     nla_put_u32(msg, NL80211_ATTR_RXMGMT_FLAGS, flags)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	return genlmsg_unicast(wiphy_net(&rdev->wiphy), msg, nlportid);

 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static void nl80211_frame_tx_status(struct wireless_dev *wdev, u64 cookie,
				    const u8 *buf, size_t len, bool ack,
				    gfp_t gfp, enum nl80211_commands command)
{
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct net_device *netdev = wdev->netdev;
	struct sk_buff *msg;
	void *hdr;

	if (command == NL80211_CMD_FRAME_TX_STATUS)
		trace_cfg80211_mgmt_tx_status(wdev, cookie, ack);
	else
		trace_cfg80211_control_port_tx_status(wdev, cookie, ack);

	msg = nlmsg_new(100 + len, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, command);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    (netdev && nla_put_u32(msg, NL80211_ATTR_IFINDEX,
				   netdev->ifindex)) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD) ||
	    nla_put(msg, NL80211_ATTR_FRAME, len, buf) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_COOKIE, cookie,
			      NL80211_ATTR_PAD) ||
	    (ack && nla_put_flag(msg, NL80211_ATTR_ACK)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_control_port_tx_status(struct wireless_dev *wdev, u64 cookie,
				     const u8 *buf, size_t len, bool ack,
				     gfp_t gfp)
{
	nl80211_frame_tx_status(wdev, cookie, buf, len, ack, gfp,
				NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS);
}
EXPORT_SYMBOL(cfg80211_control_port_tx_status);

void cfg80211_mgmt_tx_status(struct wireless_dev *wdev, u64 cookie,
			     const u8 *buf, size_t len, bool ack, gfp_t gfp)
{
	nl80211_frame_tx_status(wdev, cookie, buf, len, ack, gfp,
				NL80211_CMD_FRAME_TX_STATUS);
}
EXPORT_SYMBOL(cfg80211_mgmt_tx_status);

static int __nl80211_rx_control_port(struct net_device *dev,
				     struct sk_buff *skb,
				     bool unencrypted, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct ethhdr *ehdr = eth_hdr(skb);
	const u8 *addr = ehdr->h_source;
	u16 proto = be16_to_cpu(skb->protocol);
	struct sk_buff *msg;
	void *hdr;
	struct nlattr *frame;

	u32 nlportid = READ_ONCE(wdev->conn_owner_nlportid);

	if (!nlportid)
		return -ENOENT;

	msg = nlmsg_new(100 + skb->len, gfp);
	if (!msg)
		return -ENOMEM;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_CONTROL_PORT_FRAME);
	if (!hdr) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) ||
	    nla_put_u16(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, proto) ||
	    (unencrypted && nla_put_flag(msg,
					 NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT)))
		goto nla_put_failure;

	frame = nla_reserve(msg, NL80211_ATTR_FRAME, skb->len);
	if (!frame)
		goto nla_put_failure;

	skb_copy_bits(skb, 0, nla_data(frame), skb->len);
	genlmsg_end(msg, hdr);

	return genlmsg_unicast(wiphy_net(&rdev->wiphy), msg, nlportid);

 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

bool cfg80211_rx_control_port(struct net_device *dev,
			      struct sk_buff *skb, bool unencrypted)
{
	int ret;

	trace_cfg80211_rx_control_port(dev, skb, unencrypted);
	ret = __nl80211_rx_control_port(dev, skb, unencrypted, GFP_ATOMIC);
	trace_cfg80211_return_bool(ret == 0);
	return ret == 0;
}
EXPORT_SYMBOL(cfg80211_rx_control_port);

static struct sk_buff *cfg80211_prepare_cqm(struct net_device *dev,
					    const char *mac, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	void **cb;

	if (!msg)
		return NULL;

	cb = (void **)msg->cb;

	cb[0] = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_NOTIFY_CQM);
	if (!cb[0]) {
		nlmsg_free(msg);
		return NULL;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex))
		goto nla_put_failure;

	if (mac && nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac))
		goto nla_put_failure;

	cb[1] = nla_nest_start_noflag(msg, NL80211_ATTR_CQM);
	if (!cb[1])
		goto nla_put_failure;

	cb[2] = rdev;

	return msg;
 nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

static void cfg80211_send_cqm(struct sk_buff *msg, gfp_t gfp)
{
	void **cb = (void **)msg->cb;
	struct cfg80211_registered_device *rdev = cb[2];

	nla_nest_end(msg, cb[1]);
	genlmsg_end(msg, cb[0]);

	memset(msg->cb, 0, sizeof(msg->cb));

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
}

void cfg80211_cqm_rssi_notify(struct net_device *dev,
			      enum nl80211_cqm_rssi_threshold_event rssi_event,
			      s32 rssi_level, gfp_t gfp)
{
	struct sk_buff *msg;
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	trace_cfg80211_cqm_rssi_notify(dev, rssi_event, rssi_level);

	if (WARN_ON(rssi_event != NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW &&
		    rssi_event != NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH))
		return;

	if (wdev->cqm_config) {
		wdev->cqm_config->last_rssi_event_value = rssi_level;

		cfg80211_cqm_rssi_update(rdev, dev);

		if (rssi_level == 0)
			rssi_level = wdev->cqm_config->last_rssi_event_value;
	}

	msg = cfg80211_prepare_cqm(dev, NULL, gfp);
	if (!msg)
		return;

	if (nla_put_u32(msg, NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT,
			rssi_event))
		goto nla_put_failure;

	if (rssi_level && nla_put_s32(msg, NL80211_ATTR_CQM_RSSI_LEVEL,
				      rssi_level))
		goto nla_put_failure;

	cfg80211_send_cqm(msg, gfp);

	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_cqm_rssi_notify);

void cfg80211_cqm_txe_notify(struct net_device *dev,
			     const u8 *peer, u32 num_packets,
			     u32 rate, u32 intvl, gfp_t gfp)
{
	struct sk_buff *msg;

	msg = cfg80211_prepare_cqm(dev, peer, gfp);
	if (!msg)
		return;

	if (nla_put_u32(msg, NL80211_ATTR_CQM_TXE_PKTS, num_packets))
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_ATTR_CQM_TXE_RATE, rate))
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_ATTR_CQM_TXE_INTVL, intvl))
		goto nla_put_failure;

	cfg80211_send_cqm(msg, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_cqm_txe_notify);

void cfg80211_cqm_pktloss_notify(struct net_device *dev,
				 const u8 *peer, u32 num_packets, gfp_t gfp)
{
	struct sk_buff *msg;

	trace_cfg80211_cqm_pktloss_notify(dev, peer, num_packets);

	msg = cfg80211_prepare_cqm(dev, peer, gfp);
	if (!msg)
		return;

	if (nla_put_u32(msg, NL80211_ATTR_CQM_PKT_LOSS_EVENT, num_packets))
		goto nla_put_failure;

	cfg80211_send_cqm(msg, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_cqm_pktloss_notify);

void cfg80211_cqm_beacon_loss_notify(struct net_device *dev, gfp_t gfp)
{
	struct sk_buff *msg;

	msg = cfg80211_prepare_cqm(dev, NULL, gfp);
	if (!msg)
		return;

	if (nla_put_flag(msg, NL80211_ATTR_CQM_BEACON_LOSS_EVENT))
		goto nla_put_failure;

	cfg80211_send_cqm(msg, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_cqm_beacon_loss_notify);

static void nl80211_gtk_rekey_notify(struct cfg80211_registered_device *rdev,
				     struct net_device *netdev, const u8 *bssid,
				     const u8 *replay_ctr, gfp_t gfp)
{
	struct sk_buff *msg;
	struct nlattr *rekey_attr;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_SET_REKEY_OFFLOAD);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, bssid))
		goto nla_put_failure;

	rekey_attr = nla_nest_start_noflag(msg, NL80211_ATTR_REKEY_DATA);
	if (!rekey_attr)
		goto nla_put_failure;

	if (nla_put(msg, NL80211_REKEY_DATA_REPLAY_CTR,
		    NL80211_REPLAY_CTR_LEN, replay_ctr))
		goto nla_put_failure;

	nla_nest_end(msg, rekey_attr);

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_gtk_rekey_notify(struct net_device *dev, const u8 *bssid,
			       const u8 *replay_ctr, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	trace_cfg80211_gtk_rekey_notify(dev, bssid);
	nl80211_gtk_rekey_notify(rdev, dev, bssid, replay_ctr, gfp);
}
EXPORT_SYMBOL(cfg80211_gtk_rekey_notify);

static void
nl80211_pmksa_candidate_notify(struct cfg80211_registered_device *rdev,
			       struct net_device *netdev, int index,
			       const u8 *bssid, bool preauth, gfp_t gfp)
{
	struct sk_buff *msg;
	struct nlattr *attr;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_PMKSA_CANDIDATE);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex))
		goto nla_put_failure;

	attr = nla_nest_start_noflag(msg, NL80211_ATTR_PMKSA_CANDIDATE);
	if (!attr)
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_PMKSA_CANDIDATE_INDEX, index) ||
	    nla_put(msg, NL80211_PMKSA_CANDIDATE_BSSID, ETH_ALEN, bssid) ||
	    (preauth &&
	     nla_put_flag(msg, NL80211_PMKSA_CANDIDATE_PREAUTH)))
		goto nla_put_failure;

	nla_nest_end(msg, attr);

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_pmksa_candidate_notify(struct net_device *dev, int index,
				     const u8 *bssid, bool preauth, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	trace_cfg80211_pmksa_candidate_notify(dev, index, bssid, preauth);
	nl80211_pmksa_candidate_notify(rdev, dev, index, bssid, preauth, gfp);
}
EXPORT_SYMBOL(cfg80211_pmksa_candidate_notify);

static void nl80211_ch_switch_notify(struct cfg80211_registered_device *rdev,
				     struct net_device *netdev,
				     struct cfg80211_chan_def *chandef,
				     gfp_t gfp,
				     enum nl80211_commands notif,
				     u8 count, bool quiet)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, notif);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex))
		goto nla_put_failure;

	if (nl80211_send_chandef(msg, chandef))
		goto nla_put_failure;

	if (notif == NL80211_CMD_CH_SWITCH_STARTED_NOTIFY) {
		if (nla_put_u32(msg, NL80211_ATTR_CH_SWITCH_COUNT, count))
			goto nla_put_failure;
		if (quiet &&
		    nla_put_flag(msg, NL80211_ATTR_CH_SWITCH_BLOCK_TX))
			goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_ch_switch_notify(struct net_device *dev,
			       struct cfg80211_chan_def *chandef)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	ASSERT_WDEV_LOCK(wdev);

	trace_cfg80211_ch_switch_notify(dev, chandef);

	wdev->chandef = *chandef;
	wdev->preset_chandef = *chandef;

	if (wdev->iftype == NL80211_IFTYPE_STATION &&
	    !WARN_ON(!wdev->current_bss))
		cfg80211_update_assoc_bss_entry(wdev, chandef->chan);

	cfg80211_sched_dfs_chan_update(rdev);

	nl80211_ch_switch_notify(rdev, dev, chandef, GFP_KERNEL,
				 NL80211_CMD_CH_SWITCH_NOTIFY, 0, false);
}
EXPORT_SYMBOL(cfg80211_ch_switch_notify);

void cfg80211_ch_switch_started_notify(struct net_device *dev,
				       struct cfg80211_chan_def *chandef,
				       u8 count, bool quiet)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);

	trace_cfg80211_ch_switch_started_notify(dev, chandef);

	nl80211_ch_switch_notify(rdev, dev, chandef, GFP_KERNEL,
				 NL80211_CMD_CH_SWITCH_STARTED_NOTIFY,
				 count, quiet);
}
EXPORT_SYMBOL(cfg80211_ch_switch_started_notify);

void
nl80211_radar_notify(struct cfg80211_registered_device *rdev,
		     const struct cfg80211_chan_def *chandef,
		     enum nl80211_radar_event event,
		     struct net_device *netdev, gfp_t gfp)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_RADAR_DETECT);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx))
		goto nla_put_failure;

	/* NOP and radar events don't need a netdev parameter */
	if (netdev) {
		struct wireless_dev *wdev = netdev->ieee80211_ptr;

		if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
		    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
				      NL80211_ATTR_PAD))
			goto nla_put_failure;
	}

	if (nla_put_u32(msg, NL80211_ATTR_RADAR_EVENT, event))
		goto nla_put_failure;

	if (nl80211_send_chandef(msg, chandef))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}

void cfg80211_sta_opmode_change_notify(struct net_device *dev, const u8 *mac,
				       struct sta_opmode_info *sta_opmode,
				       gfp_t gfp)
{
	struct sk_buff *msg;
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	void *hdr;

	if (WARN_ON(!mac))
		return;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_STA_OPMODE_CHANGED);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx))
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex))
		goto nla_put_failure;

	if (nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac))
		goto nla_put_failure;

	if ((sta_opmode->changed & STA_OPMODE_SMPS_MODE_CHANGED) &&
	    nla_put_u8(msg, NL80211_ATTR_SMPS_MODE, sta_opmode->smps_mode))
		goto nla_put_failure;

	if ((sta_opmode->changed & STA_OPMODE_MAX_BW_CHANGED) &&
	    nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, sta_opmode->bw))
		goto nla_put_failure;

	if ((sta_opmode->changed & STA_OPMODE_N_SS_CHANGED) &&
	    nla_put_u8(msg, NL80211_ATTR_NSS, sta_opmode->rx_nss))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);

	return;

nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_sta_opmode_change_notify);

void cfg80211_probe_status(struct net_device *dev, const u8 *addr,
			   u64 cookie, bool acked, s32 ack_signal,
			   bool is_valid_ack_signal, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg;
	void *hdr;

	trace_cfg80211_probe_status(dev, addr, cookie, acked);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);

	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_PROBE_CLIENT);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_COOKIE, cookie,
			      NL80211_ATTR_PAD) ||
	    (acked && nla_put_flag(msg, NL80211_ATTR_ACK)) ||
	    (is_valid_ack_signal && nla_put_s32(msg, NL80211_ATTR_ACK_SIGNAL,
						ack_signal)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_probe_status);

void cfg80211_report_obss_beacon_khz(struct wiphy *wiphy, const u8 *frame,
				     size_t len, int freq, int sig_dbm)
{
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;
	void *hdr;
	struct cfg80211_beacon_registration *reg;

	trace_cfg80211_report_obss_beacon(wiphy, frame, len, freq, sig_dbm);

	spin_lock_bh(&rdev->beacon_registrations_lock);
	list_for_each_entry(reg, &rdev->beacon_registrations, list) {
		msg = nlmsg_new(len + 100, GFP_ATOMIC);
		if (!msg) {
			spin_unlock_bh(&rdev->beacon_registrations_lock);
			return;
		}

		hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_FRAME);
		if (!hdr)
			goto nla_put_failure;

		if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
		    (freq &&
		     (nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ,
				  KHZ_TO_MHZ(freq)) ||
		      nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ_OFFSET,
				  freq % 1000))) ||
		    (sig_dbm &&
		     nla_put_u32(msg, NL80211_ATTR_RX_SIGNAL_DBM, sig_dbm)) ||
		    nla_put(msg, NL80211_ATTR_FRAME, len, frame))
			goto nla_put_failure;

		genlmsg_end(msg, hdr);

		genlmsg_unicast(wiphy_net(&rdev->wiphy), msg, reg->nlportid);
	}
	spin_unlock_bh(&rdev->beacon_registrations_lock);
	return;

 nla_put_failure:
	spin_unlock_bh(&rdev->beacon_registrations_lock);
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_report_obss_beacon_khz);

#ifdef CONFIG_PM
static int cfg80211_net_detect_results(struct sk_buff *msg,
				       struct cfg80211_wowlan_wakeup *wakeup)
{
	struct cfg80211_wowlan_nd_info *nd = wakeup->net_detect;
	struct nlattr *nl_results, *nl_match, *nl_freqs;
	int i, j;

	nl_results = nla_nest_start_noflag(msg,
					   NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS);
	if (!nl_results)
		return -EMSGSIZE;

	for (i = 0; i < nd->n_matches; i++) {
		struct cfg80211_wowlan_nd_match *match = nd->matches[i];

		nl_match = nla_nest_start_noflag(msg, i);
		if (!nl_match)
			break;

		/* The SSID attribute is optional in nl80211, but for
		 * simplicity reasons it's always present in the
		 * cfg80211 structure.  If a driver can't pass the
		 * SSID, that needs to be changed.  A zero length SSID
		 * is still a valid SSID (wildcard), so it cannot be
		 * used for this purpose.
		 */
		if (nla_put(msg, NL80211_ATTR_SSID, match->ssid.ssid_len,
			    match->ssid.ssid)) {
			nla_nest_cancel(msg, nl_match);
			goto out;
		}

		if (match->n_channels) {
			nl_freqs = nla_nest_start_noflag(msg,
							 NL80211_ATTR_SCAN_FREQUENCIES);
			if (!nl_freqs) {
				nla_nest_cancel(msg, nl_match);
				goto out;
			}

			for (j = 0; j < match->n_channels; j++) {
				if (nla_put_u32(msg, j, match->channels[j])) {
					nla_nest_cancel(msg, nl_freqs);
					nla_nest_cancel(msg, nl_match);
					goto out;
				}
			}

			nla_nest_end(msg, nl_freqs);
		}

		nla_nest_end(msg, nl_match);
	}

out:
	nla_nest_end(msg, nl_results);
	return 0;
}

void cfg80211_report_wowlan_wakeup(struct wireless_dev *wdev,
				   struct cfg80211_wowlan_wakeup *wakeup,
				   gfp_t gfp)
{
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg;
	void *hdr;
	int size = 200;

	trace_cfg80211_report_wowlan_wakeup(wdev->wiphy, wdev, wakeup);

	if (wakeup)
		size += wakeup->packet_present_len;

	msg = nlmsg_new(size, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_SET_WOWLAN);
	if (!hdr)
		goto free_msg;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD))
		goto free_msg;

	if (wdev->netdev && nla_put_u32(msg, NL80211_ATTR_IFINDEX,
					wdev->netdev->ifindex))
		goto free_msg;

	if (wakeup) {
		struct nlattr *reasons;

		reasons = nla_nest_start_noflag(msg,
						NL80211_ATTR_WOWLAN_TRIGGERS);
		if (!reasons)
			goto free_msg;

		if (wakeup->disconnect &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_DISCONNECT))
			goto free_msg;
		if (wakeup->magic_pkt &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_MAGIC_PKT))
			goto free_msg;
		if (wakeup->gtk_rekey_failure &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE))
			goto free_msg;
		if (wakeup->eap_identity_req &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST))
			goto free_msg;
		if (wakeup->four_way_handshake &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE))
			goto free_msg;
		if (wakeup->rfkill_release &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_RFKILL_RELEASE))
			goto free_msg;

		if (wakeup->pattern_idx >= 0 &&
		    nla_put_u32(msg, NL80211_WOWLAN_TRIG_PKT_PATTERN,
				wakeup->pattern_idx))
			goto free_msg;

		if (wakeup->tcp_match &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH))
			goto free_msg;

		if (wakeup->tcp_connlost &&
		    nla_put_flag(msg, NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST))
			goto free_msg;

		if (wakeup->tcp_nomoretokens &&
		    nla_put_flag(msg,
				 NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS))
			goto free_msg;

		if (wakeup->packet) {
			u32 pkt_attr = NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211;
			u32 len_attr = NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN;

			if (!wakeup->packet_80211) {
				pkt_attr =
					NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023;
				len_attr =
					NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN;
			}

			if (wakeup->packet_len &&
			    nla_put_u32(msg, len_attr, wakeup->packet_len))
				goto free_msg;

			if (nla_put(msg, pkt_attr, wakeup->packet_present_len,
				    wakeup->packet))
				goto free_msg;
		}

		if (wakeup->net_detect &&
		    cfg80211_net_detect_results(msg, wakeup))
				goto free_msg;

		nla_nest_end(msg, reasons);
	}

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 free_msg:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_report_wowlan_wakeup);
#endif

void cfg80211_tdls_oper_request(struct net_device *dev, const u8 *peer,
				enum nl80211_tdls_operation oper,
				u16 reason_code, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg;
	void *hdr;

	trace_cfg80211_tdls_oper_request(wdev->wiphy, dev, peer, oper,
					 reason_code);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_TDLS_OPER);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put_u8(msg, NL80211_ATTR_TDLS_OPERATION, oper) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, peer) ||
	    (reason_code > 0 &&
	     nla_put_u16(msg, NL80211_ATTR_REASON_CODE, reason_code)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_tdls_oper_request);

static int nl80211_netlink_notify(struct notifier_block * nb,
				  unsigned long state,
				  void *_notify)
{
	struct netlink_notify *notify = _notify;
	struct cfg80211_registered_device *rdev;
	struct wireless_dev *wdev;
	struct cfg80211_beacon_registration *reg, *tmp;

	if (state != NETLINK_URELEASE || notify->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	rcu_read_lock();

	list_for_each_entry_rcu(rdev, &cfg80211_rdev_list, list) {
		struct cfg80211_sched_scan_request *sched_scan_req;

		list_for_each_entry_rcu(sched_scan_req,
					&rdev->sched_scan_req_list,
					list) {
			if (sched_scan_req->owner_nlportid == notify->portid) {
				sched_scan_req->nl_owner_dead = true;
				schedule_work(&rdev->sched_scan_stop_wk);
			}
		}

		list_for_each_entry_rcu(wdev, &rdev->wiphy.wdev_list, list) {
			cfg80211_mlme_unregister_socket(wdev, notify->portid);

			if (wdev->owner_nlportid == notify->portid) {
				wdev->nl_owner_dead = true;
				schedule_work(&rdev->destroy_work);
			} else if (wdev->conn_owner_nlportid == notify->portid) {
				schedule_work(&wdev->disconnect_wk);
			}

			cfg80211_release_pmsr(wdev, notify->portid);
		}

		spin_lock_bh(&rdev->beacon_registrations_lock);
		list_for_each_entry_safe(reg, tmp, &rdev->beacon_registrations,
					 list) {
			if (reg->nlportid == notify->portid) {
				list_del(&reg->list);
				kfree(reg);
				break;
			}
		}
		spin_unlock_bh(&rdev->beacon_registrations_lock);
	}

	rcu_read_unlock();

	/*
	 * It is possible that the user space process that is controlling the
	 * indoor setting disappeared, so notify the regulatory core.
	 */
	regulatory_netlink_notify(notify->portid);
	return NOTIFY_OK;
}

static struct notifier_block nl80211_netlink_notifier = {
	.notifier_call = nl80211_netlink_notify,
};

void cfg80211_ft_event(struct net_device *netdev,
		       struct cfg80211_ft_event_params *ft_event)
{
	struct wiphy *wiphy = netdev->ieee80211_ptr->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;
	void *hdr;

	trace_cfg80211_ft_event(wiphy, netdev, ft_event);

	if (!ft_event->target_ap)
		return;

	msg = nlmsg_new(100 + ft_event->ies_len + ft_event->ric_ies_len,
			GFP_KERNEL);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_FT_EVENT);
	if (!hdr)
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, ft_event->target_ap))
		goto out;

	if (ft_event->ies &&
	    nla_put(msg, NL80211_ATTR_IE, ft_event->ies_len, ft_event->ies))
		goto out;
	if (ft_event->ric_ies &&
	    nla_put(msg, NL80211_ATTR_IE_RIC, ft_event->ric_ies_len,
		    ft_event->ric_ies))
		goto out;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, GFP_KERNEL);
	return;
 out:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_ft_event);

void cfg80211_crit_proto_stopped(struct wireless_dev *wdev, gfp_t gfp)
{
	struct cfg80211_registered_device *rdev;
	struct sk_buff *msg;
	void *hdr;
	u32 nlportid;

	rdev = wiphy_to_rdev(wdev->wiphy);
	if (!rdev->crit_proto_nlportid)
		return;

	nlportid = rdev->crit_proto_nlportid;
	rdev->crit_proto_nlportid = 0;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_CRIT_PROTOCOL_STOP);
	if (!hdr)
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_unicast(wiphy_net(&rdev->wiphy), msg, nlportid);
	return;

 nla_put_failure:
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_crit_proto_stopped);

void nl80211_send_ap_stopped(struct wireless_dev *wdev)
{
	struct wiphy *wiphy = wdev->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_STOP_AP);
	if (!hdr)
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, wdev->netdev->ifindex) ||
	    nla_put_u64_64bit(msg, NL80211_ATTR_WDEV, wdev_id(wdev),
			      NL80211_ATTR_PAD))
		goto out;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(wiphy), msg, 0,
				NL80211_MCGRP_MLME, GFP_KERNEL);
	return;
 out:
	nlmsg_free(msg);
}

int cfg80211_external_auth_request(struct net_device *dev,
				   struct cfg80211_external_auth_params *params,
				   gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct sk_buff *msg;
	void *hdr;

	if (!wdev->conn_owner_nlportid)
		return -EINVAL;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return -ENOMEM;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_EXTERNAL_AUTH);
	if (!hdr)
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex) ||
	    nla_put_u32(msg, NL80211_ATTR_AKM_SUITES, params->key_mgmt_suite) ||
	    nla_put_u32(msg, NL80211_ATTR_EXTERNAL_AUTH_ACTION,
			params->action) ||
	    nla_put(msg, NL80211_ATTR_BSSID, ETH_ALEN, params->bssid) ||
	    nla_put(msg, NL80211_ATTR_SSID, params->ssid.ssid_len,
		    params->ssid.ssid))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	genlmsg_unicast(wiphy_net(&rdev->wiphy), msg,
			wdev->conn_owner_nlportid);
	return 0;

 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}
EXPORT_SYMBOL(cfg80211_external_auth_request);

void cfg80211_update_owe_info_event(struct net_device *netdev,
				    struct cfg80211_update_owe_info *owe_info,
				    gfp_t gfp)
{
	struct wiphy *wiphy = netdev->ieee80211_ptr->wiphy;
	struct cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct sk_buff *msg;
	void *hdr;

	trace_cfg80211_update_owe_info_event(wiphy, netdev, owe_info);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, gfp);
	if (!msg)
		return;

	hdr = nl80211hdr_put(msg, 0, 0, 0, NL80211_CMD_UPDATE_OWE_INFO);
	if (!hdr)
		goto nla_put_failure;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, rdev->wiphy_idx) ||
	    nla_put_u32(msg, NL80211_ATTR_IFINDEX, netdev->ifindex) ||
	    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, owe_info->peer))
		goto nla_put_failure;

	if (!owe_info->ie_len ||
	    nla_put(msg, NL80211_ATTR_IE, owe_info->ie_len, owe_info->ie))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&nl80211_fam, wiphy_net(&rdev->wiphy), msg, 0,
				NL80211_MCGRP_MLME, gfp);
	return;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
}
EXPORT_SYMBOL(cfg80211_update_owe_info_event);

/* initialisation/exit functions */

int __init nl80211_init(void)
{
	int err;

	/*注册80211 family*/
	err = genl_register_family(&nl80211_fam);
	if (err)
		return err;

	err = netlink_register_notifier(&nl80211_netlink_notifier);
	if (err)
		goto err_out;

	return 0;
 err_out:
	genl_unregister_family(&nl80211_fam);
	return err;
}

void nl80211_exit(void)
{
	netlink_unregister_notifier(&nl80211_netlink_notifier);
	genl_unregister_family(&nl80211_fam);
}
