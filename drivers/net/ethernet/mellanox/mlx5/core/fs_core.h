/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _MLX5_FS_CORE_
#define _MLX5_FS_CORE_

#include <linux/refcount.h>
#include <linux/mlx5/fs.h>
#include <linux/rhashtable.h>
#include <linux/llist.h>
#include <steering/fs_dr.h>

struct mlx5_modify_hdr {
	enum mlx5_flow_namespace_type ns_type;
	union {
		struct mlx5_fs_dr_action action;
		u32 id;
	};
};

struct mlx5_pkt_reformat {
	enum mlx5_flow_namespace_type ns_type;
	int reformat_type; /* from mlx5_ifc */
	union {
		struct mlx5_fs_dr_action action;
		u32 id;
	};
};

/* FS_TYPE_PRIO_CHAINS is a PRIO that will have namespaces only,
 * and those are in parallel to one another when going over them to connect
 * a new flow table. Meaning the last flow table in a TYPE_PRIO prio in one
 * parallel namespace will not automatically connect to the first flow table
 * found in any prio in any next namespace, but skip the entire containing
 * TYPE_PRIO_CHAINS prio.
 *
 * This is used to implement tc chains, each chain of prios is a different
 * namespace inside a containing TYPE_PRIO_CHAINS prio.
 */

enum fs_node_type {
	FS_TYPE_NAMESPACE,
	FS_TYPE_PRIO,
	FS_TYPE_PRIO_CHAINS,
	FS_TYPE_FLOW_TABLE,
	FS_TYPE_FLOW_GROUP,//flow group表
	FS_TYPE_FLOW_ENTRY,//flow表项
	FS_TYPE_FLOW_DEST//flow的目的地
};

enum fs_flow_table_type {
	FS_FT_NIC_RX          = 0x0,
	FS_FT_NIC_TX          = 0x1,
	FS_FT_ESW_EGRESS_ACL  = 0x2,
	FS_FT_ESW_INGRESS_ACL = 0x3,
	FS_FT_FDB             = 0X4,
	FS_FT_SNIFFER_RX	= 0X5,
	FS_FT_SNIFFER_TX	= 0X6,
	FS_FT_RDMA_RX		= 0X7,
	FS_FT_RDMA_TX		= 0X8,
	FS_FT_MAX_TYPE = FS_FT_RDMA_TX,
};

enum fs_flow_table_op_mod {
	FS_FT_OP_MOD_NORMAL,
	FS_FT_OP_MOD_LAG_DEMUX,
};

enum fs_fte_status {
	FS_FTE_STATUS_EXISTING = 1UL << 0,
};

enum mlx5_flow_steering_mode {
	MLX5_FLOW_STEERING_MODE_DMFS,
	MLX5_FLOW_STEERING_MODE_SMFS
};

struct mlx5_flow_steering {
	struct mlx5_core_dev *dev;
	enum   mlx5_flow_steering_mode	mode;
	//用于申请flow group
	struct kmem_cache		*fgs_cache;
	//用于申请flow table entry
	struct kmem_cache               *ftes_cache;
	struct mlx5_flow_root_namespace *root_ns;
	//fdb对应的root_ns
	struct mlx5_flow_root_namespace *fdb_root_ns;
	struct mlx5_flow_namespace	**fdb_sub_ns;
	//针对每个vport有一个egress_root_ns
	struct mlx5_flow_root_namespace **esw_egress_root_ns;
	//针对每个vport有一个ingress_root_ns
	struct mlx5_flow_root_namespace **esw_ingress_root_ns;
	struct mlx5_flow_root_namespace	*sniffer_tx_root_ns;
	struct mlx5_flow_root_namespace	*sniffer_rx_root_ns;
	struct mlx5_flow_root_namespace	*rdma_rx_root_ns;
	struct mlx5_flow_root_namespace	*rdma_tx_root_ns;
	struct mlx5_flow_root_namespace	*egress_root_ns;
};

struct fs_node {
	struct list_head	list;
	//指向子节点
	struct list_head	children;
	enum fs_node_type	type;//node类型(例如FS_TYPE_FLOW_GROUP，FS_TYPE_FLOW_ENTRY）
	struct fs_node		*parent;//node的父节接，例如fte的parent为flow group
	struct fs_node		*root;
	/* lock the node for writing and traversing */
	struct rw_semaphore	lock;
	refcount_t		refcount;
	bool			active;/*标明此节点已在fw中创建*/
	//fs_node在移除时需要执行硬件fw删除回调
	void			(*del_hw_func)(struct fs_node *);
	//fs_node在移除时需要执行软件删除回调
	void			(*del_sw_func)(struct fs_node *);
	atomic_t		version;
};

struct mlx5_flow_rule {
	struct fs_node				node;
	struct mlx5_flow_table			*ft;
	struct mlx5_flow_destination		dest_attr;
	/* next_ft should be accessed under chain_lock and only of
	 * destination type is FWD_NEXT_fT.
	 */
	struct list_head			next_ft;
	u32					sw_action;
};

struct mlx5_flow_handle {
	int num_rules;//rule数组大小
	struct mlx5_flow_rule *rule[];/*记录目标*/
};

/* Type of children is mlx5_flow_group */
struct mlx5_flow_table {
	struct fs_node			node;
	struct mlx5_fs_dr_table		fs_dr_table;
	//表号，用于指代
	u32				id;
	u16				vport;
	//支持的fte最大数
	unsigned int			max_fte;
	//flow table的level,flow table会被组织成层次式
	unsigned int			level;
	//table类型
	enum fs_flow_table_type		type;
	enum fs_flow_table_op_mod	op_mod;
	struct {
		bool			active;
		unsigned int		required_groups;
		unsigned int		group_size;
		unsigned int		num_groups;
		unsigned int		max_fte;//支持的最大fte数目
	} autogroup;
	/* Protect fwd_rules */
	struct mutex			lock;
	/* FWD rules that point on this flow table */
	struct list_head		fwd_rules;
	u32				flags;
	//hashtable 用于存储属于此flow table的flow groups
	struct rhltable			fgs_hash;//以掩码做为key
	enum mlx5_flow_table_miss_action def_miss_action;
	struct mlx5_flow_namespace	*ns;
};

struct mlx5_ft_underlay_qp {
	struct list_head list;
	u32 qpn;
};

#define MLX5_FTE_MATCH_PARAM_RESERVED	reserved_at_a00
/* Calculate the fte_match_param length and without the reserved length.
 * Make sure the reserved field is the last.
 */
#define MLX5_ST_SZ_DW_MATCH_PARAM					    \
	/*取MLX5_FTE_MATCH_PARAM_RESERVED成员起始offset*/\
	((MLX5_BYTE_OFF(fte_match_param, MLX5_FTE_MATCH_PARAM_RESERVED) / sizeof(u32)) + \
			/*编译时校验*/\
	 BUILD_BUG_ON_ZERO(MLX5_ST_SZ_BYTES(fte_match_param) !=		     \
			   MLX5_FLD_SZ_BYTES(fte_match_param,		     \
					     MLX5_FTE_MATCH_PARAM_RESERVED) +\
			   MLX5_BYTE_OFF(fte_match_param,		     \
					 MLX5_FTE_MATCH_PARAM_RESERVED)))

/* Type of children is mlx5_flow_rule */
struct fs_fte {
	struct fs_node			node;
	struct mlx5_fs_dr_rule		fs_dr_rule;
	//匹配字段信息（掩码信息由从属的flow group提供）
	u32				val[MLX5_ST_SZ_DW_MATCH_PARAM];
	u32				dests_size;/*此fte目标的数目*/
	//索引号（=id+group->start_index)
	u32				index;
	struct mlx5_flow_context	flow_context;
	//flow table entry的对应的动作
	struct mlx5_flow_act		action;
	enum fs_fte_status		status;
	struct mlx5_fc			*counter;
	//挂接至hashtable
	struct rhash_head		hash;
	int				modify_mask;
};

/* Type of children is mlx5_flow_table/namespace */
struct fs_prio {
	struct fs_node			node;
	unsigned int			num_levels;
	unsigned int			start_level;
	unsigned int			prio;
	unsigned int			num_ft;
};

/* Type of children is fs_prio */
struct mlx5_flow_namespace {
	/* parent == NULL => root ns */
	struct	fs_node			node;
	enum mlx5_flow_table_miss_action def_miss_action;
};

struct mlx5_flow_group_mask {
	u8	match_criteria_enable;
	//flow group下统一的掩码
	u32	match_criteria[MLX5_ST_SZ_DW_MATCH_PARAM];
};

/* Type of children is fs_fte */
//用于抽象mask(同一类mask的处于同一个flow group)
struct mlx5_flow_group {
	struct fs_node			node;
	struct mlx5_fs_dr_matcher	fs_dr_matcher;
	//flow group对应的mask
	struct mlx5_flow_group_mask	mask;
	//flow group中最小的index编号
	u32				start_index;
	//flow group中支持的最大fte数目
	u32				max_ftes;
	//负责此flow group中的fte id分配(范围0到max_ftes，fte->index值为start+此id而来)
	struct ida			fte_allocator;
	//flow group对应的id(由fw提供）
	u32				id;
	//hahstable记录此flow group下的所有fte
	struct rhashtable		ftes_hash;
	//hash节点，用于串到hashtable->fgs_hash上
	struct rhlist_head		hash;
};

struct mlx5_flow_root_namespace {
	struct mlx5_flow_namespace	ns;
	enum   mlx5_flow_steering_mode	mode;
	struct mlx5_fs_dr_domain	fs_dr_domain;
	//表类型
	enum   fs_flow_table_type	table_type;
	struct mlx5_core_dev		*dev;
	struct mlx5_flow_table		*root_ft;
	/* Should be held when chaining flow tables */
	struct mutex			chain_lock;
	struct list_head		underlay_qpns;
	//此table_type对应的flow_cmds
	const struct mlx5_flow_cmds	*cmds;
};

int mlx5_init_fc_stats(struct mlx5_core_dev *dev);
void mlx5_cleanup_fc_stats(struct mlx5_core_dev *dev);
void mlx5_fc_queue_stats_work(struct mlx5_core_dev *dev,
			      struct delayed_work *dwork,
			      unsigned long delay);
void mlx5_fc_update_sampling_interval(struct mlx5_core_dev *dev,
				      unsigned long interval);

const struct mlx5_flow_cmds *mlx5_fs_cmd_get_fw_cmds(void);

int mlx5_flow_namespace_set_peer(struct mlx5_flow_root_namespace *ns,
				 struct mlx5_flow_root_namespace *peer_ns);

int mlx5_flow_namespace_set_mode(struct mlx5_flow_namespace *ns,
				 enum mlx5_flow_steering_mode mode);

int mlx5_init_fs(struct mlx5_core_dev *dev);
void mlx5_cleanup_fs(struct mlx5_core_dev *dev);

//将_node转换为typeof(*v)类型并返回 “_node为typeof(*v)中的node成员”
#define fs_get_obj(v, _node)  {v = container_of((_node), typeof(*v), node); }

#define fs_list_for_each_entry(pos, root)		\
	list_for_each_entry(pos, root, node.list)

#define fs_list_for_each_entry_safe(pos, tmp, root)		\
	list_for_each_entry_safe(pos, tmp, root, node.list)

#define fs_for_each_ns_or_ft_reverse(pos, prio)				\
	list_for_each_entry_reverse(pos, &(prio)->node.children, list)

#define fs_for_each_ns_or_ft(pos, prio)					\
	list_for_each_entry(pos, (&(prio)->node.children), list)

#define fs_for_each_prio(pos, ns)			\
	fs_list_for_each_entry(pos, &(ns)->node.children)

#define fs_for_each_ns(pos, prio)			\
	fs_list_for_each_entry(pos, &(prio)->node.children)

#define fs_for_each_ft(pos, prio)			\
	fs_list_for_each_entry(pos, &(prio)->node.children)

#define fs_for_each_ft_safe(pos, tmp, prio)			\
	fs_list_for_each_entry_safe(pos, tmp, &(prio)->node.children)

//遍历flowtable中所有flowgroup
#define fs_for_each_fg(pos, ft)			\
	fs_list_for_each_entry(pos, &(ft)->node.children)

#define fs_for_each_fte(pos, fg)			\
	fs_list_for_each_entry(pos, &(fg)->node.children)

#define fs_for_each_dst(pos, fte)			\
	fs_list_for_each_entry(pos, &(fte)->node.children)

#define MLX5_CAP_FLOWTABLE_TYPE(mdev, cap, type) (		\
	(type == FS_FT_NIC_RX) ? MLX5_CAP_FLOWTABLE_NIC_RX(mdev, cap) :		\
	(type == FS_FT_ESW_EGRESS_ACL) ? MLX5_CAP_ESW_EGRESS_ACL(mdev, cap) :		\
	(type == FS_FT_ESW_INGRESS_ACL) ? MLX5_CAP_ESW_INGRESS_ACL(mdev, cap) :		\
	(type == FS_FT_FDB) ? MLX5_CAP_ESW_FLOWTABLE_FDB(mdev, cap) :		\
	(type == FS_FT_SNIFFER_RX) ? MLX5_CAP_FLOWTABLE_SNIFFER_RX(mdev, cap) :		\
	(type == FS_FT_SNIFFER_TX) ? MLX5_CAP_FLOWTABLE_SNIFFER_TX(mdev, cap) :		\
	(type == FS_FT_RDMA_RX) ? MLX5_CAP_FLOWTABLE_RDMA_RX(mdev, cap) :		\
	(type == FS_FT_RDMA_TX) ? MLX5_CAP_FLOWTABLE_RDMA_TX(mdev, cap) :      \
	(BUILD_BUG_ON_ZERO(FS_FT_RDMA_TX != FS_FT_MAX_TYPE))\
	)

#endif
