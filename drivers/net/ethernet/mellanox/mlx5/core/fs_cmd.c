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

#include <linux/mlx5/driver.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/mlx5_ifc.h>

#include "fs_core.h"
#include "fs_cmd.h"
#include "mlx5_core.h"
#include "eswitch.h"

static int mlx5_cmd_stub_update_root_ft(struct mlx5_flow_root_namespace *ns,
					struct mlx5_flow_table *ft,
					u32 underlay_qpn,
					bool disconnect)
{
	return 0;
}

static int mlx5_cmd_stub_create_flow_table(struct mlx5_flow_root_namespace *ns,
					   struct mlx5_flow_table *ft,
					   unsigned int log_size,
					   struct mlx5_flow_table *next_ft)
{
	return 0;
}

static int mlx5_cmd_stub_destroy_flow_table(struct mlx5_flow_root_namespace *ns,
					    struct mlx5_flow_table *ft)
{
	return 0;
}

static int mlx5_cmd_stub_modify_flow_table(struct mlx5_flow_root_namespace *ns,
					   struct mlx5_flow_table *ft,
					   struct mlx5_flow_table *next_ft)
{
	return 0;
}

static int mlx5_cmd_stub_create_flow_group(struct mlx5_flow_root_namespace *ns,
					   struct mlx5_flow_table *ft,
					   u32 *in,
					   struct mlx5_flow_group *fg)
{
	return 0;
}

static int mlx5_cmd_stub_destroy_flow_group(struct mlx5_flow_root_namespace *ns,
					    struct mlx5_flow_table *ft,
					    struct mlx5_flow_group *fg)
{
	return 0;
}

static int mlx5_cmd_stub_create_fte(struct mlx5_flow_root_namespace *ns,
				    struct mlx5_flow_table *ft,
				    struct mlx5_flow_group *group,
				    struct fs_fte *fte)
{
	return 0;
}

static int mlx5_cmd_stub_update_fte(struct mlx5_flow_root_namespace *ns,
				    struct mlx5_flow_table *ft,
				    struct mlx5_flow_group *group,
				    int modify_mask,
				    struct fs_fte *fte)
{
	return -EOPNOTSUPP;
}

static int mlx5_cmd_stub_delete_fte(struct mlx5_flow_root_namespace *ns,
				    struct mlx5_flow_table *ft,
				    struct fs_fte *fte)
{
	return 0;
}

static int mlx5_cmd_stub_packet_reformat_alloc(struct mlx5_flow_root_namespace *ns,
					       int reformat_type,
					       size_t size,
					       void *reformat_data,
					       enum mlx5_flow_namespace_type namespace,
					       struct mlx5_pkt_reformat *pkt_reformat)
{
	return 0;
}

static void mlx5_cmd_stub_packet_reformat_dealloc(struct mlx5_flow_root_namespace *ns,
						  struct mlx5_pkt_reformat *pkt_reformat)
{
}

static int mlx5_cmd_stub_modify_header_alloc(struct mlx5_flow_root_namespace *ns,
					     u8 namespace, u8 num_actions,
					     void *modify_actions,
					     struct mlx5_modify_hdr *modify_hdr)
{
	return 0;
}

static void mlx5_cmd_stub_modify_header_dealloc(struct mlx5_flow_root_namespace *ns,
						struct mlx5_modify_hdr *modify_hdr)
{
}

static int mlx5_cmd_stub_set_peer(struct mlx5_flow_root_namespace *ns,
				  struct mlx5_flow_root_namespace *peer_ns)
{
	return 0;
}

static int mlx5_cmd_stub_create_ns(struct mlx5_flow_root_namespace *ns)
{
	return 0;
}

static int mlx5_cmd_stub_destroy_ns(struct mlx5_flow_root_namespace *ns)
{
	return 0;
}

static int mlx5_cmd_update_root_ft(struct mlx5_flow_root_namespace *ns,
				   struct mlx5_flow_table *ft, u32 underlay_qpn,
				   bool disconnect)
{
	u32 in[MLX5_ST_SZ_DW(set_flow_table_root_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	if ((MLX5_CAP_GEN(dev, port_type) == MLX5_CAP_PORT_TYPE_IB) &&
	    underlay_qpn == 0)
		return 0;

	MLX5_SET(set_flow_table_root_in, in, opcode,
		 MLX5_CMD_OP_SET_FLOW_TABLE_ROOT);
	MLX5_SET(set_flow_table_root_in, in, table_type, ft->type);

	if (disconnect)
		MLX5_SET(set_flow_table_root_in, in, op_mod, 1);
	else
		MLX5_SET(set_flow_table_root_in, in, table_id, ft->id);

	MLX5_SET(set_flow_table_root_in, in, underlay_qpn, underlay_qpn);
	if (ft->vport) {
		MLX5_SET(set_flow_table_root_in, in, vport_number, ft->vport);
		MLX5_SET(set_flow_table_root_in, in, other_vport, 1);
	}

	return mlx5_cmd_exec_in(dev, set_flow_table_root, in);
}

static int mlx5_cmd_create_flow_table(struct mlx5_flow_root_namespace *ns,
				      struct mlx5_flow_table *ft,
				      unsigned int log_size,
					  /*如果非0,则ft表失配后，此表匹配，为0，则前往默认表项匹配*/
				      struct mlx5_flow_table *next_ft)
{
	int en_encap = !!(ft->flags & MLX5_FLOW_TABLE_TUNNEL_EN_REFORMAT);
	int en_decap = !!(ft->flags & MLX5_FLOW_TABLE_TUNNEL_EN_DECAP);
	int term = !!(ft->flags & MLX5_FLOW_TABLE_TERMINATION);
	u32 out[MLX5_ST_SZ_DW(create_flow_table_out)] = {};
	u32 in[MLX5_ST_SZ_DW(create_flow_table_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;
	int err;

	//请求firmware创建一个新的flow table,它会返回一个handle，用于将来操作这个flow table
	MLX5_SET(create_flow_table_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_TABLE);

	//table在转发中的角色，目前有0 NIC_RX 1 NIC_TX,4 Eswitch_fdb等
	MLX5_SET(create_flow_table_in, in, table_type, ft->type);
	MLX5_SET(create_flow_table_in, in, flow_table_context.level, ft->level);
	MLX5_SET(create_flow_table_in, in, flow_table_context.log_size, log_size);
	if (ft->vport) {
		MLX5_SET(create_flow_table_in, in, vport_number, ft->vport);
		MLX5_SET(create_flow_table_in, in, other_vport, 1);
	}

	MLX5_SET(create_flow_table_in, in, flow_table_context.decap_en,
		 en_decap);
	MLX5_SET(create_flow_table_in, in, flow_table_context.reformat_en,
		 en_encap);
	MLX5_SET(create_flow_table_in, in, flow_table_context.termination_table,
		 term);

	switch (ft->op_mod) {
	case FS_FT_OP_MOD_NORMAL:
		if (next_ft) {
			//指定table miss后行为，1：跳载到指定的表执行匹配,见miss_table_id
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.table_miss_action,
				 MLX5_FLOW_TABLE_MISS_ACTION_FWD);
			//设置表项失配后，需要匹配的table
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.table_miss_id, next_ft->id);
		} else {
			//如果表项失配，前往default表进行匹配
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.table_miss_action,
				 ft->def_miss_action);
		}
		break;

	case FS_FT_OP_MOD_LAG_DEMUX:
		MLX5_SET(create_flow_table_in, in, op_mod, 0x1);
		if (next_ft)
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.lag_master_next_table_id,
				 next_ft->id);
		break;
	}

	err = mlx5_cmd_exec_inout(dev, create_flow_table, in, out);
	if (!err)
		ft->id = MLX5_GET(create_flow_table_out, out,
				  table_id);
	return err;
}

static int mlx5_cmd_destroy_flow_table(struct mlx5_flow_root_namespace *ns,
				       struct mlx5_flow_table *ft)
{
	u32 in[MLX5_ST_SZ_DW(destroy_flow_table_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	MLX5_SET(destroy_flow_table_in, in, opcode,
		 MLX5_CMD_OP_DESTROY_FLOW_TABLE);
	MLX5_SET(destroy_flow_table_in, in, table_type, ft->type);
	MLX5_SET(destroy_flow_table_in, in, table_id, ft->id);
	if (ft->vport) {
		MLX5_SET(destroy_flow_table_in, in, vport_number, ft->vport);
		MLX5_SET(destroy_flow_table_in, in, other_vport, 1);
	}

	return mlx5_cmd_exec_in(dev, destroy_flow_table, in);
}

static int mlx5_cmd_modify_flow_table(struct mlx5_flow_root_namespace *ns,
				      struct mlx5_flow_table *ft,
				      struct mlx5_flow_table *next_ft)
{
	u32 in[MLX5_ST_SZ_DW(modify_flow_table_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	MLX5_SET(modify_flow_table_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_FLOW_TABLE);
	MLX5_SET(modify_flow_table_in, in, table_type, ft->type);
	MLX5_SET(modify_flow_table_in, in, table_id, ft->id);

	if (ft->op_mod == FS_FT_OP_MOD_LAG_DEMUX) {
		MLX5_SET(modify_flow_table_in, in, modify_field_select,
			 MLX5_MODIFY_FLOW_TABLE_LAG_NEXT_TABLE_ID);
		if (next_ft) {
			MLX5_SET(modify_flow_table_in, in,
				 flow_table_context.lag_master_next_table_id, next_ft->id);
		} else {
			MLX5_SET(modify_flow_table_in, in,
				 flow_table_context.lag_master_next_table_id, 0);
		}
	} else {
		if (ft->vport) {
			MLX5_SET(modify_flow_table_in, in, vport_number,
				 ft->vport);
			MLX5_SET(modify_flow_table_in, in, other_vport, 1);
		}
		MLX5_SET(modify_flow_table_in, in, modify_field_select,
			 MLX5_MODIFY_FLOW_TABLE_MISS_TABLE_ID);
		if (next_ft) {
			MLX5_SET(modify_flow_table_in, in,
				 flow_table_context.table_miss_action,
				 MLX5_FLOW_TABLE_MISS_ACTION_FWD);
			MLX5_SET(modify_flow_table_in, in,
				 flow_table_context.table_miss_id,
				 next_ft->id);
		} else {
			MLX5_SET(modify_flow_table_in, in,
				 flow_table_context.table_miss_action,
				 ft->def_miss_action);
		}
	}

	return mlx5_cmd_exec_in(dev, modify_flow_table, in);
}

//告知fw创建新的flow group
static int mlx5_cmd_create_flow_group(struct mlx5_flow_root_namespace *ns,
				      struct mlx5_flow_table *ft,
				      u32 *in,
				      struct mlx5_flow_group *fg)
{
	u32 out[MLX5_ST_SZ_DW(create_flow_group_out)] = {};
	struct mlx5_core_dev *dev = ns->dev;
	int err;

	MLX5_SET(create_flow_group_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_GROUP);
	MLX5_SET(create_flow_group_in, in, table_type, ft->type);
	MLX5_SET(create_flow_group_in, in, table_id, ft->id);
	if (ft->vport) {
		//other_vport为1时，需要通过vport_number访问另一个vport
		MLX5_SET(create_flow_group_in, in, vport_number, ft->vport);
		MLX5_SET(create_flow_group_in, in, other_vport, 1);
	}

	err = mlx5_cmd_exec_inout(dev, create_flow_group, in, out);
	if (!err)
		fg->id = MLX5_GET(create_flow_group_out, out,
				  group_id);
	return err;
}

static int mlx5_cmd_destroy_flow_group(struct mlx5_flow_root_namespace *ns,
				       struct mlx5_flow_table *ft,
				       struct mlx5_flow_group *fg)
{
	u32 in[MLX5_ST_SZ_DW(destroy_flow_group_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	MLX5_SET(destroy_flow_group_in, in, opcode,
		 MLX5_CMD_OP_DESTROY_FLOW_GROUP);
	MLX5_SET(destroy_flow_group_in, in, table_type, ft->type);
	MLX5_SET(destroy_flow_group_in, in, table_id, ft->id);
	MLX5_SET(destroy_flow_group_in, in, group_id, fg->id);
	if (ft->vport) {
		MLX5_SET(destroy_flow_group_in, in, vport_number, ft->vport);
		MLX5_SET(destroy_flow_group_in, in, other_vport, 1);
	}

	return mlx5_cmd_exec_in(dev, destroy_flow_group, in);
}

static int mlx5_set_extended_dest(struct mlx5_core_dev *dev,
				  struct fs_fte *fte, bool *extended_dest)
{
	int fw_log_max_fdb_encap_uplink =
		MLX5_CAP_ESW(dev, log_max_fdb_encap_uplink);
	int num_fwd_destinations = 0;
	struct mlx5_flow_rule *dst;
	int num_encap = 0;

	*extended_dest = false;
	if (!(fte->action.action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST))
		return 0;

	list_for_each_entry(dst, &fte->node.children, node.list) {
		if (dst->dest_attr.type == MLX5_FLOW_DESTINATION_TYPE_COUNTER)
			continue;
		if (dst->dest_attr.type == MLX5_FLOW_DESTINATION_TYPE_VPORT &&
		    dst->dest_attr.vport.flags & MLX5_FLOW_DEST_VPORT_REFORMAT_ID)
			num_encap++;
		num_fwd_destinations++;
	}
	if (num_fwd_destinations > 1 && num_encap > 0)
		*extended_dest = true;

	if (*extended_dest && !fw_log_max_fdb_encap_uplink) {
		mlx5_core_warn(dev, "FW does not support extended destination");
		return -EOPNOTSUPP;
	}
	if (num_encap > (1 << fw_log_max_fdb_encap_uplink)) {
		mlx5_core_warn(dev, "FW does not support more than %d encaps",
			       1 << fw_log_max_fdb_encap_uplink);
		return -EOPNOTSUPP;
	}

	return 0;
}

//填充flow table entry表项，并与firmware进行通信
static int mlx5_cmd_set_fte(struct mlx5_core_dev *dev,
			    int opmod, int modify_mask,
			    struct mlx5_flow_table *ft,
			    unsigned group_id,
			    struct fs_fte *fte)
{
	u32 out[MLX5_ST_SZ_DW(set_fte_out)] = {0};
	bool extended_dest = false;
	struct mlx5_flow_rule *dst;
	void *in_flow_context, *vlan;
	void *in_match_value;
	unsigned int inlen;
	int dst_cnt_size;
	void *in_dests;
	u32 *in;
	int err;

	if (mlx5_set_extended_dest(dev, fte, &extended_dest))
		return -EOPNOTSUPP;

	if (!extended_dest)
		dst_cnt_size = MLX5_ST_SZ_BYTES(dest_format_struct);
	else
		dst_cnt_size = MLX5_ST_SZ_BYTES(extended_dest_format);

	inlen = MLX5_ST_SZ_BYTES(set_fte_in) + fte->dests_size * dst_cnt_size;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(set_fte_in, in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	/*0表示set new Entry;1表示修改entry*/
	MLX5_SET(set_fte_in, in, op_mod, opmod);
	/**
	 * Bit Mask indicates which fields for already existing fields to modify Valid only when op_mod==modify
		Bit 0: action
		Bit 1: flow_tag
		Bit 2: Destination_List - (Size and List)
		Bit 3: Flow_Counters - (Size and List)
		Bit 4: encap_id
	 */
	MLX5_SET(set_fte_in, in, modify_enable_mask, modify_mask);
	/*
	 * Table’s role in packet processing 0x0: NIC receive
		0x1: NIC transmit
		0x2: E-Switch egress ACL
		0x3: E-Switch ingress ACL 0x4: E-Switch FDB
		0x5: Nic Sniffer Rx
		0x6: Nic Sniffer Tx
		0x7: NIC_RX_RDMA 0x8: NIC_TX_RDMA
	 * */
	MLX5_SET(set_fte_in, in, table_type, ft->type);
	/*flow所属的table*/
	MLX5_SET(set_fte_in, in, table_id,   ft->id);
	/*flow在group中的位置*/
	MLX5_SET(set_fte_in, in, flow_index, fte->index);
	MLX5_SET(set_fte_in, in, ignore_flow_level,
		 !!(fte->action.flags & FLOW_ACT_IGNORE_FLOW_LEVEL));

	if (ft->vport) {
		MLX5_SET(set_fte_in, in, vport_number, ft->vport);
		/*0 - access my vport - vport_number is reserved.
          1 - access another vport determined by vport_number on my e- switch.
          Allowed only if HCA_CAP.vport_group_manager=1*/
		MLX5_SET(set_fte_in, in, other_vport, 1);
	}

	/*构造flow_context*/
	in_flow_context = MLX5_ADDR_OF(set_fte_in, in, flow_context);
	MLX5_SET(flow_context, in_flow_context, group_id, group_id);/*flow所属的group*/

	MLX5_SET(flow_context, in_flow_context, flow_tag,
		 fte->flow_context.flow_tag);
	MLX5_SET(flow_context, in_flow_context, flow_source,
		 fte->flow_context.flow_source);

	MLX5_SET(flow_context, in_flow_context, extended_destination,
		 extended_dest);
	if (extended_dest) {
		u32 action;

		action = fte->action.action &
			~MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT;
		MLX5_SET(flow_context, in_flow_context, action, action);
	} else {
		MLX5_SET(flow_context, in_flow_context, action,
			 fte->action.action);
		if (fte->action.pkt_reformat)
			MLX5_SET(flow_context, in_flow_context, packet_reformat_id,
				 fte->action.pkt_reformat->id);
	}
	if (fte->action.modify_hdr)
		MLX5_SET(flow_context, in_flow_context, modify_header_id,
			 fte->action.modify_hdr->id);

	vlan = MLX5_ADDR_OF(flow_context, in_flow_context, push_vlan);

	MLX5_SET(vlan, vlan, ethtype, fte->action.vlan[0].ethtype);
	MLX5_SET(vlan, vlan, vid, fte->action.vlan[0].vid);
	MLX5_SET(vlan, vlan, prio, fte->action.vlan[0].prio);

	vlan = MLX5_ADDR_OF(flow_context, in_flow_context, push_vlan_2);

	MLX5_SET(vlan, vlan, ethtype, fte->action.vlan[1].ethtype);
	MLX5_SET(vlan, vlan, vid, fte->action.vlan[1].vid);
	MLX5_SET(vlan, vlan, prio, fte->action.vlan[1].prio);

	in_match_value = MLX5_ADDR_OF(flow_context, in_flow_context,
				      match_value);
	memcpy(in_match_value, &fte->val, sizeof(fte->val));

	in_dests = MLX5_ADDR_OF(flow_context, in_flow_context, destination);
	if (fte->action.action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		int list_size = 0;

		list_for_each_entry(dst, &fte->node.children, node.list) {
			unsigned int id, type = dst->dest_attr.type;

			if (type == MLX5_FLOW_DESTINATION_TYPE_COUNTER)
				continue;

			switch (type) {
			case MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE_NUM:
				id = dst->dest_attr.ft_num;
				type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
				break;
			case MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE:
				id = dst->dest_attr.ft->id;
				break;
			case MLX5_FLOW_DESTINATION_TYPE_VPORT:
				id = dst->dest_attr.vport.num;
				MLX5_SET(dest_format_struct, in_dests,
					 destination_eswitch_owner_vhca_id_valid,
					 !!(dst->dest_attr.vport.flags &
					    MLX5_FLOW_DEST_VPORT_VHCA_ID));
				MLX5_SET(dest_format_struct, in_dests,
					 destination_eswitch_owner_vhca_id,
					 dst->dest_attr.vport.vhca_id);
				if (extended_dest &&
				    dst->dest_attr.vport.pkt_reformat) {
					MLX5_SET(dest_format_struct, in_dests,
						 packet_reformat,
						 !!(dst->dest_attr.vport.flags &
						    MLX5_FLOW_DEST_VPORT_REFORMAT_ID));
					MLX5_SET(extended_dest_format, in_dests,
						 packet_reformat_id,
						 dst->dest_attr.vport.pkt_reformat->id);
				}
				break;
			default:
				id = dst->dest_attr.tir_num;
			}

			MLX5_SET(dest_format_struct, in_dests, destination_type,
				 type);
			MLX5_SET(dest_format_struct, in_dests, destination_id, id);
			in_dests += dst_cnt_size;
			list_size++;
		}

		MLX5_SET(flow_context, in_flow_context, destination_list_size,
			 list_size);
	}

	if (fte->action.action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		int max_list_size = BIT(MLX5_CAP_FLOWTABLE_TYPE(dev,
					log_max_flow_counter,
					ft->type));
		int list_size = 0;

		list_for_each_entry(dst, &fte->node.children, node.list) {
			if (dst->dest_attr.type !=
			    MLX5_FLOW_DESTINATION_TYPE_COUNTER)
				continue;

			MLX5_SET(flow_counter_list, in_dests, flow_counter_id,
				 dst->dest_attr.counter_id);
			in_dests += dst_cnt_size;
			list_size++;
		}
		if (list_size > max_list_size) {
			err = -EINVAL;
			goto err_out;
		}

		MLX5_SET(flow_context, in_flow_context, flow_counter_list_size,
			 list_size);
	}

	//发给firmware进行处理
	err = mlx5_cmd_exec(dev, in, inlen, out, sizeof(out));
err_out:
	kvfree(in);
	return err;
}

/*新增flow table entry*/
static int mlx5_cmd_create_fte(struct mlx5_flow_root_namespace *ns,
			       struct mlx5_flow_table *ft/*flow table*/,
			       struct mlx5_flow_group *group/*flow group*/,
			       struct fs_fte *fte)
{
	struct mlx5_core_dev *dev = ns->dev;
	unsigned int group_id = group->id;

	return mlx5_cmd_set_fte(dev, 0/*设置新的entry*/, 0/*表示不修改任何字段*/, ft, group_id, fte);
}

static int mlx5_cmd_update_fte(struct mlx5_flow_root_namespace *ns,
			       struct mlx5_flow_table *ft,
			       struct mlx5_flow_group *fg,
			       int modify_mask,
			       struct fs_fte *fte)
{
	int opmod;
	struct mlx5_core_dev *dev = ns->dev;
	int atomic_mod_cap = MLX5_CAP_FLOWTABLE(dev,
						flow_table_properties_nic_receive.
						flow_modify_en);
	if (!atomic_mod_cap)
		return -EOPNOTSUPP;
	opmod = 1;

	return	mlx5_cmd_set_fte(dev, opmod, modify_mask, ft, fg->id, fte);
}

static int mlx5_cmd_delete_fte(struct mlx5_flow_root_namespace *ns,
			       struct mlx5_flow_table *ft,
			       struct fs_fte *fte)
{
	u32 in[MLX5_ST_SZ_DW(delete_fte_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	MLX5_SET(delete_fte_in, in, opcode, MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY);
	MLX5_SET(delete_fte_in, in, table_type, ft->type);
	MLX5_SET(delete_fte_in, in, table_id, ft->id);
	MLX5_SET(delete_fte_in, in, flow_index, fte->index);
	if (ft->vport) {
		MLX5_SET(delete_fte_in, in, vport_number, ft->vport);
		MLX5_SET(delete_fte_in, in, other_vport, 1);
	}

	return mlx5_cmd_exec_in(dev, delete_fte, in);
}

//向fw申请一个/一组 flow counter id
int mlx5_cmd_fc_bulk_alloc(struct mlx5_core_dev *dev,
			   enum mlx5_fc_bulk_alloc_bitmask alloc_bitmask,
			   u32 *id)
{
	u32 out[MLX5_ST_SZ_DW(alloc_flow_counter_out)] = {};
	u32 in[MLX5_ST_SZ_DW(alloc_flow_counter_in)] = {};
	int err;

	MLX5_SET(alloc_flow_counter_in, in, opcode,
		 MLX5_CMD_OP_ALLOC_FLOW_COUNTER);
	MLX5_SET(alloc_flow_counter_in, in, flow_counter_bulk, alloc_bitmask);

	err = mlx5_cmd_exec_inout(dev, alloc_flow_counter, in, out);
	if (!err)
		*id = MLX5_GET(alloc_flow_counter_out, out, flow_counter_id);
	return err;
}

//向fw申请一个flow counter对应的id号
int mlx5_cmd_fc_alloc(struct mlx5_core_dev *dev, u32 *id)
{
	return mlx5_cmd_fc_bulk_alloc(dev, 0, id);
}

int mlx5_cmd_fc_free(struct mlx5_core_dev *dev, u32 id)
{
	u32 in[MLX5_ST_SZ_DW(dealloc_flow_counter_in)] = {};

	MLX5_SET(dealloc_flow_counter_in, in, opcode,
		 MLX5_CMD_OP_DEALLOC_FLOW_COUNTER);
	MLX5_SET(dealloc_flow_counter_in, in, flow_counter_id, id);
	return mlx5_cmd_exec_in(dev, dealloc_flow_counter, in);
}

int mlx5_cmd_fc_query(struct mlx5_core_dev *dev, u32 id,
		      u64 *packets, u64 *bytes)
{
	u32 out[MLX5_ST_SZ_BYTES(query_flow_counter_out) +
		MLX5_ST_SZ_BYTES(traffic_counter)] = {};
	u32 in[MLX5_ST_SZ_DW(query_flow_counter_in)] = {};
	void *stats;
	int err = 0;

	MLX5_SET(query_flow_counter_in, in, opcode,
		 MLX5_CMD_OP_QUERY_FLOW_COUNTER);
	MLX5_SET(query_flow_counter_in, in, op_mod, 0);
	MLX5_SET(query_flow_counter_in, in, flow_counter_id, id);
	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	stats = MLX5_ADDR_OF(query_flow_counter_out, out, flow_statistics);
	*packets = MLX5_GET64(traffic_counter, stats, packets);
	*bytes = MLX5_GET64(traffic_counter, stats, octets);
	return 0;
}

int mlx5_cmd_fc_get_bulk_query_out_len(int bulk_len)
{
	return MLX5_ST_SZ_BYTES(query_flow_counter_out) +
		MLX5_ST_SZ_BYTES(traffic_counter) * bulk_len;
}

int mlx5_cmd_fc_bulk_query(struct mlx5_core_dev *dev, u32 base_id, int bulk_len,
			   u32 *out)
{
	int outlen = mlx5_cmd_fc_get_bulk_query_out_len(bulk_len);
	u32 in[MLX5_ST_SZ_DW(query_flow_counter_in)] = {};

	MLX5_SET(query_flow_counter_in, in, opcode,
		 MLX5_CMD_OP_QUERY_FLOW_COUNTER);
	MLX5_SET(query_flow_counter_in, in, flow_counter_id, base_id);
	MLX5_SET(query_flow_counter_in, in, num_of_counters, bulk_len);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, outlen);
}

//知会fw初始化encap_header,返回对应的encap_id
static int mlx5_cmd_packet_reformat_alloc(struct mlx5_flow_root_namespace *ns,
					  int reformat_type,
					  size_t size,
					  void *reformat_data,
					  enum mlx5_flow_namespace_type namespace,
					  struct mlx5_pkt_reformat *pkt_reformat)
{
	u32 out[MLX5_ST_SZ_DW(alloc_packet_reformat_context_out)] = {};
	struct mlx5_core_dev *dev = ns->dev;
	void *packet_reformat_context_in;
	int max_encap_size;
	void *reformat;
	int inlen;
	int err;
	u32 *in;

	if (namespace == MLX5_FLOW_NAMESPACE_FDB)
		max_encap_size = MLX5_CAP_ESW(dev, max_encap_header_size);
	else
		max_encap_size = MLX5_CAP_FLOWTABLE(dev, max_encap_header_size);

	if (size > max_encap_size) {
		mlx5_core_warn(dev, "encap size %zd too big, max supported is %d\n",
			       size, max_encap_size);
		return -EINVAL;
	}

	in = kzalloc(MLX5_ST_SZ_BYTES(alloc_packet_reformat_context_in) + size,
		     GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	packet_reformat_context_in = MLX5_ADDR_OF(alloc_packet_reformat_context_in,
						  in, packet_reformat_context);
	reformat = MLX5_ADDR_OF(packet_reformat_context_in,
				packet_reformat_context_in,
				reformat_data);
	inlen = reformat - (void *)in  + size;

	MLX5_SET(alloc_packet_reformat_context_in, in, opcode,
		 MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT);
	MLX5_SET(packet_reformat_context_in, packet_reformat_context_in,
		 reformat_data_size, size);
	MLX5_SET(packet_reformat_context_in, packet_reformat_context_in,
		 reformat_type, reformat_type);
	//填充encap头部格式
	memcpy(reformat, reformat_data, size);

	err = mlx5_cmd_exec(dev, in, inlen, out, sizeof(out));

	pkt_reformat->id = MLX5_GET(alloc_packet_reformat_context_out,
				    out, packet_reformat_id);
	kfree(in);
	return err;
}

static void mlx5_cmd_packet_reformat_dealloc(struct mlx5_flow_root_namespace *ns,
					     struct mlx5_pkt_reformat *pkt_reformat)
{
	u32 in[MLX5_ST_SZ_DW(dealloc_packet_reformat_context_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	MLX5_SET(dealloc_packet_reformat_context_in, in, opcode,
		 MLX5_CMD_OP_DEALLOC_PACKET_REFORMAT_CONTEXT);
	MLX5_SET(dealloc_packet_reformat_context_in, in, packet_reformat_id,
		 pkt_reformat->id);

	mlx5_cmd_exec_in(dev, dealloc_packet_reformat_context, in);
}

static int mlx5_cmd_modify_header_alloc(struct mlx5_flow_root_namespace *ns,
					u8 namespace, u8 num_actions,
					void *modify_actions,
					struct mlx5_modify_hdr *modify_hdr/*向fw申请mh_id*/)
{
	u32 out[MLX5_ST_SZ_DW(alloc_modify_header_context_out)] = {};
	int max_actions, actions_size, inlen, err;
	struct mlx5_core_dev *dev = ns->dev;
	void *actions_in;
	u8 table_type;
	u32 *in;

	switch (namespace) {
	case MLX5_FLOW_NAMESPACE_FDB:
		max_actions = MLX5_CAP_ESW_FLOWTABLE_FDB(dev, max_modify_header_actions);
		table_type = FS_FT_FDB;
		break;
	case MLX5_FLOW_NAMESPACE_KERNEL:
	case MLX5_FLOW_NAMESPACE_BYPASS:
		max_actions = MLX5_CAP_FLOWTABLE_NIC_RX(dev, max_modify_header_actions);
		table_type = FS_FT_NIC_RX;
		break;
	case MLX5_FLOW_NAMESPACE_EGRESS:
		max_actions = MLX5_CAP_FLOWTABLE_NIC_TX(dev, max_modify_header_actions);
		table_type = FS_FT_NIC_TX;
		break;
	case MLX5_FLOW_NAMESPACE_ESW_INGRESS:
		max_actions = MLX5_CAP_ESW_INGRESS_ACL(dev, max_modify_header_actions);
		table_type = FS_FT_ESW_INGRESS_ACL;
		break;
	case MLX5_FLOW_NAMESPACE_RDMA_TX:
		max_actions = MLX5_CAP_FLOWTABLE_RDMA_TX(dev, max_modify_header_actions);
		table_type = FS_FT_RDMA_TX;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (num_actions > max_actions) {
		mlx5_core_warn(dev, "too many modify header actions %d, max supported %d\n",
			       num_actions, max_actions);
		return -EOPNOTSUPP;
	}

	actions_size = MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto) * num_actions;
	inlen = MLX5_ST_SZ_BYTES(alloc_modify_header_context_in) + actions_size;

	in = kzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	//构造alloc_modify_header_context消息
	MLX5_SET(alloc_modify_header_context_in, in, opcode,
		 MLX5_CMD_OP_ALLOC_MODIFY_HEADER_CONTEXT);
	MLX5_SET(alloc_modify_header_context_in, in, table_type, table_type);
	MLX5_SET(alloc_modify_header_context_in, in, num_of_actions, num_actions);

	actions_in = MLX5_ADDR_OF(alloc_modify_header_context_in, in, actions);
	memcpy(actions_in, modify_actions, actions_size);

	//调用fw命令，并读取fw响应
	err = mlx5_cmd_exec(dev, in, inlen, out, sizeof(out));

	//获得header_id
	modify_hdr->id = MLX5_GET(alloc_modify_header_context_out, out, modify_header_id);
	kfree(in);
	return err;
}

static void mlx5_cmd_modify_header_dealloc(struct mlx5_flow_root_namespace *ns,
					   struct mlx5_modify_hdr *modify_hdr)
{
	u32 in[MLX5_ST_SZ_DW(dealloc_modify_header_context_in)] = {};
	struct mlx5_core_dev *dev = ns->dev;

	MLX5_SET(dealloc_modify_header_context_in, in, opcode,
		 MLX5_CMD_OP_DEALLOC_MODIFY_HEADER_CONTEXT);
	MLX5_SET(dealloc_modify_header_context_in, in, modify_header_id,
		 modify_hdr->id);

	mlx5_cmd_exec_in(dev, dealloc_modify_header_context, in);
}

//dmfs下流表方式（旧的下流方式）已支持的table type的cmds处理
static const struct mlx5_flow_cmds mlx5_flow_cmds = {
	//告知fw创建flow table
	.create_flow_table = mlx5_cmd_create_flow_table,
	.destroy_flow_table = mlx5_cmd_destroy_flow_table,
	.modify_flow_table = mlx5_cmd_modify_flow_table,
	//告知fw创建flow group
	.create_flow_group = mlx5_cmd_create_flow_group,
	.destroy_flow_group = mlx5_cmd_destroy_flow_group,
	//告知fw创建flow table entry
	.create_fte = mlx5_cmd_create_fte,
	.update_fte = mlx5_cmd_update_fte,
	.delete_fte = mlx5_cmd_delete_fte,
	.update_root_ft = mlx5_cmd_update_root_ft,
	.packet_reformat_alloc = mlx5_cmd_packet_reformat_alloc,
	.packet_reformat_dealloc = mlx5_cmd_packet_reformat_dealloc,
	.modify_header_alloc = mlx5_cmd_modify_header_alloc,
	.modify_header_dealloc = mlx5_cmd_modify_header_dealloc,
	.set_peer = mlx5_cmd_stub_set_peer,
	.create_ns = mlx5_cmd_stub_create_ns,
	.destroy_ns = mlx5_cmd_stub_destroy_ns,
};

//暂不支持的table type的cmds处理（打桩）
static const struct mlx5_flow_cmds mlx5_flow_cmd_stubs = {
	.create_flow_table = mlx5_cmd_stub_create_flow_table,
	.destroy_flow_table = mlx5_cmd_stub_destroy_flow_table,
	.modify_flow_table = mlx5_cmd_stub_modify_flow_table,
	.create_flow_group = mlx5_cmd_stub_create_flow_group,
	.destroy_flow_group = mlx5_cmd_stub_destroy_flow_group,
	.create_fte = mlx5_cmd_stub_create_fte,
	.update_fte = mlx5_cmd_stub_update_fte,
	.delete_fte = mlx5_cmd_stub_delete_fte,
	.update_root_ft = mlx5_cmd_stub_update_root_ft,
	.packet_reformat_alloc = mlx5_cmd_stub_packet_reformat_alloc,
	.packet_reformat_dealloc = mlx5_cmd_stub_packet_reformat_dealloc,
	.modify_header_alloc = mlx5_cmd_stub_modify_header_alloc,
	.modify_header_dealloc = mlx5_cmd_stub_modify_header_dealloc,
	.set_peer = mlx5_cmd_stub_set_peer,
	.create_ns = mlx5_cmd_stub_create_ns,
	.destroy_ns = mlx5_cmd_stub_destroy_ns,
};

const struct mlx5_flow_cmds *mlx5_fs_cmd_get_fw_cmds(void)
{
	return &mlx5_flow_cmds;
}

static const struct mlx5_flow_cmds *mlx5_fs_cmd_get_stub_cmds(void)
{
	return &mlx5_flow_cmd_stubs;
}

const struct mlx5_flow_cmds *mlx5_fs_cmd_get_default(enum fs_flow_table_type type)
{
	switch (type) {
	case FS_FT_NIC_RX:
	case FS_FT_ESW_EGRESS_ACL:
	case FS_FT_ESW_INGRESS_ACL:
	case FS_FT_FDB:
	case FS_FT_SNIFFER_RX:
	case FS_FT_SNIFFER_TX:
	case FS_FT_NIC_TX:
	case FS_FT_RDMA_RX:
	case FS_FT_RDMA_TX:
		//对支持的table type返回对应的cmds
		return mlx5_fs_cmd_get_fw_cmds();
	default:
		return mlx5_fs_cmd_get_stub_cmds();
	}
}
