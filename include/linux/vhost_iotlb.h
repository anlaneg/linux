/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VHOST_IOTLB_H
#define _LINUX_VHOST_IOTLB_H

#include <linux/interval_tree_generic.h>

struct vhost_iotlb_map {
	struct rb_node rb;//用于串连到tlb->root上
	struct list_head link;//用于串到tlb->list上
	u64 start;//虚拟起始地址
	u64 last;//虚拟终止地址
	u64 size;//地址范围长度
	u64 addr;//物理起始地址
#define VHOST_MAP_RO 0x1
#define VHOST_MAP_WO 0x2
#define VHOST_MAP_RW 0x3
	u32 perm;/*地址权限*/
	u32 flags_padding;
	u64 __subtree_last;
	void *opaque;
};

#define VHOST_IOTLB_FLAG_RETIRE 0x1

struct vhost_iotlb {
	struct rb_root_cached root;/*用于map查询，用于树型存储map*/
	struct list_head list;/*用于map遍历，串连所有map*/
	unsigned int limit;/*iotlb的容量极限*/
	unsigned int nmaps;/*存入到root中的map总数*/
	unsigned int flags;
};

int vhost_iotlb_add_range_ctx(struct vhost_iotlb *iotlb, u64 start, u64 last,
			      u64 addr, unsigned int perm, void *opaque);
int vhost_iotlb_add_range(struct vhost_iotlb *iotlb, u64 start, u64 last,
			  u64 addr, unsigned int perm);
void vhost_iotlb_del_range(struct vhost_iotlb *iotlb, u64 start, u64 last);

struct vhost_iotlb *vhost_iotlb_alloc(unsigned int limit, unsigned int flags);
void vhost_iotlb_free(struct vhost_iotlb *iotlb);
void vhost_iotlb_reset(struct vhost_iotlb *iotlb);

struct vhost_iotlb_map *
vhost_iotlb_itree_first(struct vhost_iotlb *iotlb, u64 start, u64 last);
struct vhost_iotlb_map *
vhost_iotlb_itree_next(struct vhost_iotlb_map *map, u64 start, u64 last);

void vhost_iotlb_map_free(struct vhost_iotlb *iotlb,
			  struct vhost_iotlb_map *map);
#endif
