/*
 * Virtio PCI driver
 *
 * This module allows virtio devices to be used over a virtual PCI device.
 * This can be used with QEMU based VMMs like KVM or Xen.
 *
 * Copyright IBM Corp. 2007
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _LINUX_VIRTIO_PCI_H
#define _LINUX_VIRTIO_PCI_H

#include <linux/types.h>

#ifndef VIRTIO_PCI_NO_LEGACY

//virtio-pci legacy interfaces情况下BAR0会指向一个公共的配置结构体，
//其格式在virtio-v1.1的 4.1.4.8节《Legacy Interfaces: A Note on PCI Device Layout》
//有定义，以下是各数据结构体成员的offset,各字段的注释，指明了其作用及读写权限等

/* A 32-bit r/o bitmask of the features supported by the host */
#define VIRTIO_PCI_HOST_FEATURES	0

/* A 32-bit r/w bitmask of features activated by the guest */
#define VIRTIO_PCI_GUEST_FEATURES	4

/* A 32-bit r/w PFN for the currently selected queue */
#define VIRTIO_PCI_QUEUE_PFN		8

/* A 16-bit r/o queue size for the currently selected queue */
#define VIRTIO_PCI_QUEUE_NUM		12

/* A 16-bit r/w queue selector */
#define VIRTIO_PCI_QUEUE_SEL		14

/* A 16-bit r/w queue notifier */
#define VIRTIO_PCI_QUEUE_NOTIFY		16

/* An 8-bit device status register.  */
#define VIRTIO_PCI_STATUS		18

/* An 8-bit r/o interrupt status register.  Reading the value will return the
 * current contents of the ISR and will also clear it.  This is effectively
 * a read-and-acknowledge. */
#define VIRTIO_PCI_ISR			19

/* MSI-X registers: only enabled if MSI-X is enabled. */
//如果msi-x被开启，则使用此子结构
/* A 16-bit vector for configuration changes. */
#define VIRTIO_MSI_CONFIG_VECTOR        20
/* A 16-bit vector for selected queue notifications. */
#define VIRTIO_MSI_QUEUE_VECTOR         22

/* The remaining space is defined by each driver as the per-driver
 * configuration space */
//此位置为公共配置结构体的结束
#define VIRTIO_PCI_CONFIG_OFF(msix_enabled)	((msix_enabled) ? 24 : 20)
/* Deprecated: please use VIRTIO_PCI_CONFIG_OFF instead */
#define VIRTIO_PCI_CONFIG(dev)	VIRTIO_PCI_CONFIG_OFF((dev)->msix_enabled)

/* Virtio ABI version, this must match exactly */
#define VIRTIO_PCI_ABI_VERSION		0

/* How many bits to shift physical queue address written to QUEUE_PFN.
 * 12 is historical, and due to x86 page size. */
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT	12

/* The alignment to use between consumer and producer parts of vring.
 * x86 pagesize again. */
#define VIRTIO_PCI_VRING_ALIGN		4096

#endif /* VIRTIO_PCI_NO_LEGACY */

/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG		0x2
/* Vector value used to disable MSI for queue */
//不使用中断
#define VIRTIO_MSI_NO_VECTOR            0xffff

#ifndef VIRTIO_PCI_NO_MODERN

/* IDs for different capabilities.  Must all exist. */

/* Common configuration */
/*这个配置对应的结构体为：struct virtio_pci_common_cfg*/
#define VIRTIO_PCI_CAP_COMMON_CFG	1
/* Notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG	2
/* ISR access */
#define VIRTIO_PCI_CAP_ISR_CFG		3
/* Device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG	4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG		5
/* Additional shared memory capability */
#define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8

/* This is the PCI capability header: */
struct virtio_pci_cap {
	/*cap编号，这个结构对应的即为PCI_CAP_ID_VNDR*/
	__u8 cap_vndr;		/* Generic PCI field: PCI_CAP_ID_VNDR */
	/*指向下一个cap(偏移量）*/
	__u8 cap_next;		/* Generic PCI field: next ptr. */
	__u8 cap_len;		/* Generic PCI field: capability length */
	/*配置类型，不同类型对应不同的数据结构,例如：VIRTIO_PCI_CAP_COMMON_CFG*/
	__u8 cfg_type;		/* Identifies the structure. */
	/*数据结构所对应的bar*/
	__u8 bar;		/* Where to find it. */
	__u8 id;		/* Multiple capabilities of the same type */
	__u8 padding[2];	/* Pad to full dword. */
	/*配置类型对应的结构在bar的哪一个位置（偏移量）*/
	__le32 offset;		/* Offset within bar. */
	/*结构体长度*/
	__le32 length;		/* Length of the structure, in bytes. */
};

struct virtio_pci_cap64 {
	struct virtio_pci_cap cap;
	__le32 offset_hi;             /* Most sig 32 bits of offset */
	__le32 length_hi;             /* Most sig 32 bits of length */
};

/*VIRTIO_PCI_CAP_NOTIFY_CFG对应的结构体*/
struct virtio_pci_notify_cap {
	struct virtio_pci_cap cap;
	__le32 notify_off_multiplier;	/* Multiplier for queue_notify_off. */
};

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
struct virtio_pci_common_cfg {
	/* About the whole device. */
	//用于获取设备功能位的低32bit或者高32bit（写0然后读获得低32bit,写1然后读获得高32bit)
	//device_feature_select The driver uses this to select which feature bits device_feature shows. Value 0x0
	//selects Feature Bits 0 to 31, 0x1 selects Feature Bits 32 to 63, etc.
	__le32 device_feature_select;	/* read-write */
	//只读寄存器，用于向驱动标明当前设备支持哪些功能位
	//device_feature The device uses this to report which feature bits it is offering to the driver: the driver writes
	//to device_feature_select to select which feature bits are presented.
	__le32 device_feature;		/* read-only */
	//用于获取/写driver使能的功能位的低32bit或者高32bit（写0然后读获得低32bit,写1然后读获得高32bit)
	//driver_feature_select The driver uses this to select which feature bits driver_feature shows. Value 0x0
	//selects Feature Bits 0 to 31, 0x1 selects Feature Bits 32 to 63, etc.
	__le32 guest_feature_select;	/* read-write */
	//驱动功能位，驱动与接受的设备功能位
	//driver_feature The driver writes this to accept feature bits offered by the device. Driver Feature Bits se-
	//lected by driver_feature_select.
	__le32 guest_feature;		/* read-write */
	/*获取/写”配置“中断号*/
	__le16 msix_config;		/* read-write */
	//队列数
	__le16 num_queues;		/* read-only */
	//驱动通过向此寄存器写0，来reset设备
	//看virtio 1.0 spec 2.1节定义的设备状态
	__u8 device_status;		/* read-write */
	//用于保证配置原子的变量，设备每次在配置变更时会更改此值（故驱动读取此时只需要检查此值，可知配置是否已变更）
	//config_generation Configuration atomicity value. The device changes this every time the configuration
	//noticeably changes.
	__u8 config_generation;		/* read-only */

	/* About a specific virtqueue. */
	/*写这个寄存器，用于表明接下来操作哪个队列*/
	__le16 queue_select;		/* read-write */
	//vq队列大小（通过写queue_select来表明队列，再读取）
	__le16 queue_size;		/* read-write, power of 2. */
	/*负责获取配置各队列中断*/
	__le16 queue_msix_vector;	/* read-write */
	//队列是否开启(写1表示此q开启)
	__le16 queue_enable;		/* read-write */
	/*队列通知对应的offset*/
	__le16 queue_notify_off;	/* read-only */
	//队列desc,avail,used的地址配置（来源于pci层）
	__le32 queue_desc_lo;		/* read-write */
	__le32 queue_desc_hi;		/* read-write */
	__le32 queue_avail_lo;		/* read-write */
	__le32 queue_avail_hi;		/* read-write */
	__le32 queue_used_lo;		/* read-write */
	__le32 queue_used_hi;		/* read-write */
};

/*
 * Warning: do not use sizeof on this: use offsetofend for
 * specific fields you need.
 */
struct virtio_pci_modern_common_cfg {
	struct virtio_pci_common_cfg cfg;

	__le16 queue_notify_data;	/* read-write */
	__le16 queue_reset;		/* read-write */

	__le16 admin_queue_index;	/* read-only */
	__le16 admin_queue_num;		/* read-only */
};

/* Fields in VIRTIO_PCI_CAP_PCI_CFG: */
struct virtio_pci_cfg_cap {
	struct virtio_pci_cap cap;
	__u8 pci_cfg_data[4]; /* Data for BAR access. */
};

/* Macro versions of offsets for the Old Timers! */
#define VIRTIO_PCI_CAP_VNDR		0
#define VIRTIO_PCI_CAP_NEXT		1
#define VIRTIO_PCI_CAP_LEN		2
#define VIRTIO_PCI_CAP_CFG_TYPE		3
#define VIRTIO_PCI_CAP_BAR		4
#define VIRTIO_PCI_CAP_OFFSET		8
#define VIRTIO_PCI_CAP_LENGTH		12

#define VIRTIO_PCI_NOTIFY_CAP_MULT	16

#define VIRTIO_PCI_COMMON_DFSELECT	0
#define VIRTIO_PCI_COMMON_DF		4
#define VIRTIO_PCI_COMMON_GFSELECT	8
#define VIRTIO_PCI_COMMON_GF		12
#define VIRTIO_PCI_COMMON_MSIX		16
#define VIRTIO_PCI_COMMON_NUMQ		18
#define VIRTIO_PCI_COMMON_STATUS	20
#define VIRTIO_PCI_COMMON_CFGGENERATION	21
#define VIRTIO_PCI_COMMON_Q_SELECT	22
#define VIRTIO_PCI_COMMON_Q_SIZE	24
#define VIRTIO_PCI_COMMON_Q_MSIX	26
#define VIRTIO_PCI_COMMON_Q_ENABLE	28
#define VIRTIO_PCI_COMMON_Q_NOFF	30
//设置desc表低32位
#define VIRTIO_PCI_COMMON_Q_DESCLO	32
#define VIRTIO_PCI_COMMON_Q_DESCHI	36
#define VIRTIO_PCI_COMMON_Q_AVAILLO	40
#define VIRTIO_PCI_COMMON_Q_AVAILHI	44
#define VIRTIO_PCI_COMMON_Q_USEDLO	48
#define VIRTIO_PCI_COMMON_Q_USEDHI	52
#define VIRTIO_PCI_COMMON_Q_NDATA	56
#define VIRTIO_PCI_COMMON_Q_RESET	58
#define VIRTIO_PCI_COMMON_ADM_Q_IDX	60
#define VIRTIO_PCI_COMMON_ADM_Q_NUM	62

#endif /* VIRTIO_PCI_NO_MODERN */

/* Admin command status. */
#define VIRTIO_ADMIN_STATUS_OK		0

/* Admin command opcode. */
#define VIRTIO_ADMIN_CMD_LIST_QUERY	0x0
#define VIRTIO_ADMIN_CMD_LIST_USE	0x1

/* Admin command group type. */
#define VIRTIO_ADMIN_GROUP_TYPE_SRIOV	0x1

/* Transitional device admin command. */
#define VIRTIO_ADMIN_CMD_LEGACY_COMMON_CFG_WRITE	0x2
#define VIRTIO_ADMIN_CMD_LEGACY_COMMON_CFG_READ		0x3
#define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_WRITE		0x4
#define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_READ		0x5
#define VIRTIO_ADMIN_CMD_LEGACY_NOTIFY_INFO		0x6

struct __packed virtio_admin_cmd_hdr {
	__le16 opcode;
	/*
	 * 1 - SR-IOV
	 * 2-65535 - reserved
	 */
	__le16 group_type;
	/* Unused, reserved for future extensions. */
	__u8 reserved1[12];
	__le64 group_member_id;
};

struct __packed virtio_admin_cmd_status {
	__le16 status;
	__le16 status_qualifier;
	/* Unused, reserved for future extensions. */
	__u8 reserved2[4];
};

struct __packed virtio_admin_cmd_legacy_wr_data {
	__u8 offset; /* Starting offset of the register(s) to write. */
	__u8 reserved[7];
	__u8 registers[];
};

struct __packed virtio_admin_cmd_legacy_rd_data {
	__u8 offset; /* Starting offset of the register(s) to read. */
};

#define VIRTIO_ADMIN_CMD_NOTIFY_INFO_FLAGS_END 0
#define VIRTIO_ADMIN_CMD_NOTIFY_INFO_FLAGS_OWNER_DEV 0x1
#define VIRTIO_ADMIN_CMD_NOTIFY_INFO_FLAGS_OWNER_MEM 0x2

#define VIRTIO_ADMIN_CMD_MAX_NOTIFY_INFO 4

struct __packed virtio_admin_cmd_notify_info_data {
	__u8 flags; /* 0 = end of list, 1 = owner device, 2 = member device */
	__u8 bar; /* BAR of the member or the owner device */
	__u8 padding[6];
	__le64 offset; /* Offset within bar. */
};

struct virtio_admin_cmd_notify_info_result {
	struct virtio_admin_cmd_notify_info_data entries[VIRTIO_ADMIN_CMD_MAX_NOTIFY_INFO];
};

#endif
