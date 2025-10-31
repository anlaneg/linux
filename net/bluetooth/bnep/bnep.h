/* SPDX-License-Identifier: GPL-2.0-only */
/*
  BNEP protocol definition for Linux Bluetooth stack (BlueZ).
  Copyright (C) 2002 Maxim Krasnyansky <maxk@qualcomm.com>

*/

#ifndef _BNEP_H
#define _BNEP_H

#include <linux/types.h>
#include <linux/crc32.h>
#include <net/bluetooth/bluetooth.h>

/* Limits */
#define BNEP_MAX_PROTO_FILTERS		5
#define BNEP_MAX_MULTICAST_FILTERS	20

/* UUIDs */
#define BNEP_BASE_UUID	0x0000000000001000800000805F9B34FB
#define BNEP_UUID16	0x02
#define BNEP_UUID32	0x04
#define BNEP_UUID128	0x16

#define BNEP_SVC_PANU	0x1115
#define BNEP_SVC_NAP	0x1116
#define BNEP_SVC_GN	0x1117

/* Packet types */
/*普通报文（含完整以太头）*/
#define BNEP_GENERAL			0x00
/*控制类报文*/
#define BNEP_CONTROL			0x01
/*不含以太头*/
#define BNEP_COMPRESSED			0x02
/*仅含srcmac*/
#define BNEP_COMPRESSED_SRC_ONLY	0x03
/*仅含dstmac*/
#define BNEP_COMPRESSED_DST_ONLY	0x04

/* Control types */
#define BNEP_CMD_NOT_UNDERSTOOD		0x00
#define BNEP_SETUP_CONN_REQ		0x01
#define BNEP_SETUP_CONN_RSP		0x02
#define BNEP_FILTER_NET_TYPE_SET	0x03
/*BNEP_FILTER_NET_TYPE_SET响应cmd*/
#define BNEP_FILTER_NET_TYPE_RSP	0x04
#define BNEP_FILTER_MULTI_ADDR_SET	0x05
#define BNEP_FILTER_MULTI_ADDR_RSP	0x06

/* Extension types */
#define BNEP_EXT_CONTROL 0x00

/* Response messages */
#define BNEP_SUCCESS 0x00

#define BNEP_CONN_INVALID_DST 0x01
#define BNEP_CONN_INVALID_SRC 0x02
#define BNEP_CONN_INVALID_SVC 0x03
#define BNEP_CONN_NOT_ALLOWED 0x04

#define BNEP_FILTER_UNSUPPORTED_REQ	0x01
#define BNEP_FILTER_INVALID_RANGE	0x02
#define BNEP_FILTER_INVALID_MCADDR	0x02
#define BNEP_FILTER_LIMIT_REACHED	0x03
#define BNEP_FILTER_DENIED_SECURITY	0x04

/* L2CAP settings */
#define BNEP_MTU	1691
#define BNEP_PSM	0x0f
#define BNEP_FLUSH_TO	0xffff
#define BNEP_CONNECT_TO	15
#define BNEP_FILTER_TO	15

/* Headers */
#define BNEP_TYPE_MASK	0x7f
#define BNEP_EXT_HEADER	0x80

struct bnep_setup_conn_req {
	__u8 type;
	__u8 ctrl;
	__u8 uuid_size;
	__u8 service[];
} __packed;

struct bnep_set_filter_req {
	__u8 type;
	__u8 ctrl;
	__be16 len;
	__u8 list[];
} __packed;

/*控制类响应报文*/
struct bnep_control_rsp {
	__u8 type;
	__u8 ctrl;
	__be16 resp;
} __packed;

struct bnep_ext_hdr {
	__u8 type;
	__u8 len;
	__u8 data[];
} __packed;

/* BNEP ioctl defines */
#define BNEPCONNADD	_IOW('B', 200, int)
#define BNEPCONNDEL	_IOW('B', 201, int)
#define BNEPGETCONNLIST	_IOR('B', 210, int)
#define BNEPGETCONNINFO	_IOR('B', 211, int)
#define BNEPGETSUPPFEAT	_IOR('B', 212, int)

#define BNEP_SETUP_RESPONSE	0
#define BNEP_SETUP_RSP_SENT	10

struct bnep_connadd_req {
	int   sock;		/* Connected socket */
	__u32 flags;
	__u16 role;
	/*指定的网络设备名称*/
	char  device[16];	/* Name of the Ethernet device */
};

/*删除链接*/
struct bnep_conndel_req {
	__u32 flags;
	__u8  dst[ETH_ALEN];
};

/*连接信息*/
struct bnep_conninfo {
	__u32 flags;
	__u16 role;
	__u16 state;
	__u8  dst[ETH_ALEN];
	char  device[16];
};

struct bnep_connlist_req {
	__u32  cnum;
	struct bnep_conninfo __user *ci;
};

/*协议起始号，如果两者一致，则仅一个协议号*/
struct bnep_proto_filter {
	__u16 start;
	__u16 end;
};

int bnep_add_connection(struct bnep_connadd_req *req, struct socket *sock);
int bnep_del_connection(struct bnep_conndel_req *req);
int bnep_get_connlist(struct bnep_connlist_req *req);
int bnep_get_conninfo(struct bnep_conninfo *ci);

/* BNEP sessions */
struct bnep_session {
	struct list_head list;

	unsigned int  role;
	unsigned long state;
	unsigned long flags;
	atomic_t      terminate;/*标非0时，此bnep_session需要销毁*/
	struct task_struct *task;/*kernel线程bnep_session对应的task*/

	struct ethhdr eh;/*以太头信息*/
	struct msghdr msg;/*临时变量，通完这sendmsg接口发送报文用*/

	struct bnep_proto_filter proto_filter[BNEP_MAX_PROTO_FILTERS];/*被记录的协议可以出去（start,end方式）*/
	unsigned long long mc_filter;/*被命中的目的mac可以出去*/

	/*对应的l2cap socket,此socket收到的报文（sk->sk_receive_queue）将转netdev收取*/
	struct socket    *sock;
	/*收发的网络设备，此dev发送的报文将挂接在sk->sk_write_queue上，
	 * 而kernel线程bnep_session负责将sk->sk_write_queue上的socket交socket，
	 * 也将sk->sk_receive_queue送netdev;实现sock与dev之间的互通*/
	struct net_device *dev;
};

void bnep_net_setup(struct net_device *dev);
int bnep_sock_init(void);
void bnep_sock_cleanup(void);

/*将mac hash成一个小于64的数字*/
static inline int bnep_mc_hash(__u8 *addr)
{
	return crc32_be(~0, addr, ETH_ALEN) >> 26;
}

#endif
