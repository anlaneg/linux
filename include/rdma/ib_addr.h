/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 */

#ifndef IB_ADDR_H
#define IB_ADDR_H

#include <linux/ethtool.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/if_inet6.h>
#include <net/ip.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <net/net_namespace.h>

/**
 * struct rdma_dev_addr - Contains resolved RDMA hardware addresses
 * @src_dev_addr:	Source MAC address.
 * @dst_dev_addr:	Destination MAC address.
 * @broadcast:		Broadcast address of the device.
 * @dev_type:		The interface hardware type of the device.
 * @bound_dev_if:	An optional device interface index.
 * @transport:		The transport type used.
 * @net:		Network namespace containing the bound_dev_if net_dev.
 * @sgid_attr:		GID attribute to use for identified SGID
 */
struct rdma_dev_addr {
	unsigned char src_dev_addr[MAX_ADDR_LEN];/*源mac地址*/
	unsigned char dst_dev_addr[MAX_ADDR_LEN];/*目的MAC地址*/
	unsigned char broadcast[MAX_ADDR_LEN];/*广播MAC地址*/
	unsigned short dev_type;/*设备类型*/
	int bound_dev_if;/*设置的目的接口IFINDEX*/
	enum rdma_transport_type transport;/*使用哪种transport类型，例如udp,iwrap*/
	struct net *net;/*当前所属net namespace*/
	const struct ib_gid_attr *sgid_attr;/*sgid的属性信息*/
	enum rdma_network_type network;/*使用哪种网络:ipv4,ipv6,ib*/
	/*指定的报文hop limit,来源于路由*/
	int hoplimit;
};

/**
 * rdma_translate_ip - Translate a local IP address to an RDMA hardware
 *   address.
 *
 * The dev_addr->net field must be initialized.
 */
int rdma_translate_ip(const struct sockaddr *addr,
		      struct rdma_dev_addr *dev_addr);

/**
 * rdma_resolve_ip - Resolve source and destination IP addresses to
 *   RDMA hardware addresses.
 * @src_addr: An optional source address to use in the resolution.  If a
 *   source address is not provided, a usable address will be returned via
 *   the callback.
 * @dst_addr: The destination address to resolve.
 * @addr: A reference to a data location that will receive the resolved
 *   addresses.  The data location must remain valid until the callback has
 *   been invoked. The net field of the addr struct must be valid.
 * @timeout_ms: Amount of time to wait for the address resolution to complete.
 * @callback: Call invoked once address resolution has completed, timed out,
 *   or been canceled.  A status of 0 indicates success.
 * @resolve_by_gid_attr:	Resolve the ip based on the GID attribute from
 *				rdma_dev_addr.
 * @context: User-specified context associated with the call.
 */
int rdma_resolve_ip(struct sockaddr *src_addr, const struct sockaddr *dst_addr,
		    struct rdma_dev_addr *addr, unsigned long timeout_ms,
		    void (*callback)(int status, struct sockaddr *src_addr,
				     struct rdma_dev_addr *addr, void *context),
		    bool resolve_by_gid_attr, void *context);

void rdma_addr_cancel(struct rdma_dev_addr *addr);

int rdma_addr_size(const struct sockaddr *addr);
int rdma_addr_size_in6(struct sockaddr_in6 *addr);
int rdma_addr_size_kss(struct __kernel_sockaddr_storage *addr);

/*rdma设备地址8,9自节对应的为pkey*/
static inline u16 ib_addr_get_pkey(struct rdma_dev_addr *dev_addr)
{
	return ((u16)dev_addr->broadcast[8] << 8) | (u16)dev_addr->broadcast[9];
}

/*设置rdma设备地址对应的pkey*/
static inline void ib_addr_set_pkey(struct rdma_dev_addr *dev_addr, u16 pkey)
{
	dev_addr->broadcast[8] = pkey >> 8;
	dev_addr->broadcast[9] = (unsigned char) pkey;
}

static inline void ib_addr_get_mgid(struct rdma_dev_addr *dev_addr,
				    union ib_gid *gid)
{
	memcpy(gid, dev_addr->broadcast + 4, sizeof *gid);
}

static inline int rdma_addr_gid_offset(struct rdma_dev_addr *dev_addr)
{
	/*依据dev_type跳过若干字节*/
	return dev_addr->dev_type == ARPHRD_INFINIBAND ? 4 : 0;
}

static inline u16 rdma_vlan_dev_vlan_id(const struct net_device *dev)
{
	return is_vlan_dev(dev) ? vlan_dev_vlan_id(dev) : 0xffff;
}

/*将ip地址映射为gid(V6直转,V4映射为V6)*/
static inline int rdma_ip2gid(struct sockaddr *addr, union ib_gid *gid/*出参,转换后的GID*/)
{
	switch (addr->sa_family) {
	case AF_INET:
		/*将v4地址直接转换为V6地址,认定为gid*/
		ipv6_addr_set_v4mapped(((struct sockaddr_in *)
					addr)->sin_addr.s_addr,
				       (struct in6_addr *)gid);
		break;
	case AF_INET6:
		/*直接使用v6地址*/
		*(struct in6_addr *)&gid->raw =
			((struct sockaddr_in6 *)addr)->sin6_addr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* Important - sockaddr should be a union of sockaddr_in and sockaddr_in6 */
static inline void rdma_gid2ip(struct sockaddr *out, const union ib_gid *gid)
{
	if (ipv6_addr_v4mapped((struct in6_addr *)gid)) {
		struct sockaddr_in *out_in = (struct sockaddr_in *)out;
		memset(out_in, 0, sizeof(*out_in));
		out_in->sin_family = AF_INET;
		/*后4个字节为s_addr*/
		memcpy(&out_in->sin_addr.s_addr, gid->raw + 12, 4);
	} else {
		struct sockaddr_in6 *out_in = (struct sockaddr_in6 *)out;
		memset(out_in, 0, sizeof(*out_in));
		out_in->sin6_family = AF_INET6;
		memcpy(&out_in->sin6_addr.s6_addr, gid->raw, 16);
	}
}

/*
 * rdma_get/set_sgid/dgid() APIs are applicable to IB, and iWarp.
 * They are not applicable to RoCE.
 * RoCE GIDs are derived from the IP addresses.
 */
static inline void rdma_addr_get_sgid(struct rdma_dev_addr *dev_addr, union ib_gid *gid)
{
	memcpy(gid, dev_addr->src_dev_addr + rdma_addr_gid_offset(dev_addr),
	       sizeof(*gid));
}

static inline void rdma_addr_set_sgid(struct rdma_dev_addr *dev_addr, union ib_gid *gid)
{
	memcpy(dev_addr->src_dev_addr + rdma_addr_gid_offset(dev_addr), gid, sizeof *gid);
}

static inline void rdma_addr_get_dgid(struct rdma_dev_addr *dev_addr, union ib_gid *gid)
{
	memcpy(gid, dev_addr->dst_dev_addr + rdma_addr_gid_offset(dev_addr), sizeof *gid);
}

static inline void rdma_addr_set_dgid(struct rdma_dev_addr *dev_addr, union ib_gid *gid)
{
	memcpy(dev_addr->dst_dev_addr + rdma_addr_gid_offset(dev_addr), gid, sizeof *gid);
}

/*按mtu值分类ib_mtu*/
static inline enum ib_mtu iboe_get_mtu(int mtu)
{
	/*
	 * Reduce IB headers from effective IBoE MTU.
	 */
	mtu = mtu - (IB_GRH_BYTES + IB_UDP_BYTES + IB_BTH_BYTES +
		     IB_EXT_XRC_BYTES + IB_EXT_ATOMICETH_BYTES +
		     IB_ICRC_BYTES);

	if (mtu >= ib_mtu_enum_to_int(IB_MTU_4096))
		return IB_MTU_4096;
	else if (mtu >= ib_mtu_enum_to_int(IB_MTU_2048))
		return IB_MTU_2048;
	else if (mtu >= ib_mtu_enum_to_int(IB_MTU_1024))
		return IB_MTU_1024;
	else if (mtu >= ib_mtu_enum_to_int(IB_MTU_512))
		return IB_MTU_512;
	else if (mtu >= ib_mtu_enum_to_int(IB_MTU_256))
		return IB_MTU_256;
	else
		return 0;
}

/*ipv6 link local地址*/
static inline int rdma_link_local_addr(struct in6_addr *addr)
{
	if (addr->s6_addr32[0] == htonl(0xfe800000) &&
	    addr->s6_addr32[1] == 0)
		return 1;

	return 0;
}

static inline void rdma_get_ll_mac(struct in6_addr *addr, u8 *mac)
{
	memcpy(mac, &addr->s6_addr[8], 3);
	memcpy(mac + 3, &addr->s6_addr[13], 3);
	mac[0] ^= 2;
}

static inline int rdma_is_multicast_addr(struct in6_addr *addr)
{
	__be32 ipv4_addr;

	if (addr->s6_addr[0] == 0xff)
		/*ipv6确认组播*/
		return 1;

	/*如果是v4 mapped,检查ipv4是否组播*/
	ipv4_addr = addr->s6_addr32[3];
	return (ipv6_addr_v4mapped(addr) && ipv4_is_multicast(ipv4_addr));
}

static inline void rdma_get_mcast_mac(struct in6_addr *addr, u8 *mac)
{
	int i;

	mac[0] = 0x33;
	mac[1] = 0x33;
	for (i = 2; i < 6; ++i)
		mac[i] = addr->s6_addr[i + 10];
}

static inline u16 rdma_get_vlan_id(union ib_gid *dgid)
{
	u16 vid;

	vid = dgid->raw[11] << 8 | dgid->raw[12];
	return vid < 0x1000 ? vid : 0xffff;
}

static inline struct net_device *rdma_vlan_dev_real_dev(const struct net_device *dev)
{
	return is_vlan_dev(dev) ? vlan_dev_real_dev(dev) : NULL;
}

#endif /* IB_ADDR_H */
