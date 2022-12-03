/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_LINUX_SEG6_H
#define _UAPI_LINUX_SEG6_H

#include <linux/types.h>
#include <linux/in6.h>		/* For struct in6_addr. */
//此格式来源于：https://datatracker.ietf.org/doc/html/draft-ietf-6man-segment-routing-header-15
//rfc8200 4.4节Routing Header 定义了routing header
/*
 * SRH
 */
struct ipv6_sr_hdr {
    /*指明此选项后面的header type*/
	__u8	nexthdr;
	/*指明此选项的长度，8个字节一个单位，不包括前8个字节(hdrlen+1)*8为实际长度*/
	__u8	hdrlen;
	/*针对sr扩展头，此值为4*/
	__u8	type;
	/*剩余的segments数目，以0为base,比如在到达目标前有多少个节点*/
	__u8	segments_left;
	/*segments中最后一个元素的索引*/
	__u8	first_segment; /* Represents the last_entry field of SRH */
	__u8	flags;
	__u16	tag;

	struct in6_addr segments[];/*一组segments*/
};

#define SR6_FLAG1_PROTECTED	(1 << 6)
#define SR6_FLAG1_OAM		(1 << 5)
#define SR6_FLAG1_ALERT		(1 << 4)
#define SR6_FLAG1_HMAC		(1 << 3)

#define SR6_TLV_INGRESS		1
#define SR6_TLV_EGRESS		2
#define SR6_TLV_OPAQUE		3
#define SR6_TLV_PADDING		4
#define SR6_TLV_HMAC		5

#define sr_has_hmac(srh) ((srh)->flags & SR6_FLAG1_HMAC)

struct sr6_tlv {
	__u8 type;
	__u8 len;
	__u8 data[0];
};

#endif
