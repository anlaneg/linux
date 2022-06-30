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

#ifndef _UAPI_LINUX_SEG6_IPTUNNEL_H
#define _UAPI_LINUX_SEG6_IPTUNNEL_H

#include <linux/seg6.h>		/* For struct ipv6_sr_hdr. */

enum {
	SEG6_IPTUNNEL_UNSPEC,
	SEG6_IPTUNNEL_SRH,
	__SEG6_IPTUNNEL_MAX,
};
#define SEG6_IPTUNNEL_MAX (__SEG6_IPTUNNEL_MAX - 1)

struct seg6_iptunnel_encap {
	int mode;/*封装方式*/
	struct ipv6_sr_hdr srh[0];/*用户指定的segs*/
};

#define SEG6_IPTUN_ENCAP_SIZE(x) ((sizeof(*x)) + (((x)->srh->hdrlen + 1) << 3))

enum {
	SEG6_IPTUN_MODE_INLINE,/*内层封装报文本身*/
	SEG6_IPTUN_MODE_ENCAP,/*内层封装网络层*/
	SEG6_IPTUN_MODE_L2ENCAP,/*内层封装以太帧*/
};

#endif
