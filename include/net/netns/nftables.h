/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NETNS_NFTABLES_H_
#define _NETNS_NFTABLES_H_

struct netns_nftables {
	u8			gencursor;//记录当前的generations(目前仅两种）
};

#endif
