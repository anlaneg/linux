/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_TC_PED_H
#define __LINUX_TC_PED_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

enum {
	TCA_PEDIT_UNSPEC,
	TCA_PEDIT_TM,
	TCA_PEDIT_PARMS,
	TCA_PEDIT_PAD,
	TCA_PEDIT_PARMS_EX,
	TCA_PEDIT_KEYS_EX,
	TCA_PEDIT_KEY_EX,
	__TCA_PEDIT_MAX
};

#define TCA_PEDIT_MAX (__TCA_PEDIT_MAX - 1)

enum {
	TCA_PEDIT_KEY_EX_HTYPE = 1,
	TCA_PEDIT_KEY_EX_CMD = 2,
	__TCA_PEDIT_KEY_EX_MAX
};

#define TCA_PEDIT_KEY_EX_MAX (__TCA_PEDIT_KEY_EX_MAX - 1)

 /* TCA_PEDIT_KEY_EX_HDR_TYPE_NETWROK is a special case for legacy users. It
  * means no specific header type - offset is relative to the network layer
  */
enum pedit_header_type {
	/*传统修改基准，指无明确头部类型，自network头算起*/
	TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK = 0,
	/*以太头修改基准*/
	TCA_PEDIT_KEY_EX_HDR_TYPE_ETH = 1,
	/*ipv4头修改基准*/
	TCA_PEDIT_KEY_EX_HDR_TYPE_IP4 = 2,
	/*ipv6头修改基准*/
	TCA_PEDIT_KEY_EX_HDR_TYPE_IP6 = 3,
	/*tcp修改基准*/
	TCA_PEDIT_KEY_EX_HDR_TYPE_TCP = 4,
	/*udp修改基准*/
	TCA_PEDIT_KEY_EX_HDR_TYPE_UDP = 5,
	__PEDIT_HDR_TYPE_MAX,
};

#define TCA_PEDIT_HDR_TYPE_MAX (__PEDIT_HDR_TYPE_MAX - 1)

enum pedit_cmd {
	TCA_PEDIT_KEY_EX_CMD_SET = 0,
	//add方式为在原基础上添加add value的方式设置值
	TCA_PEDIT_KEY_EX_CMD_ADD = 1,
	__PEDIT_CMD_MAX,
};

#define TCA_PEDIT_CMD_MAX (__PEDIT_CMD_MAX - 1)

struct tc_pedit_key {
	__u32           mask;  /* AND */
	__u32           val;   /*XOR */
	__u32           off;  /*offset */
	/**
	 * act子句支持
	 * at AT offmask MASK shift SHIFT
This is an optional part of RAW_OP which allows to have a variable OFFSET depending on
packet data at offset AT, which is binary ANDed with MASK and right-shifted
by SHIFT before adding it to OFFSET.
	 */
	__u32           at;
	__u32           offmask;
	__u32           shift;
};

struct tc_pedit_sel {
	tc_gen;
	unsigned char           nkeys;
	unsigned char           flags;
	struct tc_pedit_key     keys[0];
};

#define tc_pedit tc_pedit_sel

#endif
