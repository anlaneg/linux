/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 1999 - 2004 Intel Corporation. All rights reserved.
 */

#ifndef _NET_BOND_3AD_H
#define _NET_BOND_3AD_H

#include <asm/byteorder.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>

/* General definitions */
#define PKT_TYPE_LACPDU         cpu_to_be16(ETH_P_SLOW)
#define AD_TIMER_INTERVAL       100 /*msec*/

#define AD_LACP_SLOW 0
#define AD_LACP_FAST 1

typedef struct mac_addr {
	u8 mac_addr_value[ETH_ALEN];
} __packed mac_addr_t;

enum {
	BOND_AD_STABLE = 0,
	BOND_AD_BANDWIDTH = 1,
	BOND_AD_COUNT = 2,
};

/* rx machine states(43.4.11 in the 802.3ad standard) */
typedef enum {
	AD_RX_DUMMY,
	AD_RX_INITIALIZE,	/* rx Machine */
	AD_RX_PORT_DISABLED,	/* rx Machine */
	AD_RX_LACP_DISABLED,	/* rx Machine */
	AD_RX_EXPIRED,		/* rx Machine */
	AD_RX_DEFAULTED,	/* rx Machine */
	AD_RX_CURRENT		/* rx Machine */
} rx_states_t;

/* periodic machine states(43.4.12 in the 802.3ad standard) */
typedef enum {
	AD_PERIODIC_DUMMY,
	AD_NO_PERIODIC,		/* periodic machine */
	AD_FAST_PERIODIC,	/* periodic machine */
	AD_SLOW_PERIODIC,	/* periodic machine */
	AD_PERIODIC_TX		/* periodic machine */
} periodic_states_t;

/* mux machine states(43.4.13 in the 802.3ad standard) */
typedef enum {
	AD_MUX_DUMMY,
	AD_MUX_DETACHED,	/* mux machine */
	AD_MUX_WAITING,		/* mux machine */
	AD_MUX_ATTACHED,	/* mux machine */
	AD_MUX_COLLECTING_DISTRIBUTING	/* mux machine */
} mux_states_t;

/* tx machine states(43.4.15 in the 802.3ad standard) */
typedef enum {
	AD_TX_DUMMY,
	AD_TRANSMIT		/* tx Machine */
} tx_states_t;

/* churn machine states(43.4.17 in the 802.3ad standard) */
typedef enum {
	 AD_CHURN_MONITOR, /* monitoring for churn */
	 AD_CHURN,         /* churn detected (error) */
	 AD_NO_CHURN       /* no churn (no error) */
} churn_state_t;

/* rx indication types */
typedef enum {
	AD_TYPE_LACPDU = 1,	/* type lacpdu */
	AD_TYPE_MARKER		/* type marker */
} pdu_type_t;

/* rx marker indication types */
typedef enum {
	AD_MARKER_INFORMATION_SUBTYPE = 1,	/* marker imformation subtype */
	AD_MARKER_RESPONSE_SUBTYPE		/* marker response subtype */
} bond_marker_subtype_t;

/* timers types(43.4.9 in the 802.3ad standard) */
typedef enum {
	AD_CURRENT_WHILE_TIMER,
	AD_ACTOR_CHURN_TIMER,
	AD_PERIODIC_TIMER,
	AD_PARTNER_CHURN_TIMER,
	AD_WAIT_WHILE_TIMER
} ad_timers_t;

#pragma pack(1)

/* Link Aggregation Control Protocol(LACP) data unit structure(43.4.2.2 in the 802.3ad standard) */
typedef struct lacpdu {
	/*lacp报文为‘1’*/
	u8 subtype;		/* = LACP(= 0x01) */
	/*指明版本号*/
	u8 version_number;
	/*actor信息类型,TLV中的T*/
	u8 tlv_type_actor_info;	/* = actor information(type/length/value) */
	/*指明actor信息长度,TLV中的L*/
	u8 actor_information_length;	/* = 20 */
	/*以下共计18字节(结束于reserved_3_1[3])，指明actor信息，TLV中的V*/
	__be16 actor_system_priority;/*本端系统优先级*/
	struct mac_addr actor_system;/*系统ID，本端系统的MAC地址。*/
	/*
	 * 端口KEY值，系统根据端口的配置生成，是端口能否成为聚合组中的一员的关键因素，
	 * 影响Key值的因素有trunk ID、接口的速率和双工模式。*/
	__be16 actor_key;
	/*接口优先级，可以配置，默认为0x8000。*/
	__be16 actor_port_priority;
	/*端口号，根据算法生成，由接口所在的槽位号、子卡号和端口号决定。*/
	__be16 actor_port;
	/*
	 * 本端状态信息，比特0~7的含义分别为：
	 * LACP_Activity：代表链路所在的聚合组参与LACP协商的方式。主动的LACP被编码为1，
	 * 	主动方式下会主动发送LACPDU报文给对方，被动方式不会主动发送协商报文，除非收到
	 * 	协商报文才会参与。
	 * LACP_Timeout：代表链路接收LACPDU报文的周期，有两种，快周期1s和慢周期30s，
	 * 	超时时间为周期的3倍。短超时被编码为1，长超时被编码为0。
	 * Aggregation：标识该链路能否被聚合组聚合。如果编码为0，该链路被认为是独立的，
	 * 	不能被聚合，即，这个链路只能作为一个个体链路运行。
	 * Synchronization：代表该链路是否已被分配到一个正确的链路聚合组，如果该链路已经
	 * 	关联了一个兼容的聚合器，那么该链路聚合组的识别与系统ID和被发送的运行Key信息是一致的。
	 * 	编码为0，代表链路当前不在正确的聚合里。
	 * Collecting：帧的收集使能位，假如编码为1，表示在这个链路上进来的帧的收集是明确使能的；
	 * 	即收集当前被使能，并且不期望在没有管理变化或接收协议信息变化的情况下被禁止。其它情况下
	 * 	这个值编码为0。
	 * Distributing：帧的分配使能位，假如编码为0，意味着在这个链路上的外出帧的分配被明确禁止，
	 * 	并且不期望在没有管理变化或接收协议信息变化的情况下被使能。其它情况下这个值编码为1。
	 * Default：诊断调试时使用，编码为1，代表接收到的对端的信息是管理配置的。假如编码为0，
	 * 	正在使用的运行伙伴信息在接收到的LACPDU里。该值不被正常LACP协议使用，仅用于诊断协议问题。
	 * Expired：诊断调试时使用，编码为1，代表本端的接收机是处于EXPIRED超时状态；假如编码为0，
	 * 	本端接收状态机处于正常状态。该值不被正常LACP协议使用，仅用于诊断协议问题。
	 * */
	u8 actor_state;
	//保留字段，可用于功能调试以及扩展。
	u8 reserved_3_1[3];		/* = 0 */
	/*partner信息类型，TLV中的T*/
	/*标识TLV的类型，值为0x02代表Partner字段。*/
	u8 tlv_type_partner_info;	/* = partner information */
	/*指明partner信息字段长度，TLV中的L*/
	u8 partner_information_length;	/* = 20 */
	/*以下共计20字节（结束于reserved_3_2[3]），指明partner_information信息，TLV中的V*/
	__be16 partner_system_priority;/*对端系统优先级。*/
	struct mac_addr partner_system;/*对端系统ID，对端系统的MAC地址。*/
	__be16 partner_key;/*对端端口KEY值。*/
	__be16 partner_port_priority;/*对端接口优先级。*/
	__be16 partner_port;/*对端端口号。*/
	u8 partner_state;/*对端状态信息。*/
	/*保留字段，可用于功能调试以及扩展。*/
	u8 reserved_3_2[3];		/* = 0 */
	/*标识TLV的类型，值为0x03代表Collector字段。*/
	/*指明collector信息类型，TLV中的T*/
	u8 tlv_type_collector_info;	/* = collector information */
	/*指明Collector信息字段长度,TLV中的L*/
	u8 collector_information_length;/* = 16 */
	/*以下共计16字节（结束于reserved_50[0])*/
	__be16 collector_max_delay;/*最大延时，以10微秒为单位。*/
	u8 reserved_12[12];/*保留字段，可用于功能调试以及扩展。*/\
	/*标识TLV的类型，值为0x00代表Terminator字段。*/
	u8 tlv_type_terminator;		/* = terminator */
	/*Terminator信息字段长度，取值为0（即0x00）。*/
	u8 terminator_length;		/* = 0 */
	/*保留字段，全置0，接收端忽略此字段。*/
	u8 reserved_50[50];		/* = 0 */
} __packed lacpdu_t;

typedef struct lacpdu_header {
	struct ethhdr hdr;/*以太头*/
	struct lacpdu lacpdu;/*lacpdu报文*/
} __packed lacpdu_header_t;

/* Marker Protocol Data Unit(PDU) structure(43.5.3.2 in the 802.3ad standard) */
typedef struct bond_marker {
	u8 subtype;		/* = 0x02  (marker PDU) */
	u8 version_number;	/* = 0x01 */
	u8 tlv_type;		/* = 0x01  (marker information) */
	/* = 0x02  (marker response information) */
	u8 marker_length;	/* = 0x16 */
	u16 requester_port;	/* The number assigned to the port by the requester */
	struct mac_addr requester_system;	/* The requester's system id */
	u32 requester_transaction_id;		/* The transaction id allocated by the requester, */
	u16 pad;		/* = 0 */
	u8 tlv_type_terminator;	/* = 0x00 */
	u8 terminator_length;	/* = 0x00 */
	u8 reserved_90[90];	/* = 0 */
} __packed bond_marker_t;

typedef struct bond_marker_header {
	struct ethhdr hdr;
	struct bond_marker marker;
} __packed bond_marker_header_t;

#pragma pack()

struct slave;
struct bonding;
struct ad_info;
struct port;

#ifdef __ia64__
#pragma pack(8)
#endif

struct bond_3ad_stats {
	atomic64_t lacpdu_rx;/*收到的lacp数目*/
	atomic64_t lacpdu_tx;/*发出的lacp数目*/
	atomic64_t lacpdu_unknown_rx;
	atomic64_t lacpdu_illegal_rx;

	atomic64_t marker_rx;
	atomic64_t marker_tx;
	atomic64_t marker_resp_rx;
	atomic64_t marker_resp_tx;
	atomic64_t marker_unknown_rx;
};

/* aggregator structure(43.4.5 in the 802.3ad standard) */
typedef struct aggregator {
	struct mac_addr aggregator_mac_address;
	u16 aggregator_identifier;
	bool is_individual;
	u16 actor_admin_aggregator_key;
	u16 actor_oper_aggregator_key;
	struct mac_addr partner_system;
	u16 partner_system_priority;
	u16 partner_oper_aggregator_key;
	u16 receive_state;	/* BOOLEAN */
	u16 transmit_state;	/* BOOLEAN */
	struct port *lag_ports;
	/* ****** PRIVATE PARAMETERS ****** */
	struct slave *slave;	/* pointer to the bond slave that this aggregator belongs to */
	u16 is_active;		/* BOOLEAN. Indicates if this aggregator is active */
	u16 num_of_ports;
} aggregator_t;

struct port_params {
	struct mac_addr system;/*系统ID*/
	u16 system_priority;/*系统优先级*/
	u16 key;/*端口KEY值*/
	u16 port_number;/*port编号*/
	u16 port_priority;/*接口优先级*/
	u16 port_state;/*port状态*/
};

/* port structure(43.4.6 in the 802.3ad standard) */
typedef struct port {
	//端口号，根据算法生成，由接口所在的槽位号、子卡号和端口号决定。对应报文中的actor_port
	u16 actor_port_number;
	//接口优先级，可以配置，默认为0x8000。对应报文中的actor_port_priority
	u16 actor_port_priority;
	//系统ID，本端系统的MAC地址。对应报文中的actor_system
	struct mac_addr actor_system;	/* This parameter is added here although it is not specified in the standard, just for simplification */
	//本端系统优先级，可以设置，默认情况下为32768(即0x8000)。对应报文中的actor_system_priority
	u16 actor_system_priority;	/* This parameter is added here although it is not specified in the standard, just for simplification */
	/*对端port状态*/
	u16 actor_port_aggregator_identifier;
	bool ntt;
	u16 actor_admin_port_key;
	//端口KEY值，系统根据端口的配置生成，是端口能否成为聚合组中的一员的关键因素，
	// 影响Key值的因素有trunk ID、接口的速率和双工模式。（对应报文中的actor_key）
	u16 actor_oper_port_key;
	u8 actor_admin_port_state;
	/*本端port状态，对应报文中的actor_state*/
	u8 actor_oper_port_state;

	struct port_params partner_admin;
	struct port_params partner_oper;/*对应报文中partner的6个字段*/

	bool is_enabled;

	/* ****** PRIVATE PARAMETERS ****** */
	u16 sm_vars;		/* all state machines variables for this port */
	rx_states_t sm_rx_state;	/* state machine rx state */
	u16 sm_rx_timer_counter;	/* state machine rx timer counter */
	periodic_states_t sm_periodic_state;	/* state machine periodic state */
	u16 sm_periodic_timer_counter;	/* state machine periodic timer counter */
	mux_states_t sm_mux_state;	/* state machine mux state */
	u16 sm_mux_timer_counter;	/* state machine mux timer counter */
	tx_states_t sm_tx_state;	/* state machine tx state */
	u16 sm_tx_timer_counter;	/* state machine tx timer counter(allways on - enter to transmit state 3 time per second) */
	u16 sm_churn_actor_timer_counter;
	u16 sm_churn_partner_timer_counter;
	u32 churn_actor_count;
	u32 churn_partner_count;
	churn_state_t sm_churn_actor_state;
	churn_state_t sm_churn_partner_state;
	/*此port所属的slave*/
	struct slave *slave;		/* pointer to the bond slave that this port belongs to */
	struct aggregator *aggregator;	/* pointer to an aggregator that this port related to */
	struct port *next_port_in_aggregator;	/* Next port on the linked list of the parent aggregator */
	u32 transaction_id;		/* continuous number for identification of Marker PDU's; */
	/*记录此port上关联的要发送的lacpdu*/
	struct lacpdu lacpdu;		/* the lacpdu that will be sent for this port */
} port_t;

/* system structure */
struct ad_system {
	u16 sys_priority;
	struct mac_addr sys_mac_addr;
};

#ifdef __ia64__
#pragma pack()
#endif

/* ========== AD Exported structures to the main bonding code ========== */
#define BOND_AD_INFO(bond)   ((bond)->ad_info)
#define SLAVE_AD_INFO(slave) ((slave)->ad_info)

struct ad_bond_info {
	struct ad_system system;	/* 802.3ad system structure */
	struct bond_3ad_stats stats;
	atomic_t agg_select_timer;		/* Timer to select aggregator after all adapter's hand shakes */
	u16 aggregator_identifier;
};

struct ad_slave_info {
	struct aggregator aggregator;	/* 802.3ad aggregator structure */
	struct port port;		/* 802.3ad port structure */
	struct bond_3ad_stats stats;
	u16 id;
};

static inline const char *bond_3ad_churn_desc(churn_state_t state)
{
	static const char *const churn_description[] = {
		"monitoring",
		"churned",
		"none",
		"unknown"
	};
	int max_size = ARRAY_SIZE(churn_description);

	if (state >= max_size)
		state = max_size - 1;

	return churn_description[state];
}

/* ========== AD Exported functions to the main bonding code ========== */
void bond_3ad_initialize(struct bonding *bond);
void bond_3ad_bind_slave(struct slave *slave);
void bond_3ad_unbind_slave(struct slave *slave);
void bond_3ad_state_machine_handler(struct work_struct *);
void bond_3ad_initiate_agg_selection(struct bonding *bond, int timeout);
void bond_3ad_adapter_speed_duplex_changed(struct slave *slave);
void bond_3ad_handle_link_change(struct slave *slave, char link);
int  bond_3ad_get_active_agg_info(struct bonding *bond, struct ad_info *ad_info);
int  __bond_3ad_get_active_agg_info(struct bonding *bond,
				    struct ad_info *ad_info);
int bond_3ad_lacpdu_recv(const struct sk_buff *skb, struct bonding *bond,
			 struct slave *slave);
int bond_3ad_set_carrier(struct bonding *bond);
void bond_3ad_update_lacp_rate(struct bonding *bond);
void bond_3ad_update_ad_actor_settings(struct bonding *bond);
int bond_3ad_stats_fill(struct sk_buff *skb, struct bond_3ad_stats *stats);
size_t bond_3ad_stats_size(void);
#endif /* _NET_BOND_3AD_H */

