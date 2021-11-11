/*
 * Equalizer Load-balancer for serial network interfaces.
 *
 * (c) Copyright 1995 Simon "Guru Aleph-Null" Janes
 * NCM: Network and Communications Management, Inc.
 *
 *
 *	This software may be used and distributed according to the terms
 *	of the GNU General Public License, incorporated herein by reference.
 * 
 * The author may be reached as simon@ncm.com, or C/O
 *    NCM
 *    Attn: Simon Janes
 *    6803 Whittier Ave
 *    McLean VA 22101
 *    Phone: 1-703-847-0040 ext 103
 */
#ifndef _LINUX_IF_EQL_H
#define _LINUX_IF_EQL_H


#include <linux/timer.h>
#include <linux/spinlock.h>
#include <uapi/linux/if_eql.h>

typedef struct slave {
	struct list_head	list;
	struct net_device	*dev;/*salve对应的网络设备*/
	long			priority;/*对应的优先级*/
	long			priority_bps;/*以bit为单位的优先级*/
	long			priority_Bps;/*以byte为单位的优先级*/
	long			bytes_queued;/*积压在此slve上待发送的报文字节长度*/
} slave_t;

typedef struct slave_queue {
	spinlock_t		lock;
	struct list_head	all_slaves;/*记录当前配置的所有slave*/
	int			num_slaves;/*all_slaves队列中slave的数目(队列长度）*/
	struct net_device	*master_dev;
} slave_queue_t;

typedef struct equalizer {
	slave_queue_t		queue;
	int			min_slaves;/*eal必须的最小slave数目*/
	int			max_slaves;/*eql容许的最大slave数目*/
	struct timer_list	timer;
} equalizer_t;  

#endif /* _LINUX_EQL_H */
