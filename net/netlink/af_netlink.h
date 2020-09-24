/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <net/sock.h>

/* flags */
//标记netlink socket属于kernel socket
#define NETLINK_F_KERNEL_SOCKET		0x1
#define NETLINK_F_RECV_PKTINFO		0x2
#define NETLINK_F_BROADCAST_SEND_ERROR	0x4
#define NETLINK_F_RECV_NO_ENOBUFS	0x8
#define NETLINK_F_LISTEN_ALL_NSID	0x10
#define NETLINK_F_CAP_ACK		0x20
#define NETLINK_F_EXT_ACK		0x40
#define NETLINK_F_STRICT_CHK		0x80

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	u32			portid;
	u32			dst_portid;
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	u32			ngroups;
	unsigned long		*groups;
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			bound;
	//如果此值为true,则收取时需要再dump一次
	bool			cb_running;
	int			dump_done_errno;
	//netlink socket回调上下文
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	//负责收取netlink消息（每个protocol一个对应的netlink_rcv)
	//所有发向kernel的netlink消息均均会调用此函数
	void			(*netlink_rcv)(struct sk_buff *skb);
	int			(*netlink_bind)(struct net *net, int group);
	void			(*netlink_unbind)(struct net *net, int group);
	struct module		*module;

	struct rhash_head	node;
	struct rcu_head		rcu;
	struct work_struct	work;
};

static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

struct netlink_table {
	struct rhashtable	hash;
	struct hlist_head	mc_list;
	struct listeners __rcu	*listeners;
	unsigned int		flags;
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;//协议属于那个模块
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	bool			(*compare)(struct net *net, struct sock *sock);
	int			registered;//此协议是否被注册（多次注册表示注册次数）
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;

#endif
