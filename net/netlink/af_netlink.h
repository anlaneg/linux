/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>

/* flags */
enum {
	//标记netlink socket属于kernel socket
	NETLINK_F_KERNEL_SOCKET,
	NETLINK_F_RECV_PKTINFO,
	NETLINK_F_BROADCAST_SEND_ERROR,
	NETLINK_F_RECV_NO_ENOBUFS,
	NETLINK_F_LISTEN_ALL_NSID,/*是否监听所有netns*/
	NETLINK_F_CAP_ACK,
	NETLINK_F_EXT_ACK,
	NETLINK_F_STRICT_CHK,
};

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	unsigned long		flags;/*标记位，可通过setsocketop设置，例如NETLINK_F_EXT_ACK*/
	u32			portid;/*本端portid*/
	u32			dst_portid;/*目的portid*/
	u32			dst_group;/*目的group*/
	u32			subscriptions;/*订阅组播组总数目（即是否加入到mc_list)*/
	u32			ngroups;/*记录groups空间大小*/
	/*本端组播group标记，用于指明具体一个group是否被订阅/退订情况*/
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
	//负责收取netlink消息（每个protocol一个对应的netlink_rcv)
	//所有发向kernel的netlink消息均均会调用此函数
	struct mutex		nl_cb_mutex;

	void			(*netlink_rcv)(struct sk_buff *skb);
	/*用于绑定/订阅新的组播组*/
	int			(*netlink_bind)(struct net *net, int group);
	/*用于group解梆*/
	void			(*netlink_unbind)(struct net *net, int group);
	void			(*netlink_release)(struct sock *sk,
						   unsigned long *groups);
	struct module		*module;/*所属kernel module*/

	struct rhash_head	node;/*用于添加进hash表*/
	struct rcu_head		rcu;
};

/*转换为netlink socket*/
static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

#define nlk_test_bit(nr, sk) test_bit(NETLINK_F_##nr, &nlk_sk(sk)->flags)

struct netlink_table {
	struct rhashtable	hash;/*用于串连所有netlink socket*/
	struct hlist_head	mc_list;/*用于串连此协议的组播发送socket列表*/
	struct listeners __rcu	*listeners;
	unsigned int		flags;
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;//协议属于那个模块
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	void                    (*release)(struct sock *sk,
					   unsigned long *groups);
	int			registered;//此协议是否被注册（多次注册表示注册次数）
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;

#endif
