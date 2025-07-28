/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_RTNETLINK_H
#define __NET_RTNETLINK_H

#include <linux/rtnetlink.h>
#include <linux/srcu.h>
#include <net/netlink.h>

typedef int (*rtnl_doit_func)(struct sk_buff *, struct nlmsghdr *,
			      struct netlink_ext_ack *);
typedef int (*rtnl_dumpit_func)(struct sk_buff *, struct netlink_callback *);

/*指明不加锁调用doit*/
enum rtnl_link_flags {
	RTNL_FLAG_DOIT_UNLOCKED		= BIT(0),
#define RTNL_FLAG_DOIT_PERNET		RTNL_FLAG_DOIT_UNLOCKED
#define RTNL_FLAG_DOIT_PERNET_WIP	RTNL_FLAG_DOIT_UNLOCKED
	RTNL_FLAG_BULK_DEL_SUPPORTED	= BIT(1),
	RTNL_FLAG_DUMP_UNLOCKED		= BIT(2),
	RTNL_FLAG_DUMP_SPLIT_NLM_DONE	= BIT(3),	/* legacy behavior */
};

enum rtnl_kinds {
	RTNL_KIND_NEW,
	RTNL_KIND_DEL,
	RTNL_KIND_GET,
	RTNL_KIND_SET
};
#define RTNL_KIND_MASK 0x3

static inline enum rtnl_kinds rtnl_msgtype_kind(int msgtype)
{
	return msgtype & RTNL_KIND_MASK;
}

/**
 *	struct rtnl_msg_handler - rtnetlink message type and handlers
 *
 *	@owner: NULL for built-in, THIS_MODULE for module
 *	@protocol: Protocol family or PF_UNSPEC
 *	@msgtype: rtnetlink message type
 *	@doit: Function pointer called for each request message
 *	@dumpit: Function pointer called for each dump request (NLM_F_DUMP) message
 *	@flags: rtnl_link_flags to modify behaviour of doit/dumpit functions
 */
struct rtnl_msg_handler {
	struct module *owner;
	int protocol;
	int msgtype;
	rtnl_doit_func doit;
	rtnl_dumpit_func dumpit;
	int flags;
};

void rtnl_unregister_all(int protocol);

int __rtnl_register_many(const struct rtnl_msg_handler *handlers, int n);
void __rtnl_unregister_many(const struct rtnl_msg_handler *handlers, int n);

#define rtnl_register_many(handlers)				\
	__rtnl_register_many(handlers, ARRAY_SIZE(handlers))
#define rtnl_unregister_many(handlers)				\
	__rtnl_unregister_many(handlers, ARRAY_SIZE(handlers))

static inline int rtnl_msg_family(const struct nlmsghdr *nlh)
{
	if (nlmsg_len(nlh) >= sizeof(struct rtgenmsg))
		return ((struct rtgenmsg *) nlmsg_data(nlh))->rtgen_family;
	else
		return AF_UNSPEC;
}

/**
 * struct rtnl_newlink_params - parameters of rtnl_link_ops::newlink()
 *
 * @src_net: Source netns of rtnetlink socket
 * @link_net: Link netns by IFLA_LINK_NETNSID, NULL if not specified
 * @peer_net: Peer netns
 * @tb: IFLA_* attributes
 * @data: IFLA_INFO_DATA attributes
 */
struct rtnl_newlink_params {
	struct net *src_net;
	struct net *link_net;
	struct net *peer_net;
	struct nlattr **tb;
	struct nlattr **data;
};

/* Get effective link netns from newlink params. Generally, this is link_net
 * and falls back to src_net. But for compatibility, a driver may * choose to
 * use dev_net(dev) instead.
 */
static inline struct net *rtnl_newlink_link_net(struct rtnl_newlink_params *p)
{
	return p->link_net ? : p->src_net;
}

/* Get peer netns from newlink params. Fallback to link netns if peer netns is
 * not specified explicitly.
 */
static inline struct net *rtnl_newlink_peer_net(struct rtnl_newlink_params *p)
{
	return p->peer_net ? : rtnl_newlink_link_net(p);
}

/**
 *	struct rtnl_link_ops - rtnetlink link operations
 *
 *	@list: Used internally, protected by link_ops_mutex and SRCU
 *	@srcu: Used internally
 *	@kind: Identifier
 *	@netns_refund: Physical device, move to init_net on netns exit
 *	@peer_type: Peer device specific netlink attribute number (e.g. VETH_INFO_PEER)
 *	@maxtype: Highest device specific netlink attribute number
 *	@policy: Netlink policy for device specific attribute validation
 *	@validate: Optional validation function for netlink/changelink parameters
 *	@alloc: netdev allocation function, can be %NULL and is then used
 *		in place of alloc_netdev_mqs(), in this case @priv_size
 *		and @setup are unused. Returns a netdev or ERR_PTR().
 *	@priv_size: sizeof net_device private space
 *	@setup: net_device setup function
 *	@newlink: Function for configuring and registering a new device
 *	@changelink: Function for changing parameters of an existing device
 *	@dellink: Function to remove a device
 *	@get_size: Function to calculate required room for dumping device
 *		   specific netlink attributes
 *	@fill_info: Function to dump device specific netlink attributes
 *	@get_xstats_size: Function to calculate required room for dumping device
 *			  specific statistics
 *	@fill_xstats: Function to dump device specific statistics
 *	@get_num_tx_queues: Function to determine number of transmit queues
 *			    to create when creating a new device.
 *	@get_num_rx_queues: Function to determine number of receive queues
 *			    to create when creating a new device.
 *	@get_link_net: Function to get the i/o netns of the device
 *	@get_linkxstats_size: Function to calculate the required room for
 *			      dumping device-specific extended link stats
 *	@fill_linkxstats: Function to dump device-specific extended link stats
 */
struct rtnl_link_ops {
	//用于挂接在link类型注册链上
	struct list_head	list;
	struct srcu_struct	srcu;

	//link名称
	const char		*kind;

	size_t			priv_size;
	struct net_device	*(*alloc)(struct nlattr *tb[],
					  const char *ifname,
					  unsigned char name_assign_type,
					  unsigned int num_tx_queues/*tx队列数*/,
					  unsigned int num_rx_queues/*rx队列数*/);
	//link初创建时，将通过此函数完成新建link的初始化工作
	void			(*setup)(struct net_device *dev);

	bool			netns_refund;
	const u16		peer_type;
	//link独有IFLA_INFO_DATA型数据的netlink type
	unsigned int		maxtype;
	//各link中netlink type独有的数据类型，用于link数据解析
	const struct nla_policy	*policy;
	//link_info_data型消息数据体校验
	int			(*validate)(struct nlattr *tb[],
					    struct nlattr *data[],
					    struct netlink_ext_ack *extack);

	//setup后，newlink将将被调用
	int			(*newlink)(struct net_device *dev,
					   struct rtnl_newlink_params *params,
					   struct netlink_ext_ack *extack);
	//link存在时，修改link配置时将被调用
	int			(*changelink)(struct net_device *dev,
					      struct nlattr *tb[],
					      struct nlattr *data[],
					      struct netlink_ext_ack *extack);
	void			(*dellink)(struct net_device *dev,
					   struct list_head *head);

	size_t			(*get_size)(const struct net_device *dev);
	int			(*fill_info)(struct sk_buff *skb,
					     const struct net_device *dev);

	size_t			(*get_xstats_size)(const struct net_device *dev);
	int			(*fill_xstats)(struct sk_buff *skb,
					       const struct net_device *dev);
	//获取设备tx队列数目
	unsigned int		(*get_num_tx_queues)(void);
	//获取设备rx队列数目
	unsigned int		(*get_num_rx_queues)(void);

	unsigned int		slave_maxtype;
	const struct nla_policy	*slave_policy;
	/*slave配置变更时调用*/
	int			(*slave_changelink)(struct net_device *dev,
						    struct net_device *slave_dev,
						    struct nlattr *tb[],
						    struct nlattr *data[],
						    struct netlink_ext_ack *extack);
	size_t			(*get_slave_size)(const struct net_device *dev,
						  const struct net_device *slave_dev);
	int			(*fill_slave_info)(struct sk_buff *skb,
						   const struct net_device *dev,
						   const struct net_device *slave_dev);
	/*获取dev所属的net namespace*/
	struct net		*(*get_link_net)(const struct net_device *dev);
	size_t			(*get_linkxstats_size)(const struct net_device *dev,
						       int attr);
	int			(*fill_linkxstats)(struct sk_buff *skb,
						   const struct net_device *dev,
						   int *prividx, int attr);
};

int rtnl_link_register(struct rtnl_link_ops *ops);
void rtnl_link_unregister(struct rtnl_link_ops *ops);

/**
 * 	struct rtnl_af_ops - rtnetlink address family operations
 *
 *	@list: Used internally, protected by RTNL and SRCU
 *	@srcu: Used internally
 * 	@family: Address family
 * 	@fill_link_af: Function to fill IFLA_AF_SPEC with address family
 * 		       specific netlink attributes.
 * 	@get_link_af_size: Function to calculate size of address family specific
 * 			   netlink attributes.
 *	@validate_link_af: Validate a IFLA_AF_SPEC attribute, must check attr
 *			   for invalid configuration settings.
 * 	@set_link_af: Function to parse a IFLA_AF_SPEC attribute and modify
 *		      net_device accordingly.
 */
struct rtnl_af_ops {
	struct list_head	list;//用于串在rtnl_af_ops链上
	struct srcu_struct	srcu;

	int			family;//对应的family（主键）

	int			(*fill_link_af)(struct sk_buff *skb,
						const struct net_device *dev,
						u32 ext_filter_mask);
	size_t			(*get_link_af_size)(const struct net_device *dev,
						    u32 ext_filter_mask);

	//针对dev校验此af独有的属性
	int			(*validate_link_af)(const struct net_device *dev,
						    const struct nlattr *attr,
						    struct netlink_ext_ack *extack);
	//针对dev设置此af独有的属性
	int			(*set_link_af)(struct net_device *dev,
					       const struct nlattr *attr,
					       struct netlink_ext_ack *extack);
	int			(*fill_stats_af)(struct sk_buff *skb,
						 const struct net_device *dev);
	size_t			(*get_stats_af_size)(const struct net_device *dev);
};

int rtnl_af_register(struct rtnl_af_ops *ops);
void rtnl_af_unregister(struct rtnl_af_ops *ops);

struct net *rtnl_link_get_net(struct net *src_net, struct nlattr *tb[]);
struct net_device *rtnl_create_link(struct net *net, const char *ifname,
				    unsigned char name_assign_type,
				    const struct rtnl_link_ops *ops,
				    struct nlattr *tb[],
				    struct netlink_ext_ack *extack);
int rtnl_delete_link(struct net_device *dev, u32 portid, const struct nlmsghdr *nlh);
int rtnl_configure_link(struct net_device *dev, const struct ifinfomsg *ifm,
			u32 portid, const struct nlmsghdr *nlh);

int rtnl_nla_parse_ifinfomsg(struct nlattr **tb, const struct nlattr *nla_peer,
			     struct netlink_ext_ack *exterr);
struct net *rtnl_get_net_ns_capable(struct sock *sk, int netnsid);

#define MODULE_ALIAS_RTNL_LINK(kind) MODULE_ALIAS("rtnl-link-" kind)

#endif
