/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INETDEVICE_H
#define _LINUX_INETDEVICE_H

#ifdef __KERNEL__

#include <linux/bitmap.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>
#include <linux/sysctl.h>
#include <linux/rtnetlink.h>
#include <linux/refcount.h>

struct ipv4_devconf {
	void	*sysctl;
	/*inet设备配置*/
	int	data[IPV4_DEVCONF_MAX];
	DECLARE_BITMAP(state, IPV4_DEVCONF_MAX);
};

#define MC_HASH_SZ_LOG 9

//inet4_dev结构体（ipv4设备结构体）
struct in_device {
	struct net_device	*dev;//关联(所属）的net_device
	netdevice_tracker	dev_tracker;

	refcount_t		refcnt;//设备引用计数
	int			dead;
	//inet4设备上所有ip地址列表
	struct in_ifaddr	__rcu *ifa_list;/* IP ifaddr chain		*/

	/*inet4设备关注的组播组*/
	struct ip_mc_list __rcu	*mc_list;	/* IP multicast filter chain    */
	struct ip_mc_list __rcu	* __rcu *mc_hash;

	int			mc_count;	/* Number of installed mcasts	*/
	spinlock_t		mc_tomb_lock;
	struct ip_mc_list	*mc_tomb;
	unsigned long		mr_v1_seen;
	unsigned long		mr_v2_seen;
	unsigned long		mr_maxdelay;
	unsigned long		mr_qi;		/* Query Interval */
	unsigned long		mr_qri;		/* Query Response Interval */
	unsigned char		mr_qrv;		/* Query Robustness Variable */
	unsigned char		mr_gq_running;
	u32			mr_ifc_count;
	struct timer_list	mr_gq_timer;	/* general query timer */
	struct timer_list	mr_ifc_timer;	/* interface change timer */

	struct neigh_parms	*arp_parms;
	//ipv4设备配置
	struct ipv4_devconf	cnf;
	struct rcu_head		rcu_head;
};

/*取attr对应的配置*/
#define IPV4_DEVCONF(cnf, attr) ((cnf).data[IPV4_DEVCONF_ ## attr - 1])
#define IPV4_DEVCONF_ALL(net, attr) \
	IPV4_DEVCONF((*(net)->ipv4.devconf_all), attr)

/*取ipv4设备具体的一个配置项*/
static inline int ipv4_devconf_get(struct in_device *in_dev, int index)
{
	index--;
	return in_dev->cnf.data[index];
}

//设置具体的一项inet4设备配置
static inline void ipv4_devconf_set(struct in_device *in_dev, int index,
				    int val)
{
	index--;
	set_bit(index, in_dev->cnf.state);
	in_dev->cnf.data[index] = val;
}

static inline void ipv4_devconf_setall(struct in_device *in_dev)
{
	bitmap_fill(in_dev->cnf.state, IPV4_DEVCONF_MAX);
}

/*Ipv4设备属性获取*/
#define IN_DEV_CONF_GET(in_dev, attr) \
	ipv4_devconf_get((in_dev), IPV4_DEVCONF_ ## attr)
/*ipv4设备属性设置*/
#define IN_DEV_CONF_SET(in_dev, attr, val) \
	ipv4_devconf_set((in_dev), IPV4_DEVCONF_ ## attr, (val))

#define IN_DEV_ANDCONF(in_dev, attr) \
	(IPV4_DEVCONF_ALL(dev_net(in_dev->dev), attr) && \
	 IN_DEV_CONF_GET((in_dev), attr))

#define IN_DEV_NET_ORCONF(in_dev, net, attr) \
	(IPV4_DEVCONF_ALL(net, attr)/*取all 设备配置*/ || \
	 IN_DEV_CONF_GET((in_dev), attr)/*取给定设备的配置*/)

#define IN_DEV_ORCONF(in_dev, attr) \
	IN_DEV_NET_ORCONF(in_dev, dev_net(in_dev->dev), attr)

#define IN_DEV_MAXCONF(in_dev, attr) \
	(max(IPV4_DEVCONF_ALL(dev_net(in_dev->dev), attr), \
	     IN_DEV_CONF_GET((in_dev), attr)))

/*ipv4设备是否处理转发状态*/
#define IN_DEV_FORWARD(in_dev)		IN_DEV_CONF_GET((in_dev), FORWARDING)
#define IN_DEV_MFORWARD(in_dev)		IN_DEV_ANDCONF((in_dev), MC_FORWARDING)
#define IN_DEV_BFORWARD(in_dev)		IN_DEV_ANDCONF((in_dev), BC_FORWARDING)
#define IN_DEV_RPFILTER(in_dev)		IN_DEV_MAXCONF((in_dev), RP_FILTER)
#define IN_DEV_SRC_VMARK(in_dev)    	IN_DEV_ORCONF((in_dev), SRC_VMARK)
#define IN_DEV_SOURCE_ROUTE(in_dev)	IN_DEV_ANDCONF((in_dev), \
						       ACCEPT_SOURCE_ROUTE)
#define IN_DEV_ACCEPT_LOCAL(in_dev)	IN_DEV_ORCONF((in_dev), ACCEPT_LOCAL)
#define IN_DEV_BOOTP_RELAY(in_dev)	IN_DEV_ANDCONF((in_dev), BOOTP_RELAY)

#define IN_DEV_LOG_MARTIANS(in_dev)	IN_DEV_ORCONF((in_dev), LOG_MARTIANS)
#define IN_DEV_PROXY_ARP(in_dev)	IN_DEV_ORCONF((in_dev), PROXY_ARP)
#define IN_DEV_PROXY_ARP_PVLAN(in_dev)	IN_DEV_ORCONF((in_dev), PROXY_ARP_PVLAN)
#define IN_DEV_SHARED_MEDIA(in_dev)	IN_DEV_ORCONF((in_dev), SHARED_MEDIA)
#define IN_DEV_TX_REDIRECTS(in_dev)	IN_DEV_ORCONF((in_dev), SEND_REDIRECTS)
#define IN_DEV_SEC_REDIRECTS(in_dev)	IN_DEV_ORCONF((in_dev), \
						      SECURE_REDIRECTS)
#define IN_DEV_IDTAG(in_dev)		IN_DEV_CONF_GET(in_dev, TAG)
#define IN_DEV_MEDIUM_ID(in_dev)	IN_DEV_CONF_GET(in_dev, MEDIUM_ID)
#define IN_DEV_PROMOTE_SECONDARIES(in_dev) \
					IN_DEV_ORCONF((in_dev), \
						      PROMOTE_SECONDARIES)
#define IN_DEV_ROUTE_LOCALNET(in_dev)	IN_DEV_ORCONF(in_dev, ROUTE_LOCALNET)
#define IN_DEV_NET_ROUTE_LOCALNET(in_dev, net)	\
	IN_DEV_NET_ORCONF(in_dev, net, ROUTE_LOCALNET)

#define IN_DEV_RX_REDIRECTS(in_dev) \
	((IN_DEV_FORWARD(in_dev) && \
	  IN_DEV_ANDCONF((in_dev), ACCEPT_REDIRECTS)) \
	 || (!IN_DEV_FORWARD(in_dev) && \
	  IN_DEV_ORCONF((in_dev), ACCEPT_REDIRECTS)))

#define IN_DEV_IGNORE_ROUTES_WITH_LINKDOWN(in_dev) \
	IN_DEV_ORCONF((in_dev), IGNORE_ROUTES_WITH_LINKDOWN)

#define IN_DEV_ARPFILTER(in_dev)	IN_DEV_ORCONF((in_dev), ARPFILTER)
#define IN_DEV_ARP_ACCEPT(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_ACCEPT)
#define IN_DEV_ARP_ANNOUNCE(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_ANNOUNCE)
#define IN_DEV_ARP_IGNORE(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_IGNORE)
#define IN_DEV_ARP_NOTIFY(in_dev)	IN_DEV_MAXCONF((in_dev), ARP_NOTIFY)
#define IN_DEV_ARP_EVICT_NOCARRIER(in_dev) IN_DEV_ANDCONF((in_dev), \
							  ARP_EVICT_NOCARRIER)

//inet4接口地址（对inet4简写成in表示很无语）
struct in_ifaddr {
	struct hlist_node	hash;
	//用于串连下一个inet4接口地址
	struct in_ifaddr	__rcu *ifa_next;
	/*地址对应的inet4设备*/
	struct in_device	*ifa_dev;
	struct rcu_head		rcu_head;
	//本端接口地址
	__be32			ifa_local;
	//对端接口地址（如果未设置对端地址，则与ifa_local相同）
	__be32			ifa_address;
	/*地址前缀掩码形式*/
	__be32			ifa_mask;
	__u32			ifa_rt_priority;
	/*广播地址*/
	__be32			ifa_broadcast;
	/*地址scope*/
	unsigned char		ifa_scope;
	/*地址前缀长度*/
	unsigned char		ifa_prefixlen;
	unsigned char		ifa_proto;
	/*地址对应的flags*/
	__u32			ifa_flags;
	/*标签*/
	char			ifa_label[IFNAMSIZ];

	/* In seconds, relative to tstamp. Expiry is at tstamp + HZ * lft. */
	__u32			ifa_valid_lft;
	__u32			ifa_preferred_lft;
	unsigned long		ifa_cstamp; /* created timestamp */
	unsigned long		ifa_tstamp; /* updated timestamp */
};

struct in_validator_info {
	__be32			ivi_addr;
	struct in_device	*ivi_dev;
	struct netlink_ext_ack	*extack;
};

int register_inetaddr_notifier(struct notifier_block *nb);
int unregister_inetaddr_notifier(struct notifier_block *nb);
int register_inetaddr_validator_notifier(struct notifier_block *nb);
int unregister_inetaddr_validator_notifier(struct notifier_block *nb);

void inet_netconf_notify_devconf(struct net *net, int event, int type,
				 int ifindex, struct ipv4_devconf *devconf);

struct net_device *__ip_dev_find(struct net *net, __be32 addr, bool devref);
static inline struct net_device *ip_dev_find(struct net *net, __be32 addr)
{
	return __ip_dev_find(net, addr, true);
}

int inet_addr_onlink(struct in_device *in_dev, __be32 a, __be32 b);
int devinet_ioctl(struct net *net, unsigned int cmd, struct ifreq *);
#ifdef CONFIG_INET
int inet_gifconf(struct net_device *dev, char __user *buf, int len, int size);
#else
static inline int inet_gifconf(struct net_device *dev, char __user *buf,
			       int len, int size)
{
	return 0;
}
#endif
void devinet_init(void);
struct in_device *inetdev_by_index(struct net *, int);
__be32 inet_select_addr(const struct net_device *dev, __be32 dst, int scope);
__be32 inet_confirm_addr(struct net *net, struct in_device *in_dev, __be32 dst,
			 __be32 local, int scope);
struct in_ifaddr *inet_ifa_byprefix(struct in_device *in_dev, __be32 prefix,
				    __be32 mask);
struct in_ifaddr *inet_lookup_ifaddr_rcu(struct net *net, __be32 addr);
//地址addr是否与ifa->ifa_address在同一个掩码下
static inline bool inet_ifa_match(__be32 addr, const struct in_ifaddr *ifa)
{
	return !((addr^ifa->ifa_address)&ifa->ifa_mask);
}

/*
 *	Check if a mask is acceptable.
 */
 
static __inline__ bool bad_mask(__be32 mask, __be32 addr)
{
	//传入的mask应为0x000000ff格式，按位取反后为0xffffff00
	__u32 hmask;
	//取mask按位取反与addr与后，如果非0，则返回true
	if (addr & (mask = ~mask))
		//用于限制必须为非0网段
		return true;
	hmask = ntohl(mask);
	//用于限制hmask从高位开始，不能有'0'，必须是一组连续的'1'
	if (hmask & (hmask+1))
		return true;
	return false;
}

//遍历此in_dev上所有ip地址列表
#define in_dev_for_each_ifa_rtnl(ifa, in_dev)			\
	for (ifa = rtnl_dereference((in_dev)->ifa_list); ifa;	\
	     ifa = rtnl_dereference(ifa->ifa_next))

//遍历此in_dev上所有ip地址列表
#define in_dev_for_each_ifa_rcu(ifa, in_dev)			\
	for (ifa = rcu_dereference((in_dev)->ifa_list); ifa;	\
	     ifa = rcu_dereference(ifa->ifa_next))

static inline struct in_device *__in_dev_get_rcu(const struct net_device *dev)
{
	//取dev对外显现的ipv4设备
	return rcu_dereference(dev->ip_ptr);
}

/*取ipv4地址*/
static inline struct in_device *in_dev_get(const struct net_device *dev)
{
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev)
		refcount_inc(&in_dev->refcnt);
	rcu_read_unlock();
	return in_dev;
}

static inline struct in_device *__in_dev_get_rtnl(const struct net_device *dev)
{
	return rtnl_dereference(dev->ip_ptr);
}

/* called with rcu_read_lock or rtnl held */
static inline bool ip_ignore_linkdown(const struct net_device *dev)
{
	struct in_device *in_dev;
	bool rc = false;

	in_dev = rcu_dereference_rtnl(dev->ip_ptr);
	if (in_dev &&
	    IN_DEV_IGNORE_ROUTES_WITH_LINKDOWN(in_dev))
		rc = true;

	return rc;
}

static inline struct neigh_parms *__in_dev_arp_parms_get_rcu(const struct net_device *dev)
{
	struct in_device *in_dev = __in_dev_get_rcu(dev);

	return in_dev ? in_dev->arp_parms : NULL;
}

void in_dev_finish_destroy(struct in_device *idev);

static inline void in_dev_put(struct in_device *idev)
{
	if (refcount_dec_and_test(&idev->refcnt))
		in_dev_finish_destroy(idev);
}

#define __in_dev_put(idev)  refcount_dec(&(idev)->refcnt)
#define in_dev_hold(idev)   refcount_inc(&(idev)->refcnt)

#endif /* __KERNEL__ */

//构造指定掩码长度的网络掩码
static __inline__ __be32 inet_make_mask(int logmask)
{
	if (logmask)
		return htonl(~((1U<<(32-logmask))-1));
	return 0;
}

//取掩码长度
static __inline__ int inet_mask_len(__be32 mask)
{
	__u32 hmask = ntohl(mask);
	if (!hmask)
		return 0;//掩码长度为0
	return 32 - ffz(~hmask);
}


#endif /* _LINUX_INETDEVICE_H */
