// SPDX-License-Identifier: GPL-2.0
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/wext.h>

#include "dev.h"

#define BUCKET_SPACE (32 - NETDEV_HASHBITS - 1)

#define get_bucket(x) ((x) >> BUCKET_SPACE)
#define get_offset(x) ((x) & ((1 << BUCKET_SPACE) - 1))
#define set_bucket_offset(b, o) ((b) << BUCKET_SPACE | (o))

//pos是一个bucket_idx合上offset的结构，通过pos可以知道需要获取哪个桶的第几个元素
static inline struct net_device *dev_from_same_bucket(struct seq_file *seq, loff_t *pos)
{
	struct net *net = seq_file_net(seq);//取对应的net
	struct net_device *dev;
	struct hlist_head *h;
	unsigned int count = 0, offset = get_offset(*pos);

	//遍历所有网络设备，自get_bucket(*pos)链上找出第offset个元素返回
	h = &net->dev_index_head[get_bucket(*pos)];
	hlist_for_each_entry_rcu(dev, h, index_hlist) {
		if (++count == offset)
			return dev;
	}

	return NULL;
}

//返回seq对应的所有dev设备
static inline struct net_device *dev_from_bucket(struct seq_file *seq, loff_t *pos)
{
	struct net_device *dev;
	unsigned int bucket;

	do {
		//获取对应的dev
		dev = dev_from_same_bucket(seq, pos);
		if (dev)
			return dev;

		//这个桶上没有元素了，切换桶号
		bucket = get_bucket(*pos) + 1;
		*pos = set_bucket_offset(bucket, 1);//置offset为１，重新获取
	} while (bucket < NETDEV_HASHENTRIES);

	return NULL;//所有桶已完成遍历，返回
}

/*
 *	This is invoked by the /proc filesystem handler to display a device
 *	in detail.
 */
static void *dev_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	rcu_read_lock();
	if (!*pos)
		return SEQ_START_TOKEN;

	if (get_bucket(*pos) >= NETDEV_HASHENTRIES)
		return NULL;

	//取pos对应的设备（pos为１）
	return dev_from_bucket(seq, pos);
}

//增加pos位置，获取下一个dev元素
static void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return dev_from_bucket(seq, pos);
}

static void dev_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static void dev_seq_printf_stats(struct seq_file *seq, struct net_device *dev)
{
	struct rtnl_link_stats64 temp;
	const struct rtnl_link_stats64 *stats = dev_get_stats(dev, &temp);

	seq_printf(seq, "%6s: %7llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu "
		   "%8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
		   dev->name, stats->rx_bytes, stats->rx_packets,
		   stats->rx_errors,
		   stats->rx_dropped + stats->rx_missed_errors,
		   stats->rx_fifo_errors,
		   stats->rx_length_errors + stats->rx_over_errors +
		    stats->rx_crc_errors + stats->rx_frame_errors,
		   stats->rx_compressed, stats->multicast,
		   stats->tx_bytes, stats->tx_packets,
		   stats->tx_errors, stats->tx_dropped,
		   stats->tx_fifo_errors, stats->collisions,
		   stats->tx_carrier_errors +
		    stats->tx_aborted_errors +
		    stats->tx_window_errors +
		    stats->tx_heartbeat_errors,
		   stats->tx_compressed);
}

/*
 *	Called from the PROCfs module. This now uses the new arbitrary sized
 *	/proc/net interface to create /proc/net/dev
 */
static int dev_seq_show(struct seq_file *seq, void *v)
{
    /*显示/proc/net/dev文件*/
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Inter-|   Receive                            "
			      "                    |  Transmit\n"
			      " face |bytes    packets errs drop fifo frame "
			      "compressed multicast|bytes    packets errs "
			      "drop fifo colls carrier compressed\n");
	else
		dev_seq_printf_stats(seq, v/*网络设备*/);
	return 0;
}

static u32 softnet_input_pkt_queue_len(struct softnet_data *sd)
{
	return skb_queue_len_lockless(&sd->input_pkt_queue);
}

static u32 softnet_process_queue_len(struct softnet_data *sd)
{
	return skb_queue_len_lockless(&sd->process_queue);
}

static struct softnet_data *softnet_get_online(loff_t *pos)
{
	struct softnet_data *sd = NULL;

	while (*pos < nr_cpu_ids)
		if (cpu_online(*pos)) {
			sd = &per_cpu(softnet_data, *pos);
			break;
		} else
			++*pos;
	return sd;
}

static void *softnet_seq_start(struct seq_file *seq, loff_t *pos)
{
	return softnet_get_online(pos);
}

static void *softnet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return softnet_get_online(pos);
}

static void softnet_seq_stop(struct seq_file *seq, void *v)
{
}

static int softnet_seq_show(struct seq_file *seq, void *v)
{
	struct softnet_data *sd = v;
	u32 input_qlen = softnet_input_pkt_queue_len(sd);/*入方向队列长度*/
	u32 process_qlen = softnet_process_queue_len(sd);
	unsigned int flow_limit_count = 0;

#ifdef CONFIG_NET_FLOW_LIMIT
	struct sd_flow_limit *fl;

	rcu_read_lock();
	fl = rcu_dereference(sd->flow_limit);
	if (fl)
		flow_limit_count = fl->count;
	rcu_read_unlock();
#endif

	/* the index is the CPU id owing this sd. Since offline CPUs are not
	 * displayed, it would be othrwise not trivial for the user-space
	 * mapping the data a specific CPU
	 */
	seq_printf(seq,
		   "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x "
		   "%08x %08x\n",
		   sd->processed/*处理数*/, sd->dropped/*丢包数*/, sd->time_squeeze, 0,
		   0, 0, 0, 0, /* was fastroute */
		   0,	/* was cpu_collision */
		   sd->received_rps, flow_limit_count,
		   input_qlen + process_qlen, (int)seq->index,
		   input_qlen, process_qlen);
	return 0;
}

static const struct seq_operations dev_seq_ops = {
	.start = dev_seq_start,
	.next  = dev_seq_next,
	.stop  = dev_seq_stop,
	.show  = dev_seq_show,
};

static const struct seq_operations softnet_seq_ops = {
	.start = softnet_seq_start,
	.next  = softnet_seq_next,
	.stop  = softnet_seq_stop,
	.show  = softnet_seq_show,
};

//给一个偏移，查找对应的packet_type
static void *ptype_get_idx(struct seq_file *seq, loff_t pos)
{
	struct list_head *ptype_list = NULL;
	struct packet_type *pt = NULL;
	struct net_device *dev;
	loff_t i = 0;
	int t;

	for_each_netdev_rcu(seq_file_net(seq), dev) {
		ptype_list = &dev->ptype_all;
		list_for_each_entry_rcu(pt, ptype_list, list) {
			if (i == pos)
				return pt;
			++i;
		}
	}

	//每个ptype计一个数(先排ptype_all)
	list_for_each_entry_rcu(pt, &ptype_all, list) {
		if (i == pos)
			return pt;
		++i;
	}

	//每个ptype计一个数（后排ptype_base)
	for (t = 0; t < PTYPE_HASH_SIZE; t++) {
		list_for_each_entry_rcu(pt, &ptype_base[t], list) {
			if (i == pos)
				return pt;
			++i;
		}
	}
	return NULL;
}

//自pos位置开始，如果pos有值，则返回pos处对应的packet_type,否则返回start_token
static void *ptype_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	rcu_read_lock();
	return *pos ? ptype_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

//返回v对应的下一个packet_type,出参pos,设置对应的偏移量
static void *ptype_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct net_device *dev;
	struct packet_type *pt;
	struct list_head *nxt;
	int hash;

	++*pos;
	//返回第0个,处理start_token
	if (v == SEQ_START_TOKEN)
		return ptype_get_idx(seq, 0);

	pt = v;//取出传入的start情况
	nxt = pt->list.next;//start的下一个
	if (pt->dev) {
		if (nxt != &pt->dev->ptype_all)
			goto found;

		dev = pt->dev;
		for_each_netdev_continue_rcu(seq_file_net(seq), dev) {
			if (!list_empty(&dev->ptype_all)) {
				nxt = dev->ptype_all.next;
				goto found;
			}
		}

		nxt = ptype_all.next;
		goto ptype_all;
	}

	if (pt->type == htons(ETH_P_ALL)) {
ptype_all:
		if (nxt != &ptype_all)
			goto found;//如果没有到达链表尾，则意味着找到了，跳found
		//已到达ptype_all的链表尾，跳ptype_base的首个
		hash = 0;
		nxt = ptype_base[0].next;
	} else
		hash = ntohs(pt->type) & PTYPE_HASH_MASK;

	//检查对应hash的首个nxt,如果相等，说明需要切换hash通（已遍历达到桶结尾）
	while (nxt == &ptype_base[hash]) {
		if (++hash >= PTYPE_HASH_SIZE)
			return NULL;
		nxt = ptype_base[hash].next;//置为下一个樋的首个元素
	}
found:
    //返回对应的packet_type
	return list_entry(nxt, struct packet_type, list);
}

static void ptype_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

//显示ptype文件内容
static int ptype_seq_show(struct seq_file *seq, void *v)
{
	struct packet_type *pt = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Type Device      Function\n");
	else if ((!pt->af_packet_net || net_eq(pt->af_packet_net, seq_file_net(seq))) &&
		 (!pt->dev || net_eq(dev_net(pt->dev), seq_file_net(seq)))) {
		if (pt->type == htons(ETH_P_ALL))
			seq_puts(seq, "ALL ");
		else
			seq_printf(seq, "%04x", ntohs(pt->type));

		seq_printf(seq, " %-8s %ps\n",
			   pt->dev ? pt->dev->name : "", pt->func);
	}

	return 0;
}

//ptype_seq文件操作集
static const struct seq_operations ptype_seq_ops = {
	.start = ptype_seq_start,
	.next  = ptype_seq_next,
	.stop  = ptype_seq_stop,
	.show  = ptype_seq_show,
};

static int __net_init dev_proc_net_init(struct net *net)
{
	int rc = -ENOMEM;

	/*创建dev文件*/
	if (!proc_create_net("dev", 0444, net->proc_net, &dev_seq_ops,
			sizeof(struct seq_net_private)))
		goto out;
	if (!proc_create_seq("softnet_stat", 0444, net->proc_net,
			 &softnet_seq_ops))
		goto out_dev;
	//创建ptype文件
	if (!proc_create_net("ptype", 0444, net->proc_net, &ptype_seq_ops,
			sizeof(struct seq_net_private)))
		goto out_softnet;

	if (wext_proc_init(net))
		goto out_ptype;
	rc = 0;
out:
	return rc;
out_ptype:
	remove_proc_entry("ptype", net->proc_net);
out_softnet:
	remove_proc_entry("softnet_stat", net->proc_net);
out_dev:
	remove_proc_entry("dev", net->proc_net);
	goto out;
}

static void __net_exit dev_proc_net_exit(struct net *net)
{
	wext_proc_exit(net);

	remove_proc_entry("ptype", net->proc_net);
	remove_proc_entry("softnet_stat", net->proc_net);
	remove_proc_entry("dev", net->proc_net);
}

static struct pernet_operations __net_initdata dev_proc_ops = {
	.init = dev_proc_net_init,
	.exit = dev_proc_net_exit,
};

//显示指定网络设备的组播硬件地址
static int dev_mc_seq_show(struct seq_file *seq, void *v)
{
	struct netdev_hw_addr *ha;
	struct net_device *dev = v;

	if (v == SEQ_START_TOKEN)
		return 0;

	netif_addr_lock_bh(dev);
	netdev_for_each_mc_addr(ha, dev) {
		seq_printf(seq, "%-4d %-15s %-5d %-5d %*phN\n",
			   dev->ifindex/*设备ifindex*/, dev->name/*设备名称*/,
			   ha->refcount/*引用计数*/, ha->global_use,
			   (int)dev->addr_len/*组播地址长度*/, ha->addr/*组播地址（mac)*/);
	}
	netif_addr_unlock_bh(dev);
	return 0;
}

static const struct seq_operations dev_mc_seq_ops = {
	.start = dev_seq_start,
	.next  = dev_seq_next,
	.stop  = dev_seq_stop,
	.show  = dev_mc_seq_show,
};

static int __net_init dev_mc_net_init(struct net *net)
{
	/*显示设备关注的组播地址*/
	if (!proc_create_net("dev_mcast", 0, net->proc_net, &dev_mc_seq_ops,
			sizeof(struct seq_net_private)))
		return -ENOMEM;
	return 0;
}

static void __net_exit dev_mc_net_exit(struct net *net)
{
	remove_proc_entry("dev_mcast", net->proc_net);
}

static struct pernet_operations __net_initdata dev_mc_net_ops = {
	.init = dev_mc_net_init,
	.exit = dev_mc_net_exit,
};

int __init dev_proc_init(void)
{
	int ret = register_pernet_subsys(&dev_proc_ops);
	if (!ret)
		return register_pernet_subsys(&dev_mc_net_ops);
	return ret;
}
