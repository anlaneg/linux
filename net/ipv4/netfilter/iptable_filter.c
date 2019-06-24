// SPDX-License-Identifier: GPL-2.0-only
/*
 * This is the 1999 rewrite of IP Firewalling, aiming for kernel 2.3.x.
 *
 * Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 * Copyright (C) 2000-2004 Netfilter Core Team <coreteam@netfilter.org>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables filter table");

#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
			    (1 << NF_INET_FORWARD) | \
			    (1 << NF_INET_LOCAL_OUT))
static int __net_init iptable_filter_table_init(struct net *net);

static const struct xt_table packet_filter = {
	.name		= "filter",
	//filter表需要注册local_in,forward,local_out三个hook点
	.valid_hooks	= FILTER_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_IPV4,//协议族为ipv4
	.priority	= NF_IP_PRI_FILTER,
	.table_init	= iptable_filter_table_init,
};

//实现报文过滤,为local_in,forward,local_out三个hook点注册的hook实现函数
//其中local_in,forward为路由查询后，local_out为主机向上发送时
static unsigned int
iptable_filter_hook(void *priv, struct sk_buff *skb,
		    const struct nf_hook_state *state)
{
	return ipt_do_table(skb, state, state->net->ipv4.iptable_filter);
}

//要注册的filter hook数组
static struct nf_hook_ops *filter_ops __read_mostly;

/* Default to forward because I got too much mail already. */
static bool forward __read_mostly = true;
module_param(forward, bool, 0000);

static int __net_init iptable_filter_table_init(struct net *net)
{
	struct ipt_replace *repl;
	int err;

	if (net->ipv4.iptable_filter)
		//已注册时直接返回
		return 0;

	//依据xt_table申请初始化表
	repl = ipt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
	/* Entry 1 is the FORWARD hook */
	//注册了三个hook点，其中第2个（即1）为FORWARD hook点
	((struct ipt_standard *)repl->entries)[1].target.verdict =
		forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;

	//注filter_ops为hook点钩子实现函数
	//初始化net->ipv4.iptable_filter指针
	err = ipt_register_table(net, &packet_filter, repl, filter_ops,
				 &net->ipv4.iptable_filter);
	kfree(repl);
	return err;
}

static int __net_init iptable_filter_net_init(struct net *net)
{
	if (net == &init_net || !forward)
		return iptable_filter_table_init(net);

	return 0;
}

static void __net_exit iptable_filter_net_exit(struct net *net)
{
	if (!net->ipv4.iptable_filter)
		return;
	ipt_unregister_table(net, net->ipv4.iptable_filter, filter_ops);
	net->ipv4.iptable_filter = NULL;
}

static struct pernet_operations iptable_filter_net_ops = {
	.init = iptable_filter_net_init,
	.exit = iptable_filter_net_exit,
};

static int __init iptable_filter_init(void)
{
	int ret;

	//创建filter的netfilter的hook点
	filter_ops = xt_hook_ops_alloc(&packet_filter, iptable_filter_hook);
	if (IS_ERR(filter_ops))
		return PTR_ERR(filter_ops);

	//注册filter在namespace创建时的操作
	ret = register_pernet_subsys(&iptable_filter_net_ops);
	if (ret < 0)
		kfree(filter_ops);

	return ret;
}

static void __exit iptable_filter_fini(void)
{
	unregister_pernet_subsys(&iptable_filter_net_ops);
	kfree(filter_ops);
}

module_init(iptable_filter_init);
module_exit(iptable_filter_fini);
