// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Tessares SA.
 */

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "protocol.h"

#define MPTCP_SYSCTL_PATH "net/mptcp"

static int mptcp_pernet_id;

#ifdef CONFIG_SYSCTL
static int mptcp_pm_type_max = __MPTCP_PM_TYPE_MAX;
#endif

struct mptcp_pernet {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *ctl_table_hdr;
#endif

	/*sysctl控制的本netns中的控制变量*/
	unsigned int add_addr_timeout;
	unsigned int close_timeout;
	unsigned int stale_loss_cnt;
	u8 mptcp_enabled;/*是否开启mptcp*/
	u8 checksum_enabled;
	u8 allow_join_initial_addr_port;
	u8 pm_type;
	char scheduler[MPTCP_SCHED_NAME_MAX];
};

static struct mptcp_pernet *mptcp_get_pernet(const struct net *net)
{
	return net_generic(net, mptcp_pernet_id);
}

int mptcp_is_enabled(const struct net *net)
{
	/*当前netns是否开启mptcp*/
	return mptcp_get_pernet(net)->mptcp_enabled;
}

unsigned int mptcp_get_add_addr_timeout(const struct net *net)
{
	return mptcp_get_pernet(net)->add_addr_timeout;
}

int mptcp_is_checksum_enabled(const struct net *net)
{
	/*当前netns是否开启checksum*/
	return mptcp_get_pernet(net)->checksum_enabled;
}

int mptcp_allow_join_id0(const struct net *net)
{
	return mptcp_get_pernet(net)->allow_join_initial_addr_port;
}

unsigned int mptcp_stale_loss_cnt(const struct net *net)
{
	return mptcp_get_pernet(net)->stale_loss_cnt;
}

unsigned int mptcp_close_timeout(const struct sock *sk)
{
	if (sock_flag(sk, SOCK_DEAD))
		return TCP_TIMEWAIT_LEN;
	return mptcp_get_pernet(sock_net(sk))->close_timeout;
}

int mptcp_get_pm_type(const struct net *net)
{
	return mptcp_get_pernet(net)->pm_type;
}

const char *mptcp_get_scheduler(const struct net *net)
{
	return mptcp_get_pernet(net)->scheduler;
}

/*默认值*/
static void mptcp_pernet_set_defaults(struct mptcp_pernet *pernet)
{
	pernet->mptcp_enabled = 1;
	pernet->add_addr_timeout = TCP_RTO_MAX;
	pernet->close_timeout = TCP_TIMEWAIT_LEN;
	pernet->checksum_enabled = 0;
	pernet->allow_join_initial_addr_port = 1;
	pernet->stale_loss_cnt = 4;
	pernet->pm_type = MPTCP_PM_TYPE_KERNEL;
	strcpy(pernet->scheduler, "default");
}

#ifdef CONFIG_SYSCTL
/*注：以下ctl_table项均没有设置data,原因是每个net ns需要有不同的data,故均在初始化时设置*/
static struct ctl_table mptcp_sysctl_table[] = {
	{
		.procname = "enabled",/*开启mptcp*/
		.maxlen = sizeof(u8),
		.mode = 0644,
		/* users with CAP_NET_ADMIN or root (not and) can change this
		 * value, same as other sysctl or the 'net' tree.
		 */
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = SYSCTL_ONE
	},
	{
		.procname = "add_addr_timeout",
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_jiffies,
	},
	{
		.procname = "checksum_enabled",
		.maxlen = sizeof(u8),
		.mode = 0644,
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = SYSCTL_ONE
	},
	{
		.procname = "allow_join_initial_addr_port",
		.maxlen = sizeof(u8),
		.mode = 0644,
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = SYSCTL_ONE
	},
	{
		.procname = "stale_loss_cnt",
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "pm_type",
		.maxlen = sizeof(u8),
		.mode = 0644,
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = &mptcp_pm_type_max
	},
	{
		.procname = "scheduler",
		.maxlen	= MPTCP_SCHED_NAME_MAX,
		.mode = 0644,
		.proc_handler = proc_dostring,
	},
	{
		.procname = "close_timeout",
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_jiffies,
	},
	{}
};

static int mptcp_pernet_new_table(struct net *net, struct mptcp_pernet *pernet)
{
	struct ctl_table_header *hdr;
	struct ctl_table *table;

	table = mptcp_sysctl_table;
	if (!net_eq(net, &init_net)) {
		/*非init_net，则需要复制一份table*/
		table = kmemdup(table, sizeof(mptcp_sysctl_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;
	}

	/*设置当前net ns的sysctl data*/
	table[0].data = &pernet->mptcp_enabled;
	table[1].data = &pernet->add_addr_timeout;
	table[2].data = &pernet->checksum_enabled;
	table[3].data = &pernet->allow_join_initial_addr_port;
	table[4].data = &pernet->stale_loss_cnt;
	table[5].data = &pernet->pm_type;
	table[6].data = &pernet->scheduler;
	table[7].data = &pernet->close_timeout;

	/*net注册sysctl路径（同样的路径，由哪个netns发起，即配置哪个netns)*/
	hdr = register_net_sysctl_sz(net, MPTCP_SYSCTL_PATH, table,
				     ARRAY_SIZE(mptcp_sysctl_table));
	if (!hdr)
		goto err_reg;

	pernet->ctl_table_hdr = hdr;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static void mptcp_pernet_del_table(struct mptcp_pernet *pernet)
{
	struct ctl_table *table = pernet->ctl_table_hdr->ctl_table_arg;

	unregister_net_sysctl_table(pernet->ctl_table_hdr);

	kfree(table);
}

#else

static int mptcp_pernet_new_table(struct net *net, struct mptcp_pernet *pernet)
{
	return 0;
}

static void mptcp_pernet_del_table(struct mptcp_pernet *pernet) {}

#endif /* CONFIG_SYSCTL */

static int __net_init mptcp_net_init(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);

	mptcp_pernet_set_defaults(pernet);

	return mptcp_pernet_new_table(net, pernet);/*初始化此netns下的mptcp sysctl变量*/
}

/* Note: the callback will only be called per extra netns */
static void __net_exit mptcp_net_exit(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);

	mptcp_pernet_del_table(pernet);
}

static struct pernet_operations mptcp_pernet_ops = {
	.init = mptcp_net_init,
	.exit = mptcp_net_exit,
	.id = &mptcp_pernet_id,
	.size = sizeof(struct mptcp_pernet),
};

void __init mptcp_init(void)
{
	mptcp_join_cookie_init();
	mptcp_proto_init();

	/*针对每个netns提供相应初始化处理*/
	if (register_pernet_subsys(&mptcp_pernet_ops) < 0)
		panic("Failed to register MPTCP pernet subsystem.\n");
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int __init mptcpv6_init(void)
{
	int err;

	err = mptcp_proto_v6_init();

	return err;
}
#endif
