// SPDX-License-Identifier: GPL-2.0-only
/*
 *  9P entry point
 *
 *  Copyright (C) 2007 by Latchesar Ionkov <lucho@ionkov.net>
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <net/9p/9p.h>
#include <linux/fs.h>
#include <linux/parser.h>
#include <net/9p/client.h>
#include <net/9p/transport.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#ifdef CONFIG_NET_9P_DEBUG
unsigned int p9_debug_level;	/* feature-rific global debug level  */
EXPORT_SYMBOL(p9_debug_level);
module_param_named(debug, p9_debug_level, uint, 0);
MODULE_PARM_DESC(debug, "9P debugging level");

void _p9_debug(enum p9_debug_flags level, const char *func,
	       const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if ((p9_debug_level & level) != level)
		return;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	if (level == P9_DEBUG_9P)
		pr_notice("(%8.8d) %pV", task_pid_nr(current), &vaf);
	else
		pr_notice("-- %s (%d): %pV", func, task_pid_nr(current), &vaf);

	va_end(args);
}
EXPORT_SYMBOL(_p9_debug);
#endif

/* Dynamic Transport Registration Routines */

static DEFINE_SPINLOCK(v9fs_trans_lock);/*保护v9fs_trans_list链表*/
static LIST_HEAD(v9fs_trans_list);/*用于记录系统中9p支持的transport*/

/**
 * v9fs_register_trans - register a new transport with 9p
 * @m: structure describing the transport module and entry points
 *
 */
void v9fs_register_trans(struct p9_trans_module *m)
{
	spin_lock(&v9fs_trans_lock);
	list_add_tail(&m->list, &v9fs_trans_list);/*注册transport*/
	spin_unlock(&v9fs_trans_lock);
}
EXPORT_SYMBOL(v9fs_register_trans);

/**
 * v9fs_unregister_trans - unregister a 9p transport
 * @m: the transport to remove
 *
 */
void v9fs_unregister_trans(struct p9_trans_module *m)
{
	spin_lock(&v9fs_trans_lock);
	list_del_init(&m->list);/*移除transport注册*/
	spin_unlock(&v9fs_trans_lock);
}
EXPORT_SYMBOL(v9fs_unregister_trans);

static struct p9_trans_module *_p9_get_trans_by_name(const char *s)
{
	struct p9_trans_module *t, *found = NULL;

	spin_lock(&v9fs_trans_lock);

	/*按名称查找已注册的transport*/
	list_for_each_entry(t, &v9fs_trans_list, list)
		if (strcmp(t->name, s) == 0 &&
		    try_module_get(t->owner)) {
			found = t;
			break;
		}

	spin_unlock(&v9fs_trans_lock);

	return found;
}

/**
 * v9fs_get_trans_by_name - get transport with the matching name
 * @s: string identifying transport
 *
 */
struct p9_trans_module *v9fs_get_trans_by_name(const char *s)
{
	struct p9_trans_module *found = NULL;

	found = _p9_get_trans_by_name(s);/*通过名称查找transport*/

#ifdef CONFIG_MODULES
	if (!found) {
		/*未找到，请求加载module并再查询*/
		request_module("9p-%s", s);
		found = _p9_get_trans_by_name(s);/*再次查找*/
	}
#endif

	return found;
}
EXPORT_SYMBOL(v9fs_get_trans_by_name);

/*内置的默认transport名称（排序为优先级）*/
static const char * const v9fs_default_transports[] = {
	"virtio", "tcp", "fd", "unix", "xen", "rdma",
};

/**
 * v9fs_get_default_trans - get the default transport
 *
 */

struct p9_trans_module *v9fs_get_default_trans(void)
{
	struct p9_trans_module *t, *found = NULL;
	int i;

	spin_lock(&v9fs_trans_lock);

	list_for_each_entry(t, &v9fs_trans_list, list)
		if (t->def && try_module_get(t->owner)) {
			found = t;/*取得default transport*/
			break;
		}

	if (!found)
		/*未找到默认的，找首个可用的*/
		list_for_each_entry(t, &v9fs_trans_list, list)
			if (try_module_get(t->owner)) {
				found = t;
				break;
			}

	spin_unlock(&v9fs_trans_lock);

	/*仍未找到，找内置默认的。*/
	for (i = 0; !found && i < ARRAY_SIZE(v9fs_default_transports); i++)
		found = v9fs_get_trans_by_name(v9fs_default_transports[i]);

	return found;
}
EXPORT_SYMBOL(v9fs_get_default_trans);

/**
 * v9fs_put_trans - put trans
 * @m: transport to put
 *
 */
void v9fs_put_trans(struct p9_trans_module *m)
{
	if (m)
		module_put(m->owner);/*释放transport对应的引用计数*/
}

/**
 * init_p9 - Initialize module
 *
 */
static int __init init_p9(void)
{
	int ret;

	ret = p9_client_init();
	if (ret)
		return ret;

	p9_error_init();
	pr_info("Installing 9P2000 support\n");

	return ret;
}

/**
 * exit_p9 - shutdown module
 *
 */

static void __exit exit_p9(void)
{
	pr_info("Unloading 9P2000 support\n");

	p9_client_exit();
}

module_init(init_p9)
module_exit(exit_p9)

MODULE_AUTHOR("Latchesar Ionkov <lucho@ionkov.net>");
MODULE_AUTHOR("Eric Van Hensbergen <ericvh@gmail.com>");
MODULE_AUTHOR("Ron Minnich <rminnich@lanl.gov>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Plan 9 Resource Sharing Support (9P2000)");
