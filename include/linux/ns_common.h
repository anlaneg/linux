/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NS_COMMON_H
#define _LINUX_NS_COMMON_H

struct proc_ns_operations;

/*namespace的公共结构*/
struct ns_common {
    /*在nsfs文件系统中，此结构被用于存放ns文件对应的dentry*/
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;/*唯一编号,来源于proc_inum_ida*/
};

#endif
