// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012 Netapp, Inc. All rights reserved.
 */
#include <linux/module.h>
#include <linux/nfs_fs.h>
#include "internal.h"
#include "nfs.h"

static struct nfs_subversion nfs_v2 = {
	.owner = THIS_MODULE,
	.nfs_fs   = &nfs_fs_type,
	.rpc_vers = &nfs_version2,
	.rpc_ops  = &nfs_v2_clientops,/*2号版本对应的client-ops*/
	.sops     = &nfs_sops,
};

static int __init init_nfs_v2(void)
{
	register_nfs_version(&nfs_v2);/*注册v2版本的nfs*/
	return 0;
}

static void __exit exit_nfs_v2(void)
{
	unregister_nfs_version(&nfs_v2);
}

MODULE_LICENSE("GPL");

module_init(init_nfs_v2);
module_exit(exit_nfs_v2);
