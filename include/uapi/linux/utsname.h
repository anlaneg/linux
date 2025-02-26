/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_UTSNAME_H
#define _UAPI_LINUX_UTSNAME_H

#define __OLD_UTS_LEN 8

struct oldold_utsname {
	char sysname[9];
	char nodename[9];
	char release[9];
	char version[9];
	char machine[9];
};

#define __NEW_UTS_LEN 64

struct old_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

struct new_utsname {
	/*存储操作系统的名称，比如在 Linux 系统中，这个字段通常为 "Linux"。*/
	char sysname[__NEW_UTS_LEN + 1];
	/*存储系统的节点名称，一般是主机名。可以通过 hostname 命令查看或修改。*/
	char nodename[__NEW_UTS_LEN + 1];
	/*存储内核的发行版本号，例如 "5.15.0 - 76 - generic"*/
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	char machine[__NEW_UTS_LEN + 1];
	char domainname[__NEW_UTS_LEN + 1];
};


#endif /* _UAPI_LINUX_UTSNAME_H */
