/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*****************************************************************************/

/*
 *	usbdevice_fs.h  --  USB device file system.
 *
 *	Copyright (C) 2000
 *          Thomas Sailer (sailer@ife.ee.ethz.ch)
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  History:
 *   0.1  04.01.2000  Created
 */

/*****************************************************************************/

#ifndef _UAPI_LINUX_USBDEVICE_FS_H
#define _UAPI_LINUX_USBDEVICE_FS_H

#include <linux/types.h>
#include <linux/magic.h>

/* --------------------------------------------------------------------- */

/* usbdevfs ioctl codes */

struct usbdevfs_ctrltransfer {
	__u8 bRequestType;
	__u8 bRequest;
	__u16 wValue;
	__u16 wIndex;
	__u16 wLength;
	__u32 timeout;  /* in milliseconds */
 	void __user *data;
};

struct usbdevfs_bulktransfer {
	unsigned int ep;
	unsigned int len;
	unsigned int timeout; /* in milliseconds */
	void __user *data;
};

struct usbdevfs_setinterface {
	unsigned int interface;
	unsigned int altsetting;
};

struct usbdevfs_disconnectsignal {
	unsigned int signr;
	void __user *context;
};

#define USBDEVFS_MAXDRIVERNAME 255

struct usbdevfs_getdriver {
	unsigned int interface;
	char driver[USBDEVFS_MAXDRIVERNAME + 1];
};

struct usbdevfs_connectinfo {
	unsigned int devnum;
	unsigned char slow;
};

struct usbdevfs_conninfo_ex {
	__u32 size;		/* Size of the structure from the kernel's */
				/* point of view. Can be used by userspace */
				/* to determine how much data can be       */
				/* used/trusted.                           */
	__u32 busnum;           /* USB bus number, as enumerated by the    */
				/* kernel, the device is connected to.     */
	__u32 devnum;           /* Device address on the bus.              */
	__u32 speed;		/* USB_SPEED_* constants from ch9.h        */
	__u8 num_ports;		/* Number of ports the device is connected */
				/* to on the way to the root hub. It may   */
				/* be bigger than size of 'ports' array so */
				/* userspace can detect overflows.         */
	__u8 ports[7];		/* List of ports on the way from the root  */
				/* hub to the device. Current limit in     */
				/* USB specification is 7 tiers (root hub, */
				/* 5 intermediate hubs, device), which     */
				/* gives at most 6 port entries.           */
};

#define USBDEVFS_URB_SHORT_NOT_OK	0x01
#define USBDEVFS_URB_ISO_ASAP		0x02
#define USBDEVFS_URB_BULK_CONTINUATION	0x04
#define USBDEVFS_URB_NO_FSBR		0x20	/* Not used */
#define USBDEVFS_URB_ZERO_PACKET	0x40
#define USBDEVFS_URB_NO_INTERRUPT	0x80

/*同步传输(Isochronous)是一种周期的、连续的单向传输方式，
 * 通常用于与时间有密切关系的信息的传输。
 * 同步传输每次传输的最大有效负荷为1024字节。*/
#define USBDEVFS_URB_TYPE_ISO		   0
/*中断传输用于非周期的、自然发生的、数据量很小的信息的传输，
 * 主要用在键盘、鼠标及操纵杆等设备上。*/
#define USBDEVFS_URB_TYPE_INTERRUPT	   1
/*控制传输方式支持双向传输，用来处理主端口到USB从端口的数据传输，
 * 包括设备控制指令、设备状态查询及确认命令。对于高速设备，
 * 允许数据包最大容量为8，16，32或64字节，对于低速设备只有8字节一种选择。*/
#define USBDEVFS_URB_TYPE_CONTROL	   2
/*批量传输方式也是一种单向传输，用于大量的、对时间没有要求的数据传输。*/
#define USBDEVFS_URB_TYPE_BULK		   3

struct usbdevfs_iso_packet_desc {
	unsigned int length;
	unsigned int actual_length;
	unsigned int status;
};

/*USB请求块(USB request block，URB)是USB设备驱动中用来
 * 描述与USB设备通信所用的基本载体和核心数据结构，
 * 与网络设备驱动中的sk_buff结构体类似，
 * 是USB主机与设备之间传输数据的封装。*/
struct usbdevfs_urb {
	unsigned char type;/*URB参数类型,例如:USBDEVFS_URB_TYPE_CONTROL*/
	/*USB端点（Endpoint） 在USB协议中，端点是设备内部的数据传输终点，
	 * 它是设备与主机进行数据交换的基本单位。
	 * 每个USB设备至少有一个端点，即端点0，这是用于控制通信的默认端点。
	 * 除此之外，设备可以根据需要定义额外的数据端点，用以传输非控制类型的数据。
	 * 方向性：USB端点可以被配置为输入端点（IN），用于从设备向主机发送数据；
	 * 或输出端点（OUT），用于接收来自主机的数据。
	 * 某些高级设备可能还支持双向端点（Bi-directional Endpoint），
	 * 能够根据需要进行数据传输方向的切换。
	 * 类型：端点根据其功能和传输特性分为以下四种类型：
	 * 控制端点（Control Endpoint）：所有USB设备都必须具有端点0，用于设备枚举、配置设置以及状态查询等控制操作。
	 * 中断端点（Interrupt Endpoint）：主要用于周期性地发送小量且时间敏感的数据，如键盘、鼠标事件等。
	 * 批量端点（Bulk Endpoint）：处理大量非实时的数据传输，适合文件传输、打印机作业等应用。
	 * 同步端点（Isochronous Endpoint）：设计用于连续流式传输，例如音频和视频流，这类数据传输对带宽和定时要求严格。
	 * 特性：每个端点都有一个唯一的地址，由端点号（Endpoint Number）标识，并且每个端点都有自己的最大包大小（Max Packet Size），
	 * 这个值决定了每次数据传输的最大字节数。
	 * */
	unsigned char endpoint;
	int status;
	unsigned int flags;
	void __user *buffer;
	int buffer_length;/*传入的buffer长度*/
	int actual_length;
	int start_frame;
	union {
		int number_of_packets;	/* Only used for isoc urbs */
		unsigned int stream_id;	/* Only used with bulk streams */
	};
	int error_count;
	unsigned int signr;	/* signal to be sent on completion,
				  or 0 if none should be sent. */
	void __user *usercontext;
	struct usbdevfs_iso_packet_desc iso_frame_desc[];
};

/* ioctls for talking directly to drivers */
struct usbdevfs_ioctl {
	int	ifno;		/* interface 0..N ; negative numbers reserved */
	int	ioctl_code;	/* MUST encode size + direction of data so the
				 * macros in <asm/ioctl.h> give correct values */
	void __user *data;	/* param buffer (in, or out) */
};

/* You can do most things with hubs just through control messages,
 * except find out what device connects to what port. */
struct usbdevfs_hub_portinfo {
	char nports;		/* number of downstream ports in this hub */
	char port [127];	/* e.g. port 3 connects to device 27 */
};

/* System and bus capability flags */
#define USBDEVFS_CAP_ZERO_PACKET		0x01
#define USBDEVFS_CAP_BULK_CONTINUATION		0x02
#define USBDEVFS_CAP_NO_PACKET_SIZE_LIM		0x04
#define USBDEVFS_CAP_BULK_SCATTER_GATHER	0x08
#define USBDEVFS_CAP_REAP_AFTER_DISCONNECT	0x10
#define USBDEVFS_CAP_MMAP			0x20
#define USBDEVFS_CAP_DROP_PRIVILEGES		0x40
#define USBDEVFS_CAP_CONNINFO_EX		0x80
#define USBDEVFS_CAP_SUSPEND			0x100

/* USBDEVFS_DISCONNECT_CLAIM flags & struct */

/* disconnect-and-claim if the driver matches the driver field */
#define USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER	0x01
/* disconnect-and-claim except when the driver matches the driver field */
#define USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER	0x02

struct usbdevfs_disconnect_claim {
	unsigned int interface;
	unsigned int flags;
	char driver[USBDEVFS_MAXDRIVERNAME + 1];
};

struct usbdevfs_streams {
	unsigned int num_streams; /* Not used by USBDEVFS_FREE_STREAMS */
	unsigned int num_eps;
	unsigned char eps[];
};

/*
 * USB_SPEED_* values returned by USBDEVFS_GET_SPEED are defined in
 * linux/usb/ch9.h
 */

#define USBDEVFS_CONTROL           _IOWR('U', 0, struct usbdevfs_ctrltransfer)
#define USBDEVFS_CONTROL32           _IOWR('U', 0, struct usbdevfs_ctrltransfer32)
#define USBDEVFS_BULK              _IOWR('U', 2, struct usbdevfs_bulktransfer)
#define USBDEVFS_BULK32              _IOWR('U', 2, struct usbdevfs_bulktransfer32)
#define USBDEVFS_RESETEP           _IOR('U', 3, unsigned int)
#define USBDEVFS_SETINTERFACE      _IOR('U', 4, struct usbdevfs_setinterface)
#define USBDEVFS_SETCONFIGURATION  _IOR('U', 5, unsigned int)
#define USBDEVFS_GETDRIVER         _IOW('U', 8, struct usbdevfs_getdriver)
#define USBDEVFS_SUBMITURB         _IOR('U', 10, struct usbdevfs_urb)
#define USBDEVFS_SUBMITURB32       _IOR('U', 10, struct usbdevfs_urb32)
#define USBDEVFS_DISCARDURB        _IO('U', 11)
#define USBDEVFS_REAPURB           _IOW('U', 12, void *)
#define USBDEVFS_REAPURB32         _IOW('U', 12, __u32)
#define USBDEVFS_REAPURBNDELAY     _IOW('U', 13, void *)
#define USBDEVFS_REAPURBNDELAY32   _IOW('U', 13, __u32)
#define USBDEVFS_DISCSIGNAL        _IOR('U', 14, struct usbdevfs_disconnectsignal)
#define USBDEVFS_DISCSIGNAL32      _IOR('U', 14, struct usbdevfs_disconnectsignal32)
#define USBDEVFS_CLAIMINTERFACE    _IOR('U', 15, unsigned int)
#define USBDEVFS_RELEASEINTERFACE  _IOR('U', 16, unsigned int)
#define USBDEVFS_CONNECTINFO       _IOW('U', 17, struct usbdevfs_connectinfo)
#define USBDEVFS_IOCTL             _IOWR('U', 18, struct usbdevfs_ioctl)
#define USBDEVFS_IOCTL32           _IOWR('U', 18, struct usbdevfs_ioctl32)
#define USBDEVFS_HUB_PORTINFO      _IOR('U', 19, struct usbdevfs_hub_portinfo)
#define USBDEVFS_RESET             _IO('U', 20)
#define USBDEVFS_CLEAR_HALT        _IOR('U', 21, unsigned int)
#define USBDEVFS_DISCONNECT        _IO('U', 22)
#define USBDEVFS_CONNECT           _IO('U', 23)
#define USBDEVFS_CLAIM_PORT        _IOR('U', 24, unsigned int)
#define USBDEVFS_RELEASE_PORT      _IOR('U', 25, unsigned int)
#define USBDEVFS_GET_CAPABILITIES  _IOR('U', 26, __u32)
#define USBDEVFS_DISCONNECT_CLAIM  _IOR('U', 27, struct usbdevfs_disconnect_claim)
#define USBDEVFS_ALLOC_STREAMS     _IOR('U', 28, struct usbdevfs_streams)
#define USBDEVFS_FREE_STREAMS      _IOR('U', 29, struct usbdevfs_streams)
#define USBDEVFS_DROP_PRIVILEGES   _IOW('U', 30, __u32)
#define USBDEVFS_GET_SPEED         _IO('U', 31)
/*
 * Returns struct usbdevfs_conninfo_ex; length is variable to allow
 * extending size of the data returned.
 */
#define USBDEVFS_CONNINFO_EX(len)  _IOC(_IOC_READ, 'U', 32, len)
#define USBDEVFS_FORBID_SUSPEND    _IO('U', 33)
#define USBDEVFS_ALLOW_SUSPEND     _IO('U', 34)
#define USBDEVFS_WAIT_FOR_RESUME   _IO('U', 35)

#endif /* _UAPI_LINUX_USBDEVICE_FS_H */
