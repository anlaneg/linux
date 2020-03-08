#ifndef _UAPI_LINUX_VIRTIO_CONFIG_H
#define _UAPI_LINUX_VIRTIO_CONFIG_H
/* This header, excluding the #ifdef __KERNEL__ part, is BSD licensed so
 * anyone can use the definitions to implement compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */

/* Virtio devices use a standardized configuration space to define their
 * features and pass configuration information, but each implementation can
 * store and access that space differently. */
#include <linux/types.h>

//看virtio 1.0规定的设备状态
/* Status byte for guest to report progress, and synchronize features. */
/* We have seen device and processed generic fields (VIRTIO_CONFIG_F_VIRTIO) */
//guest os发现了一个设备，并认为其为有效的virtio设备
#define VIRTIO_CONFIG_S_ACKNOWLEDGE	1
/* We have found a driver for the device. */
//guest os 为virtio设备找到了一个合适的驱动
#define VIRTIO_CONFIG_S_DRIVER		2
/* Driver has used its parts of the config, and is happy */
//针对设备的驱动已完成
#define VIRTIO_CONFIG_S_DRIVER_OK	4
/* Driver has finished configuring features */
//针对功能协商已完成
#define VIRTIO_CONFIG_S_FEATURES_OK	8
/* Device entered invalid state, driver must reset it */
//指明驱动需要reset它
#define VIRTIO_CONFIG_S_NEEDS_RESET	0x40
/* We've given up on this device. */
//遇到错误，放弃此设备
#define VIRTIO_CONFIG_S_FAILED		0x80

//按照virtio 1.0标准规定
//（0－23是特定设备类型对应的功能bit)
// 24-32 是队列扩展及功能协商相关的功能
// 33-X 预留的扩展
/*
Feature bits are allocated as follows:
0 to 23 Feature bits for the specific device type
24 to 32 Feature bits reserved for extensions to the queue and feature negotiation mechanisms
33 and above Feature bits reserved for future extensions.
*/
/*
 * Virtio feature bits VIRTIO_TRANSPORT_F_START through
 * VIRTIO_TRANSPORT_F_END are reserved for the transport
 * being used (e.g. virtio_ring, virtio_pci etc.), the
 * rest are per-device feature bits.
 */
#define VIRTIO_TRANSPORT_F_START	28
#define VIRTIO_TRANSPORT_F_END		38

#ifndef VIRTIO_CONFIG_NO_LEGACY
/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY	24

/* Can the device handle any descriptor layout? */
#define VIRTIO_F_ANY_LAYOUT		27
#endif /* VIRTIO_CONFIG_NO_LEGACY */

/* v1.0 compliant. */
//标记为virtio 1.0版本(如果此标记没有被设备提供，则设备为legacy设备）
//同相的，如果此标记没有被驱动提供，则驱动为legacy驱动
#define VIRTIO_F_VERSION_1		32

/*
 * If clear - device has the IOMMU bypass quirk feature.
 * If set - use platform tools to detect the IOMMU.
 *
 * Note the reverse polarity (compared to most other features),
 * this is for compatibility with legacy systems.
 */
#define VIRTIO_F_IOMMU_PLATFORM		33

/* This feature indicates support for the packed virtqueue layout. */
#define VIRTIO_F_RING_PACKED		34

/*
 * This feature indicates that memory accesses by the driver and the
 * device are ordered in a way described by the platform.
 */
#define VIRTIO_F_ORDER_PLATFORM		36

/*
 * Does the device support Single Root I/O Virtualization?
 */
#define VIRTIO_F_SR_IOV			37
#endif /* _UAPI_LINUX_VIRTIO_CONFIG_H */
