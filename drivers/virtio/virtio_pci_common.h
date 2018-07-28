#ifndef _DRIVERS_VIRTIO_VIRTIO_PCI_COMMON_H
#define _DRIVERS_VIRTIO_VIRTIO_PCI_COMMON_H
/*
 * Virtio PCI driver - APIs for common functionality for all device versions
 *
 * This module allows virtio devices to be used over a virtual PCI device.
 * This can be used with QEMU based VMMs like KVM or Xen.
 *
 * Copyright IBM Corp. 2007
 * Copyright Red Hat, Inc. 2014
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *  Rusty Russell <rusty@rustcorp.com.au>
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_pci.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>

struct virtio_pci_vq_info {
	/* the actual virtqueue */
	struct virtqueue *vq;

	/* the list node for the virtqueues list */
	struct list_head node;

	/* MSI-X vector (or none) */
	unsigned msix_vector;
};

/* Our device structure */
struct virtio_pci_device {
	struct virtio_device vdev;
	struct pci_dev *pci_dev;//记录virtio pci设备对应的pci设备

	/* In legacy mode, these two point to within ->legacy. */
	/* Where to read and clear interrupt */
	//映射中断状态字段（仅含有1个字节，目前使用了两个bit，0 bit是队列中断，1bit是配置中断）
	u8 __iomem *isr;

	/* Modern only fields */
	/* The IO mapping for the PCI config space (non-legacy mode) */
	//映射自设备（VIRTIO_PCI_CAP_COMMON_CFG capability）
	struct virtio_pci_common_cfg __iomem *common;
	/* Device-specific data (non-legacy mode)  */
	void __iomem *device;
	/* Base of vq notifications (non-legacy mode). */
	//vq通知的基地址（自此地址开始，queue_notify_off * notify_off_multiplier）
	//可以对应到每个queue对应的通知io
	void __iomem *notify_base;

	/* So we can sanity-check accesses. */
	size_t notify_len;
	size_t device_len;

	/* Capability for when we need to map notifications per-vq. */
	int notify_map_cap;

	/* Multiply queue_notify_off by this value. (non-legacy mode). */
	//每个队列对应的通知通知offset倍数
	u32 notify_offset_multiplier;

	int modern_bars;

	/* Legacy only field */
	/* the IO mapping for the PCI config space */
	void __iomem *ioaddr;

	/* a list of queues so we can dispatch IRQs */
	spinlock_t lock;
	struct list_head virtqueues;

	/* array of all queues for house-keeping */
	struct virtio_pci_vq_info **vqs;

	/* MSI-X support */
	int msix_enabled;
	int intx_enabled;
	cpumask_var_t *msix_affinity_masks;
	/* Name strings for interrupts. This size should be enough,
	 * and I'm too lazy to allocate each name separately. */
	char (*msix_names)[256];
	/* Number of available vectors */
	unsigned msix_vectors;
	/* Vectors allocated, excluding per-vq vectors if any */
	unsigned msix_used_vectors;

	/* Whether we have vector per vq */
	bool per_vq_vectors;

	//创建virtqueue
	struct virtqueue *(*setup_vq)(struct virtio_pci_device *vp_dev,
				      struct virtio_pci_vq_info *info,
				      unsigned idx,
				      void (*callback)(struct virtqueue *vq),
				      const char *name,
				      bool ctx,
				      u16 msix_vec);
	//销毁virtqueue
	void (*del_vq)(struct virtio_pci_vq_info *info);

	u16 (*config_vector)(struct virtio_pci_device *vp_dev, u16 vector);
};

/* Constants for MSI-X */
/* Use first vector for configuration changes, second and the rest for
 * virtqueues Thus, we need at least 2 vectors for MSI. */
enum {
	VP_MSIX_CONFIG_VECTOR = 0,
	VP_MSIX_VQ_VECTOR = 1,
};

/* Convert a generic virtio device to our structure */
static struct virtio_pci_device *to_vp_device(struct virtio_device *vdev)
{
	return container_of(vdev, struct virtio_pci_device, vdev);
}

/* wait for pending irq handlers */
void vp_synchronize_vectors(struct virtio_device *vdev);
/* the notify function used when creating a virt queue */
bool vp_notify(struct virtqueue *vq);
/* the config->del_vqs() implementation */
void vp_del_vqs(struct virtio_device *vdev);
/* the config->find_vqs() implementation */
int vp_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		struct virtqueue *vqs[], vq_callback_t *callbacks[],
		const char * const names[], const bool *ctx,
		struct irq_affinity *desc);
const char *vp_bus_name(struct virtio_device *vdev);

/* Setup the affinity for a virtqueue:
 * - force the affinity for per vq vector
 * - OR over all affinities for shared MSI
 * - ignore the affinity request if we're using INTX
 */
int vp_set_vq_affinity(struct virtqueue *vq, int cpu);

const struct cpumask *vp_get_vq_affinity(struct virtio_device *vdev, int index);

#if IS_ENABLED(CONFIG_VIRTIO_PCI_LEGACY)
int virtio_pci_legacy_probe(struct virtio_pci_device *);
void virtio_pci_legacy_remove(struct virtio_pci_device *);
#else
static inline int virtio_pci_legacy_probe(struct virtio_pci_device *vp_dev)
{
	return -ENODEV;
}
static inline void virtio_pci_legacy_remove(struct virtio_pci_device *vp_dev)
{
}
#endif
int virtio_pci_modern_probe(struct virtio_pci_device *);
void virtio_pci_modern_remove(struct virtio_pci_device *);

#endif
