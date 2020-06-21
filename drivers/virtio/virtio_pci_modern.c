// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Virtio PCI driver - modern (virtio 1.0) device support
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
 */

#include <linux/delay.h>
#define VIRTIO_PCI_NO_LEGACY
#define VIRTIO_RING_NO_LEGACY
#include "virtio_pci_common.h"

/*
 * Type-safe wrappers for io accesses.
 * Use these to enforce at compile time the following spec requirement:
 *
 * The driver MUST access each field using the “natural” access
 * method, i.e. 32-bit accesses for 32-bit fields, 16-bit accesses
 * for 16-bit fields and 8-bit accesses for 8-bit fields.
 */
static inline u8 vp_ioread8(u8 __iomem *addr)
{
	return ioread8(addr);
}
static inline u16 vp_ioread16 (__le16 __iomem *addr)
{
	return ioread16(addr);
}

static inline u32 vp_ioread32(__le32 __iomem *addr)
{
	return ioread32(addr);
}

static inline void vp_iowrite8(u8 value, u8 __iomem *addr)
{
	iowrite8(value, addr);
}

static inline void vp_iowrite16(u16 value, __le16 __iomem *addr)
{
	iowrite16(value, addr);
}

//向addr中写入value
static inline void vp_iowrite32(u32 value, __le32 __iomem *addr)
{
	iowrite32(value, addr);
}

static void vp_iowrite64_twopart(u64 val,
				 __le32 __iomem *lo/*低32bit地址*/, __le32 __iomem *hi/*高32bit地址*/)
{
	vp_iowrite32((u32)val, lo);
	vp_iowrite32(val >> 32, hi);
}

//映射capability对应的内存（offset是capability相对于pci config space的偏移）
//minlen是capability结构体的最小长度，align是其的对齐方式
//start是映射相对于这段数据的偏移量，size是要映射的大小,len是实际映射的大小
static void __iomem *map_capability(struct pci_dev *dev, int off,
				    size_t minlen,
				    u32 align,
				    u32 start, u32 size,
				    size_t *len)
{
	u8 bar;
	u32 offset, length;
	void __iomem *p;

	//读取bar,offset,length
	//off指示的位置是一个virtio_pci_cap结构，自此结构中先读取bar,offset,length
	pci_read_config_byte(dev, off + offsetof(struct virtio_pci_cap,
						 bar),
			     &bar);
	pci_read_config_dword(dev, off + offsetof(struct virtio_pci_cap, offset),
			     &offset);
	pci_read_config_dword(dev, off + offsetof(struct virtio_pci_cap, length),
			      &length);

	//长度小于start指定，参数有误
	if (length <= start) {
		dev_err(&dev->dev,
			"virtio_pci: bad capability len %u (>%u expected)\n",
			length, start);
		return NULL;
	}

	//自start开始，没有minlen字节，参数有误
	if (length - start < minlen) {
		dev_err(&dev->dev,
			"virtio_pci: bad capability len %u (>=%zu expected)\n",
			length, minlen);
		return NULL;
	}

	//除去start
	length -= start;

	if (start + offset < offset) {
		dev_err(&dev->dev,
			"virtio_pci: map wrap-around %u+%u\n",
			start, offset);
		return NULL;
	}

	offset += start;

	if (offset & (align - 1)) {
		dev_err(&dev->dev,
			"virtio_pci: offset %u not aligned to %u\n",
			offset, align);
		return NULL;
	}

	if (length > size)
		length = size;

	if (len)
		*len = length;

	if (minlen + offset < minlen ||
	    minlen + offset > pci_resource_len(dev, bar)) {
		dev_err(&dev->dev,
			"virtio_pci: map virtio %zu@%u "
			"out of range on bar %i length %lu\n",
			minlen, offset,
			bar, (unsigned long)pci_resource_len(dev, bar));
		return NULL;
	}

	//映射bar内存到p
	p = pci_iomap_range(dev, bar, offset, length);
	if (!p)
		dev_err(&dev->dev,
			"virtio_pci: unable to map virtio %u@%u on bar %i\n",
			length, offset, bar);
	return p;
}

/* virtio config->get_features() implementation */
//配合device_feature_select寄存器，完成设备支持的功能位读取
static u64 vp_get_features(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	u64 features;

	//向vp_dev->common->device_feature_select中写入0，并读取device_feature，做为低位
	vp_iowrite32(0, &vp_dev->common->device_feature_select);
	features = vp_ioread32(&vp_dev->common->device_feature);
	//向vp_dev->common->device_feature_select中写入1，并读取device_feature，做为低位
	vp_iowrite32(1, &vp_dev->common->device_feature_select);
	features |= ((u64)vp_ioread32(&vp_dev->common->device_feature) << 32);

	return features;
}

static void vp_transport_features(struct virtio_device *vdev, u64 features)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct pci_dev *pci_dev = vp_dev->pci_dev;

	if ((features & BIT_ULL(VIRTIO_F_SR_IOV)) &&
			pci_find_ext_capability(pci_dev, PCI_EXT_CAP_ID_SRIOV))
		__virtio_set_bit(vdev, VIRTIO_F_SR_IOV);
}

/* virtio config->finalize_features() implementation */
//设置驱动与设备协商后确定的设备应支持功能位
static int vp_finalize_features(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	u64 features = vdev->features;

	/* Give virtio_ring a chance to accept features. */
	vring_transport_features(vdev);

	/* Give virtio_pci a chance to accept features. */
	vp_transport_features(vdev, features);

	if (!__virtio_test_bit(vdev, VIRTIO_F_VERSION_1)) {
		dev_err(&vdev->dev, "virtio: device uses modern interface "
			"but does not have VIRTIO_F_VERSION_1\n");
		return -EINVAL;
	}

	vp_iowrite32(0, &vp_dev->common->guest_feature_select);
	vp_iowrite32((u32)vdev->features, &vp_dev->common->guest_feature);
	vp_iowrite32(1, &vp_dev->common->guest_feature_select);
	vp_iowrite32(vdev->features >> 32, &vp_dev->common->guest_feature);

	return 0;
}

/* virtio config->get() implementation */
//读取配置信息（自配置的device映射段读取公共配置)
static void vp_get(struct virtio_device *vdev, unsigned offset,
		   void *buf, unsigned len)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	u8 b;
	__le16 w;
	__le32 l;

	BUG_ON(offset + len > vp_dev->device_len);

	switch (len) {
	case 1:
		b = ioread8(vp_dev->device + offset);
		memcpy(buf, &b, sizeof b);
		break;
	case 2:
		w = cpu_to_le16(ioread16(vp_dev->device + offset));
		memcpy(buf, &w, sizeof w);
		break;
	case 4:
		l = cpu_to_le32(ioread32(vp_dev->device + offset));
		memcpy(buf, &l, sizeof l);
		break;
	case 8:
		//64字节时，按32字节读取两次
		l = cpu_to_le32(ioread32(vp_dev->device + offset));
		memcpy(buf, &l, sizeof l);
		l = cpu_to_le32(ioread32(vp_dev->device + offset + sizeof l));
		memcpy(buf + sizeof l, &l, sizeof l);
		break;
	default:
		BUG();
	}
}

/* the config->set() implementation.  it's symmetric to the config->get()
 * implementation */
//设置公共配置
static void vp_set(struct virtio_device *vdev, unsigned offset,
		   const void *buf, unsigned len)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	u8 b;
	__le16 w;
	__le32 l;

	BUG_ON(offset + len > vp_dev->device_len);

	switch (len) {
	case 1:
		memcpy(&b, buf, sizeof b);
		iowrite8(b, vp_dev->device + offset);
		break;
	case 2:
		memcpy(&w, buf, sizeof w);
		iowrite16(le16_to_cpu(w), vp_dev->device + offset);
		break;
	case 4:
		memcpy(&l, buf, sizeof l);
		iowrite32(le32_to_cpu(l), vp_dev->device + offset);
		break;
	case 8:
		memcpy(&l, buf, sizeof l);
		iowrite32(le32_to_cpu(l), vp_dev->device + offset);
		memcpy(&l, buf + sizeof l, sizeof l);
		iowrite32(le32_to_cpu(l), vp_dev->device + offset + sizeof l);
		break;
	default:
		BUG();
	}
}

//获取配置的版本号（用于保护配置读取的原子性）
static u32 vp_generation(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	return vp_ioread8(&vp_dev->common->config_generation);
}

/* config->{get,set}_status() implementations */
static u8 vp_get_status(struct virtio_device *vdev)
{
	//读取设备状态
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	return vp_ioread8(&vp_dev->common->device_status);
}

static void vp_set_status(struct virtio_device *vdev, u8 status)
{
	//设置设备状态
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	/* We should never be setting status to 0. */
	BUG_ON(status == 0);
	vp_iowrite8(status, &vp_dev->common->device_status);
}

static void vp_reset(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	/* 0 status means a reset. */
	//写此地址写0，reset设备
	vp_iowrite8(0, &vp_dev->common->device_status);
	/* After writing 0 to device_status, the driver MUST wait for a read of
	 * device_status to return 0 before reinitializing the device.
	 * This will flush out the status write, and flush in device writes,
	 * including MSI-X interrupts, if any.
	 */
	//等待设备reset完成
	while (vp_ioread8(&vp_dev->common->device_status))
		msleep(1);
	/* Flush pending VQ/configuration callbacks. */
	vp_synchronize_vectors(vdev);
}

static u16 vp_config_vector(struct virtio_pci_device *vp_dev, u16 vector)
{
	/* Setup the vector used for configuration events */
	vp_iowrite16(vector, &vp_dev->common->msix_config);
	/* Verify we had enough resources to assign the vector */
	/* Will also flush the write out to device */
	return vp_ioread16(&vp_dev->common->msix_config);
}

//创建virtqueue
static struct virtqueue *setup_vq(struct virtio_pci_device *vp_dev,
				  struct virtio_pci_vq_info *info,
				  unsigned index,//队列索引
				  void (*callback)(struct virtqueue *vq),//队列中断回调
				  const char *name,//队列名称
				  bool ctx,//队列是否有context
				  u16 msix_vec/*为此队列指定的中断向量*/)
{
	struct virtio_pci_common_cfg __iomem *cfg = vp_dev->common;
	struct virtqueue *vq;
	u16 num, off;
	int err;

	//要创建的队列数不能超过硬件支持的最大队列数
	if (index >= vp_ioread16(&cfg->num_queues))
		return ERR_PTR(-ENOENT);

	/* Select the queue we're interested in */
	//告知硬件我们使用index号queue，看qemu代码（后面将针对此队列进行vp_io[read/write]操作）
	vp_iowrite16(index, &cfg->queue_select);

	/* Check if queue is either not available or already active. */
	//取硬件支持的index号队列大小，如果大小为０，查询此队列是否使能
	//如果使能了，但返回num ==0，则硬件实现有误
	num = vp_ioread16(&cfg->queue_size);
	if (!num || vp_ioread16(&cfg->queue_enable))
		return ERR_PTR(-ENOENT);

	//队列数必须为2的N次方
	if (num & (num - 1)) {
		dev_warn(&vp_dev->pci_dev->dev, "bad queue size %u", num);
		return ERR_PTR(-EINVAL);
	}

	/* get offset of notification word for this vq */
	off = vp_ioread16(&cfg->queue_notify_off);

	info->msix_vector = msix_vec;

	/* create the vring */
	//创建vring，通过vp_notify通知后端
	vq = vring_create_virtqueue(index, num,
				    SMP_CACHE_BYTES, &vp_dev->vdev,
				    true, true, ctx,
				    vp_notify, callback, name);
	if (!vq)
		return ERR_PTR(-ENOMEM);

	/* activate the queue */
	//设置队列大小
	vp_iowrite16(virtqueue_get_vring_size(vq), &cfg->queue_size);
	//设置desc的物理地址（dma地址）
	vp_iowrite64_twopart(virtqueue_get_desc_addr(vq),
			     &cfg->queue_desc_lo, &cfg->queue_desc_hi);
	//设置avail的物理地址（dma地址）
	vp_iowrite64_twopart(virtqueue_get_avail_addr(vq),
			     &cfg->queue_avail_lo, &cfg->queue_avail_hi);
	//设置use的物理地址（dma地址）
	vp_iowrite64_twopart(virtqueue_get_used_addr(vq),
			     &cfg->queue_used_lo, &cfg->queue_used_hi);

	if (vp_dev->notify_base) {
		/* offset should not wrap */
		if ((u64)off * vp_dev->notify_offset_multiplier + 2
		    > vp_dev->notify_len) {
			dev_warn(&vp_dev->pci_dev->dev,
				 "bad notification offset %u (x %u) "
				 "for queue %u > %zd",
				 off, vp_dev->notify_offset_multiplier,
				 index, vp_dev->notify_len);
			err = -EINVAL;
			goto err_map_notify;
		}
		//此队列对应的通知地址
		vq->priv = (void __force *)vp_dev->notify_base +
			off * vp_dev->notify_offset_multiplier;
	} else {
		vq->priv = (void __force *)map_capability(vp_dev->pci_dev,
					  vp_dev->notify_map_cap, 2, 2,
					  off * vp_dev->notify_offset_multiplier, 2,
					  NULL);
	}

	if (!vq->priv) {
		err = -ENOMEM;
		goto err_map_notify;
	}

	if (msix_vec != VIRTIO_MSI_NO_VECTOR) {
	    //指明了中断，则为此队列配置中断
		vp_iowrite16(msix_vec, &cfg->queue_msix_vector);
		msix_vec = vp_ioread16(&cfg->queue_msix_vector);
		if (msix_vec == VIRTIO_MSI_NO_VECTOR) {
			err = -EBUSY;
			goto err_assign_vector;
		}
	}

	return vq;

err_assign_vector:
	if (!vp_dev->notify_base)
		pci_iounmap(vp_dev->pci_dev, (void __iomem __force *)vq->priv);
err_map_notify:
	vring_del_virtqueue(vq);
	return ERR_PTR(err);
}

static int vp_modern_find_vqs(struct virtio_device *vdev, unsigned nvqs,//虚队列数目
			      struct virtqueue *vqs[],//虚队列数组
			      vq_callback_t *callbacks[],//指出各队列对应的报文收包callback
			      const char * const names[],//指出各队列名称
				  const bool *ctx,//指出各队列是否有context
			      struct irq_affinity *desc)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtqueue *vq;
	int rc = vp_find_vqs(vdev, nvqs, vqs, callbacks, names, ctx, desc);

	if (rc)
		return rc;

	/* Select and activate all queues. Has to be done last: once we do
	 * this, there's no way to go back except reset.
	 */
	list_for_each_entry(vq, &vdev->vqs, list) {
		vp_iowrite16(vq->index, &vp_dev->common->queue_select);
		vp_iowrite16(1, &vp_dev->common->queue_enable);
	}

	return 0;
}

//virtqueue的删除回调
static void del_vq(struct virtio_pci_vq_info *info)
{
	struct virtqueue *vq = info->vq;
	struct virtio_pci_device *vp_dev = to_vp_device(vq->vdev);

	//告知硬件准备操作队列vq->index
	vp_iowrite16(vq->index, &vp_dev->common->queue_select);

	if (vp_dev->msix_enabled) {
		vp_iowrite16(VIRTIO_MSI_NO_VECTOR,
			     &vp_dev->common->queue_msix_vector);
		/* Flush the write out to device */
		vp_ioread16(&vp_dev->common->queue_msix_vector);
	}

	if (!vp_dev->notify_base)
		pci_iounmap(vp_dev->pci_dev, (void __force __iomem *)vq->priv);

	vring_del_virtqueue(vq);
}

static const struct virtio_config_ops virtio_pci_config_nodev_ops = {
	.get		= NULL,
	.set		= NULL,
	.generation	= vp_generation,
	.get_status	= vp_get_status,
	.set_status	= vp_set_status,
	.reset		= vp_reset,//使设备reset
	.find_vqs	= vp_modern_find_vqs,
	.del_vqs	= vp_del_vqs,
	.get_features	= vp_get_features,
	.finalize_features = vp_finalize_features,
	.bus_name	= vp_bus_name,
	.set_vq_affinity = vp_set_vq_affinity,
	.get_vq_affinity = vp_get_vq_affinity,
};

static const struct virtio_config_ops virtio_pci_config_ops = {
	.get		= vp_get,//virtio pci配置获取
	.set		= vp_set,
	.generation	= vp_generation,
	.get_status	= vp_get_status,
	.set_status	= vp_set_status,
	.reset		= vp_reset,
	.find_vqs	= vp_modern_find_vqs,//创建队列
	.del_vqs	= vp_del_vqs,
	.get_features	= vp_get_features,
	.finalize_features = vp_finalize_features,
	.bus_name	= vp_bus_name,
	.set_vq_affinity = vp_set_vq_affinity,
	.get_vq_affinity = vp_get_vq_affinity,
};

/**
 * virtio_pci_find_capability - walk capabilities to find device info.
 * @dev: the pci device
 * @cfg_type: the VIRTIO_PCI_CAP_* value we seek
 * @ioresource_types: IORESOURCE_MEM and/or IORESOURCE_IO.
 *
 * Returns offset of the capability, or 0.
 */
static inline int virtio_pci_find_capability(struct pci_dev *dev, u8 cfg_type,
					     u32 ioresource_types, int *bars)
{
	/*
	 * 见virtio 1.0 spec标准所言
	 * The location of each structure is specified using a vendor-specific PCI capability located on the capability
	   list in PCI configuration space of the device. This virtio structure capability uses little-endian format; all fields
       are read-only for the driver unless stated otherwise:
	 */
	int pos;

	//遍历Vendor-Specific cap
	for (pos = pci_find_capability(dev, PCI_CAP_ID_VNDR);
	     pos > 0;
	     pos = pci_find_next_capability(dev, pos, PCI_CAP_ID_VNDR)) {
		//读取cap对应的结构体类型
		u8 type, bar;
		pci_read_config_byte(dev, pos + offsetof(struct virtio_pci_cap,
							 cfg_type),
				     &type);
		//读取哪里可以找到此结构体
		pci_read_config_byte(dev, pos + offsetof(struct virtio_pci_cap,
							 bar),
				     &bar);

		/* Ignore structures with reserved BAR values */
		//按标准规定，目前有5种类型
		/*
		 * cfg_type identifies the structure, according to the following table:
			//Common configuration
			#define VIRTIO_PCI_CAP_COMMON_CFG 1
			//Notifications
			#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
			//ISR Status
			#define VIRTIO_PCI_CAP_ISR_CFG  3
			// Device specific configuration
			#define VIRTIO_PCI_CAP_DEVICE_CFG 4
			//PCI configuration access
			#define VIRTIO_PCI_CAP_PCI_CFG 5
		 */
		if (bar > 0x5)
			continue;

		if (type == cfg_type) {
			//找到需要的结构体bar且bar的类型与ioresource_type一致,则返回其结构体对应的位置
			if (pci_resource_len(dev, bar) &&
			    pci_resource_flags(dev, bar) & ioresource_types) {
				*bars |= (1 << bar);//设置对应的bar标记
				return pos;
			}
		}
	}
	return 0;
}

/* This is part of the ABI.  Don't screw with it. */
//校验各字段offset(需要前后端相互配合）
static inline void check_offsets(void)
{
	/* Note: disk space was harmed in compilation of this function. */
    //确保相应偏移量在合适的位置，例如desc表地址的高32位及低32位地址
	BUILD_BUG_ON(VIRTIO_PCI_CAP_VNDR !=
		     offsetof(struct virtio_pci_cap, cap_vndr));
	BUILD_BUG_ON(VIRTIO_PCI_CAP_NEXT !=
		     offsetof(struct virtio_pci_cap, cap_next));
	BUILD_BUG_ON(VIRTIO_PCI_CAP_LEN !=
		     offsetof(struct virtio_pci_cap, cap_len));
	BUILD_BUG_ON(VIRTIO_PCI_CAP_CFG_TYPE !=
		     offsetof(struct virtio_pci_cap, cfg_type));
	BUILD_BUG_ON(VIRTIO_PCI_CAP_BAR !=
		     offsetof(struct virtio_pci_cap, bar));
	BUILD_BUG_ON(VIRTIO_PCI_CAP_OFFSET !=
		     offsetof(struct virtio_pci_cap, offset));
	BUILD_BUG_ON(VIRTIO_PCI_CAP_LENGTH !=
		     offsetof(struct virtio_pci_cap, length));
	BUILD_BUG_ON(VIRTIO_PCI_NOTIFY_CAP_MULT !=
		     offsetof(struct virtio_pci_notify_cap,
			      notify_off_multiplier));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_DFSELECT !=
		     offsetof(struct virtio_pci_common_cfg,
			      device_feature_select));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_DF !=
		     offsetof(struct virtio_pci_common_cfg, device_feature));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_GFSELECT !=
		     offsetof(struct virtio_pci_common_cfg,
			      guest_feature_select));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_GF !=
		     offsetof(struct virtio_pci_common_cfg, guest_feature));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_MSIX !=
		     offsetof(struct virtio_pci_common_cfg, msix_config));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_NUMQ !=
		     offsetof(struct virtio_pci_common_cfg, num_queues));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_STATUS !=
		     offsetof(struct virtio_pci_common_cfg, device_status));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_CFGGENERATION !=
		     offsetof(struct virtio_pci_common_cfg, config_generation));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_SELECT !=
		     offsetof(struct virtio_pci_common_cfg, queue_select));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_SIZE !=
		     offsetof(struct virtio_pci_common_cfg, queue_size));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_MSIX !=
		     offsetof(struct virtio_pci_common_cfg, queue_msix_vector));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_ENABLE !=
		     offsetof(struct virtio_pci_common_cfg, queue_enable));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_NOFF !=
		     offsetof(struct virtio_pci_common_cfg, queue_notify_off));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_DESCLO !=
		     offsetof(struct virtio_pci_common_cfg, queue_desc_lo));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_DESCHI !=
		     offsetof(struct virtio_pci_common_cfg, queue_desc_hi));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_AVAILLO !=
		     offsetof(struct virtio_pci_common_cfg, queue_avail_lo));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_AVAILHI !=
		     offsetof(struct virtio_pci_common_cfg, queue_avail_hi));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_USEDLO !=
		     offsetof(struct virtio_pci_common_cfg, queue_used_lo));
	BUILD_BUG_ON(VIRTIO_PCI_COMMON_Q_USEDHI !=
		     offsetof(struct virtio_pci_common_cfg, queue_used_hi));
}

/* the PCI probing function */
//modern方式probe
int virtio_pci_modern_probe(struct virtio_pci_device *vp_dev)
{
	struct pci_dev *pci_dev = vp_dev->pci_dev;
	int err, common, isr, notify, device;
	u32 notify_length;
	u32 notify_offset;

	check_offsets();

	//如match中所言，virtio只有0x1000到0x10ff之间的设备号可用，而本函数要求必须小于等于0x107f
	//Any PCI device with PCI Vendor ID 0x1AF4, and PCI Device ID 0x1000 through 0x107F inclusive is a virtio
	//device. The actual value within this range indicates which virtio device is supported by the device. The PCI
	//Device ID is calculated by adding 0x1040 to the Virtio Device ID, as indicated in section 5. Additionally,
	//devices MAY utilize a Transitional PCI Device ID range, 0x1000 to 0x103F depending on the device type.
	/* We only own devices >= 0x1000 and <= 0x107f: leave the rest. */
	if (pci_dev->device < 0x1000 || pci_dev->device > 0x107f)
		return -ENODEV;

	//设置设备的device_id 与vendor_id
	if (pci_dev->device < 0x1040) {
		/* Transitional devices: use the PCI subsystem device id as
		 * virtio device id, same as legacy driver always did.
		 */
		vp_dev->vdev.id.device = pci_dev->subsystem_device;
	} else {
		/* Modern devices: simply use PCI device id, but start from 0x1040. */
		//通过减去0x1040我们可以在virtio spce 1.0 的section 5找到每类设备对应的类型，例如1是网设设备
		vp_dev->vdev.id.device = pci_dev->device - 0x1040;
	}
	vp_dev->vdev.id.vendor = pci_dev->subsystem_vendor;

	/* check for a common config: if not, use legacy mode (bar 0). */
	//查找VIRTIO_PCI_CAP_COMMON_CFG cap的位置，其对应的是一个由硬件定义结构体
	//见virtio 1.0 spec virtio_pci_common_cfg
	common = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_COMMON_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &vp_dev->modern_bars);
	if (!common) {
		//硬件无virtio_pci_common_cfg结构，失败
		dev_info(&pci_dev->dev,
			 "virtio_pci: leaving for legacy driver\n");
		return -ENODEV;
	}

	/* If common is there, these should be too... */
	//找VIRTIO_PCI_CAP_ISR_CFG capability位置
	//The VIRTIO_PCI_CAP_ISR_CFG capability refers to at least a single byte, which contains the 8-bit ISR
	//status field to be used for INT#x interrupt handling.
	isr = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_ISR_CFG,
					 IORESOURCE_IO | IORESOURCE_MEM,
					 &vp_dev->modern_bars);
	//找VIRTIO_PCI_CAP_NOTIFY_CFG capability位置
	//The notification location is found using the VIRTIO_PCI_CAP_NOTIFY_CFG capability. This capability is
	//immediately followed by an additional field, like so:
	notify = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_NOTIFY_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &vp_dev->modern_bars);
	if (!isr || !notify) {
		dev_err(&pci_dev->dev,
			"virtio_pci: missing capabilities %i/%i/%i\n",
			common, isr, notify);
		return -EINVAL;
	}

	//设置dma掩码(先尝试64位，如果失败了尝试32位）
	err = dma_set_mask_and_coherent(&pci_dev->dev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(&pci_dev->dev,
						DMA_BIT_MASK(32));
	if (err)
		dev_warn(&pci_dev->dev, "Failed to enable 64-bit or 32-bit DMA.  Trying to continue, but this might not work.\n");

	/* Device capability is only mandatory for devices that have
	 * device-specific configuration.
	 */
	//The VIRTIO_PCI_CAP_PCI_CFG capability creates an alternative (and likely suboptimal) access method
	//to the common configuration, notification, ISR and device-specific configuration regions.
	device = virtio_pci_find_capability(pci_dev, VIRTIO_PCI_CAP_DEVICE_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &vp_dev->modern_bars);

	//前面我们处理了5块bar,这里将这些内存匹配映射出来？
	err = pci_request_selected_regions(pci_dev, vp_dev->modern_bars,
					   "virtio-pci-modern");
	if (err)
		return err;

	err = -EINVAL;
	//映射VIRTIO_PCI_CAP_COMMON_CFG capability对应的数据，其对应的是结构体
	//virtio_pci_common_cfg,
	vp_dev->common = map_capability(pci_dev, common,
					sizeof(struct virtio_pci_common_cfg), 4,
					0, sizeof(struct virtio_pci_common_cfg),
					NULL);
	if (!vp_dev->common)
		goto err_map_common;
	//映射中断状态字段（仅含有1个字节，目前使用了两个bit，0 bit是队列中断，1bit是配置中断）
	vp_dev->isr = map_capability(pci_dev, isr, sizeof(u8), 1,
				     0, 1,
				     NULL);
	if (!vp_dev->isr)
		goto err_map_isr;

	/* Read notify_off_multiplier from config space. */
	//读取notify结构体中的notify_off_multiplier字段，通过此字段和common中的
	//queue_notify_off 我们可以计算任意queue对应的通知地址
	//cap.offset + queue_notify_off * notify_off_multiplier
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						notify_off_multiplier),
			      &vp_dev->notify_offset_multiplier);
	/* Read notify length and offset from config space. */
	//读取ntify结构体中对length字段,即通知地址可使用长度
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						cap.length),
			      &notify_length);

	//读取notify结构体中的offset字段
	pci_read_config_dword(pci_dev,
			      notify + offsetof(struct virtio_pci_notify_cap,
						cap.offset),
			      &notify_offset);

	/* We don't know how many VQs we'll map, ahead of the time.
	 * If notify length is small, map it all now.
	 * Otherwise, map each VQ individually later.
	 */
	if ((u64)notify_length + (notify_offset % PAGE_SIZE) <= PAGE_SIZE) {
		//map通知的base地址（针对一个队列通知时，采用cap.offset +
		//queue_notify_off * notify_off_multiplier + vp_dev->notify_base进行通知）
		vp_dev->notify_base = map_capability(pci_dev, notify, 2, 2,
						     0, notify_length,
						     &vp_dev->notify_len);
		if (!vp_dev->notify_base)
			goto err_map_notify;
	} else {
		vp_dev->notify_map_cap = notify;
	}

	/* Again, we don't know how much we should map, but PAGE_SIZE
	 * is more than enough for all existing devices.
	 */
	if (device) {
		//映射设备的common configuration, notification, ISR and device-specific configuration regions
		vp_dev->device = map_capability(pci_dev, device, 0, 4,
						0, PAGE_SIZE,
						&vp_dev->device_len);
		if (!vp_dev->device)
			goto err_map_device;

		vp_dev->vdev.config = &virtio_pci_config_ops;
	} else {
		//无设备时的config_ops
		vp_dev->vdev.config = &virtio_pci_config_nodev_ops;
	}

	vp_dev->config_vector = vp_config_vector;
	vp_dev->setup_vq = setup_vq;//设置virtqueue创建回调
	vp_dev->del_vq = del_vq;

	return 0;

err_map_device:
	if (vp_dev->notify_base)
		pci_iounmap(pci_dev, vp_dev->notify_base);
err_map_notify:
	pci_iounmap(pci_dev, vp_dev->isr);
err_map_isr:
	pci_iounmap(pci_dev, vp_dev->common);
err_map_common:
	return err;
}

void virtio_pci_modern_remove(struct virtio_pci_device *vp_dev)
{
	struct pci_dev *pci_dev = vp_dev->pci_dev;

	if (vp_dev->device)
		pci_iounmap(pci_dev, vp_dev->device);
	if (vp_dev->notify_base)
		pci_iounmap(pci_dev, vp_dev->notify_base);
	pci_iounmap(pci_dev, vp_dev->isr);
	pci_iounmap(pci_dev, vp_dev->common);
	pci_release_selected_regions(pci_dev, vp_dev->modern_bars);
}
