/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_CONFIG_H
#define _LINUX_VIRTIO_CONFIG_H

#include <linux/err.h>
#include <linux/bug.h>
#include <linux/virtio.h>
#include <linux/virtio_byteorder.h>
#include <uapi/linux/virtio_config.h>

struct irq_affinity;

/**
 * virtio_config_ops - operations for configuring a virtio device
 * @get: read the value of a configuration field
 *	vdev: the virtio_device
 *	offset: the offset of the configuration field
 *	buf: the buffer to write the field value into.
 *	len: the length of the buffer
 * @set: write the value of a configuration field
 *	vdev: the virtio_device
 *	offset: the offset of the configuration field
 *	buf: the buffer to read the field value from.
 *	len: the length of the buffer
 * @generation: config generation counter
 *	vdev: the virtio_device
 *	Returns the config generation counter
 * @get_status: read the status byte
 *	vdev: the virtio_device
 *	Returns the status byte
 * @set_status: write the status byte
 *	vdev: the virtio_device
 *	status: the new status byte
 * @reset: reset the device
 *	vdev: the virtio device
 *	After this, status and feature negotiation must be done again
 *	Device must not be reset from its vq/config callbacks, or in
 *	parallel with being added/removed.
 * @find_vqs: find virtqueues and instantiate them.
 *	vdev: the virtio_device
 *	nvqs: the number of virtqueues to find
 *	vqs: on success, includes new virtqueues
 *	callbacks: array of callbacks, for each virtqueue
 *		include a NULL entry for vqs that do not need a callback
 *	names: array of virtqueue names (mainly for debugging)
 *		include a NULL entry for vqs unused by driver
 *	Returns 0 on success or error status
 * @del_vqs: free virtqueues found by find_vqs().
 * @get_features: get the array of feature bits for this device.
 *	vdev: the virtio_device
 *	Returns the first 32 feature bits (all we currently need).
 * @finalize_features: confirm what device features we'll be using.
 *	vdev: the virtio_device
 *	This gives the final feature bits for the device: it can change
 *	the dev->feature bits if it wants.
 *	Returns 0 on success or error status
 * @bus_name: return the bus name associated with the device
 *	vdev: the virtio_device
 *      This returns a pointer to the bus name a la pci_name from which
 *      the caller can then copy.
 * @set_vq_affinity: set the affinity for a virtqueue.
 * @get_vq_affinity: get the affinity for a virtqueue (optional).
 */
typedef void vq_callback_t(struct virtqueue *);
struct virtio_config_ops {
	//配置项获取
	void (*get)(struct virtio_device *vdev, unsigned offset,
		    void *buf, unsigned len);
	//配置项设置
	void (*set)(struct virtio_device *vdev, unsigned offset,
		    const void *buf, unsigned len);
	u32 (*generation)(struct virtio_device *vdev);
	u8 (*get_status)(struct virtio_device *vdev);
	void (*set_status)(struct virtio_device *vdev, u8 status);
	void (*reset)(struct virtio_device *vdev);
	int (*find_vqs)(struct virtio_device *, unsigned nvqs,
			struct virtqueue *vqs[], vq_callback_t *callbacks[],
			const char * const names[], const bool *ctx,
			struct irq_affinity *desc);
	void (*del_vqs)(struct virtio_device *);
	u64 (*get_features)(struct virtio_device *vdev);
	int (*finalize_features)(struct virtio_device *vdev);
	const char *(*bus_name)(struct virtio_device *vdev);
	int (*set_vq_affinity)(struct virtqueue *vq, int cpu);
	const struct cpumask *(*get_vq_affinity)(struct virtio_device *vdev,
			int index);
};

/* If driver didn't advertise the feature, it will never appear. */
void virtio_check_driver_offered_feature(const struct virtio_device *vdev,
					 unsigned int fbit);

/**
 * __virtio_test_bit - helper to test feature bits. For use by transports.
 *                     Devices should normally use virtio_has_feature,
 *                     which includes more checks.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline bool __virtio_test_bit(const struct virtio_device *vdev,
				     unsigned int fbit)
{
	/* Did you forget to fix assumptions on max features? */
	//校验bit位小于64
	if (__builtin_constant_p(fbit))
		BUILD_BUG_ON(fbit >= 64);
	else
		BUG_ON(fbit >= 64);

	//检查vdev中fbit位是否开启
	return vdev->features & BIT_ULL(fbit);
}

/**
 * __virtio_set_bit - helper to set feature bits. For use by transports.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline void __virtio_set_bit(struct virtio_device *vdev,
				    unsigned int fbit)
{
	/* Did you forget to fix assumptions on max features? */
	if (__builtin_constant_p(fbit))
		BUILD_BUG_ON(fbit >= 64);
	else
		BUG_ON(fbit >= 64);

	vdev->features |= BIT_ULL(fbit);
}

/**
 * __virtio_clear_bit - helper to clear feature bits. For use by transports.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline void __virtio_clear_bit(struct virtio_device *vdev,
				      unsigned int fbit)
{
	/* Did you forget to fix assumptions on max features? */
	if (__builtin_constant_p(fbit))
		BUILD_BUG_ON(fbit >= 64);
	else
		BUG_ON(fbit >= 64);

	vdev->features &= ~BIT_ULL(fbit);
}

/**
 * virtio_has_feature - helper to determine if this device has this feature.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline bool virtio_has_feature(const struct virtio_device *vdev,
				      unsigned int fbit)
{
	//28以下的bit功能位是必须提供的，如果未提供，则直接挂掉
	if (fbit < VIRTIO_TRANSPORT_F_START)
		virtio_check_driver_offered_feature(vdev, fbit);

	//检查bit位是否提供
	return __virtio_test_bit(vdev, fbit);
}

/**
 * virtio_has_iommu_quirk - determine whether this device has the iommu quirk
 * @vdev: the device
 */
static inline bool virtio_has_iommu_quirk(const struct virtio_device *vdev)
{
	/*
	 * Note the reverse polarity of the quirk feature (compared to most
	 * other features), this is for compatibility with legacy systems.
	 */
	return !virtio_has_feature(vdev, VIRTIO_F_IOMMU_PLATFORM);
}

static inline
struct virtqueue *virtio_find_single_vq(struct virtio_device *vdev,
					vq_callback_t *c, const char *n)
{
	vq_callback_t *callbacks[] = { c };
	const char *names[] = { n };
	struct virtqueue *vq;
	int err = vdev->config->find_vqs(vdev, 1, &vq, callbacks, names, NULL,
					 NULL);
	if (err < 0)
		return ERR_PTR(err);
	return vq;
}

static inline
int virtio_find_vqs(struct virtio_device *vdev, unsigned nvqs,
			struct virtqueue *vqs[], vq_callback_t *callbacks[],
			const char * const names[],
			struct irq_affinity *desc)
{
	return vdev->config->find_vqs(vdev, nvqs, vqs, callbacks, names, NULL, desc);
}

static inline
int virtio_find_vqs_ctx(struct virtio_device *vdev, unsigned nvqs,
			struct virtqueue *vqs[], vq_callback_t *callbacks[],
			const char * const names[], const bool *ctx,
			struct irq_affinity *desc)
{
	return vdev->config->find_vqs(vdev, nvqs, vqs, callbacks, names, ctx,
				      desc);
}

/**
 * virtio_device_ready - enable vq use in probe function
 * @vdev: the device
 *
 * Driver must call this to use vqs in the probe function.
 *
 * Note: vqs are enabled automatically after probe returns.
 */
//设置设备状态达到DRIVER_OK
static inline
void virtio_device_ready(struct virtio_device *dev)
{
	//见virtio 1.0 sepc 3.1.1节，完成设备初始化
	unsigned status = dev->config->get_status(dev);

	BUG_ON(status & VIRTIO_CONFIG_S_DRIVER_OK);
	dev->config->set_status(dev, status | VIRTIO_CONFIG_S_DRIVER_OK);
}

static inline
const char *virtio_bus_name(struct virtio_device *vdev)
{
	if (!vdev->config->bus_name)
		return "virtio";
	return vdev->config->bus_name(vdev);
}

/**
 * virtqueue_set_affinity - setting affinity for a virtqueue
 * @vq: the virtqueue
 * @cpu: the cpu no.
 *
 * Pay attention the function are best-effort: the affinity hint may not be set
 * due to config support, irq type and sharing.
 *
 */
static inline
int virtqueue_set_affinity(struct virtqueue *vq, int cpu)
{
	struct virtio_device *vdev = vq->vdev;
	if (vdev->config->set_vq_affinity)
		return vdev->config->set_vq_affinity(vq, cpu);
	return 0;
}

//virtio规定的是小端类型
static inline bool virtio_is_little_endian(struct virtio_device *vdev)
{
	return virtio_has_feature(vdev, VIRTIO_F_VERSION_1) ||
		virtio_legacy_is_little_endian();
}

/* Memory accessors */
static inline u16 virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val)
{
	return __virtio16_to_cpu(virtio_is_little_endian(vdev), val);
}

//cpu序到virtio序转换（16bits)
static inline __virtio16 cpu_to_virtio16(struct virtio_device *vdev, u16 val)
{
	return __cpu_to_virtio16(virtio_is_little_endian(vdev), val);
}

static inline u32 virtio32_to_cpu(struct virtio_device *vdev, __virtio32 val)
{
	return __virtio32_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio32 cpu_to_virtio32(struct virtio_device *vdev, u32 val)
{
	return __cpu_to_virtio32(virtio_is_little_endian(vdev), val);
}

static inline u64 virtio64_to_cpu(struct virtio_device *vdev, __virtio64 val)
{
	return __virtio64_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio64 cpu_to_virtio64(struct virtio_device *vdev, u64 val)
{
	return __cpu_to_virtio64(virtio_is_little_endian(vdev), val);
}

/* Config space accessors. */
//按成员的字节大小进行配置读取
#define virtio_cread(vdev, structname, member, ptr)			\
	do {								\
		/* Must match the member's type, and be integer */	\
		if (!typecheck(typeof((((structname*)0)->member)), *(ptr))) \
			(*ptr) = 1;					\
									\
		switch (sizeof(*ptr)) {					\
		case 1:							\
		/*成员为1byte,故调用virtio_read8*/\
			*(ptr) = virtio_cread8(vdev,			\
					       offsetof(structname, member)); \
			break;						\
		case 2:							\
			*(ptr) = virtio_cread16(vdev,			\
						offsetof(structname, member)); \
			break;						\
		case 4:							\
			*(ptr) = virtio_cread32(vdev,			\
						offsetof(structname, member)); \
			break;						\
		case 8:							\
			*(ptr) = virtio_cread64(vdev,			\
						offsetof(structname, member)); \
			break;						\
		default:						\
			BUG();						\
		}							\
	} while(0)

/* Config space accessors. */
#define virtio_cwrite(vdev, structname, member, ptr)			\
	do {								\
		/* Must match the member's type, and be integer */	\
		if (!typecheck(typeof((((structname*)0)->member)), *(ptr))) \
			BUG_ON((*ptr) == 1);				\
									\
		switch (sizeof(*ptr)) {					\
		case 1:							\
			virtio_cwrite8(vdev,				\
				       offsetof(structname, member),	\
				       *(ptr));				\
			break;						\
		case 2:							\
			virtio_cwrite16(vdev,				\
					offsetof(structname, member),	\
					*(ptr));			\
			break;						\
		case 4:							\
			virtio_cwrite32(vdev,				\
					offsetof(structname, member),	\
					*(ptr));			\
			break;						\
		case 8:							\
			virtio_cwrite64(vdev,				\
					offsetof(structname, member),	\
					*(ptr));			\
			break;						\
		default:						\
			BUG();						\
		}							\
	} while(0)

/* Read @count fields, @bytes each. */
static inline void __virtio_cread_many(struct virtio_device *vdev,
				       unsigned int offset,
				       void *buf, size_t count, size_t bytes)
{
	u32 old, gen = vdev->config->generation ?
		vdev->config->generation(vdev) : 0;
	int i;

	do {
		old = gen;

		//完成读取count个bytes字节的工作，并调读取的值填充到buf中
		for (i = 0; i < count; i++)
			vdev->config->get(vdev, offset + bytes * i,
					  buf + i * bytes, bytes);

		gen = vdev->config->generation ?
			vdev->config->generation(vdev) : 0;
	} while (gen != old);
}

//读取len长度的字节（内部采用read_many实现）
static inline void virtio_cread_bytes(struct virtio_device *vdev,
				      unsigned int offset,
				      void *buf, size_t len)
{
	__virtio_cread_many(vdev, offset, buf, len, 1);
}

//采用vdev->config的get函数来进行读取，读取到的值存入&ret中，读取长度为sizeof(ret)来定
static inline u8 virtio_cread8(struct virtio_device *vdev, unsigned int offset)
{
	u8 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	return ret;
}

//采用vdev->config的set函数来设置，要设置的值存入在val中，要写入长度为sizeof(val)来定
static inline void virtio_cwrite8(struct virtio_device *vdev,
				  unsigned int offset, u8 val)
{
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

static inline u16 virtio_cread16(struct virtio_device *vdev,
				 unsigned int offset)
{
	u16 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	//将获取到的数据，转换为cpu序返回
	return virtio16_to_cpu(vdev, (__force __virtio16)ret);
}

static inline void virtio_cwrite16(struct virtio_device *vdev,
				   unsigned int offset, u16 val)
{
	val = (__force u16)cpu_to_virtio16(vdev, val);
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

static inline u32 virtio_cread32(struct virtio_device *vdev,
				 unsigned int offset)
{
	u32 ret;
	vdev->config->get(vdev, offset, &ret, sizeof(ret));
	return virtio32_to_cpu(vdev, (__force __virtio32)ret);
}

static inline void virtio_cwrite32(struct virtio_device *vdev,
				   unsigned int offset, u32 val)
{
	val = (__force u32)cpu_to_virtio32(vdev, val);
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

static inline u64 virtio_cread64(struct virtio_device *vdev,
				 unsigned int offset)
{
	u64 ret;
	__virtio_cread_many(vdev, offset, &ret, 1, sizeof(ret));
	return virtio64_to_cpu(vdev, (__force __virtio64)ret);
}

static inline void virtio_cwrite64(struct virtio_device *vdev,
				   unsigned int offset, u64 val)
{
	val = (__force u64)cpu_to_virtio64(vdev, val);
	vdev->config->set(vdev, offset, &val, sizeof(val));
}

//检查virtio是否支持功能fbit,如果支持，则读取此功能配置
/* Conditional config space accessors. */
#define virtio_cread_feature(vdev, fbit, structname, member, ptr)	\
	({								\
		int _r = 0;						\
		if (!virtio_has_feature(vdev, fbit))			\
			_r = -ENOENT;					\
		else							\
		/*对应的功能位被置上了，读取其配置structname类型的member成员，读到的值存在ptr中*/\
			virtio_cread((vdev), structname, member, ptr);	\
		_r;							\
	})

#endif /* _LINUX_VIRTIO_CONFIG_H */
