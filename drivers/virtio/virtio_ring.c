// SPDX-License-Identifier: GPL-2.0-or-later
/* Virtio ring implementation.
 *
 *  Copyright 2007 Rusty Russell IBM Corporation
 */
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/hrtimer.h>
#include <linux/dma-mapping.h>
#include <linux/kmsan.h>
#include <linux/spinlock.h>
#include <xen/xen.h>

#ifdef DEBUG
/* For development, we want to crash whenever the ring is screwed. */
#define BAD_RING(_vq, fmt, args...)				\
	do {							\
		dev_err(&(_vq)->vq.vdev->dev,			\
			"%s:"fmt, (_vq)->vq.name, ##args);	\
		BUG();						\
	} while (0)
/* Caller is supposed to guarantee no reentry. */
#define START_USE(_vq)						\
	do {							\
		if ((_vq)->in_use)				\
			panic("%s:in_use = %i\n",		\
			      (_vq)->vq.name, (_vq)->in_use);	\
		(_vq)->in_use = __LINE__;			\
	} while (0)
#define END_USE(_vq) \
	do { BUG_ON(!(_vq)->in_use); (_vq)->in_use = 0; } while(0)
#define LAST_ADD_TIME_UPDATE(_vq)				\
	do {							\
		ktime_t now = ktime_get();			\
								\
		/* No kick or get, with .1 second between?  Warn. */ \
		if ((_vq)->last_add_time_valid)			\
			WARN_ON(ktime_to_ms(ktime_sub(now,	\
				(_vq)->last_add_time)) > 100);	\
		(_vq)->last_add_time = now;			\
		(_vq)->last_add_time_valid = true;		\
	} while (0)
#define LAST_ADD_TIME_CHECK(_vq)				\
	do {							\
		if ((_vq)->last_add_time_valid) {		\
			WARN_ON(ktime_to_ms(ktime_sub(ktime_get(), \
				      (_vq)->last_add_time)) > 100); \
		}						\
	} while (0)
#define LAST_ADD_TIME_INVALID(_vq)				\
	((_vq)->last_add_time_valid = false)
#else
#define BAD_RING(_vq, fmt, args...)				\
	do {							\
		dev_err(&_vq->vq.vdev->dev,			\
			"%s:"fmt, (_vq)->vq.name, ##args);	\
		(_vq)->broken = true;				\
	} while (0)
#define START_USE(vq)
#define END_USE(vq)
#define LAST_ADD_TIME_UPDATE(vq)
#define LAST_ADD_TIME_CHECK(vq)
#define LAST_ADD_TIME_INVALID(vq)
#endif

struct vring_desc_state_split {
	//临时保存报文
	void *data;			/* Data for callback. */

	/* Indirect desc table and extra table, if any. These two will be
	 * allocated together. So we won't stress more to the memory allocator.
	 */
	//如果是indrect方式，则指向indirect时申请的desc数组
	struct vring_desc *indir_desc;
};

struct vring_desc_state_packed {
	void *data;			/* Data for callback. */

	/* Indirect desc table and extra table, if any. These two will be
	 * allocated together. So we won't stress more to the memory allocator.
	 */
	struct vring_packed_desc *indir_desc;
	u16 num;			/* Descriptor list length. */
	u16 last;			/* The last desc state in a list. */
};

struct vring_desc_extra {
	dma_addr_t addr;		/* Descriptor DMA addr. */
	u32 len;			/* Descriptor length. */
	u16 flags;			/* Descriptor flags. */
	/*利用next将desc_extra串起来*/
	u16 next;			/* The next desc state in a list. */
};

struct vring_virtqueue_split {
	/* Actual memory layout for this queue. */
	struct vring vring;

	/* Last written value to avail->flags */
	u16 avail_flags_shadow;

	/*
	 * Last written value to avail->idx in
	 * guest byte order.
	 */
	u16 avail_idx_shadow;

	/* Per-descriptor state. */
	struct vring_desc_state_split *desc_state;
	struct vring_desc_extra *desc_extra;

	/* DMA address and size information */
	dma_addr_t queue_dma_addr;
	size_t queue_size_in_bytes;

	/*
	 * The parameters for creating vrings are reserved for creating new
	 * vring.
	 */
	u32 vring_align;
	bool may_reduce_num;
};

struct vring_virtqueue_packed {
	/* Actual memory layout for this queue. */
	struct {
		unsigned int num;//desc队列大小
		struct vring_packed_desc *desc;//描述符表虚拟地址（num个vring_packed_desc)
		struct vring_packed_desc_event *driver;
		struct vring_packed_desc_event *device;//描述事件虑拟地址
	} vring;

	/* Driver ring wrap counter. */
	/*标准要求每个设备和驱动都需要维护一个单BIT的回绕计数器(此值初始化为1)
	 * 这个计数器每次经过最后一个DESC元素时将被反转(因为只有一个bit).
	 * 驱动通过设置VRING_PACKED_DESC_F_AVAIL位来使描述符变得有效(可被设备读取).
	 * 但它设置的值以此计数器当前值为准.例如:它在第一轮时,会将此位设置为'1',第二轮时会将此位设置为'0'
	 * 同时它通过匹配VRING_PACKED_DESC_F_USED位来确定描述符"可用",
	 * 它匹配的方法是检查这一位是否与当前计数器的值不一致.例如:它在第一轮时,通过匹配'0'理解此描述可用,
	 * 在第二轮时通过匹配'1'来理解此描述符可用.
	 * */
	bool avail_wrap_counter;/*驱动wrap计数器*/

	/* Avail used flags. */
	u16 avail_used_flags;

	/* Index of the next avail descriptor. */
	u16 next_avail_idx;/*缓存的当前有效描述符索引*/

	/*
	 * Last written value to driver->flags in
	 * guest byte order.
	 */
	u16 event_flags_shadow;

	/* Per-descriptor state. */
	struct vring_desc_state_packed *desc_state;//记录每个描述符的状态（长度与desc表相同）
	/*按标准规定,描述符被驱动提交给硬件后,如果是list,则硬件仅会写一个描述符为USED,并直接跳过链表中其余描述符.
	 * 且描述符中的NEXT标记标准规定驱动需要忽略.
	 * 因此驱动不得依赖desc表来回收描述符.
	 * 故驱动申请desc_extra(因此struct vring_packed_desc结构体的所有内容在此结构也需要)来解决这个问题.
	 * 在发送报文时将desc中的填充情况一并也写入到desc_extra,回收时依靠desc_extra来完成.
	 * */
	struct vring_desc_extra *desc_extra;/*记录每个描述符的额外信息（长度与desc表相同）*/

	/* DMA address and size information */
	dma_addr_t ring_dma_addr;//记录desc队列对应的dma地址
	/*申请的driver event物理地址（vring->driver)*/
	dma_addr_t driver_event_dma_addr;
	dma_addr_t device_event_dma_addr;/*申请的device event物理地址(vring->device)*/
	size_t ring_size_in_bytes;/*desc队列对应的内存大小*/
	size_t event_size_in_bytes;//driver-event,device-event对应的内存大小
};

struct vring_virtqueue {
	struct virtqueue vq;

	/* Is this a packed ring? */
	bool packed_ring;/*是否为packed类型的ring*/

	/* Is DMA API used? */
	bool use_dma_api;

	/* Can we use weak barriers? */
	bool weak_barriers;

	/* Other side has made a mess, don't try any more. */
	bool broken;/*指明vq是否损坏*/

	/* Host supports indirect buffers */
	/*如果设备指明支持VIRTIO_RING_F_INDIRECT_DESC,此项即为TRUE,此时在发送多片内容时
	 * 我们会先申请一个DESC,并指明这个DESC为indirect desc,然后在这个DESC中填充各个分片描述符
	 * 这样相当于扩充了vring的容量*/
	bool indirect;//是否支持indirect buffers形式（即采用链表串起来的方式）

	/* Host publishes avail event idx */
	bool event;

	/* Head of free buffer list. */
	unsigned int free_head;//空闲跟踪描述符头指针（此指针对应的desc_extra是空闲的）
	/* Number we've added since last sync. */
	unsigned int num_added;//队列中元素数（占用的描述符数量）

	/* Last used index  we've seen.
	 * for split ring, it just contains last used index
	 * for packed ring:
	 * bits up to VRING_PACKED_EVENT_F_WRAP_CTR include the last used index.
	 * bits from VRING_PACKED_EVENT_F_WRAP_CTR include the used wrap counter.
	 */
	u16 last_used_idx;//收包位置（上次收包位置）

	/* Hint for event idx: already triggered no need to disable. */
	bool event_triggered;

	union {
		/* Available for split ring */
		struct vring_virtqueue_split split;

		/* Available for packed ring */
		struct vring_virtqueue_packed packed;
	};

	/* How to notify other side. FIXME: commonalize hcalls! */
	//用于通知对端,队列vq发生变化
	bool (*notify)(struct virtqueue *vq);

	/* DMA, allocation, and size information */
	bool we_own_ring;/*是否驱动own的ring*/

	/* Device used for doing DMA */
	struct device *dma_dev;/*对应的dma设备*/

#ifdef DEBUG
	/* They're supposed to lock for us. */
	unsigned int in_use;

	/* Figure out if their kicks are too delayed. */
	bool last_add_time_valid;
	ktime_t last_add_time;
#endif
};

static struct vring_desc_extra *vring_alloc_desc_extra(unsigned int num);
static void vring_free(struct virtqueue *_vq);

/*
 * Helpers.
 */

/*_vq是类型virtqueue，其包含在结构体vring_virtqueue中，成员名为vq,
 * 此函数用于通过结构体virtqueue获取结构体vring_virtqueue*/
#define to_vvq(_vq) container_of_const(_vq, struct vring_virtqueue, vq)

static bool virtqueue_use_indirect(const struct vring_virtqueue *vq,
				   unsigned int total_sg)
{
	/*
	 * If the host supports indirect descriptor tables, and we have multiple
	 * buffers, then go indirect. FIXME: tune this threshold
	 */
	return (vq->indirect && total_sg > 1 && vq->vq.num_free);
}

/*
 * Modern virtio devices have feature bits to specify whether they need a
 * quirk and bypass the IOMMU. If not there, just use the DMA API.
 *
 * If there, the interaction between virtio and DMA API is messy.
 *
 * On most systems with virtio, physical addresses match bus addresses,
 * and it doesn't particularly matter whether we use the DMA API.
 *
 * On some systems, including Xen and any system with a physical device
 * that speaks virtio behind a physical IOMMU, we must use the DMA API
 * for virtio DMA to work at all.
 *
 * On other systems, including SPARC and PPC64, virtio-pci devices are
 * enumerated as though they are behind an IOMMU, but the virtio host
 * ignores the IOMMU, so we must either pretend that the IOMMU isn't
 * there or somehow map everything as the identity.
 *
 * For the time being, we preserve historic behavior and bypass the DMA
 * API.
 *
 * TODO: install a per-device DMA ops structure that does the right thing
 * taking into account all the above quirks, and use the DMA API
 * unconditionally on data path.
 */

static bool vring_use_dma_api(const struct virtio_device *vdev)
{
	if (!virtio_has_dma_quirk(vdev))
		return true;

	/* Otherwise, we are left to guess. */
	/*
	 * In theory, it's possible to have a buggy QEMU-supposed
	 * emulated Q35 IOMMU and Xen enabled at the same time.  On
	 * such a configuration, virtio has never worked and will
	 * not work without an even larger kludge.  Instead, enable
	 * the DMA API if we're a Xen guest, which at least allows
	 * all of the sensible Xen configurations to work correctly.
	 */
	if (xen_domain())
		return true;

	return false;
}

static bool vring_need_unmap_buffer(const struct vring_virtqueue *vring,
				    const struct vring_desc_extra *extra)
{
	return vring->use_dma_api && (extra->addr != DMA_MAPPING_ERROR);
}

size_t virtio_max_dma_size(const struct virtio_device *vdev)
{
	size_t max_segment_size = SIZE_MAX;

	if (vring_use_dma_api(vdev))
		max_segment_size = dma_max_mapping_size(vdev->dev.parent);

	return max_segment_size;
}
EXPORT_SYMBOL_GPL(virtio_max_dma_size);

/*申请size字节的buffer,并返回buffer对应的dma地址*/
static void *vring_alloc_queue(struct virtio_device *vdev, size_t size/*队列内存大小*/,
			       dma_addr_t *dma_handle/*出参，dma地址*/, gfp_t flag,
			       struct device *dma_dev)
{
	if (vring_use_dma_api(vdev)) {
		return dma_alloc_coherent(dma_dev, size,
					  dma_handle, flag);
	} else {
		/*采用alloc_pages_exact申请page*/
		void *queue = alloc_pages_exact(PAGE_ALIGN(size)/*对齐到页*/, flag);

		if (queue) {
		    //将queue起始地址转换为物理地址
			phys_addr_t phys_addr = virt_to_phys(queue);
			*dma_handle = (dma_addr_t)phys_addr;

			/*
			 * Sanity check: make sure we dind't truncate
			 * the address.  The only arches I can find that
			 * have 64-bit phys_addr_t but 32-bit dma_addr_t
			 * are certain non-highmem MIPS and x86
			 * configurations, but these configurations
			 * should never allocate physical pages above 32
			 * bits, so this is fine.  Just in case, throw a
			 * warning and abort if we end up with an
			 * unrepresentable address.
			 */
			if (WARN_ON_ONCE(*dma_handle != phys_addr)) {
				free_pages_exact(queue, PAGE_ALIGN(size));
				return NULL;
			}
		}
		return queue;
	}
}

static void vring_free_queue(struct virtio_device *vdev, size_t size,
			     void *queue, dma_addr_t dma_handle,
			     struct device *dma_dev)
{
	if (vring_use_dma_api(vdev))
		dma_free_coherent(dma_dev, size, queue, dma_handle);
	else
		free_pages_exact(queue, PAGE_ALIGN(size));
}

/*
 * The DMA ops on various arches are rather gnarly right now, and
 * making all of the arch DMA ops work on the vring device itself
 * is a mess.
 */
static struct device *vring_dma_dev(const struct vring_virtqueue *vq)
{
	return vq->dma_dev;
}

/* Map one sg entry. */
static int vring_map_one_sg(const struct vring_virtqueue *vq, struct scatterlist *sg,
			    enum dma_data_direction direction, dma_addr_t *addr,
			    u32 *len, bool premapped)
{
	if (premapped) {
		*addr = sg_dma_address(sg);/*直接返回DMA地址*/
		*len = sg_dma_len(sg);
		return 0;
	}

	*len = sg->length;

	if (!vq->use_dma_api) {
		/*
		 * If DMA is not used, KMSAN doesn't know that the scatterlist
		 * is initialized by the hardware. Explicitly check/unpoison it
		 * depending on the direction.
		 */
		kmsan_handle_dma(sg_page(sg), sg->offset, sg->length, direction);
		*addr = (dma_addr_t)sg_phys(sg);
		return 0;
	}

	/*
	 * We can't use dma_map_sg, because we don't use scatterlists in
	 * the way it expects (we don't guarantee that the scatterlist
	 * will exist for the lifetime of the mapping).
	 */
	*addr = dma_map_page(vring_dma_dev(vq),
			    sg_page(sg), sg->offset, sg->length,
			    direction);

	if (dma_mapping_error(vring_dma_dev(vq), *addr))
		return -ENOMEM;

	return 0;
}

static dma_addr_t vring_map_single(const struct vring_virtqueue *vq,
				   void *cpu_addr, size_t size,
				   enum dma_data_direction direction)
{
	if (!vq->use_dma_api)
		return (dma_addr_t)virt_to_phys(cpu_addr);

	return dma_map_single(vring_dma_dev(vq),
			      cpu_addr, size, direction);
}

static int vring_mapping_error(const struct vring_virtqueue *vq,
			       dma_addr_t addr)
{
	if (!vq->use_dma_api)
		return 0;

	return dma_mapping_error(vring_dma_dev(vq), addr);
}

static void virtqueue_init(struct vring_virtqueue *vq, u32 num)
{
	vq->vq.num_free = num;/*空闲描述符数量为NUM个*/

	if (vq->packed_ring)
		vq->last_used_idx = 0 | (1 << VRING_PACKED_EVENT_F_WRAP_CTR);
	else
		vq->last_used_idx = 0;

	vq->event_triggered = false;
	vq->num_added = 0;/*VQ初始化,元素数为零个*/

#ifdef DEBUG
	vq->in_use = false;
	vq->last_add_time_valid = false;
#endif
}


/*
 * Split ring specific functions - *_split().
 */

static unsigned int vring_unmap_one_split(const struct vring_virtqueue *vq,
					  struct vring_desc_extra *extra)
{
	u16 flags;

	flags = extra->flags;

	if (flags & VRING_DESC_F_INDIRECT) {
		if (!vq->use_dma_api)
			goto out;

		dma_unmap_single(vring_dma_dev(vq),
				 extra->addr,
				 extra->len,
				 (flags & VRING_DESC_F_WRITE) ?
				 DMA_FROM_DEVICE : DMA_TO_DEVICE);
	} else {
		if (!vring_need_unmap_buffer(vq, extra))
			goto out;

		dma_unmap_page(vring_dma_dev(vq),
			       extra->addr,
			       extra->len,
			       (flags & VRING_DESC_F_WRITE) ?
			       DMA_FROM_DEVICE : DMA_TO_DEVICE);
	}

out:
	return extra->next;
}

//申请total_sg个vring_desc描述符，并将它们串成一串
static struct vring_desc *alloc_indirect_split(struct virtqueue *_vq,
					       unsigned int total_sg,
					       gfp_t gfp)
{
	struct vring_desc_extra *extra;
	struct vring_desc *desc;
	unsigned int i, size;

	/*
	 * We require lowmem mappings for the descriptors because
	 * otherwise virt_to_phys will give us bogus addresses in the
	 * virtqueue.
	 */
	gfp &= ~__GFP_HIGHMEM;

	size = sizeof(*desc) * total_sg + sizeof(*extra) * total_sg;

	//申请total_sg个struct vring_desc结构体
	desc = kmalloc(size, gfp);
	if (!desc)
		return NULL;

	extra = (struct vring_desc_extra *)&desc[total_sg];

	//将desc数组串起来，使next指向i+1
	for (i = 0; i < total_sg; i++)
		extra[i].next = i + 1;

	return desc;
}

static inline unsigned int virtqueue_add_desc_split(struct virtqueue *vq,
						    struct vring_desc *desc,
						    struct vring_desc_extra *extra,
						    unsigned int i,
						    dma_addr_t addr,
						    unsigned int len,
						    u16 flags, bool premapped)
{
	u16 next;

	desc[i].flags = cpu_to_virtio16(vq->vdev, flags);
	desc[i].addr = cpu_to_virtio64(vq->vdev, addr);
	desc[i].len = cpu_to_virtio32(vq->vdev, len);

	extra[i].addr = premapped ? DMA_MAPPING_ERROR : addr;
	extra[i].len = len;
	extra[i].flags = flags;

	next = extra[i].next;

	desc[i].next = cpu_to_virtio16(vq->vdev, next);

	return next;
}

static inline int virtqueue_add_split(struct virtqueue *_vq,
				      struct scatterlist *sgs[],//记录发送与接收的scatterlist
				      unsigned int total_sg,//scatterlist结构总数
				      unsigned int out_sgs,//要发送出去的scatterlist总数
				      unsigned int in_sgs,//要接受的scatterlist总数
				      void *data,//要发送的报文
				      void *ctx,
				      bool premapped,
				      gfp_t gfp)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct vring_desc_extra *extra;
	struct scatterlist *sg;
	struct vring_desc *desc;
	unsigned int i, n, avail, descs_used, prev, err_idx;
	int head;
	bool indirect;

	START_USE(vq);

	BUG_ON(data == NULL);
	BUG_ON(ctx && vq->indirect);//在indirect方式时，ctx必须为NULL

	if (unlikely(vq->broken)) {
		END_USE(vq);
		return -EIO;
	}

	LAST_ADD_TIME_UPDATE(vq);

	BUG_ON(total_sg == 0);

	head = vq->free_head;//取空闲描述符

	if (virtqueue_use_indirect(vq, total_sg))
		//支持indirect方式，故需要一次性申请total_sg个desc,并将其串起来
		//其next指向的是从0开始的序号
		desc = alloc_indirect_split(_vq, total_sg, gfp);
	else {
		//直接情况下为NULL
		desc = NULL;
		//total_sg一定小于等于vq->vring.num，否则无法发送出去
		WARN_ON_ONCE(total_sg > vq->split.vring.num && !vq->indirect);
	}

	if (desc) {
		/* Use a single buffer which doesn't continue */
		indirect = true;
		/* Set up rest to use this indirect table. */
		i = 0;
		descs_used = 1;//indirect情况下，仅会用掉一个描述符
		extra = (struct vring_desc_extra *)&desc[total_sg];
	} else {
		indirect = false;
		desc = vq->split.vring.desc;
		extra = vq->split.desc_extra;
		//取空闲的desc头指针
		i = head;
		//指出需要用多少desc
		descs_used = total_sg;//非indirect情况下，会用掉total_sg个描述符
	}

	if (unlikely(vq->vq.num_free < descs_used)) {
		//空闲描述符数量不足，不能发送
		pr_debug("Can't add buf len %i - avail = %i\n",
			 descs_used, vq->vq.num_free);
		/* FIXME: for historical reasons, we force a notify here if
		 * there are outgoing parts to the buffer.  Presumably the
		 * host should service the ring ASAP. */
		if (out_sgs)
			//通知对端，快点收包，尽快释放desc
			vq->notify(&vq->vq);
		if (indirect)
			kfree(desc);
		END_USE(vq);
		return -ENOSPC;
	}

	//处理待发送的sgs
	for (n = 0; n < out_sgs; n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			dma_addr_t addr;
			u32 len;

			//取sg中数据对应的dma地址
			if (vring_map_one_sg(vq, sg, DMA_TO_DEVICE, &addr, &len, premapped))
				goto unmap_release;

			prev = i;
			/* Note that we trust indirect descriptor
			 * table since it use stream DMA mapping.
			 */
			//用sg填充描述符
			i = virtqueue_add_desc_split(_vq, desc, extra, i, addr, len,
						     VRING_DESC_F_NEXT,
						     premapped);
		}
	}

	//处理待接收的sgs
	for (; n < (out_sgs + in_sgs); n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			dma_addr_t addr;
			u32 len;

			//填充待接收的sgs
			if (vring_map_one_sg(vq, sg, DMA_FROM_DEVICE, &addr, &len, premapped))
				goto unmap_release;

			prev = i;
			/* Note that we trust indirect descriptor
			 * table since it use stream DMA mapping.
			 */
			i = virtqueue_add_desc_split(_vq, desc, extra, i, addr, len,
						     VRING_DESC_F_NEXT |
						     VRING_DESC_F_WRITE,
						     premapped);
		}
	}

	/* Last one doesn't continue. */
	//指明desc[prev]为最后一个描述符
	desc[prev].flags &= cpu_to_virtio16(_vq->vdev, ~VRING_DESC_F_NEXT);
	if (!indirect && vring_need_unmap_buffer(vq, &extra[prev]))
		vq->split.desc_extra[prev & (vq->split.vring.num - 1)].flags &=
			~VRING_DESC_F_NEXT;

	if (indirect) {
		/* Now that the indirect table is filled in, map it. */
		dma_addr_t addr = vring_map_single(
			vq, desc, total_sg * sizeof(struct vring_desc),
			DMA_TO_DEVICE);
		if (vring_mapping_error(vq, addr))
			goto unmap_release;

		//针对indirect方式，由addr指向的是由total_sg个描述符组成的desc list,现在使head描述符描述出它们
		//并在flags中标明此描述符为indirect方式
		virtqueue_add_desc_split(_vq, vq->split.vring.desc,
					 vq->split.desc_extra,
					 head, addr,
					 total_sg * sizeof(struct vring_desc),
					 VRING_DESC_F_INDIRECT, false);
	}

	/* We're using some buffers from the free list. */
	vq->vq.num_free -= descs_used;//减去已使用的desc

	/* Update free pointer */
	//更新首个空闲desc的指针
	if (indirect)
		vq->free_head = vq->split.desc_extra[head].next;
	else
		vq->free_head = i;

	/* Store token and indirect buffer state. */
	//设置要发送的报文
	vq->split.desc_state[head].data = data;
	if (indirect)
		//indirect方式时，使其指向申请的desc数组
		vq->split.desc_state[head].indir_desc = desc;
	else
		//这种情况未阅读
		vq->split.desc_state[head].indir_desc = ctx;

	/* Put entry in available array (but don't update avail->idx until they
	 * do sync). */
	//将head指针放入到有效ring中
	avail = vq->split.avail_idx_shadow & (vq->split.vring.num - 1);
	vq->split.vring.avail->ring[avail] = cpu_to_virtio16(_vq->vdev, head);

	/* Descriptors and available array need to be set before we expose the
	 * new available array entries. */
	//更新有效索引(avail->idx)
	virtio_wmb(vq->weak_barriers);
	vq->split.avail_idx_shadow++;
	vq->split.vring.avail->idx = cpu_to_virtio16(_vq->vdev,
						vq->split.avail_idx_shadow);
	vq->num_added++;//队列中元素数增加

	pr_debug("Added buffer head %i to %p\n", head, vq);
	END_USE(vq);

	/* This is very unlikely, but theoretically possible.  Kick
	 * just in case. */
	//当队列中含有的元素数等于65535时，进行kick
	if (unlikely(vq->num_added == (1 << 16) - 1))
		virtqueue_kick(_vq);

	return 0;

unmap_release:
	err_idx = i;

	if (indirect)
		i = 0;
	else
		i = head;

	for (n = 0; n < total_sg; n++) {
		if (i == err_idx)
			break;

		i = vring_unmap_one_split(vq, &extra[i]);
	}

	if (indirect)
		kfree(desc);

	END_USE(vq);
	return -ENOMEM;
}

static bool virtqueue_kick_prepare_split(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 new, old;
	bool needs_kick;

	START_USE(vq);
	/* We need to expose available array entries before checking avail
	 * event. */
	virtio_mb(vq->weak_barriers);

	old = vq->split.avail_idx_shadow - vq->num_added;
	new = vq->split.avail_idx_shadow;
	vq->num_added = 0;

	LAST_ADD_TIME_CHECK(vq);
	LAST_ADD_TIME_INVALID(vq);

	if (vq->event) {
		needs_kick = vring_need_event(virtio16_to_cpu(_vq->vdev,
					vring_avail_event(&vq->split.vring)),
					      new, old);
	} else {
		needs_kick = !(vq->split.vring.used->flags &
					cpu_to_virtio16(_vq->vdev,
						VRING_USED_F_NO_NOTIFY));
	}
	END_USE(vq);
	return needs_kick;
}

static void detach_buf_split(struct vring_virtqueue *vq, unsigned int head,
			     void **ctx)
{
	struct vring_desc_extra *extra;
	unsigned int i, j;
	__virtio16 nextflag = cpu_to_virtio16(vq->vq.vdev, VRING_DESC_F_NEXT);

	/* Clear data ptr. */
	vq->split.desc_state[head].data = NULL;

	extra = vq->split.desc_extra;

	/* Put back on free list: unmap first-level descriptors and find end */
	i = head;

	while (vq->split.vring.desc[i].flags & nextflag) {
		vring_unmap_one_split(vq, &extra[i]);
		i = vq->split.desc_extra[i].next;
		vq->vq.num_free++;
	}

	vring_unmap_one_split(vq, &extra[i]);
	vq->split.desc_extra[i].next = vq->free_head;
	vq->free_head = head;

	/* Plus final descriptor */
	vq->vq.num_free++;

	if (vq->indirect) {
		struct vring_desc *indir_desc =
				vq->split.desc_state[head].indir_desc;
		u32 len, num;

		/* Free the indirect table, if any, now that it's unmapped. */
		if (!indir_desc)
			return;
		len = vq->split.desc_extra[head].len;

		BUG_ON(!(vq->split.desc_extra[head].flags &
				VRING_DESC_F_INDIRECT));
		BUG_ON(len == 0 || len % sizeof(struct vring_desc));

		num = len / sizeof(struct vring_desc);

		extra = (struct vring_desc_extra *)&indir_desc[num];

		if (vq->use_dma_api) {
			for (j = 0; j < num; j++)
				vring_unmap_one_split(vq, &extra[j]);
		}

		kfree(indir_desc);
		vq->split.desc_state[head].indir_desc = NULL;
	} else if (ctx) {
		*ctx = vq->split.desc_state[head].indir_desc;
	}
}

static bool more_used_split(const struct vring_virtqueue *vq)
{
	return vq->last_used_idx != virtio16_to_cpu(vq->vq.vdev,
			vq->split.vring.used->idx);
}

static void *virtqueue_get_buf_ctx_split(struct virtqueue *_vq,
					 unsigned int *len,
					 void **ctx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	void *ret;
	unsigned int i;
	u16 last_used;

	START_USE(vq);

	if (unlikely(vq->broken)) {
		END_USE(vq);
		return NULL;
	}

	if (!more_used_split(vq)) {
		pr_debug("No more buffers in queue\n");
		END_USE(vq);
		return NULL;
	}

	/* Only get used array entries after they have been exposed by host. */
	virtio_rmb(vq->weak_barriers);

	last_used = (vq->last_used_idx & (vq->split.vring.num - 1));
	i = virtio32_to_cpu(_vq->vdev,
			vq->split.vring.used->ring[last_used].id);
	*len = virtio32_to_cpu(_vq->vdev,
			vq->split.vring.used->ring[last_used].len);

	if (unlikely(i >= vq->split.vring.num)) {
		BAD_RING(vq, "id %u out of range\n", i);
		return NULL;
	}
	if (unlikely(!vq->split.desc_state[i].data)) {
		BAD_RING(vq, "id %u is not a head!\n", i);
		return NULL;
	}

	/* detach_buf_split clears data, so grab it now. */
	ret = vq->split.desc_state[i].data;
	detach_buf_split(vq, i, ctx);
	vq->last_used_idx++;
	/* If we expect an interrupt for the next entry, tell host
	 * by writing event index and flush out the write before
	 * the read in the next get_buf call. */
	if (!(vq->split.avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT))
		virtio_store_mb(vq->weak_barriers,
				&vring_used_event(&vq->split.vring),
				cpu_to_virtio16(_vq->vdev, vq->last_used_idx));

	LAST_ADD_TIME_INVALID(vq);

	END_USE(vq);
	return ret;
}

static void virtqueue_disable_cb_split(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!(vq->split.avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT)) {
		vq->split.avail_flags_shadow |= VRING_AVAIL_F_NO_INTERRUPT;

		/*
		 * If device triggered an event already it won't trigger one again:
		 * no need to disable.
		 */
		if (vq->event_triggered)
			return;

		if (vq->event)
			/* TODO: this is a hack. Figure out a cleaner value to write. */
			vring_used_event(&vq->split.vring) = 0x0;
		else
			vq->split.vring.avail->flags =
				cpu_to_virtio16(_vq->vdev,
						vq->split.avail_flags_shadow);
	}
}

static unsigned int virtqueue_enable_cb_prepare_split(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 last_used_idx;

	START_USE(vq);

	/* We optimistically turn back on interrupts, then check if there was
	 * more to do. */
	/* Depending on the VIRTIO_RING_F_EVENT_IDX feature, we need to
	 * either clear the flags bit or point the event index at the next
	 * entry. Always do both to keep code simple. */
	if (vq->split.avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT) {
		vq->split.avail_flags_shadow &= ~VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vq->split.vring.avail->flags =
				cpu_to_virtio16(_vq->vdev,
						vq->split.avail_flags_shadow);
	}
	vring_used_event(&vq->split.vring) = cpu_to_virtio16(_vq->vdev,
			last_used_idx = vq->last_used_idx);
	END_USE(vq);
	return last_used_idx;
}

static bool virtqueue_poll_split(struct virtqueue *_vq, unsigned int last_used_idx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return (u16)last_used_idx != virtio16_to_cpu(_vq->vdev,
			vq->split.vring.used->idx);
}

static bool virtqueue_enable_cb_delayed_split(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 bufs;

	START_USE(vq);

	/* We optimistically turn back on interrupts, then check if there was
	 * more to do. */
	/* Depending on the VIRTIO_RING_F_USED_EVENT_IDX feature, we need to
	 * either clear the flags bit or point the event index at the next
	 * entry. Always update the event index to keep code simple. */
	if (vq->split.avail_flags_shadow & VRING_AVAIL_F_NO_INTERRUPT) {
		vq->split.avail_flags_shadow &= ~VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vq->split.vring.avail->flags =
				cpu_to_virtio16(_vq->vdev,
						vq->split.avail_flags_shadow);
	}
	/* TODO: tune this threshold */
	bufs = (u16)(vq->split.avail_idx_shadow - vq->last_used_idx) * 3 / 4;

	virtio_store_mb(vq->weak_barriers,
			&vring_used_event(&vq->split.vring),
			cpu_to_virtio16(_vq->vdev, vq->last_used_idx + bufs));

	if (unlikely((u16)(virtio16_to_cpu(_vq->vdev, vq->split.vring.used->idx)
					- vq->last_used_idx) > bufs)) {
		END_USE(vq);
		return false;
	}

	END_USE(vq);
	return true;
}

static void *virtqueue_detach_unused_buf_split(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	unsigned int i;
	void *buf;

	START_USE(vq);

	for (i = 0; i < vq->split.vring.num; i++) {
		if (!vq->split.desc_state[i].data)
			continue;
		/* detach_buf_split clears data, so grab it now. */
		buf = vq->split.desc_state[i].data;
		detach_buf_split(vq, i, NULL);
		vq->split.avail_idx_shadow--;
		vq->split.vring.avail->idx = cpu_to_virtio16(_vq->vdev,
				vq->split.avail_idx_shadow);
		END_USE(vq);
		return buf;
	}
	/* That should have freed everything. */
	BUG_ON(vq->vq.num_free != vq->split.vring.num);

	END_USE(vq);
	return NULL;
}

static void virtqueue_vring_init_split(struct vring_virtqueue_split *vring_split,
				       struct vring_virtqueue *vq)
{
	struct virtio_device *vdev;

	vdev = vq->vq.vdev;

	vring_split->avail_flags_shadow = 0;
	vring_split->avail_idx_shadow = 0;

	/* No callback?  Tell other side not to bother us. */
	if (!vq->vq.callback) {
		vring_split->avail_flags_shadow |= VRING_AVAIL_F_NO_INTERRUPT;
		if (!vq->event)
			vring_split->vring.avail->flags = cpu_to_virtio16(vdev,
					vring_split->avail_flags_shadow);
	}
}

static void virtqueue_reinit_split(struct vring_virtqueue *vq)
{
	int num;

	num = vq->split.vring.num;

	vq->split.vring.avail->flags = 0;
	vq->split.vring.avail->idx = 0;

	/* reset avail event */
	vq->split.vring.avail->ring[num] = 0;

	vq->split.vring.used->flags = 0;
	vq->split.vring.used->idx = 0;

	/* reset used event */
	*(__virtio16 *)&(vq->split.vring.used->ring[num]) = 0;

	virtqueue_init(vq, num);

	virtqueue_vring_init_split(&vq->split, vq);
}

static void virtqueue_vring_attach_split(struct vring_virtqueue *vq,
					 struct vring_virtqueue_split *vring_split)
{
	vq->split = *vring_split;

	/* Put everything in free lists. */
	vq->free_head = 0;
}

static int vring_alloc_state_extra_split(struct vring_virtqueue_split *vring_split)
{
	struct vring_desc_state_split *state;
	struct vring_desc_extra *extra;
	u32 num = vring_split->vring.num;

	state = kmalloc_array(num, sizeof(struct vring_desc_state_split), GFP_KERNEL);
	if (!state)
		goto err_state;

	extra = vring_alloc_desc_extra(num);
	if (!extra)
		goto err_extra;

	memset(state, 0, num * sizeof(struct vring_desc_state_split));

	vring_split->desc_state = state;
	vring_split->desc_extra = extra;
	return 0;

err_extra:
	kfree(state);
err_state:
	return -ENOMEM;
}

static void vring_free_split(struct vring_virtqueue_split *vring_split,
			     struct virtio_device *vdev, struct device *dma_dev)
{
	vring_free_queue(vdev, vring_split->queue_size_in_bytes,
			 vring_split->vring.desc,
			 vring_split->queue_dma_addr,
			 dma_dev);

	kfree(vring_split->desc_state);
	kfree(vring_split->desc_extra);
}

static int vring_alloc_queue_split(struct vring_virtqueue_split *vring_split,
				   struct virtio_device *vdev,
				   u32 num,
				   unsigned int vring_align,
				   bool may_reduce_num,
				   struct device *dma_dev)
{
	void *queue = NULL;
	dma_addr_t dma_addr;

	/* We assume num is a power of 2. */
	if (!is_power_of_2(num)) {
		dev_warn(&vdev->dev, "Bad virtqueue length %u\n", num);
		return -EINVAL;
	}

	/* TODO: allocate each queue chunk individually */
	for (; num && vring_size(num, vring_align) > PAGE_SIZE; num /= 2) {
		queue = vring_alloc_queue(vdev, vring_size(num, vring_align),
					  &dma_addr,
					  GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
					  dma_dev);
		if (queue)
			break;
		if (!may_reduce_num)
			return -ENOMEM;
	}

	if (!num)
		return -ENOMEM;

	if (!queue) {
		/* Try to get a single page. You are my only hope! */
		queue = vring_alloc_queue(vdev, vring_size(num, vring_align),
					  &dma_addr, GFP_KERNEL | __GFP_ZERO,
					  dma_dev);
	}
	if (!queue)
		return -ENOMEM;

	vring_init(&vring_split->vring, num, queue, vring_align);

	vring_split->queue_dma_addr = dma_addr;
	vring_split->queue_size_in_bytes = vring_size(num, vring_align);

	vring_split->vring_align = vring_align;
	vring_split->may_reduce_num = may_reduce_num;

	return 0;
}

static struct virtqueue *__vring_new_virtqueue_split(unsigned int index,
					       struct vring_virtqueue_split *vring_split,
					       struct virtio_device *vdev,
					       bool weak_barriers,
					       bool context,
					       bool (*notify)(struct virtqueue *),
					       void (*callback)(struct virtqueue *),
					       const char *name,
					       struct device *dma_dev)
{
	struct vring_virtqueue *vq;
	int err;

	//申请连续内存，创建vring_virtqueue及vring.num个描述符
	vq = kmalloc(sizeof(*vq), GFP_KERNEL);
	if (!vq)
		return NULL;

	vq->packed_ring = false;/*非packed类型的ring*/
	vq->vq.callback = callback;
	vq->vq.vdev = vdev;
	vq->vq.name = name;
	vq->vq.index = index;
	vq->vq.reset = false;
	vq->we_own_ring = false;
	vq->notify = notify;/*设置notify函数*/
	vq->weak_barriers = weak_barriers;
#ifdef CONFIG_VIRTIO_HARDEN_NOTIFICATION
	vq->broken = true;
#else
	vq->broken = false;
#endif
	vq->dma_dev = dma_dev;
	vq->use_dma_api = vring_use_dma_api(vdev);

	vq->indirect = virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC) &&
		!context;
	vq->event = virtio_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX);

	if (virtio_has_feature(vdev, VIRTIO_F_ORDER_PLATFORM))
		vq->weak_barriers = false;

	err = vring_alloc_state_extra_split(vring_split);
	if (err) {
		kfree(vq);
		return NULL;
	}

	virtqueue_vring_init_split(vring_split, vq);

	virtqueue_init(vq, vring_split->vring.num);
	virtqueue_vring_attach_split(vq, vring_split);

	spin_lock(&vdev->vqs_list_lock);
	list_add_tail(&vq->vq.list, &vdev->vqs);
	spin_unlock(&vdev->vqs_list_lock);
	return &vq->vq;
}

static struct virtqueue *vring_create_virtqueue_split(
	unsigned int index,
	unsigned int num,
	unsigned int vring_align,
	struct virtio_device *vdev,
	bool weak_barriers,
	bool may_reduce_num,
	bool context,
	bool (*notify)(struct virtqueue *),
	void (*callback)(struct virtqueue *),
	const char *name,
	struct device *dma_dev)
{
	struct vring_virtqueue_split vring_split = {};
	struct virtqueue *vq;
	int err;

	err = vring_alloc_queue_split(&vring_split, vdev, num, vring_align,
				      may_reduce_num, dma_dev);
	if (err)
		return NULL;

	vq = __vring_new_virtqueue_split(index, &vring_split, vdev, weak_barriers,
				   context, notify, callback, name, dma_dev);
	if (!vq) {
		vring_free_split(&vring_split, vdev, dma_dev);
		return NULL;
	}

	to_vvq(vq)->we_own_ring = true;

	return vq;
}

static int virtqueue_resize_split(struct virtqueue *_vq, u32 num)
{
	struct vring_virtqueue_split vring_split = {};
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct virtio_device *vdev = _vq->vdev;
	int err;

	err = vring_alloc_queue_split(&vring_split, vdev, num,
				      vq->split.vring_align,
				      vq->split.may_reduce_num,
				      vring_dma_dev(vq));
	if (err)
		goto err;

	err = vring_alloc_state_extra_split(&vring_split);
	if (err)
		goto err_state_extra;

	vring_free(&vq->vq);

	virtqueue_vring_init_split(&vring_split, vq);

	virtqueue_init(vq, vring_split.vring.num);
	virtqueue_vring_attach_split(vq, &vring_split);

	return 0;

err_state_extra:
	vring_free_split(&vring_split, vdev, vring_dma_dev(vq));
err:
	virtqueue_reinit_split(vq);
	return -ENOMEM;
}


/*
 * Packed ring specific functions - *_packed().
 */
static bool packed_used_wrap_counter(u16 last_used_idx)
{
	return !!(last_used_idx & (1 << VRING_PACKED_EVENT_F_WRAP_CTR));
}

static u16 packed_last_used(u16 last_used_idx)
{
	return last_used_idx & ~(-(1 << VRING_PACKED_EVENT_F_WRAP_CTR));
}

static void vring_unmap_extra_packed(const struct vring_virtqueue *vq,
				     const struct vring_desc_extra *extra)
{
	u16 flags;

	flags = extra->flags;

	if (flags & VRING_DESC_F_INDIRECT) {
		if (!vq->use_dma_api)
			return;

		dma_unmap_single(vring_dma_dev(vq),
				 extra->addr, extra->len,
				 (flags & VRING_DESC_F_WRITE) ?
				 DMA_FROM_DEVICE : DMA_TO_DEVICE);
	} else {
		if (!vring_need_unmap_buffer(vq, extra))
			return;

		dma_unmap_page(vring_dma_dev(vq),
			       extra->addr, extra->len,
			       (flags & VRING_DESC_F_WRITE) ?
			       DMA_FROM_DEVICE : DMA_TO_DEVICE);
	}
}

static struct vring_packed_desc *alloc_indirect_packed(unsigned int total_sg,
						       gfp_t gfp)
{
	struct vring_desc_extra *extra;
	struct vring_packed_desc *desc;
	int i, size;

	/*
	 * We require lowmem mappings for the descriptors because
	 * otherwise virt_to_phys will give us bogus addresses in the
	 * virtqueue.
	 */
	gfp &= ~__GFP_HIGHMEM;

	size = (sizeof(*desc) + sizeof(*extra)) * total_sg;

	desc = kmalloc(size, gfp);
	if (!desc)
		return NULL;

	extra = (struct vring_desc_extra *)&desc[total_sg];

	for (i = 0; i < total_sg; i++)
		extra[i].next = i + 1;

	return desc;
}

static int virtqueue_add_indirect_packed(struct vring_virtqueue *vq,
					 struct scatterlist *sgs[],
					 unsigned int total_sg,
					 unsigned int out_sgs,
					 unsigned int in_sgs,
					 void *data,
					 bool premapped,
					 gfp_t gfp)
{
	struct vring_desc_extra *extra;
	struct vring_packed_desc *desc;
	struct scatterlist *sg;
	unsigned int i, n, err_idx, len;
	u16 head, id;
	dma_addr_t addr;

	head = vq->packed.next_avail_idx;
	/*单独申请一个indirect packed描述符*/
	desc = alloc_indirect_packed(total_sg, gfp);
	if (!desc)
		return -ENOMEM;

	extra = (struct vring_desc_extra *)&desc[total_sg];

	if (unlikely(vq->vq.num_free < 1)) {
		pr_debug("Can't add buf len 1 - avail = 0\n");
		kfree(desc);
		END_USE(vq);
		return -ENOSPC;
	}

	i = 0;
	id = vq->free_head;
	BUG_ON(id == vq->packed.vring.num);

	/*填充indirect描述符*/
	for (n = 0; n < out_sgs + in_sgs; n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			if (vring_map_one_sg(vq, sg, n < out_sgs ?
					     DMA_TO_DEVICE : DMA_FROM_DEVICE,
					     &addr, &len, premapped))
				goto unmap_release;

			desc[i].flags = cpu_to_le16(n < out_sgs ?
						0 : VRING_DESC_F_WRITE);
			desc[i].addr = cpu_to_le64(addr);
			desc[i].len = cpu_to_le32(len);

			if (unlikely(vq->use_dma_api)) {
				extra[i].addr = premapped ? DMA_MAPPING_ERROR : addr;
				extra[i].len = len;
				extra[i].flags = n < out_sgs ?  0 : VRING_DESC_F_WRITE;
			}

			i++;
		}
	}

	/* Now that the indirect table is filled in, map it. */
	addr = vring_map_single(vq, desc,
			total_sg * sizeof(struct vring_packed_desc),
			DMA_TO_DEVICE);
	if (vring_mapping_error(vq, addr))
		goto unmap_release;

	vq->packed.vring.desc[head].addr = cpu_to_le64(addr);/*将indirect描述符地址指出来*/
	vq->packed.vring.desc[head].len = cpu_to_le32(total_sg *
				sizeof(struct vring_packed_desc));
	vq->packed.vring.desc[head].id = cpu_to_le16(id);

	if (vq->use_dma_api) {
		vq->packed.desc_extra[id].addr = addr;
		vq->packed.desc_extra[id].len = total_sg *
				sizeof(struct vring_packed_desc);
		vq->packed.desc_extra[id].flags = VRING_DESC_F_INDIRECT |
						  vq->packed.avail_used_flags;
	}

	/*
	 * A driver MUST NOT make the first descriptor in the list
	 * available before all subsequent descriptors comprising
	 * the list are made available.
	 */
	virtio_wmb(vq->weak_barriers);
	vq->packed.vring.desc[head].flags = cpu_to_le16(VRING_DESC_F_INDIRECT |
						vq->packed.avail_used_flags);/*写上flags*/

	/* We're using some buffers from the free list. */
	vq->vq.num_free -= 1;/*占用了一个描述符*/

	/* Update free pointer */
	n = head + 1;
	if (n >= vq->packed.vring.num) {
		n = 0;
		/*按标准规定当我们提供RING的最后一个描述符时,此值需要更改*/
		vq->packed.avail_wrap_counter ^= 1;
		vq->packed.avail_used_flags ^=
				1 << VRING_PACKED_DESC_F_AVAIL |
				1 << VRING_PACKED_DESC_F_USED;
	}
	vq->packed.next_avail_idx = n;
	vq->free_head = vq->packed.desc_extra[id].next;

	/* Store token and indirect buffer state. */
	vq->packed.desc_state[id].num = 1;
	vq->packed.desc_state[id].data = data;
	vq->packed.desc_state[id].indir_desc = desc;
	vq->packed.desc_state[id].last = id;

	vq->num_added += 1;

	pr_debug("Added buffer head %i to %p\n", head, vq);
	END_USE(vq);

	return 0;

unmap_release:
	err_idx = i;

	for (i = 0; i < err_idx; i++)
		vring_unmap_extra_packed(vq, &extra[i]);

	kfree(desc);

	END_USE(vq);
	return -ENOMEM;
}

/*采用packed方式发送sgs描述的buffers*/
static inline int virtqueue_add_packed(struct virtqueue *_vq,
				       struct scatterlist *sgs[]/*要读/写的buffer（支持批量发送,此时sgs长度大于1)*/,
				       unsigned int total_sg/*sgs数组长度*/,
				       unsigned int out_sgs,
				       unsigned int in_sgs,
				       void *data/*buffer关联的数据*/,
				       void *ctx,
				       bool premapped,
				       gfp_t gfp)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct vring_packed_desc *desc;
	struct scatterlist *sg;
	unsigned int i, n, c, descs_used, err_idx, len;
	__le16 head_flags, flags;
	u16 head, id, prev, curr, avail_used_flags;
	int err;

	START_USE(vq);

	BUG_ON(data == NULL);
	BUG_ON(ctx && vq->indirect);

	if (unlikely(vq->broken)) {
		/*队列已损坏,报错*/
		END_USE(vq);
		return -EIO;
	}

	LAST_ADD_TIME_UPDATE(vq);

	BUG_ON(total_sg == 0);

	if (virtqueue_use_indirect(vq, total_sg)) {
		/*设备支持indirect flag*/
		err = virtqueue_add_indirect_packed(vq, sgs, total_sg, out_sgs,
						    in_sgs, data, premapped, gfp);
		if (err != -ENOMEM) {
			/*不论成功失败,只要不是NOMEM均自此处返回*/
			END_USE(vq);
			return err;
		}

		/* fall back on direct */
	}

	head = vq->packed.next_avail_idx;/*当前有效描述符索引位置*/
	/*备份变量,用于解决处理过程中失败的情况,用于还原avail_used_flags标记;
	 * 同样的, 如果发送中失败了,本函数调用时第一个描述符已填写,如何回退?
	 * 所以后面函数在处理时,是在最后才填写第一个描述符的.*/
	avail_used_flags = vq->packed.avail_used_flags;

	WARN_ON_ONCE(total_sg > vq->packed.vring.num && !vq->indirect);

	desc = vq->packed.vring.desc;/*指向PACKED vring描述符表*/
	i = head;/*当前有效描述符索引位置*/
	descs_used = total_sg;

	if (unlikely(vq->vq.num_free < descs_used)) {
		/*当前空闲的描述符数目小于需要的描述符数目，返回空间不足*/
		pr_debug("Can't add buf len %i - avail = %i\n",
			 descs_used, vq->vq.num_free);
		END_USE(vq);
		return -ENOSPC;
	}

	id = vq->free_head;/*可用的首个PACKED vring描述符id*/
	BUG_ON(id == vq->packed.vring.num);

	curr = id;/*记录当前desc_extra描述符编号,下一个编号通过desc_extra[curr].next获得*/
	c = 0;/*记录当前正在处理第几个SG,利用此变量可了解是否在处理最后一个SG*/
	for (n = 0/*用于跟踪out_sgs,in_sgs以便分清楚权限*/; n < out_sgs + in_sgs; n++) {
		for (sg = sgs[n]; sg; sg = sg_next(sg)) {
			dma_addr_t addr;

			/*获得此sg指明buffer对应的dma地址*/
			if (vring_map_one_sg(vq, sg, n < out_sgs ?
					     DMA_TO_DEVICE : DMA_FROM_DEVICE,
					     &addr, &len, premapped))
				goto unmap_release;

			/*准备描述符标记:
			 * 1.next标记,如果在填充最后一个描述符,则不包含此标记,否则包含此标记;
			 * 2.write标记,如果是RX BUFFER,则添加WRITE标记,否则为TX BUFFER不包含此标记;
			 * 3.USED,AVAIL标记,linux driver这里简化处理,按标准规定此标记以DRIVER WRAP COUNTER
			 *   当前值为准,即当此值为'0',则在此位清零表示占用,反之写'1'来表示占用.
			 *   linux driver在初始化时当此值设置1<<VRING_PACKED_DESC_F_AVAIL(暗含了对VRING_PACKED_DESC_F_USED位置零),
			 *   在每次DRIVER WRAP COUNTER变更时反转此位与VRING_PACKED_DESC_F_USED位,故这里简单实现为取值
			 *   并赋值.
			 *   如标准所言,对于"可用的"的描述符,其AVAIL与USED标记位最是不同的.对于"已使用完"的描述符,其AVAIL与USED标记位总是相同的.
			 *   */
			flags = cpu_to_le16(vq->packed.avail_used_flags |
				    (++c == total_sg ? 0 : VRING_DESC_F_NEXT/*多个报文时有next标记*/) |
				    (n < out_sgs ? 0 : VRING_DESC_F_WRITE));
			if (i == head)
				/*为了支持回退,第一个描述符暂不填写标记*/
				head_flags = flags;
			else
				desc[i].flags = flags;/*为此描述符打上描记*/

			/*packed vring发送BUFFER给设备时,需要填充packed描述符,并为其关联一个描述符ID,然后触发通知给设备(不在此函数里)*/
			desc[i].addr = cpu_to_le64(addr);
			desc[i].len = cpu_to_le32(len);
			desc[i].id = cpu_to_le16(id);/*总时填首个desc_extra对应的id号*/

			/*如果不需要做unmap,则仅需要回收描述符,即next链串起来即可方便跳转;
			 * 如果要做unmap就需要记录dma地址及长度以及读写标记,链结束标记*/
			if (unlikely(vq->use_dma_api)) {
				/*填写描述符额外信息，记录dma地址及标记*/
				vq->packed.desc_extra[curr].addr = premapped ?
					DMA_MAPPING_ERROR : addr;
				vq->packed.desc_extra[curr].len = len;
				vq->packed.desc_extra[curr].flags =
					le16_to_cpu(flags);
			}
			prev = curr;
			/*将跟踪描述符串起来,初始化时已从0串起来了,回收时也是按顺序串起来的,
			 * 故这里直接从next获得下一个跟踪描述符*/
			curr = vq->packed.desc_extra[curr].next;

			if ((unlikely(++i/*切到下一个描述符*/ >= vq->packed.vring.num))) {
				/*切到下一个描述透露，如果出现绕回，则标记反转*/
				i = 0;/*达到队列结尾,描述符索引回到0号位置*/
				/*达到最后一个描述符,avail_used_flags标记位反转*/
				vq->packed.avail_used_flags ^=
					1 << VRING_PACKED_DESC_F_AVAIL |
					1 << VRING_PACKED_DESC_F_USED;
			}
		}
	}

	/*刚才我们在处理过程中没有反转此计数器,这里执行反转.
	 * 我们为什么不在循环里考虑反转此计数器?
	 * １.需要恢复.(这个理由不充分,avail_used_flags在内部也反转过了,同时也支持了恢复)
	 * ２.只是一个选择而已.
	 * */
	if (i <= head)
		/*反转绕回标记*/
		vq->packed.avail_wrap_counter ^= 1;

	/* We're using some buffers from the free list. */
	vq->vq.num_free -= descs_used;/*减少我们使用掉的描述符*/

	/* Update free pointer */
	vq->packed.next_avail_idx = i;/*记录下一次填充时首个描述符位置*/
	vq->free_head = curr;/*记录跟踪描述符起始位置,下次关联的id号*/

	/* Store token. */
	vq->packed.desc_state[id].num = descs_used;/*记录此链表占用了desc_used个描述符*/
	vq->packed.desc_state[id].data = data;/*此链表关联的数据*/
	vq->packed.desc_state[id].indir_desc = ctx;
	vq->packed.desc_state[id].last = prev;/*记录此链表结尾占用的描述符编号*/

	/*
	 * A driver MUST NOT make the first descriptor in the list
	 * available before all subsequent descriptors comprising
	 * the list are made available.
	 */
	virtio_wmb(vq->weak_barriers);/*写屏障*/
	vq->packed.vring.desc[head].flags = head_flags;/*使首个描述符标记有效,使硬件可以看到.*/
	vq->num_added += descs_used;/*记录vq中元素总数*/

	pr_debug("Added buffer head %i to %p\n", head, vq);
	END_USE(vq);

	return 0;

unmap_release:
	err_idx = i;
	i = head;
	curr = vq->free_head;

	vq->packed.avail_used_flags = avail_used_flags;/*发送失败,执行回退*/

	for (n = 0; n < total_sg; n++) {
		if (i == err_idx)
			break;
		vring_unmap_extra_packed(vq, &vq->packed.desc_extra[curr]);
		curr = vq->packed.desc_extra[curr].next;
		i++;
		if (i >= vq->packed.vring.num)
			i = 0;
	}

	END_USE(vq);
	return -EIO;
}

static bool virtqueue_kick_prepare_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 new, old, off_wrap, flags, wrap_counter, event_idx;
	bool needs_kick;
	union {
		struct {
			__le16 off_wrap;
			__le16 flags;
		};
		u32 u32;
	} snapshot;

	START_USE(vq);

	/*
	 * We need to expose the new flags value before checking notification
	 * suppressions.
	 */
	virtio_mb(vq->weak_barriers);

	old = vq->packed.next_avail_idx - vq->num_added;
	new = vq->packed.next_avail_idx;
	vq->num_added = 0;

	snapshot.u32 = *(u32 *)vq->packed.vring.device;
	flags = le16_to_cpu(snapshot.flags);

	LAST_ADD_TIME_CHECK(vq);
	LAST_ADD_TIME_INVALID(vq);

	if (flags != VRING_PACKED_EVENT_FLAG_DESC) {
		needs_kick = (flags != VRING_PACKED_EVENT_FLAG_DISABLE);
		goto out;
	}

	off_wrap = le16_to_cpu(snapshot.off_wrap);

	wrap_counter = off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR;
	event_idx = off_wrap & ~(1 << VRING_PACKED_EVENT_F_WRAP_CTR);
	if (wrap_counter != vq->packed.avail_wrap_counter)
		event_idx -= vq->packed.vring.num;

	needs_kick = vring_need_event(event_idx, new, old);
out:
	END_USE(vq);
	return needs_kick;
}

static void detach_buf_packed(struct vring_virtqueue *vq,
			      unsigned int id, void **ctx)
{
	struct vring_desc_state_packed *state = NULL;
	struct vring_packed_desc *desc;
	unsigned int i, curr;

	state = &vq->packed.desc_state[id];

	/* Clear data ptr. */
	state->data = NULL;

	vq->packed.desc_extra[state->last].next = vq->free_head;
	vq->free_head = id;
	vq->vq.num_free += state->num;

	if (unlikely(vq->use_dma_api)) {
		curr = id;
		for (i = 0; i < state->num; i++) {
			vring_unmap_extra_packed(vq,
						 &vq->packed.desc_extra[curr]);
			curr = vq->packed.desc_extra[curr].next;
		}
	}

	if (vq->indirect) {
		struct vring_desc_extra *extra;
		u32 len, num;

		/* Free the indirect table, if any, now that it's unmapped. */
		desc = state->indir_desc;
		if (!desc)
			return;

		if (vq->use_dma_api) {
			len = vq->packed.desc_extra[id].len;
			num = len / sizeof(struct vring_packed_desc);

			extra = (struct vring_desc_extra *)&desc[num];

			for (i = 0; i < num; i++)
				vring_unmap_extra_packed(vq, &extra[i]);
		}
		kfree(desc);
		state->indir_desc = NULL;
	} else if (ctx) {
		*ctx = state->indir_desc;
	}
}

static inline bool is_used_desc_packed(const struct vring_virtqueue *vq,
				       u16 idx, bool used_wrap_counter)
{
	bool avail, used;
	u16 flags;

	/*取idx对应的描述符*/
	flags = le16_to_cpu(vq->packed.vring.desc[idx].flags);
	avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));/*描述符是否有avail标记*/
	used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));/*描述符是否有used标记*/

	return avail == used && used == used_wrap_counter;
}

static bool more_used_packed(const struct vring_virtqueue *vq)
{
	u16 last_used;
	u16 last_used_idx;
	bool used_wrap_counter;

	last_used_idx = READ_ONCE(vq->last_used_idx);
	last_used = packed_last_used(last_used_idx);
	used_wrap_counter = packed_used_wrap_counter(last_used_idx);
	return is_used_desc_packed(vq, last_used, used_wrap_counter);
}

//packed类型报文获取，返回报文起始指针及报文长度
static void *virtqueue_get_buf_ctx_packed(struct virtqueue *_vq,
					  unsigned int *len/*出参，报文长度*/,
					  void **ctx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 last_used, id, last_used_idx;
	bool used_wrap_counter;
	void *ret;/*待返回的buffer地址*/

	START_USE(vq);

	if (unlikely(vq->broken)) {
		/*队列损坏*/
		END_USE(vq);
		return NULL;
	}

	if (!more_used_packed(vq)) {
		/*队列中没有buffer*/
		pr_debug("No more buffers in queue\n");
		END_USE(vq);
		return NULL;
	}

	/* Only get used elements after they have been exposed by host. */
	virtio_rmb(vq->weak_barriers);

	last_used_idx = READ_ONCE(vq->last_used_idx);/*上次收的位置*/
	used_wrap_counter = packed_used_wrap_counter(last_used_idx);
	last_used = packed_last_used(last_used_idx);
	id = le16_to_cpu(vq->packed.vring.desc[last_used].id);
	*len = le32_to_cpu(vq->packed.vring.desc[last_used].len);

	if (unlikely(id >= vq->packed.vring.num)) {
		/*填写的id有误*/
		BAD_RING(vq, "id %u out of range\n", id);
		return NULL;
	}
	if (unlikely(!vq->packed.desc_state[id].data)) {
		BAD_RING(vq, "id %u is not a head!\n", id);
		return NULL;
	}

	/* detach_buf_packed clears data, so grab it now. */
	ret = vq->packed.desc_state[id].data;/*报文buffer地址*/
	detach_buf_packed(vq, id, ctx);

	//更新last_used_idx(用于标记收包位置）
	last_used += vq->packed.desc_state[id].num;
	if (unlikely(last_used >= vq->packed.vring.num)) {
		last_used -= vq->packed.vring.num;/*处理回绕问题*/
		used_wrap_counter ^= 1;
	}

	last_used = (last_used | (used_wrap_counter << VRING_PACKED_EVENT_F_WRAP_CTR));
	WRITE_ONCE(vq->last_used_idx, last_used);/*记录last_used,以备下次使用*/

	/*
	 * If we expect an interrupt for the next entry, tell host
	 * by writing event index and flush out the write before
	 * the read in the next get_buf call.
	 */
	if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DESC)
		virtio_store_mb(vq->weak_barriers,
				&vq->packed.vring.driver->off_wrap,
				cpu_to_le16(vq->last_used_idx));

	LAST_ADD_TIME_INVALID(vq);

	END_USE(vq);
	return ret;
}

static void virtqueue_disable_cb_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->packed.event_flags_shadow != VRING_PACKED_EVENT_FLAG_DISABLE) {
		vq->packed.event_flags_shadow = VRING_PACKED_EVENT_FLAG_DISABLE;

		/*
		 * If device triggered an event already it won't trigger one again:
		 * no need to disable.
		 */
		if (vq->event_triggered)
			return;

		vq->packed.vring.driver->flags =
			cpu_to_le16(vq->packed.event_flags_shadow);
	}
}

static unsigned int virtqueue_enable_cb_prepare_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	START_USE(vq);

	/*
	 * We optimistically turn back on interrupts, then check if there was
	 * more to do.
	 */

	if (vq->event) {
		vq->packed.vring.driver->off_wrap =
			cpu_to_le16(vq->last_used_idx);
		/*
		 * We need to update event offset and event wrap
		 * counter first before updating event flags.
		 */
		virtio_wmb(vq->weak_barriers);
	}

	if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DISABLE) {
		vq->packed.event_flags_shadow = vq->event ?
				VRING_PACKED_EVENT_FLAG_DESC :
				VRING_PACKED_EVENT_FLAG_ENABLE;
		vq->packed.vring.driver->flags =
				cpu_to_le16(vq->packed.event_flags_shadow);
	}

	END_USE(vq);
	return vq->last_used_idx;
}

static bool virtqueue_poll_packed(struct virtqueue *_vq, u16 off_wrap)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	bool wrap_counter;
	u16 used_idx;

	wrap_counter = off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR;
	used_idx = off_wrap & ~(1 << VRING_PACKED_EVENT_F_WRAP_CTR);

	return is_used_desc_packed(vq, used_idx, wrap_counter);
}

static bool virtqueue_enable_cb_delayed_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 used_idx, wrap_counter, last_used_idx;
	u16 bufs;

	START_USE(vq);

	/*
	 * We optimistically turn back on interrupts, then check if there was
	 * more to do.
	 */

	if (vq->event) {
		/* TODO: tune this threshold */
		bufs = (vq->packed.vring.num - vq->vq.num_free) * 3 / 4;
		last_used_idx = READ_ONCE(vq->last_used_idx);
		wrap_counter = packed_used_wrap_counter(last_used_idx);

		used_idx = packed_last_used(last_used_idx) + bufs;
		if (used_idx >= vq->packed.vring.num) {
			used_idx -= vq->packed.vring.num;
			wrap_counter ^= 1;
		}

		vq->packed.vring.driver->off_wrap = cpu_to_le16(used_idx |
			(wrap_counter << VRING_PACKED_EVENT_F_WRAP_CTR));

		/*
		 * We need to update event offset and event wrap
		 * counter first before updating event flags.
		 */
		virtio_wmb(vq->weak_barriers);
	}

	if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DISABLE) {
		vq->packed.event_flags_shadow = vq->event ?
				VRING_PACKED_EVENT_FLAG_DESC :
				VRING_PACKED_EVENT_FLAG_ENABLE;
		vq->packed.vring.driver->flags =
				cpu_to_le16(vq->packed.event_flags_shadow);
	}

	/*
	 * We need to update event suppression structure first
	 * before re-checking for more used buffers.
	 */
	virtio_mb(vq->weak_barriers);

	last_used_idx = READ_ONCE(vq->last_used_idx);
	wrap_counter = packed_used_wrap_counter(last_used_idx);
	used_idx = packed_last_used(last_used_idx);
	if (is_used_desc_packed(vq, used_idx, wrap_counter)) {
		END_USE(vq);
		return false;
	}

	END_USE(vq);
	return true;
}

static void *virtqueue_detach_unused_buf_packed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	unsigned int i;
	void *buf;

	START_USE(vq);

	for (i = 0; i < vq->packed.vring.num; i++) {
		if (!vq->packed.desc_state[i].data)
			continue;/*此描述符无附带data,忽略*/
		/* detach_buf clears data, so grab it now. */
		buf = vq->packed.desc_state[i].data;
		detach_buf_packed(vq, i, NULL);
		END_USE(vq);
		return buf;
	}
	/* That should have freed everything. */
	BUG_ON(vq->vq.num_free != vq->packed.vring.num);

	END_USE(vq);
	return NULL;
}

static struct vring_desc_extra *vring_alloc_desc_extra(unsigned int num)
{
	struct vring_desc_extra *desc_extra;
	unsigned int i;

	/*每个描述符对应一个vring_desc_extra*/
	desc_extra = kmalloc_array(num, sizeof(struct vring_desc_extra),
				   GFP_KERNEL);
	if (!desc_extra)
		return NULL;

	memset(desc_extra, 0, num * sizeof(struct vring_desc_extra));

	/*利用next还需要串起来*/
	for (i = 0; i < num - 1; i++)
		desc_extra[i].next = i + 1;

	return desc_extra;
}

static void vring_free_packed(struct vring_virtqueue_packed *vring_packed,
			      struct virtio_device *vdev,
			      struct device *dma_dev)
{
	if (vring_packed->vring.desc)
		vring_free_queue(vdev, vring_packed->ring_size_in_bytes,
				 vring_packed->vring.desc,
				 vring_packed->ring_dma_addr,
				 dma_dev);

	if (vring_packed->vring.driver)
		vring_free_queue(vdev, vring_packed->event_size_in_bytes,
				 vring_packed->vring.driver,
				 vring_packed->driver_event_dma_addr,
				 dma_dev);

	if (vring_packed->vring.device)
		vring_free_queue(vdev, vring_packed->event_size_in_bytes,
				 vring_packed->vring.device,
				 vring_packed->device_event_dma_addr,
				 dma_dev);

	kfree(vring_packed->desc_state);
	kfree(vring_packed->desc_extra);
}

/*申请packed类型vring，填充结构体vring_packed*/
static int vring_alloc_queue_packed(struct vring_virtqueue_packed *vring_packed,
				    struct virtio_device *vdev,
				    u32 num/*队列深度*/, struct device *dma_dev)
{
	/*当前virtio设备PACKED VRING共有三个部分, "描述符RING","驱动事件抑制", "设备EVENT抑制"*/
	struct vring_packed_desc *ring;
	struct vring_packed_desc_event *driver, *device;
	dma_addr_t ring_dma_addr, driver_event_dma_addr, device_event_dma_addr;
	size_t ring_size_in_bytes, event_size_in_bytes;

	//desc队列占用的内存大小
	ring_size_in_bytes = num * sizeof(struct vring_packed_desc);

	//申请desc队列,取得desc队列对应的dma地址
	ring = vring_alloc_queue(vdev, ring_size_in_bytes,
				 &ring_dma_addr/*指向desc队列起始的dma地址*/,
				 GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
				 dma_dev);
	if (!ring)
		goto err;

	vring_packed->vring.desc         = ring;
	vring_packed->ring_dma_addr      = ring_dma_addr;
	vring_packed->ring_size_in_bytes = ring_size_in_bytes;

	event_size_in_bytes = sizeof(struct vring_packed_desc_event);

	//申请一个driver desc event
	driver = vring_alloc_queue(vdev, event_size_in_bytes,
				   &driver_event_dma_addr/*指向event的dma地址*/,
				   GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
				   dma_dev);
	if (!driver)
		goto err;

	vring_packed->vring.driver          = driver;
	vring_packed->event_size_in_bytes   = event_size_in_bytes;
	vring_packed->driver_event_dma_addr = driver_event_dma_addr;

	//申请一个device desc event
	device = vring_alloc_queue(vdev, event_size_in_bytes,
				   &device_event_dma_addr,
				   GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
				   dma_dev);
	if (!device)
		goto err;

	vring_packed->vring.device          = device;
	vring_packed->device_event_dma_addr = device_event_dma_addr;

	vring_packed->vring.num = num;

	return 0;

err:
	vring_free_packed(vring_packed, vdev, dma_dev);
	return -ENOMEM;
}

static int vring_alloc_state_extra_packed(struct vring_virtqueue_packed *vring_packed)
{
	struct vring_desc_state_packed *state;
	struct vring_desc_extra *extra;
	u32 num = vring_packed->vring.num;

	/*每个描述符对应一个vring_desc_state_packed*/
	state = kmalloc_array(num, sizeof(struct vring_desc_state_packed), GFP_KERNEL);
	if (!state)
		goto err_desc_state;

	memset(state, 0, num * sizeof(struct vring_desc_state_packed));

	/*每个描述符对应一个额外的结构体*/
	extra = vring_alloc_desc_extra(num);
	if (!extra)
		goto err_desc_extra;

	vring_packed->desc_state = state;
	vring_packed->desc_extra = extra;

	return 0;

err_desc_extra:
	kfree(state);
err_desc_state:
	return -ENOMEM;
}

static void virtqueue_vring_init_packed(struct vring_virtqueue_packed *vring_packed,
					bool callback)
{
	vring_packed->next_avail_idx = 0;
	vring_packed->avail_wrap_counter = 1;/*按标准要求此值初始化为1*/
	vring_packed->event_flags_shadow = 0;
	vring_packed->avail_used_flags = 1 << VRING_PACKED_DESC_F_AVAIL;/*暗含了第一轮将used标记置为O*/

	/* No callback?  Tell other side not to bother us. */
	if (!callback) {
		/*无回调，中断被禁用*/
		vring_packed->event_flags_shadow = VRING_PACKED_EVENT_FLAG_DISABLE;
		vring_packed->vring.driver->flags =
			cpu_to_le16(vring_packed->event_flags_shadow);
	}
}

static void virtqueue_vring_attach_packed(struct vring_virtqueue *vq,
					  struct vring_virtqueue_packed *vring_packed)
{
	vq->packed = *vring_packed;

	/* Put everything in free lists. */
	vq->free_head = 0;
}

static void virtqueue_reinit_packed(struct vring_virtqueue *vq)
{
	memset(vq->packed.vring.device, 0, vq->packed.event_size_in_bytes);
	memset(vq->packed.vring.driver, 0, vq->packed.event_size_in_bytes);

	/* we need to reset the desc.flags. For more, see is_used_desc_packed() */
	memset(vq->packed.vring.desc, 0, vq->packed.ring_size_in_bytes);

	virtqueue_init(vq, vq->packed.vring.num);
	virtqueue_vring_init_packed(&vq->packed, !!vq->vq.callback);
}

static struct virtqueue *__vring_new_virtqueue_packed(unsigned int index,
					       struct vring_virtqueue_packed *vring_packed,
					       struct virtio_device *vdev,
					       bool weak_barriers,
					       bool context,
					       bool (*notify)(struct virtqueue *),
					       void (*callback)(struct virtqueue *),
					       const char *name,
					       struct device *dma_dev)
{
	struct vring_virtqueue *vq;
	int err;

	//申请vq
	vq = kmalloc(sizeof(*vq), GFP_KERNEL);
	if (!vq)
		return NULL;

	vq->vq.callback = callback;
	vq->vq.vdev = vdev;
	vq->vq.name = name;
	vq->vq.index = index;
	vq->vq.reset = false;
	vq->we_own_ring = false;
	vq->notify = notify;/*设置notify函数*/
	vq->weak_barriers = weak_barriers;
#ifdef CONFIG_VIRTIO_HARDEN_NOTIFICATION
	vq->broken = true;
#else
	vq->broken = false;
#endif
	vq->packed_ring = true;/*指明创建的为packed类型的vring*/
	vq->dma_dev = dma_dev;
	vq->use_dma_api = vring_use_dma_api(vdev);/*命名用dma api，则需要执行unmap*/

	vq->indirect = virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC) &&
		!context;
	vq->event = virtio_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX);

	if (virtio_has_feature(vdev, VIRTIO_F_ORDER_PLATFORM))
		vq->weak_barriers = false;

	/*申请packed vring所需的extra内存*/
	err = vring_alloc_state_extra_packed(vring_packed);
	if (err) {
		kfree(vq);
		return NULL;
	}

	virtqueue_vring_init_packed(vring_packed, !!callback);

	virtqueue_init(vq, vring_packed->vring.num);
	virtqueue_vring_attach_packed(vq, vring_packed);

	spin_lock(&vdev->vqs_list_lock);
	list_add_tail(&vq->vq.list, &vdev->vqs);/*将此vq挂接到vdev*/
	spin_unlock(&vdev->vqs_list_lock);
	return &vq->vq;
}

//创建packed类型的virtqueue
static struct virtqueue *vring_create_virtqueue_packed(
	unsigned int index/*队列编号*/,
	unsigned int num/*队列长度*/,
	unsigned int vring_align/*vring对齐方式*/,
	struct virtio_device *vdev,
	bool weak_barriers,
	bool may_reduce_num,
	bool context,
	bool (*notify)(struct virtqueue *)/*向对端的通知函数*/,
	void (*callback)(struct virtqueue *)/*packed类型报文收取函数*/,
	const char *name/*要创建的vq名称*/,
	struct device *dma_dev)
{
	struct vring_virtqueue_packed vring_packed = {};
	struct virtqueue *vq;

	if (vring_alloc_queue_packed(&vring_packed, vdev, num, dma_dev))
		return NULL;

	vq = __vring_new_virtqueue_packed(index, &vring_packed, vdev, weak_barriers,
					context, notify, callback, name, dma_dev);
	if (!vq) {
		vring_free_packed(&vring_packed, vdev, dma_dev);
		return NULL;
	}

	to_vvq(vq)->we_own_ring = true;

	return vq;
}

static int virtqueue_resize_packed(struct virtqueue *_vq, u32 num)
{
	struct vring_virtqueue_packed vring_packed = {};
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct virtio_device *vdev = _vq->vdev;
	int err;

	if (vring_alloc_queue_packed(&vring_packed, vdev, num, vring_dma_dev(vq)))
		goto err_ring;

	err = vring_alloc_state_extra_packed(&vring_packed);
	if (err)
		goto err_state_extra;

	vring_free(&vq->vq);

	virtqueue_vring_init_packed(&vring_packed, !!vq->vq.callback);

	virtqueue_init(vq, vring_packed.vring.num);
	virtqueue_vring_attach_packed(vq, &vring_packed);

	return 0;

err_state_extra:
	vring_free_packed(&vring_packed, vdev, vring_dma_dev(vq));
err_ring:
	virtqueue_reinit_packed(vq);
	return -ENOMEM;
}

static int virtqueue_disable_and_recycle(struct virtqueue *_vq,
					 void (*recycle)(struct virtqueue *vq, void *buf))
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct virtio_device *vdev = vq->vq.vdev;
	void *buf;
	int err;

	if (!vq->we_own_ring)
		return -EPERM;

	if (!vdev->config->disable_vq_and_reset)
		return -ENOENT;

	if (!vdev->config->enable_vq_after_reset)
		return -ENOENT;

	err = vdev->config->disable_vq_and_reset(_vq);
	if (err)
		return err;

	while ((buf = virtqueue_detach_unused_buf(_vq)) != NULL)
		recycle(_vq, buf);

	return 0;
}

static int virtqueue_enable_after_reset(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct virtio_device *vdev = vq->vq.vdev;

	if (vdev->config->enable_vq_after_reset(_vq))
		return -EBUSY;

	return 0;
}

/*
 * Generic functions and exported symbols.
 */

static inline int virtqueue_add(struct virtqueue *_vq,
				struct scatterlist *sgs[],
				unsigned int total_sg/*sgs数组有效长度*/,
				unsigned int out_sgs,
				unsigned int in_sgs,
				void *data/*buffer关联的data*/,
				void *ctx,
				bool premapped,
				gfp_t gfp)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed_ring ? virtqueue_add_packed(_vq, sgs, total_sg,
					out_sgs, in_sgs, data, ctx, premapped, gfp)/*采用packed形式发送*/ :
				 virtqueue_add_split(_vq, sgs, total_sg,
					out_sgs, in_sgs, data, ctx, premapped, gfp);/*采用split形式发送*/
}

/**
 * virtqueue_add_sgs - expose buffers to other end
 * @_vq: the struct virtqueue we're talking about.
 * @sgs: array of terminated scatterlists.
 * @out_sgs: the number of scatterlists readable by other side
 * @in_sgs: the number of scatterlists which are writable (after readable ones)
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
//将sgs及data填充到虚队列中
int virtqueue_add_sgs(struct virtqueue *_vq,
		      struct scatterlist *sgs[],
		      unsigned int out_sgs,
		      unsigned int in_sgs,
		      void *data,
		      gfp_t gfp)
{
	unsigned int i, total_sg = 0;

	/* Count them first. */
	//先计算scatter总数量（list被展开计算）
	for (i = 0; i < out_sgs + in_sgs; i++) {
		struct scatterlist *sg;

		for (sg = sgs[i]; sg; sg = sg_next(sg))
			total_sg++;
	}
	return virtqueue_add(_vq, sgs, total_sg, out_sgs, in_sgs,
			     data, NULL, false, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_sgs);

/**
 * virtqueue_add_outbuf - expose output buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg readable by other side
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_outbuf(struct virtqueue *vq,
			 struct scatterlist *sg, unsigned int num/*sg有效数目*/,
			 void *data/*buffer关联的data*/,
			 gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 1/*指明为发送的SG*/, 0, data, NULL, false, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_outbuf);

/**
 * virtqueue_add_outbuf_premapped - expose output buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg readable by other side
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Return:
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_outbuf_premapped(struct virtqueue *vq,
				   struct scatterlist *sg, unsigned int num,
				   void *data,
				   gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 1, 0, data, NULL, true, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_outbuf_premapped);

/**
 * virtqueue_add_inbuf - expose input buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg writable by other side
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_inbuf(struct virtqueue *vq,
			struct scatterlist *sg, unsigned int num,
			void *data,
			gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 0, 1/*指明为接收的SG*/, data, NULL, false, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_inbuf);

/**
 * virtqueue_add_inbuf_ctx - expose input buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg writable by other side
 * @data: the token identifying the buffer.
 * @ctx: extra context for the token
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_inbuf_ctx(struct virtqueue *vq,
			struct scatterlist *sg, unsigned int num,
			void *data,
			void *ctx,
			gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 0, 1/*指明为接收的SG*/, data, ctx, false, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_inbuf_ctx);

/**
 * virtqueue_add_inbuf_premapped - expose input buffers to other end
 * @vq: the struct virtqueue we're talking about.
 * @sg: scatterlist (must be well-formed and terminated!)
 * @num: the number of entries in @sg writable by other side
 * @data: the token identifying the buffer.
 * @ctx: extra context for the token
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Return:
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_inbuf_premapped(struct virtqueue *vq,
				  struct scatterlist *sg, unsigned int num,
				  void *data,
				  void *ctx,
				  gfp_t gfp)
{
	return virtqueue_add(vq, &sg, num, 0, 1, data, ctx, true, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_inbuf_premapped);

/**
 * virtqueue_dma_dev - get the dma dev
 * @_vq: the struct virtqueue we're talking about.
 *
 * Returns the dma dev. That can been used for dma api.
 */
struct device *virtqueue_dma_dev(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->use_dma_api)
		return vring_dma_dev(vq);
	else
		return NULL;
}
EXPORT_SYMBOL_GPL(virtqueue_dma_dev);

/**
 * virtqueue_kick_prepare - first half of split virtqueue_kick call.
 * @_vq: the struct virtqueue
 *
 * Instead of virtqueue_kick(), you can do:
 *	if (virtqueue_kick_prepare(vq))
 *		virtqueue_notify(vq);
 *
 * This is sometimes useful because the virtqueue_kick_prepare() needs
 * to be serialized, but the actual virtqueue_notify() call does not.
 */
bool virtqueue_kick_prepare(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed_ring ? virtqueue_kick_prepare_packed(_vq) :
				 virtqueue_kick_prepare_split(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_kick_prepare);

/**
 * virtqueue_notify - second half of split virtqueue_kick call.
 * @_vq: the struct virtqueue
 *
 * This does not need to be serialized.
 *
 * Returns false if host notify failed or queue is broken, otherwise true.
 */
bool virtqueue_notify(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (unlikely(vq->broken))
		return false;

	/* Prod other side to tell it about changes. */
	//告诉后端队列_vq有变化
	if (!vq->notify(_vq)) {
		vq->broken = true;/*vq通知失败，指明broken*/
		return false;
	}
	return true;
}
EXPORT_SYMBOL_GPL(virtqueue_notify);

/**
 * virtqueue_kick - update after add_buf
 * @vq: the struct virtqueue
 *
 * After one or more virtqueue_add_* calls, invoke this to kick
 * the other side.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 *
 * Returns false if kick failed, otherwise true.
 */
bool virtqueue_kick(struct virtqueue *vq)
{
	//如果需要kick,则进行通知
	if (virtqueue_kick_prepare(vq))
		return virtqueue_notify(vq);
	return true;
}
EXPORT_SYMBOL_GPL(virtqueue_kick);

/**
 * virtqueue_get_buf_ctx - get the next used buffer
 * @_vq: the struct virtqueue we're talking about.
 * @len: the length written into the buffer
 * @ctx: extra context for the token
 *
 * If the device wrote data into the buffer, @len will be set to the
 * amount written.  This means you don't need to clear the buffer
 * beforehand to ensure there's no data leakage in the case of short
 * writes.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 *
 * Returns NULL if there are no used buffers, or the "data" token
 * handed to virtqueue_add_*().
 */
//自_vq中收取一个buf,返回buf的长度。及buf对应的指针
void *virtqueue_get_buf_ctx(struct virtqueue *_vq, unsigned int *len/*出参，报文长度*/,
			    void **ctx)
{
	//由virtqueue获得vring_virtqueue
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed_ring ? virtqueue_get_buf_ctx_packed(_vq, len, ctx) /*packed方式*/:
				 virtqueue_get_buf_ctx_split(_vq, len, ctx);
}
EXPORT_SYMBOL_GPL(virtqueue_get_buf_ctx);

/*自vq中取一个buffer,并返回它对应的长度*/
void *virtqueue_get_buf(struct virtqueue *_vq, unsigned int *len/*出参,buffer长度*/)
{
	return virtqueue_get_buf_ctx(_vq, len, NULL);
}
EXPORT_SYMBOL_GPL(virtqueue_get_buf);
/**
 * virtqueue_disable_cb - disable callbacks
 * @_vq: the struct virtqueue we're talking about.
 *
 * Note that this is not necessarily synchronous, hence unreliable and only
 * useful as an optimization.
 *
 * Unlike other operations, this need not be serialized.
 */
void virtqueue_disable_cb(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->packed_ring)
		virtqueue_disable_cb_packed(_vq);
	else
		virtqueue_disable_cb_split(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_disable_cb);

/**
 * virtqueue_enable_cb_prepare - restart callbacks after disable_cb
 * @_vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks; it returns current queue state
 * in an opaque unsigned value. This value should be later tested by
 * virtqueue_poll, to detect a possible race between the driver checking for
 * more work, and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
unsigned int virtqueue_enable_cb_prepare(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->event_triggered)
		vq->event_triggered = false;

	return vq->packed_ring ? virtqueue_enable_cb_prepare_packed(_vq) :
				 virtqueue_enable_cb_prepare_split(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_enable_cb_prepare);

/**
 * virtqueue_poll - query pending used buffers
 * @_vq: the struct virtqueue we're talking about.
 * @last_used_idx: virtqueue state (from call to virtqueue_enable_cb_prepare).
 *
 * Returns "true" if there are pending used buffers in the queue.
 *
 * This does not need to be serialized.
 */
bool virtqueue_poll(struct virtqueue *_vq, unsigned int last_used_idx)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (unlikely(vq->broken))
		return false;

	virtio_mb(vq->weak_barriers);
	return vq->packed_ring ? virtqueue_poll_packed(_vq, last_used_idx) :
				 virtqueue_poll_split(_vq, last_used_idx);
}
EXPORT_SYMBOL_GPL(virtqueue_poll);

/**
 * virtqueue_enable_cb - restart callbacks after disable_cb.
 * @_vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks; it returns "false" if there are pending
 * buffers in the queue, to detect a possible race between the driver
 * checking for more work, and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
bool virtqueue_enable_cb(struct virtqueue *_vq)
{
	unsigned int last_used_idx = virtqueue_enable_cb_prepare(_vq);

	return !virtqueue_poll(_vq, last_used_idx);
}
EXPORT_SYMBOL_GPL(virtqueue_enable_cb);

/**
 * virtqueue_enable_cb_delayed - restart callbacks after disable_cb.
 * @_vq: the struct virtqueue we're talking about.
 *
 * This re-enables callbacks but hints to the other side to delay
 * interrupts until most of the available buffers have been processed;
 * it returns "false" if there are many pending buffers in the queue,
 * to detect a possible race between the driver checking for more work,
 * and enabling callbacks.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 */
bool virtqueue_enable_cb_delayed(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->event_triggered)
		data_race(vq->event_triggered = false);

	return vq->packed_ring ? virtqueue_enable_cb_delayed_packed(_vq) :
				 virtqueue_enable_cb_delayed_split(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_enable_cb_delayed);

/**
 * virtqueue_detach_unused_buf - detach first unused buffer
 * @_vq: the struct virtqueue we're talking about.
 *
 * Returns NULL or the "data" token handed to virtqueue_add_*().
 * This is not valid on an active queue; it is useful for device
 * shutdown or the reset queue.
 */
void *virtqueue_detach_unused_buf(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed_ring ? virtqueue_detach_unused_buf_packed(_vq) :
				 virtqueue_detach_unused_buf_split(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_detach_unused_buf);

static inline bool more_used(const struct vring_virtqueue *vq)
{
	return vq->packed_ring ? more_used_packed(vq) : more_used_split(vq);
}

/**
 * vring_interrupt - notify a virtqueue on an interrupt
 * @irq: the IRQ number (ignored)
 * @_vq: the struct virtqueue to notify
 *
 * Calls the callback function of @_vq to process the virtqueue
 * notification.
 */
//执行vq的中断回调
irqreturn_t vring_interrupt(int irq, void *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!more_used(vq)) {
		pr_debug("virtqueue interrupt with no work for %p\n", vq);
		return IRQ_NONE;
	}

	if (unlikely(vq->broken)) {
#ifdef CONFIG_VIRTIO_HARDEN_NOTIFICATION
		dev_warn_once(&vq->vq.vdev->dev,
			      "virtio vring IRQ raised before DRIVER_OK");
		return IRQ_NONE;
#else
		return IRQ_HANDLED;
#endif
	}

	/* Just a hint for performance: so it's ok that this can be racy! */
	if (vq->event)
		data_race(vq->event_triggered = true);

	pr_debug("virtqueue callback for %p (%p)\n", vq, vq->vq.callback);
	if (vq->vq.callback)
		vq->vq.callback(&vq->vq);

	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(vring_interrupt);

struct virtqueue *vring_create_virtqueue(
	unsigned int index/*队列序号*/,
	unsigned int num/*队列长度*/,
	unsigned int vring_align/*vq对齐方式*/,
	struct virtio_device *vdev/*所属设备*/,
	bool weak_barriers,
	bool may_reduce_num,
	bool context/*队列是否有context*/,
	bool (*notify)(struct virtqueue *)/*向对端的通知函数*/,
	void (*callback)(struct virtqueue *)/*队列报文处理回调*/,
	const char *name/*队列名称*/)
{
    //如果virtio开启packed功能，则创建packed类型的vring
	if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED))
		return vring_create_virtqueue_packed(index, num, vring_align,
				vdev, weak_barriers, may_reduce_num,
				context, notify, callback, name, vdev->dev.parent);

	/*未开启packed,默认创建split类型的vring*/
	return vring_create_virtqueue_split(index, num, vring_align,
			vdev, weak_barriers, may_reduce_num,
			context, notify, callback, name, vdev->dev.parent);
}
EXPORT_SYMBOL_GPL(vring_create_virtqueue);

struct virtqueue *vring_create_virtqueue_dma(
	unsigned int index,
	unsigned int num,
	unsigned int vring_align,
	struct virtio_device *vdev,
	bool weak_barriers,
	bool may_reduce_num,
	bool context,
	bool (*notify)(struct virtqueue *),
	void (*callback)(struct virtqueue *),
	const char *name,
	struct device *dma_dev)
{

	if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED))
		return vring_create_virtqueue_packed(index, num, vring_align,
				vdev, weak_barriers, may_reduce_num,
				context, notify, callback, name, dma_dev);

	return vring_create_virtqueue_split(index, num, vring_align,
			vdev, weak_barriers, may_reduce_num,
			context, notify, callback, name, dma_dev);
}
EXPORT_SYMBOL_GPL(vring_create_virtqueue_dma);

/**
 * virtqueue_resize - resize the vring of vq
 * @_vq: the struct virtqueue we're talking about.
 * @num: new ring num
 * @recycle: callback to recycle unused buffers
 * @recycle_done: callback to be invoked when recycle for all unused buffers done
 *
 * When it is really necessary to create a new vring, it will set the current vq
 * into the reset state. Then call the passed callback to recycle the buffer
 * that is no longer used. Only after the new vring is successfully created, the
 * old vring will be released.
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error.
 * 0: success.
 * -ENOMEM: Failed to allocate a new ring, fall back to the original ring size.
 *  vq can still work normally
 * -EBUSY: Failed to sync with device, vq may not work properly
 * -ENOENT: Transport or device not supported
 * -E2BIG/-EINVAL: num error
 * -EPERM: Operation not permitted
 *
 */
int virtqueue_resize(struct virtqueue *_vq, u32 num,
		     void (*recycle)(struct virtqueue *vq, void *buf),
		     void (*recycle_done)(struct virtqueue *vq))
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	int err, err_reset;

	if (num > vq->vq.num_max)
		return -E2BIG;

	if (!num)
		return -EINVAL;

	if ((vq->packed_ring ? vq->packed.vring.num : vq->split.vring.num) == num)
		return 0;

	err = virtqueue_disable_and_recycle(_vq, recycle);
	if (err)
		return err;
	if (recycle_done)
		recycle_done(_vq);

	if (vq->packed_ring)
		err = virtqueue_resize_packed(_vq, num);
	else
		err = virtqueue_resize_split(_vq, num);

	err_reset = virtqueue_enable_after_reset(_vq);
	if (err_reset)
		return err_reset;

	return err;
}
EXPORT_SYMBOL_GPL(virtqueue_resize);

/**
 * virtqueue_reset - detach and recycle all unused buffers
 * @_vq: the struct virtqueue we're talking about.
 * @recycle: callback to recycle unused buffers
 * @recycle_done: callback to be invoked when recycle for all unused buffers done
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error.
 * 0: success.
 * -EBUSY: Failed to sync with device, vq may not work properly
 * -ENOENT: Transport or device not supported
 * -EPERM: Operation not permitted
 */
int virtqueue_reset(struct virtqueue *_vq,
		    void (*recycle)(struct virtqueue *vq, void *buf),
		    void (*recycle_done)(struct virtqueue *vq))
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	int err;

	err = virtqueue_disable_and_recycle(_vq, recycle);
	if (err)
		return err;
	if (recycle_done)
		recycle_done(_vq);

	if (vq->packed_ring)
		virtqueue_reinit_packed(vq);
	else
		virtqueue_reinit_split(vq);

	return virtqueue_enable_after_reset(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_reset);

struct virtqueue *vring_new_virtqueue(unsigned int index,
				      unsigned int num,
				      unsigned int vring_align,
				      struct virtio_device *vdev,
				      bool weak_barriers,
				      bool context,
				      void *pages,
				      bool (*notify)(struct virtqueue *vq),
				      void (*callback)(struct virtqueue *vq),
				      const char *name)
{
	struct vring_virtqueue_split vring_split = {};

	if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED)) {
		/*设备有PACKED标记*/
		struct vring_virtqueue_packed vring_packed = {};

		vring_packed.vring.num = num;
		vring_packed.vring.desc = pages;
		return __vring_new_virtqueue_packed(index, &vring_packed,
						    vdev, weak_barriers,
						    context, notify, callback,
						    name, vdev->dev.parent);
	}

	vring_init(&vring_split.vring, num, pages, vring_align);
	return __vring_new_virtqueue_split(index, &vring_split, vdev, weak_barriers,
				     context, notify, callback, name,
				     vdev->dev.parent);
}
EXPORT_SYMBOL_GPL(vring_new_virtqueue);

/*释放virtqueue*/
static void vring_free(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (vq->we_own_ring) {
		/*仅在ring是我们创建的情况下做释放操作*/
		if (vq->packed_ring/*packed类型的vring*/) {
			/*移除desc表*/
			vring_free_queue(vq->vq.vdev,
					 vq->packed.ring_size_in_bytes,
					 vq->packed.vring.desc,
					 vq->packed.ring_dma_addr,
					 vring_dma_dev(vq));

			vring_free_queue(vq->vq.vdev,
					 vq->packed.event_size_in_bytes,
					 vq->packed.vring.driver,
					 vq->packed.driver_event_dma_addr,
					 vring_dma_dev(vq));

			vring_free_queue(vq->vq.vdev,
					 vq->packed.event_size_in_bytes,
					 vq->packed.vring.device,
					 vq->packed.device_event_dma_addr,
					 vring_dma_dev(vq));

			kfree(vq->packed.desc_state);
			kfree(vq->packed.desc_extra);
		} else {
			vring_free_queue(vq->vq.vdev,
					 vq->split.queue_size_in_bytes,
					 vq->split.vring.desc,
					 vq->split.queue_dma_addr,
					 vring_dma_dev(vq));
		}
	}
	if (!vq->packed_ring) {
		kfree(vq->split.desc_state);
		kfree(vq->split.desc_extra);
	}
}

void vring_del_virtqueue(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	spin_lock(&vq->vq.vdev->vqs_list_lock);
	list_del(&_vq->list);/*将此vq自链表上移除*/
	spin_unlock(&vq->vq.vdev->vqs_list_lock);

	vring_free(_vq);

	kfree(vq);
}
EXPORT_SYMBOL_GPL(vring_del_virtqueue);

u32 vring_notification_data(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	u16 next;

	if (vq->packed_ring)
		next = (vq->packed.next_avail_idx &
				~(-(1 << VRING_PACKED_EVENT_F_WRAP_CTR))) |
			vq->packed.avail_wrap_counter <<
				VRING_PACKED_EVENT_F_WRAP_CTR;
	else
		next = vq->split.avail_idx_shadow;

	return next << 16 | _vq->index;
}
EXPORT_SYMBOL_GPL(vring_notification_data);

/* Manipulates transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev)
{
	unsigned int i;

	for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++) {
		switch (i) {
		case VIRTIO_RING_F_INDIRECT_DESC:
			break;
		case VIRTIO_RING_F_EVENT_IDX:
			break;
		case VIRTIO_F_VERSION_1:
			break;
		case VIRTIO_F_ACCESS_PLATFORM:
			break;
		case VIRTIO_F_RING_PACKED:
			break;
		case VIRTIO_F_ORDER_PLATFORM:
			break;
		case VIRTIO_F_NOTIFICATION_DATA:
			break;
		default:
			/* We don't understand this bit. */
			__virtio_clear_bit(vdev, i);
		}
	}
}
EXPORT_SYMBOL_GPL(vring_transport_features);

/**
 * virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @_vq: the struct virtqueue containing the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
unsigned int virtqueue_get_vring_size(const struct virtqueue *_vq)
{

	const struct vring_virtqueue *vq = to_vvq(_vq);

	return vq->packed_ring ? vq->packed.vring.num/*packed队列长度*/ : vq->split.vring.num;
}
EXPORT_SYMBOL_GPL(virtqueue_get_vring_size);

/*
 * This function should only be called by the core, not directly by the driver.
 */
void __virtqueue_break(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	/* Pairs with READ_ONCE() in virtqueue_is_broken(). */
	WRITE_ONCE(vq->broken, true);
}
EXPORT_SYMBOL_GPL(__virtqueue_break);

/*
 * This function should only be called by the core, not directly by the driver.
 */
void __virtqueue_unbreak(struct virtqueue *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	/* Pairs with READ_ONCE() in virtqueue_is_broken(). */
	WRITE_ONCE(vq->broken, false);
}
EXPORT_SYMBOL_GPL(__virtqueue_unbreak);

bool virtqueue_is_broken(const struct virtqueue *_vq)
{
	const struct vring_virtqueue *vq = to_vvq(_vq);

	return READ_ONCE(vq->broken);
}
EXPORT_SYMBOL_GPL(virtqueue_is_broken);

/*
 * This should prevent the device from being used, allowing drivers to
 * recover.  You may need to grab appropriate locks to flush.
 */
void virtio_break_device(struct virtio_device *dev)
{
	struct virtqueue *_vq;

	spin_lock(&dev->vqs_list_lock);
	list_for_each_entry(_vq, &dev->vqs, list) {
		struct vring_virtqueue *vq = to_vvq(_vq);

		/* Pairs with READ_ONCE() in virtqueue_is_broken(). */
		WRITE_ONCE(vq->broken, true);
	}
	spin_unlock(&dev->vqs_list_lock);
}
EXPORT_SYMBOL_GPL(virtio_break_device);

/*
 * This should allow the device to be used by the driver. You may
 * need to grab appropriate locks to flush the write to
 * vq->broken. This should only be used in some specific case e.g
 * (probing and restoring). This function should only be called by the
 * core, not directly by the driver.
 */
void __virtio_unbreak_device(struct virtio_device *dev)
{
	struct virtqueue *_vq;

	spin_lock(&dev->vqs_list_lock);
	list_for_each_entry(_vq, &dev->vqs, list) {
		struct vring_virtqueue *vq = to_vvq(_vq);

		/* Pairs with READ_ONCE() in virtqueue_is_broken(). */
		WRITE_ONCE(vq->broken, false);
	}
	spin_unlock(&dev->vqs_list_lock);
}
EXPORT_SYMBOL_GPL(__virtio_unbreak_device);

//获得vq desc表的起始地址
dma_addr_t virtqueue_get_desc_addr(const struct virtqueue *_vq)
{
	const struct vring_virtqueue *vq = to_vvq(_vq);

	BUG_ON(!vq->we_own_ring);

	if (vq->packed_ring)
	    //如果为packed_ring,则使用ring_dma_addr起始地址做为desc表的起始地址
		return vq->packed.ring_dma_addr;

	return vq->split.queue_dma_addr;
}
EXPORT_SYMBOL_GPL(virtqueue_get_desc_addr);

//获得vq avail表的起始地址
dma_addr_t virtqueue_get_avail_addr(const struct virtqueue *_vq)
{
	const struct vring_virtqueue *vq = to_vvq(_vq);

	BUG_ON(!vq->we_own_ring);

	if (vq->packed_ring)
		return vq->packed.driver_event_dma_addr;

	return vq->split.queue_dma_addr +
		((char *)vq->split.vring.avail - (char *)vq->split.vring.desc);
}
EXPORT_SYMBOL_GPL(virtqueue_get_avail_addr);

//获得vq used表的起始地址
dma_addr_t virtqueue_get_used_addr(const struct virtqueue *_vq)
{
	const struct vring_virtqueue *vq = to_vvq(_vq);

	BUG_ON(!vq->we_own_ring);

	if (vq->packed_ring)
		return vq->packed.device_event_dma_addr;

	return vq->split.queue_dma_addr +
		((char *)vq->split.vring.used - (char *)vq->split.vring.desc);
}
EXPORT_SYMBOL_GPL(virtqueue_get_used_addr);

/* Only available for split ring */
const struct vring *virtqueue_get_vring(const struct virtqueue *vq)
{
	return &to_vvq(vq)->split.vring;
}
EXPORT_SYMBOL_GPL(virtqueue_get_vring);

/**
 * virtqueue_dma_map_single_attrs - map DMA for _vq
 * @_vq: the struct virtqueue we're talking about.
 * @ptr: the pointer of the buffer to do dma
 * @size: the size of the buffer to do dma
 * @dir: DMA direction
 * @attrs: DMA Attrs
 *
 * The caller calls this to do dma mapping in advance. The DMA address can be
 * passed to this _vq when it is in pre-mapped mode.
 *
 * return DMA address. Caller should check that by virtqueue_dma_mapping_error().
 */
dma_addr_t virtqueue_dma_map_single_attrs(struct virtqueue *_vq, void *ptr,
					  size_t size,
					  enum dma_data_direction dir,
					  unsigned long attrs)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!vq->use_dma_api) {
		kmsan_handle_dma(virt_to_page(ptr), offset_in_page(ptr), size, dir);
		return (dma_addr_t)virt_to_phys(ptr);
	}

	return dma_map_single_attrs(vring_dma_dev(vq), ptr, size, dir, attrs);
}
EXPORT_SYMBOL_GPL(virtqueue_dma_map_single_attrs);

/**
 * virtqueue_dma_unmap_single_attrs - unmap DMA for _vq
 * @_vq: the struct virtqueue we're talking about.
 * @addr: the dma address to unmap
 * @size: the size of the buffer
 * @dir: DMA direction
 * @attrs: DMA Attrs
 *
 * Unmap the address that is mapped by the virtqueue_dma_map_* APIs.
 *
 */
void virtqueue_dma_unmap_single_attrs(struct virtqueue *_vq, dma_addr_t addr,
				      size_t size, enum dma_data_direction dir,
				      unsigned long attrs)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!vq->use_dma_api)
		return;

	dma_unmap_single_attrs(vring_dma_dev(vq), addr, size, dir, attrs);
}
EXPORT_SYMBOL_GPL(virtqueue_dma_unmap_single_attrs);

/**
 * virtqueue_dma_mapping_error - check dma address
 * @_vq: the struct virtqueue we're talking about.
 * @addr: DMA address
 *
 * Returns 0 means dma valid. Other means invalid dma address.
 */
int virtqueue_dma_mapping_error(struct virtqueue *_vq, dma_addr_t addr)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!vq->use_dma_api)
		return 0;

	return dma_mapping_error(vring_dma_dev(vq), addr);
}
EXPORT_SYMBOL_GPL(virtqueue_dma_mapping_error);

/**
 * virtqueue_dma_need_sync - check a dma address needs sync
 * @_vq: the struct virtqueue we're talking about.
 * @addr: DMA address
 *
 * Check if the dma address mapped by the virtqueue_dma_map_* APIs needs to be
 * synchronized
 *
 * return bool
 */
bool virtqueue_dma_need_sync(struct virtqueue *_vq, dma_addr_t addr)
{
	struct vring_virtqueue *vq = to_vvq(_vq);

	if (!vq->use_dma_api)
		return false;

	return dma_need_sync(vring_dma_dev(vq), addr);
}
EXPORT_SYMBOL_GPL(virtqueue_dma_need_sync);

/**
 * virtqueue_dma_sync_single_range_for_cpu - dma sync for cpu
 * @_vq: the struct virtqueue we're talking about.
 * @addr: DMA address
 * @offset: DMA address offset
 * @size: buf size for sync
 * @dir: DMA direction
 *
 * Before calling this function, use virtqueue_dma_need_sync() to confirm that
 * the DMA address really needs to be synchronized
 *
 */
void virtqueue_dma_sync_single_range_for_cpu(struct virtqueue *_vq,
					     dma_addr_t addr,
					     unsigned long offset, size_t size,
					     enum dma_data_direction dir)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct device *dev = vring_dma_dev(vq);

	if (!vq->use_dma_api)
		return;

	dma_sync_single_range_for_cpu(dev, addr, offset, size, dir);
}
EXPORT_SYMBOL_GPL(virtqueue_dma_sync_single_range_for_cpu);

/**
 * virtqueue_dma_sync_single_range_for_device - dma sync for device
 * @_vq: the struct virtqueue we're talking about.
 * @addr: DMA address
 * @offset: DMA address offset
 * @size: buf size for sync
 * @dir: DMA direction
 *
 * Before calling this function, use virtqueue_dma_need_sync() to confirm that
 * the DMA address really needs to be synchronized
 */
void virtqueue_dma_sync_single_range_for_device(struct virtqueue *_vq,
						dma_addr_t addr,
						unsigned long offset, size_t size,
						enum dma_data_direction dir)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	struct device *dev = vring_dma_dev(vq);

	if (!vq->use_dma_api)
		return;

	dma_sync_single_range_for_device(dev, addr, offset, size, dir);
}
EXPORT_SYMBOL_GPL(virtqueue_dma_sync_single_range_for_device);

MODULE_DESCRIPTION("Virtio ring implementation");
MODULE_LICENSE("GPL");
