#ifndef _UAPI_LINUX_VIRTIO_RING_H
#define _UAPI_LINUX_VIRTIO_RING_H
/* An interface for efficient virtio implementation, currently for use by KVM,
 * but hopefully others soon.  Do NOT change this since it will
 * break existing servers and clients.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
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
 * SUCH DAMAGE.
 *
 * Copyright Rusty Russell IBM Corporation 2007. */
#ifndef __KERNEL__
#include <stdint.h>
#endif
#include <linux/types.h>
#include <linux/virtio_types.h>

/* This marks a buffer as continuing via the next field. */
//标记其next指向下一个描述符
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
//标记这个buffer可写（如为0，则表示可读）
#define VRING_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. */
/*标记这个描述符内包含有一组描述符指明的BUFFER链*/
#define VRING_DESC_F_INDIRECT	4

/*
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
/*标记此描述符有效*/
#define VRING_PACKED_DESC_F_AVAIL	7
/*标记此描述符被使用*/
#define VRING_PACKED_DESC_F_USED	15

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY	1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT	1

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE	0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE	0x1
/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC	0x2

/*
 * Wrap counter bit shift in event suppression structure
 * of packed ring.
 */
#define VRING_PACKED_EVENT_F_WRAP_CTR	15

/* We support indirect buffer descriptors */
/*标明设备支持大请求(a large number of large requests.)*/
#define VIRTIO_RING_F_INDIRECT_DESC	28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX		29

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

/**
 * struct vring_desc - Virtio ring descriptors,
 * 16 bytes long. These can chain together via @next.
 *
 * @addr: buffer address (guest-physical)
 * @len: buffer length
 * @flags: descriptor flags
 * @next: index of the next descriptor in the chain,
 *        if the VRING_DESC_F_NEXT flag is set. We chain unused
 *        descriptors via this, too.
 */
/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". */
//如virtio 1.0 spec所言
//The descriptor table refers to the buffers the driver is using for the device. addr is a physical address, and
//the buffers can be chained via next. Each descriptor describes a buffer which is read-only for the device
//(“device-readable”) or write-only for the device (“device-writable”), but a chain of descriptors can contain
//both device-readable and device-writable buffers.
struct vring_desc {
	__virtio64 addr;
	__virtio32 len;
	__virtio16 flags;//见VRING_DESC_F_NEXT相关标记
	__virtio16 next;//指向下一个vring_desc索引
};

struct vring_avail {
	__virtio16 flags;
	//The driver uses the available ring to offer buffers to the device: each ring entry refers to the head of a
	//descriptor chain. It is only written by the driver and read by the device.
	//idx field indicates where the driver would put the next descriptor entry in the ring (modulo the queue size).
	//This starts at 0, and increases.
	__virtio16 idx;//队列中目前有效位置（即可存放或可读取的极限位置；驱动写，设备读）
	__virtio16 ring[];//长度为num个（见vring)
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	__virtio32 id;//描述符索引
	/* Total length of the descriptor chain which was used (written to) */
	__virtio32 len;//描述符链buffer总可写长度
};

typedef struct vring_used_elem __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
	vring_used_elem_t;

struct vring_used {
	__virtio16 flags;
	/*当前used表位置，设备收时写此值，使软件知道哪些可收，发时写此值，使软件知道哪些已发完*/
	__virtio16 idx;
	vring_used_elem_t ring[];//长度为num（见vring)，已完成使用的索引符索引＋描述符数目
};

/*
 * The ring element addresses are passed between components with different
 * alignments assumptions. Thus, we might need to decrease the compiler-selected
 * alignment, and so must use a typedef to make sure the aligned attribute
 * actually takes hold:
 *
 * https://gcc.gnu.org/onlinedocs//gcc/Common-Type-Attributes.html#Common-Type-Attributes
 *
 * When used on a struct, or struct member, the aligned attribute can only
 * increase the alignment; in order to decrease it, the packed attribute must
 * be specified as well. When used as part of a typedef, the aligned attribute
 * can both increase and decrease alignment, and specifying the packed
 * attribute generates a warning.
 */
typedef struct vring_desc __attribute__((aligned(VRING_DESC_ALIGN_SIZE)))
	vring_desc_t;
typedef struct vring_avail __attribute__((aligned(VRING_AVAIL_ALIGN_SIZE)))
	vring_avail_t;
typedef struct vring_used __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
	vring_used_t;

//按virtio 1.0 spec所言
//When the driver wants to send a buffer to the device, it fills in a slot
//in the descriptor table (or chains several together), and writes the
//descriptor index into the available ring. It then notifies the device.
//When the device has finished a buffer, it writes the descriptor index
//into the used ring, and sends an interrupt.
struct vring {
	//The number of descriptors in the table is defined by the queue size for this virtqueue: this is the maximum
	//possible descriptor chain length.
	unsigned int num;//队列大小

	vring_desc_t *desc;//描述符表(用于存放要发送给用户的信息）

	vring_avail_t *avail;//avail表（写者维护，读者只读，用于知会读者目前哪些数据已可以进行读取）

	vring_used_t *used;//已用表（写者只读，读者维护,用于知会写者，目前哪些数据已被读者完成读取）
};

#ifndef VIRTIO_RING_NO_LEGACY

/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *	// The actual descriptors (16 bytes each)
 *	struct vring_desc desc[num];
 *
 *	// A ring of available descriptor heads with free-running index.
 *	__virtio16 avail_flags;
 *	__virtio16 avail_idx;
 *	__virtio16 available[num];
 *	__virtio16 used_event_idx;
 *
 *	// Padding to the next align boundary.
 *	char pad[];
 *
 *	// A ring of used descriptor heads with free-running index.
 *	__virtio16 used_flags;
 *	__virtio16 used_idx;
 *	struct vring_used_elem used[num];
 *	__virtio16 avail_event_idx;
 * };
 */
/* We publish the used event index at the end of the available ring, and vice
 * versa. They are at the end for backwards compatibility. */
#define vring_used_event(vr) ((vr)->avail->ring[(vr)->num])
#define vring_avail_event(vr) (*(__virtio16 *)&(vr)->used->ring[(vr)->num])

//初始化vring
static inline void vring_init(struct vring *vr, unsigned int num, void *p,
			      unsigned long align)
{
	//查看vring_size函数
	//p分三部分：
	//1为num*sizeof(vring_desc)为desc部分
	//2为avail,其包含的ring有num个成员
	//3为used,其包含的ring有num个成员
	vr->num = num;
	vr->desc = p;
	vr->avail = (struct vring_avail *)((char *)p + num * sizeof(struct vring_desc));
	vr->used = (void *)(((uintptr_t)&vr->avail->ring[num] + sizeof(__virtio16)
		+ align-1) & ~(align - 1));
}

static inline unsigned vring_size(unsigned int num, unsigned long align)
{
	//这块比dpdk写的不容易看懂多了
	//num个vring_desc
	//sizeof(__virtio16)*(3+num) 即用来表示 sizeof(vring_avail)+ num*sizeof(__virio16)
	//也就是申请avail结构且数组大小为num
	//sizeof(__vrrtio16)*3 + sizeof(struct vring_used_elem) * num
	//也就是申请used结构且数组大小为num
	return ((sizeof(struct vring_desc) * num + sizeof(__virtio16) * (3 + num)
		 + align - 1) & ~(align - 1))
		+ sizeof(__virtio16) * 3 + sizeof(struct vring_used_elem) * num;
}

#endif /* VIRTIO_RING_NO_LEGACY */

/* The following is used with USED_EVENT_IDX and AVAIL_EVENT_IDX */
/* Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event? */
static inline int vring_need_event(__u16 event_idx, __u16 new_idx, __u16 old)
{
	/* Note: Xen has similar logic for notification hold-off
	 * in include/xen/interface/io/ring.h with req_event and req_prod
	 * corresponding to event_idx + 1 and new_idx respectively.
	 * Note also that req_event and req_prod in Xen start at 1,
	 * event indexes in virtio start at 0. */
	return (__u16)(new_idx - event_idx - 1) < (__u16)(new_idx - old);
}

struct vring_packed_desc_event {
	/* Descriptor Ring Change Event Offset/Wrap Counter. */
	__le16 off_wrap;
	/* Descriptor Ring Change Event Flags. */
	__le16 flags;
};

struct vring_packed_desc {
	/* Buffer Address. */
	__le64 addr;
	/* Buffer Length. */
	__le32 len;
	/* Buffer ID. */
	__le16 id;
	/* The flags depending on descriptor type. */
	__le16 flags;/*描述符对应的标记位，例如*/
};

#endif /* _UAPI_LINUX_VIRTIO_RING_H */
