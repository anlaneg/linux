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
#define VRING_DESC_F_NEXT	1 //标记其next指向下一个描述符
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT	4

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY	1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT	1

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC	28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX		29

/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". */
//如virtio 1.0 spec所言
//The descriptor table refers to the buffers the driver is using for the device. addr is a physical address, and
//the buffers can be chained via next. Each descriptor describes a buffer which is read-only for the device
//(“device-readable”) or write-only for the device (“device-writable”), but a chain of descriptors can contain
//both device-readable and device-writable buffers.
struct vring_desc {
	/* Address (guest-physical). */
	__virtio64 addr;
	/* Length. */
	__virtio32 len;
	/* The flags as indicated above. */
	__virtio16 flags;//见VRING_DESC_F_NEXT相关标记
	/* We chain unused descriptors via this, too */
	__virtio16 next;//指向下一个vring_desc索引
};

struct vring_avail {
	__virtio16 flags;
	//The driver uses the available ring to offer buffers to the device: each ring entry refers to the head of a
	//descriptor chain. It is only written by the driver and read by the device.
	//idx field indicates where the driver would put the next descriptor entry in the ring (modulo the queue size).
	//This starts at 0, and increases.
	__virtio16 idx;//队列中目前有效位置（即可存放或可读取的极限位置）
	__virtio16 ring[];//长度为num个（见vring)
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	__virtio32 id;//描述符索引
	/* Total length of the descriptor chain which was used (written to) */
	__virtio32 len;//描述符数目
};

struct vring_used {
	__virtio16 flags;
	__virtio16 idx;
	struct vring_used_elem ring[];//长度为num（见vring)，已完成使用的索引符索引＋描述符数目
};

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

	struct vring_desc *desc;//描述符表(用于存放要发送给用户的信息）

	struct vring_avail *avail;//avail表（写者维护，读者只读，用于知会读者目前哪些数据已可以进行读取）

	struct vring_used *used;//已用表（写者只读，读者维护,用于知会写者，目前哪些数据已被读者完成读取）
};

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

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
	vr->avail = p + num*sizeof(struct vring_desc);
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

#endif /* _UAPI_LINUX_VIRTIO_RING_H */
