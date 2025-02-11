/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_IODEV_H__
#define __KVM_IODEV_H__

#include <linux/kvm_types.h>
#include <linux/errno.h>

struct kvm_io_device;
struct kvm_vcpu;

/**
 * kvm_io_device_ops are called under kvm slots_lock.
 * read and write handlers return 0 if the transaction has been handled,
 * or non-zero to have it passed to the next device.
 **/
struct kvm_io_device_ops {
    //读设备指定地址
	int (*read)(struct kvm_vcpu *vcpu,
		    struct kvm_io_device *this,
		    gpa_t addr,
		    int len,
		    void *val);
	//写设备指定地址
	int (*write)(struct kvm_vcpu *vcpu,
		     struct kvm_io_device *this,
		     gpa_t addr,
		     int len,
		     const void *val);
	void (*destructor)(struct kvm_io_device *this);
};


struct kvm_io_device {
	const struct kvm_io_device_ops *ops;
};

//为kvm io device设置ops
static inline void kvm_iodevice_init(struct kvm_io_device *dev,
				     const struct kvm_io_device_ops *ops)
{
	dev->ops = ops;
}

//向kvm io device请求读addr起始的数据，如果失败返回非0
static inline int kvm_iodevice_read(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev, gpa_t addr,
				    int l, void *v)
{
	return dev->ops->read ? dev->ops->read(vcpu, dev, addr, l, v)
				: -EOPNOTSUPP;
}

//kvm io设备写
static inline int kvm_iodevice_write(struct kvm_vcpu *vcpu,
				     struct kvm_io_device *dev, gpa_t addr,
				     int l, const void *v)
{
	/*通过kvm_io_device来进行写操作（如果其后对应的是ioeventfd,则会触发用户态通知）*/
	return dev->ops->write ? dev->ops->write(vcpu, dev, addr, l, v)
				 : -EOPNOTSUPP;
}

#endif /* __KVM_IODEV_H__ */
