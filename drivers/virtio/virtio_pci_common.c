// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Virtio PCI driver - common functionality for all device versions
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

#include "virtio_pci_common.h"

static bool force_legacy = false;

#if IS_ENABLED(CONFIG_VIRTIO_PCI_LEGACY)
module_param(force_legacy, bool, 0444);
MODULE_PARM_DESC(force_legacy,
		 "Force legacy mode for transitional virtio 1 devices");
#endif

/* wait for pending irq handlers */
void vp_synchronize_vectors(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	int i;

	if (vp_dev->intx_enabled)
		synchronize_irq(vp_dev->pci_dev->irq);

	for (i = 0; i < vp_dev->msix_vectors; ++i)
		synchronize_irq(pci_irq_vector(vp_dev->pci_dev, i));
}

/* the notify function used when creating a virt queue */
//通过对vq->priv地址写虚队列的index完成队列通知
bool vp_notify(struct virtqueue *vq)
{
	/* we write the queue's selector into the notification register to
	 * signal the other end */
	//通知后端队列vq->index发生变化（vq->priv为此队列对应的通知地址）
	/*向vq->priv写队列编号，用于通知对端此队列发生变化*/
	iowrite16(vq->index, (void __iomem *)vq->priv);
	return true;
}

/* Handle a configuration change: Tell driver if it wants to know. */
//virtio设备发生配置变更中断，告知驱动配置变更
static irqreturn_t vp_config_changed(int irq, void *opaque)
{
	struct virtio_pci_device *vp_dev = opaque;

	virtio_config_changed(&vp_dev->vdev);
	return IRQ_HANDLED;
}

/* Notify all virtqueues on an interrupt. */
//用一个中断通知所有virtqueues
static irqreturn_t vp_vring_interrupt(int irq, void *opaque)
{
	struct virtio_pci_device *vp_dev = opaque;
	struct virtio_pci_vq_info *info;
	irqreturn_t ret = IRQ_NONE;
	unsigned long flags;

	spin_lock_irqsave(&vp_dev->lock, flags);
	//遍历所有vq,处理此中断
	list_for_each_entry(info, &vp_dev->virtqueues, node) {
		if (vring_interrupt(irq, info->vq) == IRQ_HANDLED)
			ret = IRQ_HANDLED;
	}
	spin_unlock_irqrestore(&vp_dev->lock, flags);

	return ret;
}

/* A small wrapper to also acknowledge the interrupt when it's handled.
 * I really need an EIO hook for the vring so I can ack the interrupt once we
 * know that we'll be handling the IRQ but before we invoke the callback since
 * the callback may notify the host which results in the host attempting to
 * raise an interrupt that we would then mask once we acknowledged the
 * interrupt. */
static irqreturn_t vp_interrupt(int irq, void *opaque)
{
	struct virtio_pci_device *vp_dev = opaque;
	u8 isr;

	/* reading the ISR has the effect of also clearing it so it's very
	 * important to save off the value. */
	isr = ioread8(vp_dev->isr);

	/* It's definitely not us if the ISR was not high */
	if (!isr)
		return IRQ_NONE;

	/* Configuration change?  Tell driver if it wants to know. */
	if (isr & VIRTIO_PCI_ISR_CONFIG)
	    /*处理配置中断*/
		vp_config_changed(irq, opaque);

	//处理队列中断
	return vp_vring_interrupt(irq, opaque);
}

static int vp_request_msix_vectors(struct virtio_device *vdev, int nvectors/*请求的中断数*/,
				   bool per_vq_vectors/*是否每个vq一个中断*/, struct irq_affinity *desc)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	/*virtio设备名称*/
	const char *name = dev_name(&vp_dev->vdev.dev);
	unsigned int flags = PCI_IRQ_MSIX;/*默认请求msi-x类型中断*/
	unsigned int i, v;
	int err = -ENOMEM;

	vp_dev->msix_vectors = nvectors;

	vp_dev->msix_names = kmalloc_array(nvectors,
					   sizeof(*vp_dev->msix_names),
					   GFP_KERNEL);
	if (!vp_dev->msix_names)
		goto error;
	vp_dev->msix_affinity_masks
		= kcalloc(nvectors, sizeof(*vp_dev->msix_affinity_masks),
			  GFP_KERNEL);
	if (!vp_dev->msix_affinity_masks)
		goto error;
	for (i = 0; i < nvectors; ++i)
		if (!alloc_cpumask_var(&vp_dev->msix_affinity_masks[i],
					GFP_KERNEL))
			goto error;

	if (desc) {
	    /*如果有cpu亲昵性配置，则添加flags*/
		flags |= PCI_IRQ_AFFINITY;
		desc->pre_vectors++; /* virtio config vector */
	}

	//为vp_dev设备请求nvectors个中断
	err = pci_alloc_irq_vectors_affinity(vp_dev->pci_dev, nvectors,
					     nvectors, flags, desc);
	if (err < 0)
		goto error;

	/*设备开启msix中断*/
	vp_dev->msix_enabled = 1;

	/* Set the vector used for configuration */
	//设置首个中断，用于配置
	v = vp_dev->msix_used_vectors;
	snprintf(vp_dev->msix_names[v], sizeof *vp_dev->msix_names,
		 "%s-config", name);
	err = request_irq(pci_irq_vector(vp_dev->pci_dev, v),
			  vp_config_changed, 0, vp_dev->msix_names[v],
			  vp_dev);
	if (err)
		goto error;
	++vp_dev->msix_used_vectors;

	//指定virtio-pci设备开启v号中断
	v = vp_dev->config_vector(vp_dev, v);
	/* Verify we had enough resources to assign the vector */
	if (v == VIRTIO_MSI_NO_VECTOR) {
	    //开启中断失败
		err = -EBUSY;
		goto error;
	}

	if (!per_vq_vectors) {
	    //此情况下，所有vector共享中断
		/* Shared vector for all VQs */
		v = vp_dev->msix_used_vectors;
		snprintf(vp_dev->msix_names[v], sizeof *vp_dev->msix_names,
			 "%s-virtqueues", name);
		err = request_irq(pci_irq_vector(vp_dev->pci_dev, v),
				  vp_vring_interrupt, 0, vp_dev->msix_names[v],
				  vp_dev);
		if (err)
			goto error;
		++vp_dev->msix_used_vectors;
	}
	return 0;
error:
	return err;
}

//创建vq,设置vq物理地址，中断号
static struct virtqueue *vp_setup_vq(struct virtio_device *vdev, unsigned int index/*虚队列编号*/,
				     void (*callback/*虚队列报文中断回调*/)(struct virtqueue *vq),
				     const char *name/*虚队列名称*/,
				     bool ctx/*虚队列是否有context*/,
				     u16 msix_vec/*中断号*/)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtio_pci_vq_info *info = kmalloc(sizeof *info, GFP_KERNEL);
	struct virtqueue *vq;
	unsigned long flags;

	/* fill out our structure that represents an active queue */
	if (!info)
		return ERR_PTR(-ENOMEM);

	//调用setup_vq创建virtqueue
	vq = vp_dev->setup_vq(vp_dev, info, index/*vq索引号*/, callback, name/*vq名称*/, ctx,
			      msix_vec/*vq使用的中断号*/);
	if (IS_ERR(vq))
		goto out_info;

	info->vq = vq;
	if (callback) {
		spin_lock_irqsave(&vp_dev->lock, flags);
		//将info添加到virtqueues队列
		list_add(&info->node, &vp_dev->virtqueues);
		spin_unlock_irqrestore(&vp_dev->lock, flags);
	} else {
		INIT_LIST_HEAD(&info->node);
	}

	/*为设备关联index号vq_info*/
	vp_dev->vqs[index] = info;
	return vq;

out_info:
	kfree(info);
	return vq;
}

static void vp_del_vq(struct virtqueue *vq)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vq->vdev);
	struct virtio_pci_vq_info *info = vp_dev->vqs[vq->index];
	unsigned long flags;

	/*
	 * If it fails during re-enable reset vq. This way we won't rejoin
	 * info->node to the queue. Prevent unexpected irqs.
	 */
	if (!vq->reset) {
		spin_lock_irqsave(&vp_dev->lock, flags);
		list_del(&info->node);
		spin_unlock_irqrestore(&vp_dev->lock, flags);
	}

	vp_dev->del_vq(info);
	kfree(info);
}

/* the config->del_vqs() implementation */
void vp_del_vqs(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtqueue *vq, *n;
	int i;

	/*遍历vdev下所有vq*/
	list_for_each_entry_safe(vq/*当前遍历的队列*/, n/*下一个队列*/, &vdev->vqs, list) {
		if (vp_dev->is_avq(vdev, vq->index))
			/*跳过admin vq*/
			continue;

		if (vp_dev->per_vq_vectors) {
			int v = vp_dev->vqs[vq->index]->msix_vector;

			if (v != VIRTIO_MSI_NO_VECTOR) {
				/*为此队列申请了中断，释放此中断*/
				int irq = pci_irq_vector(vp_dev->pci_dev, v);

				irq_update_affinity_hint(irq, NULL);
				free_irq(irq, vq);
			}
		}
		vp_del_vq(vq);/*调用回调完成vq资源释放*/
	}
	vp_dev->per_vq_vectors = false;

	if (vp_dev->intx_enabled) {
		free_irq(vp_dev->pci_dev->irq, vp_dev);
		vp_dev->intx_enabled = 0;
	}

	for (i = 0; i < vp_dev->msix_used_vectors; ++i)
		free_irq(pci_irq_vector(vp_dev->pci_dev, i), vp_dev);

	if (vp_dev->msix_affinity_masks) {
		for (i = 0; i < vp_dev->msix_vectors; i++)
			free_cpumask_var(vp_dev->msix_affinity_masks[i]);
	}

	if (vp_dev->msix_enabled) {
		/* Disable the vector used for configuration */
		vp_dev->config_vector(vp_dev, VIRTIO_MSI_NO_VECTOR);

		pci_free_irq_vectors(vp_dev->pci_dev);
		vp_dev->msix_enabled = 0;
	}

	vp_dev->msix_vectors = 0;
	vp_dev->msix_used_vectors = 0;
	kfree(vp_dev->msix_names);
	vp_dev->msix_names = NULL;
	kfree(vp_dev->msix_affinity_masks);
	vp_dev->msix_affinity_masks = NULL;
	kfree(vp_dev->vqs);
	vp_dev->vqs = NULL;
}

static int vp_find_vqs_msix(struct virtio_device *vdev, unsigned int nvqs/*虚队列数目*/,
		struct virtqueue *vqs[]/*出参，创建的各虚队列地址*/, vq_callback_t *callbacks[]/*各队列对应的rx,tx报文中断回调*/,
		const char * const names[]/*各vq名称*/, bool per_vq_vectors/*是否每个队列一个msi-x向量*/,
		const bool *ctx,
		struct irq_affinity *desc)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	u16 msix_vec;
	int i, err, nvectors, allocated_vectors, queue_idx = 0;

	//创建nvqs个virtio_pci_vq_info指针
	vp_dev->vqs = kcalloc(nvqs, sizeof(*vp_dev->vqs), GFP_KERNEL);
	if (!vp_dev->vqs)
		return -ENOMEM;

	if (per_vq_vectors) {
		/* Best option: one for change interrupt, one per vq. */
		nvectors = 1;
		for (i = 0; i < nvqs; ++i)
			if (names[i] && callbacks[i])
				++nvectors;/*已命名，并具有callback的vq数目，即中断总数*/
	} else {
		/* Second best: one for change, shared for all vqs. */
		nvectors = 2;/*占用2个中断*/
	}

	err = vp_request_msix_vectors(vdev, nvectors/*中断数*/, per_vq_vectors,
				      per_vq_vectors ? desc : NULL);
	if (err)
		goto error_find;

	vp_dev->per_vq_vectors = per_vq_vectors;
	allocated_vectors = vp_dev->msix_used_vectors;
	//遍历创建各个队列
	for (i = 0; i < nvqs; ++i) {
		if (!names[i]) {
			vqs[i] = NULL;/*未提供name,置为NULL*/
			continue;
		}

		//未给定回调，置不使用中断
		if (!callbacks[i])
			msix_vec = VIRTIO_MSI_NO_VECTOR;
		else if (vp_dev->per_vq_vectors)
		    //每个vq一个中断，按序分配申请的中断
			msix_vec = allocated_vectors++;
		else
			msix_vec = VP_MSIX_VQ_VECTOR;
		//创建第i个虚队列
		vqs[i] = vp_setup_vq(vdev, queue_idx++/*队列编号*/, callbacks[i], names[i],
				     ctx ? ctx[i] : false,
				     msix_vec/*队列对应的中断*/);
		if (IS_ERR(vqs[i])) {
			err = PTR_ERR(vqs[i]);
			goto error_find;
		}

		if (!vp_dev->per_vq_vectors || msix_vec == VIRTIO_MSI_NO_VECTOR)
			continue;

		/* allocate per-vq irq if available and necessary */
		snprintf(vp_dev->msix_names[msix_vec],
			 sizeof *vp_dev->msix_names,
			 "%s-%s",
			 dev_name(&vp_dev->vdev.dev), names[i]);
		/*针对msix_vec号中断，指定中断时调用其对应的callback*/
		err = request_irq(pci_irq_vector(vp_dev->pci_dev, msix_vec),
				  vring_interrupt, 0,
				  vp_dev->msix_names[msix_vec],
				  vqs[i]);
		if (err)
			goto error_find;
	}
	return 0;

error_find:
	vp_del_vqs(vdev);
	return err;
}

static int vp_find_vqs_intx(struct virtio_device *vdev, unsigned int nvqs,
		struct virtqueue *vqs[], vq_callback_t *callbacks[],
		const char * const names[], const bool *ctx)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	int i, err, queue_idx = 0;

	vp_dev->vqs = kcalloc(nvqs, sizeof(*vp_dev->vqs), GFP_KERNEL);
	if (!vp_dev->vqs)
		return -ENOMEM;

	//配置中断处理函数
	err = request_irq(vp_dev->pci_dev->irq, vp_interrupt, IRQF_SHARED,
			dev_name(&vdev->dev), vp_dev);
	if (err)
		goto out_del_vqs;

	vp_dev->intx_enabled = 1;
	vp_dev->per_vq_vectors = false;
	for (i = 0; i < nvqs; ++i) {
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		}
		vqs[i] = vp_setup_vq(vdev, queue_idx++, callbacks[i], names[i],
				     ctx ? ctx[i] : false,
				     VIRTIO_MSI_NO_VECTOR);
		if (IS_ERR(vqs[i])) {
			err = PTR_ERR(vqs[i]);
			goto out_del_vqs;
		}
	}

	return 0;
out_del_vqs:
	vp_del_vqs(vdev);
	return err;
}

/* the config->find_vqs() implementation */
int vp_find_vqs(struct virtio_device *vdev, unsigned int nvqs/*虚队列（vq)总数目*/,
		struct virtqueue *vqs[]/*出参，各vq地址*/, vq_callback_t *callbacks[]/*指出各vq对应的callback*/,
		const char * const names[]/*指出各vq名称*/, const bool *ctx/*指出各vq是否有context*/,
		struct irq_affinity *desc)
{
	int err;

	/* Try MSI-X with one vector per queue. */
	//尝试为每个队列申请个msi-x向量
	err = vp_find_vqs_msix(vdev, nvqs, vqs, callbacks, names, true, ctx, desc);
	if (!err)
		return 0;
	//尝试失败，按virtio标准规定，至少２个，至多0x800个向量，故尝试２个
	//A device that has an MSI-X capability SHOULD support at least 2 and at most 0x800 MSI-X vectors.
	/* Fallback: MSI-X with one vector for config, one shared for queues. */
	err = vp_find_vqs_msix(vdev, nvqs, vqs, callbacks, names, false, ctx, desc);
	if (!err)
		return 0;
	/* Is there an interrupt? If not give up. */
	if (!(to_vp_device(vdev)->pci_dev->irq))
		return err;
	/* Finally fall back to regular interrupts. */
	return vp_find_vqs_intx(vdev, nvqs, vqs, callbacks, names, ctx);
}

const char *vp_bus_name(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);

	return pci_name(vp_dev->pci_dev);/*获得pci设备名称*/
}

/* Setup the affinity for a virtqueue:
 * - force the affinity for per vq vector
 * - OR over all affinities for shared MSI
 * - ignore the affinity request if we're using INTX
 */
int vp_set_vq_affinity(struct virtqueue *vq, const struct cpumask *cpu_mask)
{
	struct virtio_device *vdev = vq->vdev;
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtio_pci_vq_info *info = vp_dev->vqs[vq->index];/*取vq info*/
	struct cpumask *mask;
	unsigned int irq;

	if (!vq->callback)
		return -EINVAL;

	if (vp_dev->msix_enabled) {
		mask = vp_dev->msix_affinity_masks[info->msix_vector];/*取中断的affinity*/
		irq = pci_irq_vector(vp_dev->pci_dev, info->msix_vector);
		if (!cpu_mask)
			irq_update_affinity_hint(irq, NULL);
		else {
			/*设置中断affinity*/
			cpumask_copy(mask, cpu_mask);
			irq_set_affinity_and_hint(irq, mask);
		}
	}
	return 0;
}

const struct cpumask *vp_get_vq_affinity(struct virtio_device *vdev, int index)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);

	if (!vp_dev->per_vq_vectors ||
	    vp_dev->vqs[index]->msix_vector == VIRTIO_MSI_NO_VECTOR)
		return NULL;

	return pci_irq_get_affinity(vp_dev->pci_dev,
				    vp_dev->vqs[index]->msix_vector);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_pci_freeze(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	int ret;

	ret = virtio_device_freeze(&vp_dev->vdev);

	if (!ret)
		pci_disable_device(pci_dev);
	return ret;
}

static int virtio_pci_restore(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	int ret;

	ret = pci_enable_device(pci_dev);
	if (ret)
		return ret;

	pci_set_master(pci_dev);
	return virtio_device_restore(&vp_dev->vdev);
}

static bool vp_supports_pm_no_reset(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	u16 pmcsr;

	if (!pci_dev->pm_cap)
		return false;

	pci_read_config_word(pci_dev, pci_dev->pm_cap + PCI_PM_CTRL, &pmcsr);
	if (PCI_POSSIBLE_ERROR(pmcsr)) {
		dev_err(dev, "Unable to query pmcsr");
		return false;
	}

	return pmcsr & PCI_PM_CTRL_NO_SOFT_RESET;
}

static int virtio_pci_suspend(struct device *dev)
{
	return vp_supports_pm_no_reset(dev) ? 0 : virtio_pci_freeze(dev);
}

static int virtio_pci_resume(struct device *dev)
{
	return vp_supports_pm_no_reset(dev) ? 0 : virtio_pci_restore(dev);
}

static const struct dev_pm_ops virtio_pci_pm_ops = {
	.suspend = virtio_pci_suspend,
	.resume = virtio_pci_resume,
	.freeze = virtio_pci_freeze,
	.thaw = virtio_pci_restore,
	.poweroff = virtio_pci_freeze,
	.restore = virtio_pci_restore,
};
#endif


/* Qumranet donated their vendor ID for devices 0x1000 thru 0x10FF. */
static const struct pci_device_id virtio_pci_id_table[] = {
	//只匹配vendor(Qumranet把他们的vendor id中0x1000到0x10ff的设备号给了redhat）
	//故这个匹配命中之后，仍然需要检查deice id是否在0x1000与0x10ff之间
	{ PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, PCI_ANY_ID) },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, virtio_pci_id_table);

static void virtio_pci_release_dev(struct device *_d)
{
	struct virtio_device *vdev = dev_to_virtio(_d);
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);

	/* As struct device is a kobject, it's not safe to
	 * free the memory (including the reference counter itself)
	 * until it's release callback. */
	kfree(vp_dev);
}

//virtio_pci设备probe
static int virtio_pci_probe(struct pci_dev *pci_dev,
			    const struct pci_device_id *id)
{
	struct virtio_pci_device *vp_dev, *reg_dev = NULL;
	int rc;

	/* allocate our structure and fill it out */
	//申请virtio pci设备
	vp_dev = kzalloc(sizeof(struct virtio_pci_device), GFP_KERNEL);
	if (!vp_dev)
		return -ENOMEM;

	/*设置驱动私有数据为struct virtio_pci_device*/
	pci_set_drvdata(pci_dev, vp_dev);
	vp_dev->vdev.dev.parent = &pci_dev->dev;
	vp_dev->vdev.dev.release = virtio_pci_release_dev;
	vp_dev->pci_dev = pci_dev;
	INIT_LIST_HEAD(&vp_dev->virtqueues);
	spin_lock_init(&vp_dev->lock);

	/* enable the device */
	rc = pci_enable_device(pci_dev);
	if (rc)
		goto err_enable_device;

	if (force_legacy) {
		//如果强制按legacy设备probe，则先按legacy尝试probe
		rc = virtio_pci_legacy_probe(vp_dev);
		/* Also try modern mode if we can't map BAR0 (no IO space). */
		if (rc == -ENODEV || rc == -ENOMEM)
			//如果legacy_probe失败，则进行modern_probe
			rc = virtio_pci_modern_probe(vp_dev);
		if (rc)
			goto err_probe;
	} else {
		//优先进行modern probe,如果失败再进行legacy_probe
		rc = virtio_pci_modern_probe(vp_dev);
		if (rc == -ENODEV)
			rc = virtio_pci_legacy_probe(vp_dev);
		if (rc)
			goto err_probe;
	}

	pci_set_master(pci_dev);

	//注册完成识别的virtio设备（例如引发virtio_net驱动probe此设备）
	rc = register_virtio_device(&vp_dev->vdev);
	reg_dev = vp_dev;
	if (rc)
		goto err_register;

	return 0;

err_register:
	if (vp_dev->is_legacy)
		virtio_pci_legacy_remove(vp_dev);
	else
		virtio_pci_modern_remove(vp_dev);
err_probe:
	pci_disable_device(pci_dev);
err_enable_device:
	if (reg_dev)
		put_device(&vp_dev->vdev.dev);
	else
		kfree(vp_dev);
	return rc;
}

static void virtio_pci_remove(struct pci_dev *pci_dev)
{
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	struct device *dev = get_device(&vp_dev->vdev.dev);

	/*
	 * Device is marked broken on surprise removal so that virtio upper
	 * layers can abort any ongoing operation.
	 */
	if (!pci_device_is_present(pci_dev))
		virtio_break_device(&vp_dev->vdev);

	pci_disable_sriov(pci_dev);

	unregister_virtio_device(&vp_dev->vdev);

	if (vp_dev->is_legacy)
		virtio_pci_legacy_remove(vp_dev);
	else
		virtio_pci_modern_remove(vp_dev);

	pci_disable_device(pci_dev);
	put_device(dev);
}

//virtio设备的sriov支持
static int virtio_pci_sriov_configure(struct pci_dev *pci_dev, int num_vfs)
{
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	struct virtio_device *vdev = &vp_dev->vdev;
	int ret;

	if (!(vdev->config->get_status(vdev) & VIRTIO_CONFIG_S_DRIVER_OK))
		/*此设备还未完成驱动适配*/
		return -EBUSY;

	if (!__virtio_test_bit(vdev, VIRTIO_F_SR_IOV))
		/*设备未开启sriov能力,直接返回*/
		return -EINVAL;

	if (pci_vfs_assigned(pci_dev))
		return -EPERM;

	if (num_vfs == 0) {
	    //要求关闭virtio-pci设备的sriov功能
		pci_disable_sriov(pci_dev);
		return 0;
	}

	//开启virtio-pci设备的sriov功能
	ret = pci_enable_sriov(pci_dev, num_vfs);
	if (ret < 0)
		return ret;

	return num_vfs;
}

static struct pci_driver virtio_pci_driver = {
	.name		= "virtio-pci",
	//用于pci设备与driver间的match,只要vendor是redhat，则就能匹配
	.id_table	= virtio_pci_id_table,
	//virtio-pci是pci bus的一个驱动，故当pci bus probe一个设备时，首先pci bus的probe函数将被调用
	//然后pci bus的probe函数会调用本函数完成probe过程,从而完成设备识别，当设备添加进kernel时，
	//由于设备从属于virtio_bus，故virtio-bus上的驱动会来probe此设备，例如virtio-net驱动
	.probe		= virtio_pci_probe,
	.remove		= virtio_pci_remove,
#ifdef CONFIG_PM_SLEEP
	.driver.pm	= &virtio_pci_pm_ops,
#endif
	.sriov_configure = virtio_pci_sriov_configure,/*virtio设备支持sriov*/
};

struct virtio_device *virtio_pci_vf_get_pf_dev(struct pci_dev *pdev)
{
	struct virtio_pci_device *pf_vp_dev;

	pf_vp_dev = pci_iov_get_pf_drvdata(pdev, &virtio_pci_driver);
	if (IS_ERR(pf_vp_dev))
		return NULL;

	return &pf_vp_dev->vdev;
}

//注册pci驱动
module_pci_driver(virtio_pci_driver);

MODULE_AUTHOR("Anthony Liguori <aliguori@us.ibm.com>");
MODULE_DESCRIPTION("virtio-pci");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");
