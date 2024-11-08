// SPDX-License-Identifier: GPL-2.0
/*
 * PCI Express I/O Virtualization (IOV) support
 *   Single Root IOV 1.0
 *   Address Translation Service 1.0
 *
 * Copyright (C) 2009 Intel Corporation, Yu Zhao <yu.zhao@intel.com>
 */

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/delay.h>
#include "pci.h"

#define VIRTFN_ID_LEN	17	/* "virtfn%u\0" for 2^32 - 1 */

/*生成vf_id对应的bus信息*/
int pci_iov_virtfn_bus(struct pci_dev *dev, int vf_id)
{
	if (!dev->is_physfn)
		return -EINVAL;
	return dev->bus->number + ((dev->devfn + dev->sriov->offset +
				    dev->sriov->stride * vf_id) >> 8);
}

int pci_iov_virtfn_devfn(struct pci_dev *dev, int vf_id)
{
	if (!dev->is_physfn)
		return -EINVAL;
	return (dev->devfn + dev->sriov->offset +
		dev->sriov->stride * vf_id) & 0xff;
}
EXPORT_SYMBOL_GPL(pci_iov_virtfn_devfn);

int pci_iov_vf_id(struct pci_dev *dev)
{
	struct pci_dev *pf;

	if (!dev->is_virtfn)
		return -EINVAL;

	pf = pci_physfn(dev);
	return (pci_dev_id(dev) - (pci_dev_id(pf) + pf->sriov->offset)) /
	       pf->sriov->stride;
}
EXPORT_SYMBOL_GPL(pci_iov_vf_id);

/**
 * pci_iov_get_pf_drvdata - Return the drvdata of a PF
 * @dev: VF pci_dev
 * @pf_driver: Device driver required to own the PF
 *
 * This must be called from a context that ensures that a VF driver is attached.
 * The value returned is invalid once the VF driver completes its remove()
 * callback.
 *
 * Locking is achieved by the driver core. A VF driver cannot be probed until
 * pci_enable_sriov() is called and pci_disable_sriov() does not return until
 * all VF drivers have completed their remove().
 *
 * The PF driver must call pci_disable_sriov() before it begins to destroy the
 * drvdata.
 */
void *pci_iov_get_pf_drvdata(struct pci_dev *dev, struct pci_driver *pf_driver)
{
	struct pci_dev *pf_dev;

	if (!dev->is_virtfn)
		return ERR_PTR(-EINVAL);
	pf_dev = dev->physfn;
	if (pf_dev->driver != pf_driver)
		return ERR_PTR(-EINVAL);
	return pci_get_drvdata(pf_dev);
}
EXPORT_SYMBOL_GPL(pci_iov_get_pf_drvdata);

/*
 * Per SR-IOV spec sec 3.3.10 and 3.3.11, First VF Offset and VF Stride may
 * change when NumVFs changes.
 *
 * Update iov->offset and iov->stride when NumVFs is written.
 */
static inline void pci_iov_set_numvfs(struct pci_dev *dev, int nr_virtfn)
{
	struct pci_sriov *iov = dev->sriov;

	pci_write_config_word(dev, iov->pos + PCI_SRIOV_NUM_VF, nr_virtfn);
	pci_read_config_word(dev, iov->pos + PCI_SRIOV_VF_OFFSET, &iov->offset);
	pci_read_config_word(dev, iov->pos + PCI_SRIOV_VF_STRIDE, &iov->stride);
}

/*
 * The PF consumes one bus number.  NumVFs, First VF Offset, and VF Stride
 * determine how many additional bus numbers will be consumed by VFs.
 *
 * Iterate over all valid NumVFs, validate offset and stride, and calculate
 * the maximum number of bus numbers that could ever be required.
 */
static int compute_max_vf_buses(struct pci_dev *dev)
{
	struct pci_sriov *iov = dev->sriov;
	int nr_virtfn, busnr, rc = 0;

	for (nr_virtfn = iov->total_VFs; nr_virtfn; nr_virtfn--) {
		pci_iov_set_numvfs(dev, nr_virtfn);
		if (!iov->offset || (nr_virtfn > 1 && !iov->stride)) {
			rc = -EIO;
			goto out;
		}

		busnr = pci_iov_virtfn_bus(dev, nr_virtfn - 1);
		if (busnr > iov->max_VF_buses)
			iov->max_VF_buses = busnr;
	}

out:
	pci_iov_set_numvfs(dev, 0);
	return rc;
}

static struct pci_bus *virtfn_add_bus(struct pci_bus *bus, int busnr)
{
	struct pci_bus *child;

	if (bus->number == busnr)
		return bus;

	child = pci_find_bus(pci_domain_nr(bus), busnr);
	if (child)
		return child;

	child = pci_add_new_bus(bus, NULL, busnr);
	if (!child)
		return NULL;

	pci_bus_insert_busn_res(child, busnr, busnr);

	return child;
}

static void virtfn_remove_bus(struct pci_bus *physbus, struct pci_bus *virtbus)
{
	if (physbus != virtbus && list_empty(&virtbus->devices))
		pci_remove_bus(virtbus);
}

resource_size_t pci_iov_resource_size(struct pci_dev *dev, int resno)
{
	if (!dev->is_physfn)
		return 0;

	return dev->sriov->barsz[resno - PCI_IOV_RESOURCES];
}

static void pci_read_vf_config_common(struct pci_dev *virtfn)
{
	struct pci_dev *physfn = virtfn->physfn;

	/*
	 * Some config registers are the same across all associated VFs.
	 * Read them once from VF0 so we can skip reading them from the
	 * other VFs.
	 *
	 * PCIe r4.0, sec 9.3.4.1, technically doesn't require all VFs to
	 * have the same Revision ID and Subsystem ID, but we assume they
	 * do.
	 */
	pci_read_config_dword(virtfn, PCI_CLASS_REVISION,
			      &physfn->sriov->class);
	pci_read_config_byte(virtfn, PCI_HEADER_TYPE,
			     &physfn->sriov->hdr_type);
	pci_read_config_word(virtfn, PCI_SUBSYSTEM_VENDOR_ID,
			     &physfn->sriov->subsystem_vendor);
	pci_read_config_word(virtfn, PCI_SUBSYSTEM_ID,
			     &physfn->sriov->subsystem_device);
}

int pci_iov_sysfs_link(struct pci_dev *dev,
		struct pci_dev *virtfn, int id)
{
	char buf[VIRTFN_ID_LEN];
	int rc;

	/*在dev下创建virtfn%u的link,使其指向vf*/
	sprintf(buf, "virtfn%u", id);
	rc = sysfs_create_link(&dev->dev.kobj, &virtfn->dev.kobj, buf);
	if (rc)
		goto failed;
	/*在vf设备下创建physfn,使其指向pf*/
	rc = sysfs_create_link(&virtfn->dev.kobj, &dev->dev.kobj, "physfn");
	if (rc)
		goto failed1;

	/*通知uevent*/
	kobject_uevent(&virtfn->dev.kobj, KOBJ_CHANGE);

	return 0;

failed1:
	sysfs_remove_link(&dev->dev.kobj, buf);
failed:
	return rc;
}

//添加sriov第i个虚设备
#ifdef CONFIG_PCI_MSI
static ssize_t sriov_vf_total_msix_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	u32 vf_total_msix = 0;

	device_lock(dev);
	if (!pdev->driver || !pdev->driver->sriov_get_vf_total_msix)
		goto unlock;

	vf_total_msix = pdev->driver->sriov_get_vf_total_msix(pdev);
unlock:
	device_unlock(dev);
	return sysfs_emit(buf, "%u\n", vf_total_msix);
}
static DEVICE_ATTR_RO(sriov_vf_total_msix);

static ssize_t sriov_vf_msix_count_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct pci_dev *vf_dev = to_pci_dev(dev);
	struct pci_dev *pdev = pci_physfn(vf_dev);
	int val, ret = 0;

	if (kstrtoint(buf, 0, &val) < 0)
		return -EINVAL;

	if (val < 0)
		return -EINVAL;

	device_lock(&pdev->dev);
	if (!pdev->driver || !pdev->driver->sriov_set_msix_vec_count) {
		ret = -EOPNOTSUPP;
		goto err_pdev;
	}

	device_lock(&vf_dev->dev);
	if (vf_dev->driver) {
		/*
		 * A driver is already attached to this VF and has configured
		 * itself based on the current MSI-X vector count. Changing
		 * the vector size could mess up the driver, so block it.
		 */
		ret = -EBUSY;
		goto err_dev;
	}

	ret = pdev->driver->sriov_set_msix_vec_count(vf_dev, val);

err_dev:
	device_unlock(&vf_dev->dev);
err_pdev:
	device_unlock(&pdev->dev);
	return ret ? : count;
}
static DEVICE_ATTR_WO(sriov_vf_msix_count);
#endif

static struct attribute *sriov_vf_dev_attrs[] = {
#ifdef CONFIG_PCI_MSI
	&dev_attr_sriov_vf_msix_count.attr,
#endif
	NULL,
};

static umode_t sriov_vf_attrs_are_visible(struct kobject *kobj,
					  struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct pci_dev *pdev = to_pci_dev(dev);

	if (!pdev->is_virtfn)
		return 0;

	return a->mode;
}

const struct attribute_group sriov_vf_dev_attr_group = {
	.attrs = sriov_vf_dev_attrs,
	.is_visible = sriov_vf_attrs_are_visible,
};

/*添加编号为id的vf*/
int pci_iov_add_virtfn(struct pci_dev *dev, int id)
{
	int i;
	int rc = -ENOMEM;
	u64 size;
	struct pci_dev *virtfn;
	struct resource *res;
	struct pci_sriov *iov = dev->sriov;
	struct pci_bus *bus;

	/*尝试添加id号vf对应的bus*/
	bus = virtfn_add_bus(dev->bus, pci_iov_virtfn_bus(dev, id));
	if (!bus)
		goto failed;

	virtfn = pci_alloc_dev(bus);
	if (!virtfn)
		goto failed0;

	virtfn->devfn = pci_iov_virtfn_devfn(dev, id);
	virtfn->vendor = dev->vendor;
	virtfn->device = iov->vf_device;
	virtfn->is_virtfn = 1;
	virtfn->physfn = pci_dev_get(dev);
	virtfn->no_command_memory = 1;

	if (id == 0)
		pci_read_vf_config_common(virtfn);

	rc = pci_setup_device(virtfn);
	if (rc)
		goto failed1;

	virtfn->dev.parent = dev->dev.parent;
	virtfn->multifunction = 0;

	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		res = &dev->resource[i + PCI_IOV_RESOURCES];
		if (!res->parent)
			continue;
		virtfn->resource[i].name = pci_name(virtfn);
		virtfn->resource[i].flags = res->flags;
		size = pci_iov_resource_size(dev, i + PCI_IOV_RESOURCES);
		virtfn->resource[i].start = res->start + size * id;
		virtfn->resource[i].end = virtfn->resource[i].start + size - 1;
		rc = request_resource(res, &virtfn->resource[i]);
		BUG_ON(rc);
	}

	pci_device_add(virtfn, virtfn->bus);
	/*创建physfn及virtfn%u两个link,使其分别指向vf的pf,pf的第id个vf*/
	rc = pci_iov_sysfs_link(dev, virtfn, id);
	if (rc)
		goto failed1;

	//将虚拟出来的sriov设备添加到pci bus上,促使设备查找驱动
	pci_bus_add_device(virtfn);

	return 0;

failed1:
	pci_stop_and_remove_bus_device(virtfn);
	pci_dev_put(dev);
failed0:
	virtfn_remove_bus(dev->bus, bus);
failed:

	return rc;
}

void pci_iov_remove_virtfn(struct pci_dev *dev, int id)
{
	char buf[VIRTFN_ID_LEN];
	struct pci_dev *virtfn;

	virtfn = pci_get_domain_bus_and_slot(pci_domain_nr(dev->bus),
					     pci_iov_virtfn_bus(dev, id),
					     pci_iov_virtfn_devfn(dev, id));
	if (!virtfn)
		return;

	sprintf(buf, "virtfn%u", id);
	sysfs_remove_link(&dev->dev.kobj, buf);
	/*
	 * pci_stop_dev() could have been called for this virtfn already,
	 * so the directory for the virtfn may have been removed before.
	 * Double check to avoid spurious sysfs warnings.
	 */
	if (virtfn->dev.kobj.sd)
		sysfs_remove_link(&virtfn->dev.kobj, "physfn");

	pci_stop_and_remove_bus_device(virtfn);
	virtfn_remove_bus(dev->bus, virtfn->bus);

	/* balance pci_get_domain_bus_and_slot() */
	pci_dev_put(virtfn);
	pci_dev_put(dev);
}

//显示sriov设备vf总数的显示
static ssize_t sriov_totalvfs_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sysfs_emit(buf, "%u\n", pci_sriov_get_totalvfs(pdev));
}

//显示sriov设备生效vf总数显示
static ssize_t sriov_numvfs_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	u16 num_vfs;

	/* Serialize vs sriov_numvfs_store() so readers see valid num_VFs */
	device_lock(&pdev->dev);
	num_vfs = pdev->sriov->num_VFs;
	device_unlock(&pdev->dev);

	return sysfs_emit(buf, "%u\n", num_vfs);
}

/*
 * num_vfs > 0; number of VFs to enable
 * num_vfs = 0; disable all VFs
 *
 * Note: SRIOV spec does not allow partial VF
 *	 disable, so it's all or none.
 */
//用户写入numvfs,要求创建指定数量vf
static ssize_t sriov_numvfs_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int ret = 0;
	u16 num_vfs;

	//获得用户录入的值
	if (kstrtou16(buf, 0, &num_vfs) < 0)
		return -EINVAL;

	//检查是否超过接口限制
	if (num_vfs > pci_sriov_get_totalvfs(pdev))
		return -ERANGE;

	device_lock(&pdev->dev);

	//vf数量未变化，退出
	if (num_vfs == pdev->sriov->num_VFs)
		goto exit;

	/* is PF driver loaded */
	if (!pdev->driver) {
		pci_info(pdev, "no driver bound to device; cannot configure SR-IOV\n");
		ret = -ENOENT;
		goto exit;
	}

	/* is PF driver loaded w/callback */
	//未找到要应的setup回调
	if (!pdev->driver->sriov_configure) {
		pci_info(pdev, "driver does not support SR-IOV configuration via sysfs\n");
		ret = -ENOENT;
		goto exit;
	}

	//关闭所有vf
	if (num_vfs == 0) {
		/* disable VFs */
		ret = pdev->driver->sriov_configure(pdev, 0);
		goto exit;
	}

	/* enable VFs */
	//之前已开始了vf,再设置需要先关闭再开启
	if (pdev->sriov->num_VFs) {
		pci_warn(pdev, "%d VFs already enabled. Disable before enabling %d VFs\n",
			 pdev->sriov->num_VFs, num_vfs);
		ret = -EBUSY;
		goto exit;
	}

	//通过回调使能sriov，返回启动的vf数目
	ret = pdev->driver->sriov_configure(pdev, num_vfs);
	if (ret < 0)
		goto exit;

	//未按要求全部开启
	if (ret != num_vfs)
		pci_warn(pdev, "%d VFs requested; only %d enabled\n",
			 num_vfs, ret);

exit:
	device_unlock(&pdev->dev);

	if (ret < 0)
		return ret;

	return count;
}

static ssize_t sriov_offset_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sysfs_emit(buf, "%u\n", pdev->sriov->offset);
}

static ssize_t sriov_stride_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sysfs_emit(buf, "%u\n", pdev->sriov->stride);
}

static ssize_t sriov_vf_device_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sysfs_emit(buf, "%x\n", pdev->sriov->vf_device);
}

static ssize_t sriov_drivers_autoprobe_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	return sysfs_emit(buf, "%u\n", pdev->sriov->drivers_autoprobe);
}

static ssize_t sriov_drivers_autoprobe_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	bool drivers_autoprobe;

	if (kstrtobool(buf, &drivers_autoprobe) < 0)
		return -EINVAL;

	pdev->sriov->drivers_autoprobe = drivers_autoprobe;

	return count;
}

//设置sriov vf总数量的读取
static DEVICE_ATTR_RO(sriov_totalvfs);
//提供sriov vf生效数量的设置/读取
static DEVICE_ATTR_RW(sriov_numvfs);
static DEVICE_ATTR_RO(sriov_offset);
static DEVICE_ATTR_RO(sriov_stride);
static DEVICE_ATTR_RO(sriov_vf_device);
static DEVICE_ATTR_RW(sriov_drivers_autoprobe);

static struct attribute *sriov_pf_dev_attrs[] = {
	&dev_attr_sriov_totalvfs.attr,
	&dev_attr_sriov_numvfs.attr,
	&dev_attr_sriov_offset.attr,
	&dev_attr_sriov_stride.attr,
	&dev_attr_sriov_vf_device.attr,
	&dev_attr_sriov_drivers_autoprobe.attr,
#ifdef CONFIG_PCI_MSI
	&dev_attr_sriov_vf_total_msix.attr,
#endif
	NULL,
};

static umode_t sriov_pf_attrs_are_visible(struct kobject *kobj,
					  struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);

	if (!dev_is_pf(dev))
		return 0;

	return a->mode;
}

const struct attribute_group sriov_pf_dev_attr_group = {
	.attrs = sriov_pf_dev_attrs,
	.is_visible = sriov_pf_attrs_are_visible,
};

int __weak pcibios_sriov_enable(struct pci_dev *pdev, u16 num_vfs)
{
	return 0;
}

int __weak pcibios_sriov_disable(struct pci_dev *pdev)
{
	return 0;
}

static int sriov_add_vfs(struct pci_dev *dev, u16 num_vfs)
{
	unsigned int i;
	int rc;

	if (dev->no_vf_scan)
		return 0;

	/*添加num_vfs个vf*/
	for (i = 0; i < num_vfs; i++) {
		rc = pci_iov_add_virtfn(dev, i);
		if (rc)
			goto failed;
	}
	return 0;
failed:
	while (i--)
		pci_iov_remove_virtfn(dev, i);

	return rc;
}

static int sriov_enable(struct pci_dev *dev, int nr_virtfn/*要开启的vf数量*/)
{
	int rc;
	int i;
	int nres;
	u16 initial;
	struct resource *res;
	struct pci_dev *pdev;
	struct pci_sriov *iov = dev->sriov;
	int bars = 0;
	int bus;

	if (!nr_virtfn)
		return 0;

	if (iov->num_VFs)
		return -EINVAL;

	//当前有多少个虚设备
	pci_read_config_word(dev, iov->pos + PCI_SRIOV_INITIAL_VF, &initial);
	if (initial > iov->total_VFs ||
	    (!(iov->cap & PCI_SRIOV_CAP_VFM) && (initial != iov->total_VFs)))
		return -EIO;

	if (nr_virtfn < 0 || nr_virtfn > iov->total_VFs ||
	    (!(iov->cap & PCI_SRIOV_CAP_VFM) && (nr_virtfn > initial)))
	    /*要求的数量小于0，或者大于total,或者不支持sriov或者大于当前的initial,报错*/
		return -EINVAL;

	nres = 0;
	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		bars |= (1 << (i + PCI_IOV_RESOURCES));
		res = &dev->resource[i + PCI_IOV_RESOURCES];
		if (res->parent)
			nres++;
	}
	if (nres != iov->nres) {
		pci_err(dev, "not enough MMIO resources for SR-IOV\n");
		return -ENOMEM;
	}

	/*取最后一个vf对应的bus号*/
	bus = pci_iov_virtfn_bus(dev, nr_virtfn - 1);
	if (bus > dev->bus->busn_res.end) {
	    /*如果最后一个bus的资源大于dev->bus能提供的，则报错*/
		pci_err(dev, "can't enable %d VFs (bus %02x out of range of %pR)\n",
			nr_virtfn, bus, &dev->bus->busn_res);
		return -ENOMEM;
	}

	if (pci_enable_resources(dev, bars)) {
		pci_err(dev, "SR-IOV: IOV BARS not allocated\n");
		return -ENOMEM;
	}

	if (iov->link != dev->devfn) {
		pdev = pci_get_slot(dev->bus, iov->link);
		if (!pdev)
			return -ENODEV;

		if (!pdev->is_physfn) {
			pci_dev_put(pdev);
			return -ENOSYS;
		}

		rc = sysfs_create_link(&dev->dev.kobj,
					&pdev->dev.kobj, "dep_link");
		pci_dev_put(pdev);
		if (rc)
			return rc;
	}

	iov->initial_VFs = initial;
	if (nr_virtfn < initial)
		initial = nr_virtfn;

	rc = pcibios_sriov_enable(dev, initial);
	if (rc) {
		pci_err(dev, "failure %d from pcibios_sriov_enable()\n", rc);
		goto err_pcibios;
	}

	pci_iov_set_numvfs(dev, nr_virtfn);
	iov->ctrl |= PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE;
	pci_cfg_access_lock(dev);
	pci_write_config_word(dev, iov->pos + PCI_SRIOV_CTRL, iov->ctrl);
	msleep(100);
	pci_cfg_access_unlock(dev);

	//添加initial个sriov的vf设备
	rc = sriov_add_vfs(dev, initial);
	if (rc)
		goto err_pcibios;

	kobject_uevent(&dev->dev.kobj, KOBJ_CHANGE);
	iov->num_VFs = nr_virtfn;

	return 0;

err_pcibios:
	iov->ctrl &= ~(PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE);
	pci_cfg_access_lock(dev);
	pci_write_config_word(dev, iov->pos + PCI_SRIOV_CTRL, iov->ctrl);
	ssleep(1);
	pci_cfg_access_unlock(dev);

	pcibios_sriov_disable(dev);

	if (iov->link != dev->devfn)
		sysfs_remove_link(&dev->dev.kobj, "dep_link");

	pci_iov_set_numvfs(dev, 0);
	return rc;
}

static void sriov_del_vfs(struct pci_dev *dev)
{
	struct pci_sriov *iov = dev->sriov;
	int i;

	for (i = 0; i < iov->num_VFs; i++)
		pci_iov_remove_virtfn(dev, i);
}

static void sriov_disable(struct pci_dev *dev)
{
	struct pci_sriov *iov = dev->sriov;

	if (!iov->num_VFs)
		return;

	sriov_del_vfs(dev);
	iov->ctrl &= ~(PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE);
	pci_cfg_access_lock(dev);
	pci_write_config_word(dev, iov->pos + PCI_SRIOV_CTRL, iov->ctrl);
	ssleep(1);
	pci_cfg_access_unlock(dev);

	pcibios_sriov_disable(dev);

	if (iov->link != dev->devfn)
		sysfs_remove_link(&dev->dev.kobj, "dep_link");

	iov->num_VFs = 0;
	pci_iov_set_numvfs(dev, 0);
}

static int sriov_init(struct pci_dev *dev, int pos)
{
	int i, bar64;
	int rc;
	int nres;
	u32 pgsz;
	u16 ctrl, total;
	struct pci_sriov *iov;
	struct resource *res;
	const char *res_name;
	struct pci_dev *pdev;

	pci_read_config_word(dev, pos + PCI_SRIOV_CTRL, &ctrl);
	if (ctrl & PCI_SRIOV_CTRL_VFE) {
		pci_write_config_word(dev, pos + PCI_SRIOV_CTRL, 0);
		ssleep(1);
	}

	ctrl = 0;
	list_for_each_entry(pdev, &dev->bus->devices, bus_list)
		if (pdev->is_physfn)
			goto found;

	pdev = NULL;
	if (pci_ari_enabled(dev->bus))
		ctrl |= PCI_SRIOV_CTRL_ARI;

found:
	pci_write_config_word(dev, pos + PCI_SRIOV_CTRL, ctrl);

	//通过pci读取sriov的total_vf总数
	pci_read_config_word(dev, pos + PCI_SRIOV_TOTAL_VF, &total);
	if (!total)
		return 0;

	pci_read_config_dword(dev, pos + PCI_SRIOV_SUP_PGSIZE, &pgsz);
	i = PAGE_SHIFT > 12 ? PAGE_SHIFT - 12 : 0;
	pgsz &= ~((1 << i) - 1);
	if (!pgsz)
		return -EIO;

	pgsz &= ~(pgsz - 1);
	pci_write_config_dword(dev, pos + PCI_SRIOV_SYS_PGSIZE, pgsz);

	iov = kzalloc(sizeof(*iov), GFP_KERNEL);
	if (!iov)
		return -ENOMEM;

	nres = 0;
	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		res = &dev->resource[i + PCI_IOV_RESOURCES];
		res_name = pci_resource_name(dev, i + PCI_IOV_RESOURCES);

		/*
		 * If it is already FIXED, don't change it, something
		 * (perhaps EA or header fixups) wants it this way.
		 */
		if (res->flags & IORESOURCE_PCI_FIXED)
			bar64 = (res->flags & IORESOURCE_MEM_64) ? 1 : 0;
		else
			bar64 = __pci_read_base(dev, pci_bar_unknown, res,
						pos + PCI_SRIOV_BAR + i * 4);
		if (!res->flags)
			continue;
		if (resource_size(res) & (PAGE_SIZE - 1)) {
			rc = -EIO;
			goto failed;
		}
		iov->barsz[i] = resource_size(res);
		res->end = res->start + resource_size(res) * total - 1;
		pci_info(dev, "%s %pR: contains BAR %d for %d VFs\n",
			 res_name, res, i, total);
		i += bar64;
		nres++;
	}

	iov->pos = pos;
	iov->nres = nres;
	iov->ctrl = ctrl;
	iov->total_VFs = total;
	/*设置最大支持的vf数量*/
	iov->driver_max_VFs = total;/*设置设备的最大VFS*/
	pci_read_config_word(dev, pos + PCI_SRIOV_VF_DID, &iov->vf_device);
	iov->pgsz = pgsz;
	iov->self = dev;
	iov->drivers_autoprobe = true;
	pci_read_config_dword(dev, pos + PCI_SRIOV_CAP, &iov->cap);
	pci_read_config_byte(dev, pos + PCI_SRIOV_FUNC_LINK, &iov->link);
	if (pci_pcie_type(dev) == PCI_EXP_TYPE_RC_END)
		iov->link = PCI_DEVFN(PCI_SLOT(dev->devfn), iov->link);

	if (pdev)
		iov->dev = pci_dev_get(pdev);
	else
		iov->dev = dev;

	dev->sriov = iov;
	dev->is_physfn = 1;/*指明此dev为pf*/
	rc = compute_max_vf_buses(dev);
	if (rc)
		goto fail_max_buses;

	return 0;

fail_max_buses:
	dev->sriov = NULL;
	dev->is_physfn = 0;/*指明此设备非pf*/
failed:
	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++) {
		res = &dev->resource[i + PCI_IOV_RESOURCES];
		res->flags = 0;
	}

	kfree(iov);
	return rc;
}

static void sriov_release(struct pci_dev *dev)
{
	BUG_ON(dev->sriov->num_VFs);

	if (dev != dev->sriov->dev)
		pci_dev_put(dev->sriov->dev);

	kfree(dev->sriov);
	dev->sriov = NULL;
}

static void sriov_restore_state(struct pci_dev *dev)
{
	int i;
	u16 ctrl;
	struct pci_sriov *iov = dev->sriov;

	pci_read_config_word(dev, iov->pos + PCI_SRIOV_CTRL, &ctrl);
	if (ctrl & PCI_SRIOV_CTRL_VFE)
		return;

	/*
	 * Restore PCI_SRIOV_CTRL_ARI before pci_iov_set_numvfs() because
	 * it reads offset & stride, which depend on PCI_SRIOV_CTRL_ARI.
	 */
	ctrl &= ~PCI_SRIOV_CTRL_ARI;
	ctrl |= iov->ctrl & PCI_SRIOV_CTRL_ARI;
	pci_write_config_word(dev, iov->pos + PCI_SRIOV_CTRL, ctrl);

	for (i = 0; i < PCI_SRIOV_NUM_BARS; i++)
		pci_update_resource(dev, i + PCI_IOV_RESOURCES);

	pci_write_config_dword(dev, iov->pos + PCI_SRIOV_SYS_PGSIZE, iov->pgsz);
	pci_iov_set_numvfs(dev, iov->num_VFs);
	pci_write_config_word(dev, iov->pos + PCI_SRIOV_CTRL, iov->ctrl);
	if (iov->ctrl & PCI_SRIOV_CTRL_VFE)
		msleep(100);
}

/**
 * pci_iov_init - initialize the IOV capability
 * @dev: the PCI device
 *
 * Returns 0 on success, or negative on failure.
 */
int pci_iov_init(struct pci_dev *dev)
{
	int pos;

	if (!pci_is_pcie(dev))
		return -ENODEV;

	//网卡有sriov能力，则初始化sriov
	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (pos)
		return sriov_init(dev, pos);

	return -ENODEV;
}

/**
 * pci_iov_release - release resources used by the IOV capability
 * @dev: the PCI device
 */
void pci_iov_release(struct pci_dev *dev)
{
	if (dev->is_physfn)
		sriov_release(dev);
}

/**
 * pci_iov_remove - clean up SR-IOV state after PF driver is detached
 * @dev: the PCI device
 */
void pci_iov_remove(struct pci_dev *dev)
{
	struct pci_sriov *iov = dev->sriov;

	if (!dev->is_physfn)
		return;

	iov->driver_max_VFs = iov->total_VFs;
	if (iov->num_VFs)
		pci_warn(dev, "driver left SR-IOV enabled after remove\n");
}

/**
 * pci_iov_update_resource - update a VF BAR
 * @dev: the PCI device
 * @resno: the resource number
 *
 * Update a VF BAR in the SR-IOV capability of a PF.
 */
void pci_iov_update_resource(struct pci_dev *dev, int resno)
{
	struct pci_sriov *iov = dev->is_physfn ? dev->sriov : NULL;
	struct resource *res = dev->resource + resno;
	int vf_bar = resno - PCI_IOV_RESOURCES;
	struct pci_bus_region region;
	u16 cmd;
	u32 new;
	int reg;

	/*
	 * The generic pci_restore_bars() path calls this for all devices,
	 * including VFs and non-SR-IOV devices.  If this is not a PF, we
	 * have nothing to do.
	 */
	if (!iov)
		return;

	pci_read_config_word(dev, iov->pos + PCI_SRIOV_CTRL, &cmd);
	if ((cmd & PCI_SRIOV_CTRL_VFE) && (cmd & PCI_SRIOV_CTRL_MSE)) {
		dev_WARN(&dev->dev, "can't update enabled VF BAR%d %pR\n",
			 vf_bar, res);
		return;
	}

	/*
	 * Ignore unimplemented BARs, unused resource slots for 64-bit
	 * BARs, and non-movable resources, e.g., those described via
	 * Enhanced Allocation.
	 */
	if (!res->flags)
		return;

	if (res->flags & IORESOURCE_UNSET)
		return;

	if (res->flags & IORESOURCE_PCI_FIXED)
		return;

	pcibios_resource_to_bus(dev->bus, &region, res);
	new = region.start;
	new |= res->flags & ~PCI_BASE_ADDRESS_MEM_MASK;

	reg = iov->pos + PCI_SRIOV_BAR + 4 * vf_bar;
	pci_write_config_dword(dev, reg, new);
	if (res->flags & IORESOURCE_MEM_64) {
		new = region.start >> 16 >> 16;
		pci_write_config_dword(dev, reg + 4, new);
	}
}

resource_size_t __weak pcibios_iov_resource_alignment(struct pci_dev *dev,
						      int resno)
{
	return pci_iov_resource_size(dev, resno);
}

/**
 * pci_sriov_resource_alignment - get resource alignment for VF BAR
 * @dev: the PCI device
 * @resno: the resource number
 *
 * Returns the alignment of the VF BAR found in the SR-IOV capability.
 * This is not the same as the resource size which is defined as
 * the VF BAR size multiplied by the number of VFs.  The alignment
 * is just the VF BAR size.
 */
resource_size_t pci_sriov_resource_alignment(struct pci_dev *dev, int resno)
{
	return pcibios_iov_resource_alignment(dev, resno);
}

/**
 * pci_restore_iov_state - restore the state of the IOV capability
 * @dev: the PCI device
 */
void pci_restore_iov_state(struct pci_dev *dev)
{
	if (dev->is_physfn)
		sriov_restore_state(dev);
}

/**
 * pci_vf_drivers_autoprobe - set PF property drivers_autoprobe for VFs
 * @dev: the PCI device
 * @auto_probe: set VF drivers auto probe flag
 */
void pci_vf_drivers_autoprobe(struct pci_dev *dev, bool auto_probe)
{
	if (dev->is_physfn)
		dev->sriov->drivers_autoprobe = auto_probe;
}

/**
 * pci_iov_bus_range - find bus range used by Virtual Function
 * @bus: the PCI bus
 *
 * Returns max number of buses (exclude current one) used by Virtual
 * Functions.
 */
int pci_iov_bus_range(struct pci_bus *bus)
{
	int max = 0;
	struct pci_dev *dev;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		if (!dev->is_physfn)
			continue;
		if (dev->sriov->max_VF_buses > max)
			max = dev->sriov->max_VF_buses;
	}

	return max ? max - bus->number : 0;
}

/**
 * pci_enable_sriov - enable the SR-IOV capability
 * @dev: the PCI device
 * @nr_virtfn: number of virtual functions to enable
 *
 * Returns 0 on success, or negative on failure.
 */
int pci_enable_sriov(struct pci_dev *dev, int nr_virtfn/*要开启的vf数量*/)
{
	might_sleep();

	if (!dev->is_physfn)
		return -ENOSYS;

	return sriov_enable(dev, nr_virtfn);
}
EXPORT_SYMBOL_GPL(pci_enable_sriov);

/**
 * pci_disable_sriov - disable the SR-IOV capability
 * @dev: the PCI device
 */
void pci_disable_sriov(struct pci_dev *dev)
{
	might_sleep();

	if (!dev->is_physfn)
		return;

	sriov_disable(dev);
}
EXPORT_SYMBOL_GPL(pci_disable_sriov);

/**
 * pci_num_vf - return number of VFs associated with a PF device_release_driver
 * @dev: the PCI device
 *
 * Returns number of VFs, or 0 if SR-IOV is not enabled.
 */
int pci_num_vf(struct pci_dev *dev)
{
	if (!dev->is_physfn)
		return 0;

	return dev->sriov->num_VFs;/*此设备vf数目*/
}
EXPORT_SYMBOL_GPL(pci_num_vf);

/**
 * pci_vfs_assigned - returns number of VFs are assigned to a guest
 * @dev: the PCI device
 *
 * Returns number of VFs belonging to this device that are assigned to a guest.
 * If device is not a physical function returns 0.
 */
int pci_vfs_assigned(struct pci_dev *dev)
{
	struct pci_dev *vfdev;
	unsigned int vfs_assigned = 0;
	unsigned short dev_id;

	/* only search if we are a PF */
	if (!dev->is_physfn)
		return 0;

	/*
	 * determine the device ID for the VFs, the vendor ID will be the
	 * same as the PF so there is no need to check for that one
	 */
	dev_id = dev->sriov->vf_device;

	/* loop through all the VFs to see if we own any that are assigned */
	vfdev = pci_get_device(dev->vendor, dev_id, NULL);
	while (vfdev) {
		/*
		 * It is considered assigned if it is a virtual function with
		 * our dev as the physical function and the assigned bit is set
		 */
		if (vfdev->is_virtfn && (vfdev->physfn == dev) &&
			pci_is_dev_assigned(vfdev))
			vfs_assigned++;

		vfdev = pci_get_device(dev->vendor, dev_id, vfdev);
	}

	return vfs_assigned;
}
EXPORT_SYMBOL_GPL(pci_vfs_assigned);

/**
 * pci_sriov_set_totalvfs -- reduce the TotalVFs available
 * @dev: the PCI PF device
 * @numvfs: number that should be used for TotalVFs supported
 *
 * Should be called from PF driver's probe routine with
 * device's mutex held.
 *
 * Returns 0 if PF is an SRIOV-capable device and
 * value of numvfs valid. If not a PF return -ENOSYS;
 * if numvfs is invalid return -EINVAL;
 * if VFs already enabled, return -EBUSY.
 */
int pci_sriov_set_totalvfs(struct pci_dev *dev, u16 numvfs)
{
    //仅容许物理设备设置最大vf数目
	if (!dev->is_physfn)
		return -ENOSYS;

	//设置的vf数量不得大于total_VFS
	if (numvfs > dev->sriov->total_VFs)
		return -EINVAL;

	/* Shouldn't change if VFs already enabled */
	if (dev->sriov->ctrl & PCI_SRIOV_CTRL_VFE)
		return -EBUSY;

	/*设置当前driver支持的最大vf数量*/
	dev->sriov->driver_max_VFs = numvfs;
	return 0;
}
EXPORT_SYMBOL_GPL(pci_sriov_set_totalvfs);

/**
 * pci_sriov_get_totalvfs -- get total VFs supported on this device
 * @dev: the PCI PF device
 *
 * For a PCIe device with SRIOV support, return the PCIe
 * SRIOV capability value of TotalVFs or the value of driver_max_VFs
 * if the driver reduced it.  Otherwise 0.
 */
int pci_sriov_get_totalvfs(struct pci_dev *dev)
{
	//仅pf支持sriov方式
	if (!dev->is_physfn)
		return 0;

	//返回支持的最大vf
	return dev->sriov->driver_max_VFs;
}
EXPORT_SYMBOL_GPL(pci_sriov_get_totalvfs);

/**
 * pci_sriov_configure_simple - helper to configure SR-IOV
 * @dev: the PCI device
 * @nr_virtfn: number of virtual functions to enable, 0 to disable
 *
 * Enable or disable SR-IOV for devices that don't require any PF setup
 * before enabling SR-IOV.  Return value is negative on error, or number of
 * VFs allocated on success.
 */
int pci_sriov_configure_simple(struct pci_dev *dev, int nr_virtfn)
{
	int rc;

	might_sleep();

	if (!dev->is_physfn)
		return -ENODEV;

	if (pci_vfs_assigned(dev)) {
		pci_warn(dev, "Cannot modify SR-IOV while VFs are assigned\n");
		return -EPERM;
	}

	if (nr_virtfn == 0) {
		sriov_disable(dev);
		return 0;
	}

	rc = sriov_enable(dev, nr_virtfn);
	if (rc < 0)
		return rc;

	return nr_virtfn;
}
EXPORT_SYMBOL_GPL(pci_sriov_configure_simple);
