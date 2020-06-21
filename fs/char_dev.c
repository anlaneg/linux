// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/char_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
#include <linux/tty.h>

#include "internal.h"

static struct kobj_map *cdev_map;

static DEFINE_MUTEX(chrdevs_lock);

#define CHRDEV_MAJOR_HASH_SIZE 255

static struct char_device_struct {
    //用于串连位于同一个index中的其它字符设备
	struct char_device_struct *next;
	//char设置的major编号
	unsigned int major;
	unsigned int baseminor;
	int minorct;
	//char设备名称
	char name[64];
	//对应的字符设备
	struct cdev *cdev;		/* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];
//*chardevs用于保存系统中所有char设备，在chardevs中存放时，采用major_to_index定位到具体
//的桶，然后按照baseminor进行排序，支持baseminor，minorct合起来指定多个char设备，故在插入时
//需要检查(baseminor,baseminor+minorct)集合间是否有重叠，如果无重叠，则会按升序均放在冲突链上

/* index in the above */
static inline int major_to_index(unsigned major)
{
	return major % CHRDEV_MAJOR_HASH_SIZE;
}

#ifdef CONFIG_PROC_FS

//用于显示所有字符设备
void chrdev_show(struct seq_file *f, off_t offset)
{
	struct char_device_struct *cd;

	mutex_lock(&chrdevs_lock);
	for (cd = chrdevs[major_to_index(offset)]; cd; cd = cd->next) {
		if (cd->major == offset)
			seq_printf(f, "%3d %s\n", cd->major, cd->name);
	}
	mutex_unlock(&chrdevs_lock);
}

#endif /* CONFIG_PROC_FS */

//获取空闲的major
//优先占用234-255之间的chardev,如果这段空间被用，则采用hash方式在0-255之间
//在冲突链上进行查找（分配的id号是从384到511之间）
static int find_dynamic_major(void)
{
	int i;
	struct char_device_struct *cd;

	//检查chrdevs中是否存在空的设备位置（234到255之间，采用数组方式存储）
	for (i = ARRAY_SIZE(chrdevs)-1; i >= CHRDEV_MAJOR_DYN_END; i--) {
		if (chrdevs[i] == NULL)
			return i;
	}

	//384到511之间的为动态扩展，此时采用hash链方式存储
	for (i = CHRDEV_MAJOR_DYN_EXT_START;
	     i >= CHRDEV_MAJOR_DYN_EXT_END; i--) {
		//0-255之间采用的是链式存储
		for (cd = chrdevs[major_to_index(i)]; cd; cd = cd->next)
			if (cd->major == i)
				break;//如果major相同，则跳出

		//查找到了可用的chardev
		if (cd == NULL)
			return i;
	}

	return -EBUSY;
}

/*
 * Register a single major with a specified minor range.
 *
 * If major == 0 this function will dynamically allocate an unused major.
 * If major > 0 this function will attempt to reserve the range of minors
 * with given major.
 *
 */
//申请minorct个major的字符设备，同时占用[baseminor,baseminor+minor)之间的minor
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
			   int minorct, const char *name)
{
	struct char_device_struct *cd, *curr, *prev = NULL;
	int ret;
	int i;

	if (major >= CHRDEV_MAJOR_MAX) {
		pr_err("CHRDEV \"%s\" major requested (%u) is greater than the maximum (%u)\n",
		       name, major, CHRDEV_MAJOR_MAX-1);
		return ERR_PTR(-EINVAL);
	}

	if (minorct > MINORMASK + 1 - baseminor) {
		pr_err("CHRDEV \"%s\" minor range requested (%u-%u) is out of range of maximum range (%u-%u) for a single major\n",
			name, baseminor, baseminor + minorct - 1, 0, MINORMASK);
		return ERR_PTR(-EINVAL);
	}

	//为char设备申请内存
	cd = kzalloc(sizeof(struct char_device_struct), GFP_KERNEL);
	if (cd == NULL)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&chrdevs_lock);

	//如果major为0，则选用动态的major
	if (major == 0) {
		ret = find_dynamic_major();
		if (ret < 0) {
			//动态申请的dynamic均已用完，返回失败
			pr_err("CHRDEV \"%s\" dynamic allocation region is full\n",
			       name);
			goto out;
		}
		//为其申请一个major
		major = ret;
	}

	ret = -EBUSY;
	//计算hash
	i = major_to_index(major);
	//准备将curr存放入chrdevs中（采用hash方式存放）
	for (curr = chrdevs[i]; curr; prev = curr, curr = curr->next) {
		//按major进行排序，如果major相等，按baseminor进行排序
		//如果baseminor小于我们，则检查baseminor＋minorct是否大于我们的baseminor
		//如果大于我们的baseminor，则我们需要排在其前面(此时不是重叠的吗？后面针对这种报错)
		if (curr->major < major)
			continue;

		if (curr->major > major)
			break;

		//检查是否发生了范围重叠，如果有重叠，则报错
		//cp->baseminor+cp->minorct　不能与我们的baseminor＋minorct重复
		if (curr->baseminor + curr->minorct <= baseminor)
			continue;

		if (curr->baseminor >= baseminor + minorct)
			break;

		goto out;
	}

	cd->major = major;
	cd->baseminor = baseminor;
	cd->minorct = minorct;
	strlcpy(cd->name, name, sizeof(cd->name));

	if (!prev) {
		cd->next = curr;
		chrdevs[i] = cd;
	} else {
		cd->next = prev->next;
		prev->next = cd;
	}

	mutex_unlock(&chrdevs_lock);
	return cd;
out:
	mutex_unlock(&chrdevs_lock);
	kfree(cd);
	return ERR_PTR(ret);
}

//归还major,返回其对应的char_dev
static struct char_device_struct *
__unregister_chrdev_region(unsigned major, unsigned baseminor, int minorct)
{
	struct char_device_struct *cd = NULL, **cp;
	int i = major_to_index(major);

	mutex_lock(&chrdevs_lock);
	//查找对应的cp
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major == major &&
		    (*cp)->baseminor == baseminor &&
		    (*cp)->minorct == minorct)
			break;
	if (*cp) {
	    //有对应的cp,设置cd(准备返回）
		cd = *cp;
		//将此元素移除
		*cp = cd->next;
	}
	mutex_unlock(&chrdevs_lock);
	return cd;//返回对应的cd
}

/**
 * register_chrdev_region() - register a range of device numbers
 * @from: the first in the desired range of device numbers; must include
 *        the major number.
 * @count: the number of consecutive device numbers required
 * @name: the name of the device or driver.
 *
 * Return value is zero on success, a negative error code on failure.
 */
//注册一组chardev设备号(静态注册)
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
	struct char_device_struct *cd;
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		cd = __register_chrdev_region(MAJOR(n), MINOR(n),
			       next - n, name);
		if (IS_ERR(cd))
			goto fail;
	}
	return 0;
fail:
    //注册失败，还原已成功的注册
	to = n;
	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
	return PTR_ERR(cd);
}

/**
 * alloc_chrdev_region() - register a range of char device numbers
 * @dev: output parameter for first assigned number
 * @baseminor: first of the requested range of minor numbers
 * @count: the number of minor numbers required
 * @name: the name of the associated device or driver
 *
 * Allocates a range of char device numbers.  The major number will be
 * chosen dynamically, and returned (along with the first minor number)
 * in @dev.  Returns zero or a negative error code.
 */
//申请一组（count个）char设备，major动态申请，minor占用[baseminor,baseminor+count)
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{
	//注册char设备(明确传入的major＝0，即major采用动态申请，自baseminor开始，占用count个），并设置dev_t
	struct char_device_struct *cd;
	cd = __register_chrdev_region(0, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	//构造dev_t
	*dev = MKDEV(cd->major, cd->baseminor);
	return 0;
}

/**
 * __register_chrdev() - create and register a cdev occupying a range of minors
 * @major: major device number or 0 for dynamic allocation
 * @baseminor: first of the requested range of minor numbers
 * @count: the number of minor numbers required
 * @name: name of this range of devices
 * @fops: file operations associated with this devices
 *
 * If @major == 0 this functions will dynamically allocate a major and return
 * its number.
 *
 * If @major > 0 this function will attempt to reserve a device with the given
 * major number and will return zero on success.
 *
 * Returns a -ve errno on failure.
 *
 * The name of this device has nothing to do with the name of the device in
 * /dev. It only helps to keep track of the different owners of devices. If
 * your module name has only one type of devices it's ok to use e.g. the name
 * of the module here.
 */
//申请count个name字符设备，并字符设备注册对应的fops
int __register_chrdev(unsigned int major, unsigned int baseminor,
		      unsigned int count, const char *name,
		      const struct file_operations *fops)
{
	struct char_device_struct *cd;
	struct cdev *cdev;
	int err = -ENOMEM;

	//申请count个字符设备
	cd = __register_chrdev_region(major, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);

	//申请字符设备结构
	cdev = cdev_alloc();
	if (!cdev)
		goto out2;

	cdev->owner = fops->owner;
	cdev->ops = fops;
	kobject_set_name(&cdev->kobj, "%s", name);

	err = cdev_add(cdev, MKDEV(cd->major, baseminor), count);
	if (err)
		goto out;

	cd->cdev = cdev;

	return major ? 0 : cd->major;
out:
	kobject_put(&cdev->kobj);
out2:
	kfree(__unregister_chrdev_region(cd->major, baseminor, count));
	return err;
}

/**
 * unregister_chrdev_region() - unregister a range of device numbers
 * @from: the first in the range of numbers to unregister
 * @count: the number of device numbers to unregister
 *
 * This function will unregister a range of @count device numbers,
 * starting with @from.  The caller should normally be the one who
 * allocated those numbers in the first place...
 */
//解注册字符设备
void unregister_chrdev_region(dev_t from, unsigned count)
{
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
}

/**
 * __unregister_chrdev - unregister and destroy a cdev
 * @major: major device number
 * @baseminor: first of the range of minor numbers
 * @count: the number of minor numbers this cdev is occupying
 * @name: name of this range of devices
 *
 * Unregister and destroy the cdev occupying the region described by
 * @major, @baseminor and @count.  This function undoes what
 * __register_chrdev() did.
 */
//释放(major,baseminor,count）对应的字符设备
void __unregister_chrdev(unsigned int major, unsigned int baseminor,
			 unsigned int count, const char *name)
{
	struct char_device_struct *cd;

	cd = __unregister_chrdev_region(major, baseminor, count);
	if (cd && cd->cdev)
		cdev_del(cd->cdev);
	kfree(cd);
}

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
	struct module *owner = p->owner;
	struct kobject *kobj;

	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get_unless_zero(&p->kobj);
	if (!kobj)
		module_put(owner);
	return kobj;
}

void cdev_put(struct cdev *p)
{
	if (p) {
		struct module *owner = p->owner;
		kobject_put(&p->kobj);
		module_put(owner);
	}
}

/*
 * Called every time a character special file is opened
 */
//字符设备open函数（所有字符设备均自此处进入，然后查询cdev_map拿到真正的设备)
static int chrdev_open(struct inode *inode, struct file *filp)
{
	const struct file_operations *fops;
	struct cdev *p;
	struct cdev *new = NULL;
	int ret = 0;

	spin_lock(&cdev_lock);
	p = inode->i_cdev;
	if (!p) {
		//如果inode还未明确对应的cdev,则进行查找
		struct kobject *kobj;
		int idx;
		spin_unlock(&cdev_lock);
		//查找cdev_map,所有的cdev均被注册到cdev_map中，我们采用inode->i_rdev来获取字符
		//设备对应的dev_t
		kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
		if (!kobj)
			//对应的字符设备不存在
			return -ENXIO;

		//自kobj获得其对应的cdev (例如至此获得uio对应的cdev)
		new = container_of(kobj, struct cdev, kobj);
		spin_lock(&cdev_lock);
		/* Check i_cdev again in case somebody beat us to it while
		   we dropped the lock. */
		p = inode->i_cdev;
		if (!p) {
			//设置此inode对应的字符设备
			inode->i_cdev = p = new;
			list_add(&inode->i_devices, &p->list);
			new = NULL;
		} else if (!cdev_get(p))
			//如果已设置对应的cdev，则增加引用计数，如失败，则报设备不存在
			ret = -ENXIO;
	} else if (!cdev_get(p))
		ret = -ENXIO;
	spin_unlock(&cdev_lock);
	cdev_put(new);
	if (ret)
		return ret;

	ret = -ENXIO;
	//取实际操作的dev的ops
	fops = fops_get(p->ops);
	if (!fops)
		goto out_cdev_put;

	//替换filp中的fops为实际操作的dev的ops
	replace_fops(filp, fops);
	if (filp->f_op->open) {
		//有open回调时，调用open回调
		ret = filp->f_op->open(inode, filp);
		if (ret)
			goto out_cdev_put;
	}

	return 0;

 out_cdev_put:
	cdev_put(p);
	return ret;
}

void cd_forget(struct inode *inode)
{
	spin_lock(&cdev_lock);
	list_del_init(&inode->i_devices);
	inode->i_cdev = NULL;
	inode->i_mapping = &inode->i_data;
	spin_unlock(&cdev_lock);
}

static void cdev_purge(struct cdev *cdev)
{
	spin_lock(&cdev_lock);
	while (!list_empty(&cdev->list)) {
		struct inode *inode;
		inode = container_of(cdev->list.next, struct inode, i_devices);
		list_del_init(&inode->i_devices);
		inode->i_cdev = NULL;
	}
	spin_unlock(&cdev_lock);
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the special file...
 */
//字符设备的默认文件操作集
const struct file_operations def_chr_fops = {
	//所有字符设备的open入口，在此函数内部再具体分辨操作的是那个字符设备，然后替换filp的f_ops
	//并调用其对应的open函数
	.open = chrdev_open,
	.llseek = noop_llseek,
};

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
	struct cdev *p = data;
	return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
	struct cdev *p = data;
	return cdev_get(p) ? 0 : -1;
}

/**
 * cdev_add() - add a char device to the system
 * @p: the cdev structure for the device
 * @dev: the first device number for which this device is responsible
 * @count: the number of consecutive minor numbers corresponding to this
 *         device
 *
 * cdev_add() adds the device represented by @p to the system, making it
 * live immediately.  A negative error code is returned on failure.
 */
//添加cdev到cdev_map（用于保证字符设备在打开时，进入chrdev_open函数，从而进入到用户定义的ops）
int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	int error;

	p->dev = dev;
	p->count = count;

	if (WARN_ON(dev == WHITEOUT_DEV))
		return -EBUSY;

	//所有的chardev均会被加入到cdev_map中
	error = kobj_map(cdev_map, dev, count, NULL,
			 exact_match, exact_lock, p);
	if (error)
		return error;

	kobject_get(p->kobj.parent);

	return 0;
}

/**
 * cdev_set_parent() - set the parent kobject for a char device
 * @p: the cdev structure
 * @kobj: the kobject to take a reference to
 *
 * cdev_set_parent() sets a parent kobject which will be referenced
 * appropriately so the parent is not freed before the cdev. This
 * should be called before cdev_add.
 */
void cdev_set_parent(struct cdev *p, struct kobject *kobj)
{
	WARN_ON(!kobj->state_initialized);
	p->kobj.parent = kobj;
}

/**
 * cdev_device_add() - add a char device and it's corresponding
 *	struct device, linkink
 * @dev: the device structure
 * @cdev: the cdev structure
 *
 * cdev_device_add() adds the char device represented by @cdev to the system,
 * just as cdev_add does. It then adds @dev to the system using device_add
 * The dev_t for the char device will be taken from the struct device which
 * needs to be initialized first. This helper function correctly takes a
 * reference to the parent device so the parent will not get released until
 * all references to the cdev are released.
 *
 * This helper uses dev->devt for the device number. If it is not set
 * it will not add the cdev and it will be equivalent to device_add.
 *
 * This function should be used whenever the struct cdev and the
 * struct device are members of the same structure whose lifetime is
 * managed by the struct device.
 *
 * NOTE: Callers must assume that userspace was able to open the cdev and
 * can call cdev fops callbacks at any time, even if this function fails.
 */
int cdev_device_add(struct cdev *cdev, struct device *dev)
{
	int rc = 0;

	if (dev->devt) {
		cdev_set_parent(cdev, &dev->kobj);

		rc = cdev_add(cdev, dev->devt, 1);
		if (rc)
			return rc;
	}

	rc = device_add(dev);
	if (rc)
		cdev_del(cdev);

	return rc;
}

/**
 * cdev_device_del() - inverse of cdev_device_add
 * @dev: the device structure
 * @cdev: the cdev structure
 *
 * cdev_device_del() is a helper function to call cdev_del and device_del.
 * It should be used whenever cdev_device_add is used.
 *
 * If dev->devt is not set it will not remove the cdev and will be equivalent
 * to device_del.
 *
 * NOTE: This guarantees that associated sysfs callbacks are not running
 * or runnable, however any cdevs already open will remain and their fops
 * will still be callable even after this function returns.
 */
void cdev_device_del(struct cdev *cdev, struct device *dev)
{
	device_del(dev);
	if (dev->devt)
		cdev_del(cdev);
}

//移除dev
static void cdev_unmap(dev_t dev, unsigned count)
{
	kobj_unmap(cdev_map, dev, count);
}

/**
 * cdev_del() - remove a cdev from the system
 * @p: the cdev structure to be removed
 *
 * cdev_del() removes @p from the system, possibly freeing the structure
 * itself.
 *
 * NOTE: This guarantees that cdev device will no longer be able to be
 * opened, however any cdevs already open will remain and their fops will
 * still be callable even after cdev_del returns.
 */
void cdev_del(struct cdev *p)
{
	cdev_unmap(p->dev, p->count);
	kobject_put(&p->kobj);
}


static void cdev_default_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	struct kobject *parent = kobj->parent;

	cdev_purge(p);
	kobject_put(parent);
}

static void cdev_dynamic_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	struct kobject *parent = kobj->parent;

	cdev_purge(p);
	kfree(p);
	kobject_put(parent);
}

static struct kobj_type ktype_cdev_default = {
	.release	= cdev_default_release,
};

static struct kobj_type ktype_cdev_dynamic = {
	.release	= cdev_dynamic_release,
};

/**
 * cdev_alloc() - allocate a cdev structure
 *
 * Allocates and returns a cdev structure, or NULL on failure.
 */
//cdev结构申请
struct cdev *cdev_alloc(void)
{
	struct cdev *p = kzalloc(sizeof(struct cdev), GFP_KERNEL);
	if (p) {
		INIT_LIST_HEAD(&p->list);
		kobject_init(&p->kobj, &ktype_cdev_dynamic);
	}
	return p;
}

/**
 * cdev_init() - initialize a cdev structure
 * @cdev: the structure to initialize
 * @fops: the file_operations for this device
 *
 * Initializes @cdev, remembering @fops, making it ready to add to the
 * system with cdev_add().
 */
//初始化cdev,设置字符设备的文件操作符
void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
	memset(cdev, 0, sizeof *cdev);
	INIT_LIST_HEAD(&cdev->list);
	kobject_init(&cdev->kobj, &ktype_cdev_default);
	cdev->ops = fops;//设置字符设备的操作集
}

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("char-major-%d", MAJOR(dev));
	return NULL;
}

//初始化cdev_map
void __init chrdev_init(void)
{
	cdev_map = kobj_map_init(base_probe, &chrdevs_lock);
}


/* Let modules do char dev stuff */
EXPORT_SYMBOL(register_chrdev_region);
EXPORT_SYMBOL(unregister_chrdev_region);
EXPORT_SYMBOL(alloc_chrdev_region);
EXPORT_SYMBOL(cdev_init);
EXPORT_SYMBOL(cdev_alloc);
EXPORT_SYMBOL(cdev_del);
//将字符设备加入到系统
EXPORT_SYMBOL(cdev_add);
EXPORT_SYMBOL(cdev_set_parent);
EXPORT_SYMBOL(cdev_device_add);
EXPORT_SYMBOL(cdev_device_del);
EXPORT_SYMBOL(__register_chrdev);
EXPORT_SYMBOL(__unregister_chrdev);
