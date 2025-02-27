// SPDX-License-Identifier: GPL-2.0
/*
 * linux/drivers/char/misc.c
 *
 * Generic misc open routine by Johan Myreen
 *
 * Based on code from Linus
 *
 * Teemu Rantanen's Microsoft Busmouse support and Derrick Cole's
 *   changes incorporated into 0.97pl4
 *   by Peter Cervasio (pete%q106fm.uucp@wupost.wustl.edu) (08SEP92)
 *   See busmouse.c for particulars.
 *
 * Made things a lot mode modular - easy to compile in just one or two
 * of the misc drivers, as they are now completely independent. Linus.
 *
 * Support for loadable modules. 8-Sep-95 Philip Blundell <pjb27@cam.ac.uk>
 *
 * Fixed a failing symbol register to free the device registration
 *		Alan Cox <alan@lxorguk.ukuu.org.uk> 21-Jan-96
 *
 * Dynamic minors and /proc/mice by Alessandro Rubini. 26-Mar-96
 *
 * Renamed to misc and miscdevice to be more accurate. Alan Cox 26-Mar-96
 *
 * Handling of mouse minor numbers for kerneld:
 *  Idea by Jacques Gelinas <jack@solucorp.qc.ca>,
 *  adapted by Bjorn Ekwall <bj0rn@blox.se>
 *  corrected by Alan Cox <alan@lxorguk.ukuu.org.uk>
 *
 * Changes for kmod (from kerneld):
 *	Cyrus Durgin <cider@speakeasy.org>
 *
 * Added devfs support. Richard Gooch <rgooch@atnf.csiro.au>  10-Jan-1998
 */

#include <linux/module.h>

#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/tty.h>
#include <linux/kmod.h>
#include <linux/gfp.h>

/*
 * Head entry for the doubly linked miscdevice list
 */
static LIST_HEAD(misc_list);/*记录系统中所有misc设备*/
static DEFINE_MUTEX(misc_mtx);

/*
 * Assigned numbers, used for dynamic minors
 */
#define DYNAMIC_MINORS 128 /* like dynamic majors */
//记录哪些动态minors已分配（bitmap)
static DEFINE_IDA(misc_minors_ida);

/*为misc设备申请minor*/
static int misc_minor_alloc(void)
{
	int ret;

	ret = ida_alloc_max(&misc_minors_ida, DYNAMIC_MINORS - 1, GFP_KERNEL);
	if (ret >= 0) {
		ret = DYNAMIC_MINORS - ret - 1;
	} else {
		ret = ida_alloc_range(&misc_minors_ida, MISC_DYNAMIC_MINOR + 1,
				      MINORMASK, GFP_KERNEL);
	}
	return ret;
}

static void misc_minor_free(int minor)
{
	if (minor < DYNAMIC_MINORS)
		ida_free(&misc_minors_ida, DYNAMIC_MINORS - minor - 1);
	else if (minor > MISC_DYNAMIC_MINOR)
		ida_free(&misc_minors_ida, minor);
}

#ifdef CONFIG_PROC_FS
static void *misc_seq_start(struct seq_file *seq, loff_t *pos)
{
	mutex_lock(&misc_mtx);
	return seq_list_start(&misc_list, *pos);
}

static void *misc_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return seq_list_next(v, &misc_list, pos);
}

static void misc_seq_stop(struct seq_file *seq, void *v)
{
	mutex_unlock(&misc_mtx);
}

static int misc_seq_show(struct seq_file *seq, void *v)
{
	const struct miscdevice *p = list_entry(v, struct miscdevice, list);

	/*显示minor及设备名称*/
	seq_printf(seq, "%3i %s\n", p->minor, p->name ? p->name : "");
	return 0;
}

/*遍历misc_list，显示系统中所有misc设备的minor及名称，用于/proc/misc文件显示函数*/
static const struct seq_operations misc_seq_ops = {
	.start = misc_seq_start,
	.next  = misc_seq_next,
	.stop  = misc_seq_stop,
	.show  = misc_seq_show,/*显示misc设备信息*/
};
#endif

static int misc_open(struct inode *inode, struct file *file)
{
	int minor = iminor(inode);
	struct miscdevice *c = NULL, *iter;
	int err = -ENODEV;
	const struct file_operations *new_fops = NULL;

	mutex_lock(&misc_mtx);

	/*遍历misc_list上串连的misc设备*/
	list_for_each_entry(iter, &misc_list, list) {
		if (iter->minor != minor)
			/*minor不相等，忽略*/
			continue;
		/*匹配，返回其对应的设备及操作集*/
		c = iter;
		new_fops = fops_get(iter->fops);
		break;
	}

	if (!new_fops) {
		/*没有查找到设备，动态请求加载模块*/
		mutex_unlock(&misc_mtx);
		request_module("char-major-%d-%d", MISC_MAJOR, minor);
		mutex_lock(&misc_mtx);

		/*再查询一遍*/
		list_for_each_entry(iter, &misc_list, list) {
			if (iter->minor != minor)
				continue;
			c = iter;
			new_fops = fops_get(iter->fops);
			break;
		}
		if (!new_fops)
			goto fail;
	}

	/*
	 * Place the miscdevice in the file's
	 * private_data so it can be used by the
	 * file operations, including f_op->open below
	 */
	file->private_data = c;/*更新私有数据为misc设备*/

	err = 0;
	replace_fops(file, new_fops);/*更新fops*/
	if (file->f_op->open)
		/*使用新的fops->open进行进一步处理*/
		err = file->f_op->open(inode, file);
fail:
	mutex_unlock(&misc_mtx);
	return err;
}

static char *misc_devnode(const struct device *dev, umode_t *mode)
{
	const struct miscdevice *c = dev_get_drvdata(dev);

	if (mode && c->mode)
		*mode = c->mode;/*设备mode*/
	if (c->nodename)
		return kstrdup(c->nodename, GFP_KERNEL);
	return NULL;/*返回node名称*/
}

static const struct class misc_class = {
	.name		= "misc",
	.devnode	= misc_devnode,
};

static const struct file_operations misc_fops = {
	.owner		= THIS_MODULE,
	.open		= misc_open,/*处理misc设备的open*/
	.llseek		= noop_llseek,
};

/**
 *	misc_register	-	register a miscellaneous device
 *	@misc: device structure
 *
 *	Register a miscellaneous device with the kernel. If the minor
 *	number is set to %MISC_DYNAMIC_MINOR a minor number is assigned
 *	and placed in the minor field of the structure. For other cases
 *	the minor number requested is used.
 *
 *	The structure passed is linked into the kernel and may not be
 *	destroyed until it has been unregistered. By default, an open()
 *	syscall to the device sets file->private_data to point to the
 *	structure. Drivers don't need open in fops for this.
 *
 *	A zero is returned on success and a negative errno code for
 *	failure.
 */

int misc_register(struct miscdevice *misc)
{
	dev_t dev;
	int err = 0;
	//是否使用动态编号
	bool is_dynamic = (misc->minor == MISC_DYNAMIC_MINOR);

	/*初始化list*/
	INIT_LIST_HEAD(&misc->list);

	mutex_lock(&misc_mtx);

	if (is_dynamic) {
	    //为动态minor分配一个编号
		int i = misc_minor_alloc();

		if (i < 0) {
		    //查找不到时，返回最大值
			err = -EBUSY;
			goto out;
		}
		//自最后一个位置开始分配，方便bitmap的查询更快速（起始情况下时）
		misc->minor = i;
	} else {
	    //指定了minor，故先检查是否此minor是否已分配
		struct miscdevice *c;

		list_for_each_entry(c, &misc_list, list) {
			if (c->minor == misc->minor) {
				err = -EBUSY;/*不可分配*/
				goto out;
			}
		}
	}

	dev = MKDEV(MISC_MAJOR, misc->minor);

	/*创建misc对应的device*/
	misc->this_device =
		device_create_with_groups(&misc_class, misc->parent, dev,
					  misc/*驱动的私有数据*/, misc->groups, "%s"/*设备名称format*/, misc->name);
	if (IS_ERR(misc->this_device)) {
	    //注册失败，回退动态minor占用的那个编号
		if (is_dynamic) {
			misc_minor_free(misc->minor);
			misc->minor = MISC_DYNAMIC_MINOR;
		}
		err = PTR_ERR(misc->this_device);
		goto out;
	}

	/*
	 * Add it to the front, so that later devices can "override"
	 * earlier defaults
	 */
	list_add(&misc->list, &misc_list);
 out:
	mutex_unlock(&misc_mtx);
	return err;
}
EXPORT_SYMBOL(misc_register);

/**
 *	misc_deregister - unregister a miscellaneous device
 *	@misc: device to unregister
 *
 *	Unregister a miscellaneous device that was previously
 *	successfully registered with misc_register().
 */
//解注册misc类设备
void misc_deregister(struct miscdevice *misc)
{
	//检查是否已被解注册
	if (WARN_ON(list_empty(&misc->list)))
		return;

	mutex_lock(&misc_mtx);
	list_del(&misc->list);/*移除注册*/
	device_destroy(&misc_class, MKDEV(MISC_MAJOR, misc->minor));
	misc_minor_free(misc->minor);
	mutex_unlock(&misc_mtx);
}
EXPORT_SYMBOL(misc_deregister);

static int __init misc_init(void)
{
	int err;
	struct proc_dir_entry *ret;

	/*创建/proc/misc文件，显示各misc设备对应的minor*/
	ret = proc_create_seq("misc", 0, NULL, &misc_seq_ops);
	/*注册misc class*/
	err = class_register(&misc_class);
	if (err)
		goto fail_remove;

	err = -EIO;
	/*先注册misc字符设备，通过其可定位具体的misc设备*/
	if (register_chrdev(MISC_MAJOR, "misc", &misc_fops))
		goto fail_printk;
	return 0;

fail_printk:
	pr_err("unable to get major %d for misc devices\n", MISC_MAJOR);
	class_unregister(&misc_class);
fail_remove:
	if (ret)
		remove_proc_entry("misc", NULL);
	return err;
}
subsys_initcall(misc_init);
