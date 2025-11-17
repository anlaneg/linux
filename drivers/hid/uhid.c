// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * User-space I/O driver support for HID subsystem
 * Copyright (c) 2012 David Herrmann
 */

/*
 */

#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/uhid.h>
#include <linux/wait.h>

#define UHID_NAME	"uhid"
#define UHID_BUFSIZE	32

struct uhid_device {
	struct mutex devlock;

	/* This flag tracks whether the HID device is usable for commands from
	 * userspace. The flag is already set before hid_add_device(), which
	 * runs in workqueue context, to allow hid_add_device() to communicate
	 * with userspace.
	 * However, if hid_add_device() fails, the flag is cleared without
	 * holding devlock.
	 * We guarantee that if @running changes from true to false while you're
	 * holding @devlock, it's still fine to access @hid.
	 */
	bool running;

	__u8 *rd_data;
	uint rd_size;/*记录rd_data数组长度*/

	/* When this is NULL, userspace may use UHID_CREATE/UHID_CREATE2. */
	struct hid_device *hid;/*对应的hid设备*/
	struct uhid_event input_buf;

	wait_queue_head_t waitq;
	spinlock_t qlock;
	__u8 head;
	__u8 tail;
	struct uhid_event *outq[UHID_BUFSIZE];

	/* blocking GET_REPORT support; state changes protected by qlock */
	struct mutex report_lock;
	wait_queue_head_t report_wait;
	bool report_running;
	u32 report_id;/*负责report id*/
	u32 report_type;
	struct uhid_event report_buf;/*临时记录用户态响应内容*/
	struct work_struct worker;
};

static struct miscdevice uhid_misc;

static void uhid_device_add_worker(struct work_struct *work)
{
	struct uhid_device *uhid = container_of(work, struct uhid_device, worker);
	int ret;

	/*注册hid设备*/
	ret = hid_add_device(uhid->hid);
	if (ret) {
		hid_err(uhid->hid, "Cannot register HID device: error %d\n", ret);

		/* We used to call hid_destroy_device() here, but that's really
		 * messy to get right because we have to coordinate with
		 * concurrent writes from userspace that might be in the middle
		 * of using uhid->hid.
		 * Just leave uhid->hid as-is for now, and clean it up when
		 * userspace tries to close or reinitialize the uhid instance.
		 *
		 * However, we do have to clear the ->running flag and do a
		 * wakeup to make sure userspace knows that the device is gone.
		 */
		WRITE_ONCE(uhid->running, false);
		wake_up_interruptible(&uhid->report_wait);
	}
}

/*向uhid->outq中写入event,供读取*/
static void uhid_queue(struct uhid_device *uhid, struct uhid_event *ev)
{
	__u8 newhead;

	newhead = (uhid->head + 1) % UHID_BUFSIZE;/*下一个要写的位置*/

	if (newhead != uhid->tail) {
		/*填写可读取的event*/
		uhid->outq[uhid->head] = ev;
		uhid->head = newhead;/*更新下次要写的位置*/
		wake_up_interruptible(&uhid->waitq);
	} else {
		/*队列写满了*/
		hid_warn(uhid->hid, "Output queue is full\n");
		kfree(ev);
	}
}

/*向uhid->outq中写入event（无参数）,供读取*/
static int uhid_queue_event(struct uhid_device *uhid, __u32 event)
{
	unsigned long flags;
	struct uhid_event *ev;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	ev->type = event;/*指明事件id,此事件无参数*/

	spin_lock_irqsave(&uhid->qlock, flags);
	uhid_queue(uhid, ev);/*无参数event入队，待用户态读取*/
	spin_unlock_irqrestore(&uhid->qlock, flags);

	return 0;
}

static int uhid_hid_start(struct hid_device *hid)
{
	struct uhid_device *uhid = hid->driver_data;
	struct uhid_event *ev;
	unsigned long flags;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	ev->type = UHID_START;/*事件id为start(指明hid设备启动，用于回应create）*/

	/*指明事件参数*/
	if (hid->report_enum[HID_FEATURE_REPORT].numbered)
		ev->u.start.dev_flags |= UHID_DEV_NUMBERED_FEATURE_REPORTS;
	if (hid->report_enum[HID_OUTPUT_REPORT].numbered)
		ev->u.start.dev_flags |= UHID_DEV_NUMBERED_OUTPUT_REPORTS;
	if (hid->report_enum[HID_INPUT_REPORT].numbered)
		ev->u.start.dev_flags |= UHID_DEV_NUMBERED_INPUT_REPORTS;

	spin_lock_irqsave(&uhid->qlock, flags);
	uhid_queue(uhid, ev);/*UHID_START事件入队待用户态读取*/
	spin_unlock_irqrestore(&uhid->qlock, flags);

	return 0;
}

static void uhid_hid_stop(struct hid_device *hid)
{
	struct uhid_device *uhid = hid->driver_data;

	hid->claimed = 0;
	uhid_queue_event(uhid, UHID_STOP);/*report stop事件*/
}

static int uhid_hid_open(struct hid_device *hid)
{
	struct uhid_device *uhid = hid->driver_data;

	return uhid_queue_event(uhid, UHID_OPEN);/*report open事件*/
}

static void uhid_hid_close(struct hid_device *hid)
{
	struct uhid_device *uhid = hid->driver_data;

	uhid_queue_event(uhid, UHID_CLOSE);/*report close事件*/
}

static int uhid_hid_parse(struct hid_device *hid)
{
	struct uhid_device *uhid = hid->driver_data;

	/*设置hid->dev_rdesc，hid->dev_rsize*/
	return hid_parse_report(hid, uhid->rd_data, uhid->rd_size);
}

/* must be called with report_lock held */
static int __uhid_report_queue_and_wait(struct uhid_device *uhid,
					struct uhid_event *ev/*提供给用户态待读取的event*/,
					__u32 *report_id/*出参，event对应的请求id号*/)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&uhid->qlock, flags);
	*report_id = ++uhid->report_id;
	uhid->report_type = ev->type + 1;
	uhid->report_running = true;/*标明在等待响应*/
	uhid_queue(uhid, ev);/*event入队，待用户态读取*/
	spin_unlock_irqrestore(&uhid->qlock, flags);

	/*等待被唤醒*/
	ret = wait_event_interruptible_timeout(uhid->report_wait,
				!uhid->report_running/*收到响应*/ || !READ_ONCE(uhid->running),
				5 * HZ/*超时时间*/);
	if (!ret || !READ_ONCE(uhid->running) || uhid->report_running)
		ret = -EIO;
	else if (ret < 0)
		ret = -ERESTARTSYS;
	else
		ret = 0;

	uhid->report_running = false;

	return ret;
}

static void uhid_report_wake_up(struct uhid_device *uhid, u32 id/*请求id*/,
				const struct uhid_event *ev/*用户态传入的event*/)
{
	unsigned long flags;

	spin_lock_irqsave(&uhid->qlock, flags);

	/* id for old report; drop it silently */
	if (uhid->report_type != ev->type || uhid->report_id != id)
		goto unlock;/*响应与我们预期的id及type不相等，忽略*/
	if (!uhid->report_running)
		goto unlock;/*report还未在running,忽略*/

	/*记录收到的响应*/
	memcpy(&uhid->report_buf, ev, sizeof(*ev));
	uhid->report_running = false;/*标记不再等响应*/
	wake_up_interruptible(&uhid->report_wait);/*唤醒等待者*/

unlock:
	spin_unlock_irqrestore(&uhid->qlock, flags);
}

/*产生get report事件等待用户态读取，并收取用户态get report reply的响应内容*/
static int uhid_hid_get_report(struct hid_device *hid, unsigned char rnum,
			       u8 *buf/*出参，响应内容*/, size_t count/*buf长度*/, u8 rtype)
{
	struct uhid_device *uhid = hid->driver_data;
	struct uhid_get_report_reply_req *req;
	struct uhid_event *ev;
	int ret;

	if (!READ_ONCE(uhid->running))
		return -EIO;/*未运行*/

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	/*指明get_report事件，并填充*/
	ev->type = UHID_GET_REPORT;
	ev->u.get_report.rnum = rnum;
	ev->u.get_report.rtype = rtype;

	ret = mutex_lock_interruptible(&uhid->report_lock);
	if (ret) {
		kfree(ev);
		return ret;
	}

	/* this _always_ takes ownership of @ev */
	/*get report事件入队，待用户态读取，并等待响应*/
	ret = __uhid_report_queue_and_wait(uhid, ev, &ev->u.get_report.id);
	if (ret)
		goto unlock;

	req = &uhid->report_buf.u.get_report_reply;
	if (req->err) {
		/*响应状态指明：出错*/
		ret = -EIO;
	} else {
		/*指明响应内容长度*/
		ret = min3(count, (size_t)req->size, (size_t)UHID_DATA_MAX);
		memcpy(buf, req->data, ret);/*指明响应内容*/
	}

unlock:
	mutex_unlock(&uhid->report_lock);
	return ret;
}

static int uhid_hid_set_report(struct hid_device *hid, unsigned char rnum,
			       const u8 *buf/*入参，事件对应的数据*/, size_t count/*buf长度*/, u8 rtype)
{
	struct uhid_device *uhid = hid->driver_data;
	struct uhid_event *ev;
	int ret;

	if (!READ_ONCE(uhid->running) || count > UHID_DATA_MAX)
		return -EIO;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	ev->type = UHID_SET_REPORT;/*指明为set report*/
	ev->u.set_report.rnum = rnum;
	ev->u.set_report.rtype = rtype;
	ev->u.set_report.size = count;
	memcpy(ev->u.set_report.data, buf, count);

	ret = mutex_lock_interruptible(&uhid->report_lock);
	if (ret) {
		kfree(ev);
		return ret;
	}

	/* this _always_ takes ownership of @ev */
	/*set report事件入队，待用户态读取，并等待用户态响应*/
	ret = __uhid_report_queue_and_wait(uhid, ev, &ev->u.set_report.id);
	if (ret)
		goto unlock;

	if (uhid->report_buf.u.set_report_reply.err)
		/*响应状态指明为出错*/
		ret = -EIO;
	else
		ret = count;/*成功响应*/

unlock:
	mutex_unlock(&uhid->report_lock);
	return ret;
}

static int uhid_hid_raw_request(struct hid_device *hid, unsigned char reportnum/*请求数量*/,
				__u8 *buf, size_t len, unsigned char rtype/*report类型*/,
				int reqtype/*get还是set report请求*/)
{
	u8 u_rtype;

	/*rtype转换为u_rtype*/
	switch (rtype) {
	case HID_FEATURE_REPORT:
		u_rtype = UHID_FEATURE_REPORT;/*指明为feature*/
		break;
	case HID_OUTPUT_REPORT:
		u_rtype = UHID_OUTPUT_REPORT;
		break;
	case HID_INPUT_REPORT:
		u_rtype = UHID_INPUT_REPORT;
		break;
	default:
		return -EINVAL;/*参数无效*/
	}

	/*产生get report/set report event*/
	switch (reqtype) {
	case HID_REQ_GET_REPORT:
		return uhid_hid_get_report(hid, reportnum, buf/*出参，响应内容*/, len, u_rtype);
	case HID_REQ_SET_REPORT:
		return uhid_hid_set_report(hid, reportnum, buf/*入参，请求内容*/, len, u_rtype);
	default:
		return -EIO;
	}
}

static int uhid_hid_output_raw(struct hid_device *hid, __u8 *buf, size_t count,
			       unsigned char report_type)
{
	struct uhid_device *uhid = hid->driver_data;
	__u8 rtype;
	unsigned long flags;
	struct uhid_event *ev;

	switch (report_type) {
	case HID_FEATURE_REPORT:
		rtype = UHID_FEATURE_REPORT;
		break;
	case HID_OUTPUT_REPORT:
		rtype = UHID_OUTPUT_REPORT;
		break;
	default:
		return -EINVAL;
	}

	if (count < 1 || count > UHID_DATA_MAX)
		return -EINVAL;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	/*指明事件为output，并指明参数*/
	ev->type = UHID_OUTPUT;
	ev->u.output.size = count;
	ev->u.output.rtype = rtype;
	memcpy(ev->u.output.data, buf, count);

	spin_lock_irqsave(&uhid->qlock, flags);
	uhid_queue(uhid, ev);/*output事件入队，待用户态读取*/
	spin_unlock_irqrestore(&uhid->qlock, flags);

	return count;
}

static int uhid_hid_output_report(struct hid_device *hid, __u8 *buf,
				  size_t count)
{
	/*产生UHID_OUTPUT_REPORT事件给用户态*/
	return uhid_hid_output_raw(hid, buf, count, HID_OUTPUT_REPORT);
}

/*uhid对应的ll_driver*/
static const struct hid_ll_driver uhid_hid_driver = {
	.start = uhid_hid_start,/*产生UHID_START事件给用户态*/
	.stop = uhid_hid_stop,/*产生UHID_STOP事件给用户态*/
	.open = uhid_hid_open,/*产生UHID_OPEN事件给用户态*/
	.close = uhid_hid_close,/*产生UHID_CLOSE事件给用户态*/
	.parse = uhid_hid_parse,/*设置hid->dev_rsize,hid->dev_rdesc*/
	.raw_request = uhid_hid_raw_request,/*按参数产生get/set report event给用户态*/
	.output_report = uhid_hid_output_report,/*按参数产生产生UHID_OUTPUT_REPORT事件给用户态*/
	.max_buffer_size = UHID_DATA_MAX,
};

#ifdef CONFIG_COMPAT

/* Apparently we haven't stepped on these rakes enough times yet. */
struct uhid_create_req_compat {
	__u8 name[128];
	__u8 phys[64];
	__u8 uniq[64];

	compat_uptr_t rd_data;
	__u16 rd_size;

	__u16 bus;
	__u32 vendor;
	__u32 product;
	__u32 version;
	__u32 country;
} __attribute__((__packed__));

static int uhid_event_from_user(const char __user *buffer, size_t len,
				struct uhid_event *event)
{
	if (in_compat_syscall()) {
		u32 type;

		if (get_user(type, buffer))
			return -EFAULT;

		if (type == UHID_CREATE) {
			/*
			 * This is our messed up request with compat pointer.
			 * It is largish (more than 256 bytes) so we better
			 * allocate it from the heap.
			 */
			struct uhid_create_req_compat *compat;

			compat = kzalloc(sizeof(*compat), GFP_KERNEL);
			if (!compat)
				return -ENOMEM;

			buffer += sizeof(type);
			len -= sizeof(type);
			if (copy_from_user(compat, buffer,
					   min(len, sizeof(*compat)))) {
				kfree(compat);
				return -EFAULT;
			}

			/* Shuffle the data over to proper structure */
			event->type = type;

			memcpy(event->u.create.name, compat->name,
				sizeof(compat->name));
			memcpy(event->u.create.phys, compat->phys,
				sizeof(compat->phys));
			memcpy(event->u.create.uniq, compat->uniq,
				sizeof(compat->uniq));

			event->u.create.rd_data = compat_ptr(compat->rd_data);
			event->u.create.rd_size = compat->rd_size;

			event->u.create.bus = compat->bus;
			event->u.create.vendor = compat->vendor;
			event->u.create.product = compat->product;
			event->u.create.version = compat->version;
			event->u.create.country = compat->country;

			kfree(compat);
			return 0;
		}
		/* All others can be copied directly */
	}

	if (copy_from_user(event, buffer, min(len, sizeof(*event))))
		return -EFAULT;

	return 0;
}
#else
static int uhid_event_from_user(const char __user *buffer, size_t len,
				struct uhid_event *event)
{
	if (copy_from_user(event, buffer, min(len, sizeof(*event))))
		return -EFAULT;

	return 0;
}
#endif

static int uhid_dev_create2(struct uhid_device *uhid,
			    const struct uhid_event *ev)
{
	struct hid_device *hid;
	size_t rd_size;
	void *rd_data;
	int ret;

	if (uhid->hid)
		/*已创建*/
		return -EALREADY;

	rd_size = ev->u.create2.rd_size;
	if (rd_size <= 0 || rd_size > HID_MAX_DESCRIPTOR_SIZE)
		return -EINVAL;/*rd_data数组长度有误*/

	rd_data = kmemdup(ev->u.create2.rd_data, rd_size, GFP_KERNEL);
	if (!rd_data)
		return -ENOMEM;

	/*填充rd_size,rd_data*/
	uhid->rd_size = rd_size;
	uhid->rd_data = rd_data;

	/*申请创建hid_device*/
	hid = hid_allocate_device();
	if (IS_ERR(hid)) {
		ret = PTR_ERR(hid);
		goto err_free;
	}

	BUILD_BUG_ON(sizeof(hid->name) != sizeof(ev->u.create2.name));
	strscpy(hid->name, ev->u.create2.name, sizeof(hid->name));/*设备名称*/
	BUILD_BUG_ON(sizeof(hid->phys) != sizeof(ev->u.create2.phys));
	strscpy(hid->phys, ev->u.create2.phys, sizeof(hid->phys));
	BUILD_BUG_ON(sizeof(hid->uniq) != sizeof(ev->u.create2.uniq));
	strscpy(hid->uniq, ev->u.create2.uniq, sizeof(hid->uniq));

	hid->ll_driver = &uhid_hid_driver;/*指定驱动*/
	hid->bus = ev->u.create2.bus;
	hid->vendor = ev->u.create2.vendor;
	hid->product = ev->u.create2.product;
	hid->version = ev->u.create2.version;
	hid->country = ev->u.create2.country;
	hid->driver_data = uhid;/*指向uhid device*/
	hid->dev.parent = uhid_misc.this_device;/*指向此字符设备*/

	uhid->hid = hid;
	uhid->running = true;/*指明设备已running*/

	/* Adding of a HID device is done through a worker, to allow HID drivers
	 * which use feature requests during .probe to work, without they would
	 * be blocked on devlock, which is held by uhid_char_write.
	 */
	schedule_work(&uhid->worker);/*启动worker添加设备*/

	return 0;

err_free:
	kfree(uhid->rd_data);
	uhid->rd_data = NULL;
	uhid->rd_size = 0;
	return ret;
}

static int uhid_dev_create(struct uhid_device *uhid,
			   struct uhid_event *ev)
{
	struct uhid_create_req orig;

	orig = ev->u.create;

	if (orig.rd_size <= 0 || orig.rd_size > HID_MAX_DESCRIPTOR_SIZE)
		return -EINVAL;/*rd_size有误*/
	if (copy_from_user(&ev->u.create2.rd_data, orig.rd_data, orig.rd_size))
		return -EFAULT;

	memcpy(ev->u.create2.name, orig.name, sizeof(orig.name));
	memcpy(ev->u.create2.phys, orig.phys, sizeof(orig.phys));
	memcpy(ev->u.create2.uniq, orig.uniq, sizeof(orig.uniq));
	ev->u.create2.rd_size = orig.rd_size;
	ev->u.create2.bus = orig.bus;
	ev->u.create2.vendor = orig.vendor;
	ev->u.create2.product = orig.product;
	ev->u.create2.version = orig.version;
	ev->u.create2.country = orig.country;

	return uhid_dev_create2(uhid, ev);
}

static int uhid_dev_destroy(struct uhid_device *uhid)
{
	if (!uhid->hid)
		return -EINVAL;

	WRITE_ONCE(uhid->running, false);/*指明设备停止运行*/
	wake_up_interruptible(&uhid->report_wait);

	cancel_work_sync(&uhid->worker);

	hid_destroy_device(uhid->hid);
	uhid->hid = NULL;
	kfree(uhid->rd_data);

	return 0;
}

static int uhid_dev_input(struct uhid_device *uhid, struct uhid_event *ev)
{
	if (!READ_ONCE(uhid->running))
		return -EINVAL;

	hid_input_report(uhid->hid, HID_INPUT_REPORT, ev->u.input.data/*参数*/,
			 min_t(size_t, ev->u.input.size/*参数长度*/, UHID_DATA_MAX), 0);

	return 0;
}

static int uhid_dev_input2(struct uhid_device *uhid, struct uhid_event *ev)
{
	if (!READ_ONCE(uhid->running))
		return -EINVAL;

	hid_input_report(uhid->hid, HID_INPUT_REPORT, ev->u.input2.data,
			 min_t(size_t, ev->u.input2.size, UHID_DATA_MAX), 0);

	return 0;
}

static int uhid_dev_get_report_reply(struct uhid_device *uhid,
				     struct uhid_event *ev)
{
	if (!READ_ONCE(uhid->running))
		return -EINVAL;/*未处于运行状态，返回无效*/

	uhid_report_wake_up(uhid, ev->u.get_report_reply.id, ev);
	return 0;
}

static int uhid_dev_set_report_reply(struct uhid_device *uhid,
				     struct uhid_event *ev)
{
	if (!READ_ONCE(uhid->running))
		return -EINVAL;

	uhid_report_wake_up(uhid, ev->u.set_report_reply.id, ev);
	return 0;
}

static int uhid_char_open(struct inode *inode, struct file *file)
{
	struct uhid_device *uhid;

	uhid = kzalloc(sizeof(*uhid), GFP_KERNEL);
	if (!uhid)
		return -ENOMEM;

	mutex_init(&uhid->devlock);
	mutex_init(&uhid->report_lock);
	spin_lock_init(&uhid->qlock);
	init_waitqueue_head(&uhid->waitq);
	init_waitqueue_head(&uhid->report_wait);
	uhid->running = false;
	INIT_WORK(&uhid->worker, uhid_device_add_worker);

	file->private_data = uhid;/*文件私有数据置为uhid*/
	stream_open(inode, file);/*打开此文件*/

	return 0;
}

static int uhid_char_release(struct inode *inode, struct file *file)
{
	struct uhid_device *uhid = file->private_data;
	unsigned int i;

	uhid_dev_destroy(uhid);

	for (i = 0; i < UHID_BUFSIZE; ++i)
		kfree(uhid->outq[i]);

	kfree(uhid);

	return 0;
}

static ssize_t uhid_char_read(struct file *file, char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct uhid_device *uhid = file->private_data;
	int ret;
	unsigned long flags;
	size_t len;

	/* they need at least the "type" member of uhid_event */
	if (count < sizeof(__u32))
		return -EINVAL;/*读的长度不得小于4字节*/

try_again:
	if (file->f_flags & O_NONBLOCK) {
		if (uhid->head == uhid->tail)
			return -EAGAIN;/*无数据，返回*/
	} else {
		/*等待队列不为空*/
		ret = wait_event_interruptible(uhid->waitq,
						uhid->head != uhid->tail);
		if (ret)
			return ret;
	}

	ret = mutex_lock_interruptible(&uhid->devlock);
	if (ret)
		return ret;

	if (uhid->head == uhid->tail) {
		mutex_unlock(&uhid->devlock);
		goto try_again;/*队列为空*/
	} else {
		len = min(count, sizeof(**uhid->outq));
		if (copy_to_user(buffer, uhid->outq[uhid->tail], len)) {
			ret = -EFAULT;
		} else {
			/*数据已复制到buffer,原空间清空*/
			kfree(uhid->outq[uhid->tail]);
			uhid->outq[uhid->tail] = NULL;

			spin_lock_irqsave(&uhid->qlock, flags);
			/*uhid->tail移动*/
			uhid->tail = (uhid->tail + 1) % UHID_BUFSIZE;
			spin_unlock_irqrestore(&uhid->qlock, flags);
		}
	}

	mutex_unlock(&uhid->devlock);
	return ret ? ret : len;
}

/*按收到的event type进行处理*/
static ssize_t uhid_char_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct uhid_device *uhid = file->private_data;
	int ret;
	size_t len;

	/* we need at least the "type" member of uhid_event */
	if (count < sizeof(__u32))
		return -EINVAL;

	ret = mutex_lock_interruptible(&uhid->devlock);
	if (ret)
		return ret;

	memset(&uhid->input_buf, 0, sizeof(uhid->input_buf));
	len = min(count, sizeof(uhid->input_buf));

	/*读取用户输入，填充到uhid->input_buf*/
	ret = uhid_event_from_user(buffer, len, &uhid->input_buf);
	if (ret)
		goto unlock;

	switch (uhid->input_buf.type) {
	case UHID_CREATE:
		/*
		 * 'struct uhid_create_req' contains a __user pointer which is
		 * copied from, so it's unsafe to allow this with elevated
		 * privileges (e.g. from a setuid binary) or via kernel_write().
		 */
		if (file->f_cred != current_cred()) {
			pr_err_once("UHID_CREATE from different security context by process %d (%s), this is not allowed.\n",
				    task_tgid_vnr(current), current->comm);
			ret = -EACCES;
			goto unlock;
		}
		ret = uhid_dev_create(uhid, &uhid->input_buf);
		break;
	case UHID_CREATE2:
		ret = uhid_dev_create2(uhid, &uhid->input_buf);
		break;
	case UHID_DESTROY:
		ret = uhid_dev_destroy(uhid);
		break;
	case UHID_INPUT:
		ret = uhid_dev_input(uhid, &uhid->input_buf);
		break;
	case UHID_INPUT2:
		ret = uhid_dev_input2(uhid, &uhid->input_buf);
		break;
	case UHID_GET_REPORT_REPLY:
		/*收到用户态传入的get report响应*/
		ret = uhid_dev_get_report_reply(uhid, &uhid->input_buf);
		break;
	case UHID_SET_REPORT_REPLY:
		/*收到用户态传入的set report响应*/
		ret = uhid_dev_set_report_reply(uhid, &uhid->input_buf);
		break;
	default:
		ret = -EOPNOTSUPP;
	}

unlock:
	mutex_unlock(&uhid->devlock);

	/* return "count" not "len" to not confuse the caller */
	return ret ? ret : count;
}

static __poll_t uhid_char_poll(struct file *file, poll_table *wait)
{
	struct uhid_device *uhid = file->private_data;
	__poll_t mask = EPOLLOUT | EPOLLWRNORM; /* uhid is always writable */

	poll_wait(file, &uhid->waitq, wait);

	if (uhid->head != uhid->tail)
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static const struct file_operations uhid_fops = {
	.owner		= THIS_MODULE,
	.open		= uhid_char_open,
	.release	= uhid_char_release,
	.read		= uhid_char_read,
	.write		= uhid_char_write,
	.poll		= uhid_char_poll,
};

/*uhid字符设备*/
static struct miscdevice uhid_misc = {
	.fops		= &uhid_fops,
	.minor		= UHID_MINOR,
	.name		= UHID_NAME,
};
module_misc_device(uhid_misc);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Herrmann <dh.herrmann@gmail.com>");
MODULE_DESCRIPTION("User-space I/O driver support for HID subsystem");
MODULE_ALIAS_MISCDEV(UHID_MINOR);
MODULE_ALIAS("devname:" UHID_NAME);
