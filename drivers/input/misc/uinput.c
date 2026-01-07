// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  User level driver support for input subsystem
 *
 * Heavily based on evdev.c by Vojtech Pavlik
 *
 * Author: Aristeu Sergio Rozanski Filho <aris@cathedrallabs.org>
 *
 * Changes/Revisions:
 *	0.4	01/09/2014 (Benjamin Tissoires <benjamin.tissoires@redhat.com>)
 *		- add UI_GET_SYSNAME ioctl
 *	0.3	09/04/2006 (Anssi Hannula <anssi.hannula@gmail.com>)
 *		- updated ff support for the changes in kernel interface
 *		- added MODULE_VERSION
 *	0.2	16/10/2004 (Micah Dowty <micah@navi.cx>)
 *		- added force feedback support
 *              - added UI_SET_PHYS
 *	0.1	20/06/2002
 *		- first public version
 */
#include <uapi/linux/uinput.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/overflow.h>
#include <linux/input/mt.h>
#include "../input-compat.h"

#define UINPUT_NAME		"uinput"
#define UINPUT_BUFFER_SIZE	16
#define UINPUT_NUM_REQUESTS	16
#define UINPUT_TIMESTAMP_ALLOWED_OFFSET_SECS 10

enum uinput_state { UIST_NEW_DEVICE, UIST_SETUP_COMPLETE, UIST_CREATED };

struct uinput_request {
	unsigned int		id;
	unsigned int		code;	/* UI_FF_UPLOAD, UI_FF_ERASE */

	int			retval;
	struct completion	done;

	union {
		unsigned int	effect_id;
		struct {
			struct ff_effect *effect;
			struct ff_effect *old;
		} upload;
	} u;
};

struct uinput_device {
	struct input_dev	*dev;/*对应的input dev*/
	struct mutex		mutex;
	enum uinput_state	state;/*设备状态*/
	wait_queue_head_t	waitq;
	unsigned char		ready;
	unsigned char		head;/*指向队头*/
	unsigned char		tail;/*指向队尾（读取操作增加此变量）*/
	struct input_event	buff[UINPUT_BUFFER_SIZE];
	unsigned int		ff_effects_max;

	struct uinput_request	*requests[UINPUT_NUM_REQUESTS];
	wait_queue_head_t	requests_waitq;
	spinlock_t		requests_lock;
};

/*将事件写入到udev->buff中*/
static int uinput_dev_event(struct input_dev *dev,
			    unsigned int type, unsigned int code, int value)
{
	struct uinput_device	*udev = input_get_drvdata(dev);
	struct timespec64	ts;

	ktime_get_ts64(&ts);

	/*存入event到udev->buff*/
	udev->buff[udev->head] = (struct input_event) {
		.input_event_sec = ts.tv_sec,
		.input_event_usec = ts.tv_nsec / NSEC_PER_USEC,
		.type = type,
		.code = code,
		.value = value,
	};

	/*head指针前移*/
	udev->head = (udev->head + 1) % UINPUT_BUFFER_SIZE;

	wake_up_interruptible(&udev->waitq);/*唤醒等待者*/

	return 0;
}

/* Atomically allocate an ID for the given request. Returns 0 on success. */
static bool uinput_request_alloc_id(struct uinput_device *udev,
				    struct uinput_request *request)
{
	unsigned int id;
	bool reserved = false;

	spin_lock(&udev->requests_lock);

	for (id = 0; id < UINPUT_NUM_REQUESTS; id++) {
		if (!udev->requests[id]) {
			request->id = id;
			udev->requests[id] = request;
			reserved = true;
			break;
		}
	}

	spin_unlock(&udev->requests_lock);
	return reserved;
}

static struct uinput_request *uinput_request_find(struct uinput_device *udev,
						  unsigned int id)
{
	/* Find an input request, by ID. Returns NULL if the ID isn't valid. */
	if (id >= UINPUT_NUM_REQUESTS)
		return NULL;

	return udev->requests[id];
}

static int uinput_request_reserve_slot(struct uinput_device *udev,
				       struct uinput_request *request)
{
	/* Allocate slot. If none are available right away, wait. */
	return wait_event_interruptible(udev->requests_waitq,
					uinput_request_alloc_id(udev, request));
}

static void uinput_request_release_slot(struct uinput_device *udev,
					unsigned int id)
{
	/* Mark slot as available */
	spin_lock(&udev->requests_lock);
	udev->requests[id] = NULL;
	spin_unlock(&udev->requests_lock);

	wake_up(&udev->requests_waitq);
}

static int uinput_request_send(struct uinput_device *udev,
			       struct uinput_request *request)
{
	int retval;

	retval = mutex_lock_interruptible(&udev->mutex);
	if (retval)
		return retval;

	if (udev->state != UIST_CREATED) {
		retval = -ENODEV;
		goto out;
	}

	init_completion(&request->done);

	/*
	 * Tell our userspace application about this new request
	 * by queueing an input event.
	 */
	uinput_dev_event(udev->dev, EV_UINPUT, request->code, request->id);

 out:
	mutex_unlock(&udev->mutex);
	return retval;
}

static int uinput_request_submit(struct uinput_device *udev,
				 struct uinput_request *request)
{
	int retval;

	retval = uinput_request_reserve_slot(udev, request);
	if (retval)
		return retval;

	retval = uinput_request_send(udev, request);
	if (retval)
		goto out;

	if (!wait_for_completion_timeout(&request->done, 30 * HZ)) {
		retval = -ETIMEDOUT;
		goto out;
	}

	retval = request->retval;

 out:
	uinput_request_release_slot(udev, request->id);
	return retval;
}

/*
 * Fail all outstanding requests so handlers don't wait for the userspace
 * to finish processing them.
 */
static void uinput_flush_requests(struct uinput_device *udev)
{
	struct uinput_request *request;
	int i;

	spin_lock(&udev->requests_lock);

	for (i = 0; i < UINPUT_NUM_REQUESTS; i++) {
		request = udev->requests[i];
		if (request) {
			request->retval = -ENODEV;
			complete(&request->done);
		}
	}

	spin_unlock(&udev->requests_lock);
}

static void uinput_dev_set_gain(struct input_dev *dev, u16 gain)
{
	uinput_dev_event(dev, EV_FF, FF_GAIN, gain);
}

static void uinput_dev_set_autocenter(struct input_dev *dev, u16 magnitude)
{
	uinput_dev_event(dev, EV_FF, FF_AUTOCENTER, magnitude);
}

static int uinput_dev_playback(struct input_dev *dev, int effect_id, int value)
{
	return uinput_dev_event(dev, EV_FF, effect_id, value);
}

static int uinput_dev_upload_effect(struct input_dev *dev,
				    struct ff_effect *effect,
				    struct ff_effect *old)
{
	struct uinput_device *udev = input_get_drvdata(dev);
	struct uinput_request request;

	/*
	 * uinput driver does not currently support periodic effects with
	 * custom waveform since it does not have a way to pass buffer of
	 * samples (custom_data) to userspace. If ever there is a device
	 * supporting custom waveforms we would need to define an additional
	 * ioctl (UI_UPLOAD_SAMPLES) but for now we just bail out.
	 */
	if (effect->type == FF_PERIODIC &&
			effect->u.periodic.waveform == FF_CUSTOM)
		return -EINVAL;

	request.code = UI_FF_UPLOAD;
	request.u.upload.effect = effect;
	request.u.upload.old = old;

	return uinput_request_submit(udev, &request);
}

static int uinput_dev_erase_effect(struct input_dev *dev, int effect_id)
{
	struct uinput_device *udev = input_get_drvdata(dev);
	struct uinput_request request;

	if (!test_bit(EV_FF, dev->evbit))
		return -ENOSYS;

	request.code = UI_FF_ERASE;
	request.u.effect_id = effect_id;

	return uinput_request_submit(udev, &request);
}

static int uinput_dev_flush(struct input_dev *dev, struct file *file)
{
	/*
	 * If we are called with file == NULL that means we are tearing
	 * down the device, and therefore we can not handle FF erase
	 * requests: either we are handling UI_DEV_DESTROY (and holding
	 * the udev->mutex), or the file descriptor is closed and there is
	 * nobody on the other side anymore.
	 */
	return file ? input_ff_flush(dev, file) : 0;
}

static void uinput_destroy_device(struct uinput_device *udev)
{
	const char *name, *phys;
	struct input_dev *dev = udev->dev;
	enum uinput_state old_state = udev->state;/*保存旧状态*/

	udev->state = UIST_NEW_DEVICE;/*更新为new device状态*/

	if (dev) {
		name = dev->name;
		phys = dev->phys;
		if (old_state == UIST_CREATED) {
			uinput_flush_requests(udev);
			input_unregister_device(dev);
		} else {
			input_free_device(dev);
		}
		kfree(name);
		kfree(phys);
		udev->dev = NULL;
	}
}

static int uinput_create_device(struct uinput_device *udev)
{
	struct input_dev *dev = udev->dev;
	int error, nslot;

	if (udev->state != UIST_SETUP_COMPLETE) {
		/*必须先达到此状态，才能执行此ioctl*/
		printk(KERN_DEBUG "%s: write device info first\n", UINPUT_NAME);
		return -EINVAL;
	}

	if (test_bit(EV_ABS, dev->evbit)) {
		input_alloc_absinfo(dev);
		if (!dev->absinfo) {
			error = -EINVAL;
			goto fail1;
		}

		if (test_bit(ABS_MT_SLOT, dev->absbit)) {
			nslot = input_abs_get_max(dev, ABS_MT_SLOT) + 1;
			error = input_mt_init_slots(dev, nslot, 0);
			if (error)
				goto fail1;
		} else if (test_bit(ABS_MT_POSITION_X, dev->absbit)) {
			input_set_events_per_packet(dev, 60);
		}
	}

	if (test_bit(EV_FF, dev->evbit) && !udev->ff_effects_max) {
		printk(KERN_DEBUG "%s: ff_effects_max should be non-zero when FF_BIT is set\n",
			UINPUT_NAME);
		error = -EINVAL;
		goto fail1;
	}

	if (udev->ff_effects_max) {
		error = input_ff_create(dev, udev->ff_effects_max);
		if (error)
			goto fail1;

		dev->ff->upload = uinput_dev_upload_effect;
		dev->ff->erase = uinput_dev_erase_effect;
		dev->ff->playback = uinput_dev_playback;
		dev->ff->set_gain = uinput_dev_set_gain;
		dev->ff->set_autocenter = uinput_dev_set_autocenter;
		/*
		 * The standard input_ff_flush() implementation does
		 * not quite work for uinput as we can't reasonably
		 * handle FF requests during device teardown.
		 */
		dev->flush = uinput_dev_flush;
	}

	dev->event = uinput_dev_event;

	input_set_drvdata(udev->dev, udev);

	error = input_register_device(udev->dev);
	if (error)
		goto fail2;

	udev->state = UIST_CREATED;/*变更为created状态*/

	return 0;

 fail2:	input_ff_destroy(dev);
 fail1: uinput_destroy_device(udev);
	return error;
}

static int uinput_open(struct inode *inode, struct file *file)
{
	struct uinput_device *newdev;

	newdev = kzalloc(sizeof(*newdev), GFP_KERNEL);
	if (!newdev)
		return -ENOMEM;

	mutex_init(&newdev->mutex);
	spin_lock_init(&newdev->requests_lock);
	init_waitqueue_head(&newdev->requests_waitq);
	init_waitqueue_head(&newdev->waitq);
	newdev->state = UIST_NEW_DEVICE;/*初始化为new device状态*/

	file->private_data = newdev;/*指给file做为私有数据*/
	stream_open(inode, file);

	return 0;
}

static int uinput_validate_absinfo(struct input_dev *dev, unsigned int code,
				   const struct input_absinfo *abs)
{
	int min, max, range;

	min = abs->minimum;
	max = abs->maximum;

	if ((min != 0 || max != 0) && max < min) {
		printk(KERN_DEBUG
		       "%s: invalid abs[%02x] min:%d max:%d\n",
		       UINPUT_NAME, code, min, max);
		return -EINVAL;
	}

	if (!check_sub_overflow(max, min, &range) && abs->flat > range) {
		printk(KERN_DEBUG
		       "%s: abs_flat #%02x out of range: %d (min:%d/max:%d)\n",
		       UINPUT_NAME, code, abs->flat, min, max);
		return -EINVAL;
	}

	/*
	 * Limit number of contacts to a reasonable value (100). This
	 * ensures that we need less than 2 pages for struct input_mt
	 * (we are not using in-kernel slot assignment so not going to
	 * allocate memory for the "red" table), and we should have no
	 * trouble getting this much memory.
	 */
	if (code == ABS_MT_SLOT && max > 99) {
		printk(KERN_DEBUG
		       "%s: unreasonably large number of slots requested: %d\n",
		       UINPUT_NAME, max);
		return -EINVAL;
	}

	return 0;
}

static int uinput_validate_absbits(struct input_dev *dev)
{
	unsigned int cnt;
	int error;

	if (!test_bit(EV_ABS, dev->evbit))
		return 0;

	/*
	 * Check if absmin/absmax/absfuzz/absflat are sane.
	 */

	for_each_set_bit(cnt, dev->absbit, ABS_CNT) {
		if (!dev->absinfo)
			return -EINVAL;

		error = uinput_validate_absinfo(dev, cnt, &dev->absinfo[cnt]);
		if (error)
			return error;
	}

	return 0;
}

static int uinput_dev_setup(struct uinput_device *udev,
			    struct uinput_setup __user *arg)
{
	struct uinput_setup setup;
	struct input_dev *dev;

	if (udev->state == UIST_CREATED)
		return -EINVAL;/*已达到created事件，报错*/

	if (copy_from_user(&setup, arg, sizeof(setup)))
		return -EFAULT;

	if (!setup.name[0])
		return -EINVAL;

	dev = udev->dev;
	dev->id = setup.id;
	udev->ff_effects_max = setup.ff_effects_max;

	kfree(dev->name);
	dev->name = kstrndup(setup.name, UINPUT_MAX_NAME_SIZE, GFP_KERNEL);
	if (!dev->name)
		return -ENOMEM;

	udev->state = UIST_SETUP_COMPLETE;
	return 0;
}

static int uinput_abs_setup(struct uinput_device *udev,
			    struct uinput_setup __user *arg, size_t size)
{
	struct uinput_abs_setup setup = {};
	struct input_dev *dev;
	int error;

	if (size > sizeof(setup))
		return -E2BIG;

	if (udev->state == UIST_CREATED)
		return -EINVAL;

	if (copy_from_user(&setup, arg, size))
		return -EFAULT;

	if (setup.code > ABS_MAX)
		return -ERANGE;

	dev = udev->dev;

	error = uinput_validate_absinfo(dev, setup.code, &setup.absinfo);
	if (error)
		return error;

	input_alloc_absinfo(dev);
	if (!dev->absinfo)
		return -ENOMEM;

	set_bit(setup.code, dev->absbit);
	dev->absinfo[setup.code] = setup.absinfo;
	return 0;
}

/* legacy setup via write() */
static int uinput_setup_device_legacy(struct uinput_device *udev,
				      const char __user *buffer, size_t count)
{
	struct uinput_user_dev	*user_dev;
	struct input_dev	*dev;
	int			i;
	int			retval;

	if (count != sizeof(struct uinput_user_dev))
		return -EINVAL;/*大小必须符合约定*/

	if (!udev->dev) {
		/*申请input设备*/
		udev->dev = input_allocate_device();
		if (!udev->dev)
			return -ENOMEM;
	}

	dev = udev->dev;

	user_dev = memdup_user(buffer, sizeof(struct uinput_user_dev));
	if (IS_ERR(user_dev))
		return PTR_ERR(user_dev);

	udev->ff_effects_max = user_dev->ff_effects_max;

	/* Ensure name is filled in */
	if (!user_dev->name[0]) {
		/*必须提供设备名称*/
		retval = -EINVAL;
		goto exit;
	}

	/*设置设备名称*/
	kfree(dev->name);
	dev->name = kstrndup(user_dev->name, UINPUT_MAX_NAME_SIZE,
			     GFP_KERNEL);
	if (!dev->name) {
		retval = -ENOMEM;
		goto exit;
	}

	dev->id.bustype	= user_dev->id.bustype;
	dev->id.vendor	= user_dev->id.vendor;
	dev->id.product	= user_dev->id.product;
	dev->id.version	= user_dev->id.version;

	for (i = 0; i < ABS_CNT; i++) {
		input_abs_set_max(dev, i, user_dev->absmax[i]);
		input_abs_set_min(dev, i, user_dev->absmin[i]);
		input_abs_set_fuzz(dev, i, user_dev->absfuzz[i]);
		input_abs_set_flat(dev, i, user_dev->absflat[i]);
	}

	retval = uinput_validate_absbits(dev);
	if (retval < 0)
		goto exit;

	udev->state = UIST_SETUP_COMPLETE;/*变更设备状态*/
	retval = count;

 exit:
	kfree(user_dev);
	return retval;
}

/*
 * Returns true if the given timestamp is valid (i.e., if all the following
 * conditions are satisfied), false otherwise.
 * 1) given timestamp is positive
 * 2) it's within the allowed offset before the current time
 * 3) it's not in the future
 */
static bool is_valid_timestamp(const ktime_t timestamp)
{
	ktime_t zero_time;
	ktime_t current_time;
	ktime_t min_time;
	ktime_t offset;

	zero_time = ktime_set(0, 0);
	if (ktime_compare(zero_time, timestamp) >= 0)
		return false;

	current_time = ktime_get();
	offset = ktime_set(UINPUT_TIMESTAMP_ALLOWED_OFFSET_SECS, 0);
	min_time = ktime_sub(current_time, offset);

	if (ktime_after(min_time, timestamp) || ktime_after(timestamp, current_time))
		return false;

	return true;
}

static ssize_t uinput_inject_events(struct uinput_device *udev,
				    const char __user *buffer, size_t count)
{
	struct input_event ev;
	size_t bytes = 0;
	ktime_t timestamp;

	if (count != 0 && count < input_event_size())
		return -EINVAL;

	while (bytes + input_event_size() <= count) {
		/*
		 * Note that even if some events were fetched successfully
		 * we are still going to return EFAULT instead of partial
		 * count to let userspace know that it got it's buffers
		 * all wrong.
		 */
		if (input_event_from_user(buffer + bytes, &ev))
			return -EFAULT;

		timestamp = ktime_set(ev.input_event_sec, ev.input_event_usec * NSEC_PER_USEC);
		if (is_valid_timestamp(timestamp))
			input_set_timestamp(udev->dev, timestamp);

		input_event(udev->dev, ev.type, ev.code, ev.value);/*注入事件*/
		bytes += input_event_size();/*更新读取的长度*/
		cond_resched();
	}

	return bytes;
}

static ssize_t uinput_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	struct uinput_device *udev = file->private_data;
	int retval;

	if (count == 0)
		return 0;

	retval = mutex_lock_interruptible(&udev->mutex);
	if (retval)
		return retval;

	retval = udev->state == UIST_CREATED ?
			uinput_inject_events(udev, buffer, count) /*注入事件*/:
			uinput_setup_device_legacy(udev, buffer, count)/*申请input设备，变更状态为UIST_SETUP_COMPLETE*/;

	mutex_unlock(&udev->mutex);

	return retval;
}

/*取udev->tail指向的事件*/
static bool uinput_fetch_next_event(struct uinput_device *udev,
				    struct input_event *event)
{
	bool have_event;

	spin_lock_irq(&udev->dev->event_lock);

	have_event = udev->head != udev->tail;/*两者如不相等，则有事件*/
	if (have_event) {
		/*取事件*/
		*event = udev->buff[udev->tail];
		/*更新tail*/
		udev->tail = (udev->tail + 1) % UINPUT_BUFFER_SIZE;
	}

	spin_unlock_irq(&udev->dev->event_lock);

	return have_event;/*返回是否有事件已读取*/
}

static ssize_t uinput_events_to_user(struct uinput_device *udev,
				     char __user *buffer, size_t count)
{
	struct input_event event;
	size_t read = 0;

	while (read + input_event_size() <= count &&
	       uinput_fetch_next_event(udev, &event)) {

		/*写入到用户态*/
		if (input_event_to_user(buffer + read, &event))
			return -EFAULT;

		/*写入的字节数*/
		read += input_event_size();
	}

	/*返回写入的字节数*/
	return read;
}

/*读取存放在udev->buff的event*/
static ssize_t uinput_read(struct file *file, char __user *buffer,
			   size_t count, loff_t *ppos)
{
	struct uinput_device *udev = file->private_data;
	ssize_t retval;

	if (count != 0 && count < input_event_size())
		return -EINVAL;

	do {
		retval = mutex_lock_interruptible(&udev->mutex);
		if (retval)
			return retval;

		if (udev->state != UIST_CREATED)
			retval = -ENODEV;
		else if (udev->head == udev->tail &&
			 (file->f_flags & O_NONBLOCK))
			/*队列为空，且指明了非阻塞*/
			retval = -EAGAIN;
		else
			/*队列可能非空，写到用户态*/
			retval = uinput_events_to_user(udev, buffer, count);

		mutex_unlock(&udev->mutex);

		if (retval || count == 0)
			break;/*读取到了，退出*/

		if (!(file->f_flags & O_NONBLOCK))
			/*没有指定非阻塞，等待条件*/
			retval = wait_event_interruptible(udev->waitq,
						  udev->head != udev->tail ||
						  udev->state != UIST_CREATED);
	} while (retval == 0);

	return retval;
}

static __poll_t uinput_poll(struct file *file, poll_table *wait)
{
	struct uinput_device *udev = file->private_data;
	__poll_t mask = EPOLLOUT | EPOLLWRNORM; /* uinput is always writable */

	poll_wait(file, &udev->waitq, wait);

	if (udev->head != udev->tail)
		/*队列不为空，返回pollin事件*/
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static int uinput_release(struct inode *inode, struct file *file)
{
	struct uinput_device *udev = file->private_data;

	uinput_destroy_device(udev);
	kfree(udev);

	return 0;
}

#ifdef CONFIG_COMPAT
struct uinput_ff_upload_compat {
	__u32			request_id;
	__s32			retval;
	struct ff_effect_compat	effect;
	struct ff_effect_compat	old;
};

static int uinput_ff_upload_to_user(char __user *buffer,
				    const struct uinput_ff_upload *ff_up)
{
	if (in_compat_syscall()) {
		struct uinput_ff_upload_compat ff_up_compat;

		ff_up_compat.request_id = ff_up->request_id;
		ff_up_compat.retval = ff_up->retval;
		/*
		 * It so happens that the pointer that gives us the trouble
		 * is the last field in the structure. Since we don't support
		 * custom waveforms in uinput anyway we can just copy the whole
		 * thing (to the compat size) and ignore the pointer.
		 */
		memcpy(&ff_up_compat.effect, &ff_up->effect,
			sizeof(struct ff_effect_compat));
		memcpy(&ff_up_compat.old, &ff_up->old,
			sizeof(struct ff_effect_compat));

		if (copy_to_user(buffer, &ff_up_compat,
				 sizeof(struct uinput_ff_upload_compat)))
			return -EFAULT;
	} else {
		if (copy_to_user(buffer, ff_up,
				 sizeof(struct uinput_ff_upload)))
			return -EFAULT;
	}

	return 0;
}

static int uinput_ff_upload_from_user(const char __user *buffer,
				      struct uinput_ff_upload *ff_up)
{
	if (in_compat_syscall()) {
		struct uinput_ff_upload_compat ff_up_compat;

		if (copy_from_user(&ff_up_compat, buffer,
				   sizeof(struct uinput_ff_upload_compat)))
			return -EFAULT;

		ff_up->request_id = ff_up_compat.request_id;
		ff_up->retval = ff_up_compat.retval;
		memcpy(&ff_up->effect, &ff_up_compat.effect,
			sizeof(struct ff_effect_compat));
		memcpy(&ff_up->old, &ff_up_compat.old,
			sizeof(struct ff_effect_compat));

	} else {
		if (copy_from_user(ff_up, buffer,
				   sizeof(struct uinput_ff_upload)))
			return -EFAULT;
	}

	return 0;
}

#else

static int uinput_ff_upload_to_user(char __user *buffer,
				    const struct uinput_ff_upload *ff_up)
{
	if (copy_to_user(buffer, ff_up, sizeof(struct uinput_ff_upload)))
		return -EFAULT;

	return 0;
}

static int uinput_ff_upload_from_user(const char __user *buffer,
				      struct uinput_ff_upload *ff_up)
{
	if (copy_from_user(ff_up, buffer, sizeof(struct uinput_ff_upload)))
		return -EFAULT;

	return 0;
}

#endif

#define uinput_set_bit(_arg, _bit, _max)		\
({							\
	int __ret = 0;					\
	if (udev->state == UIST_CREATED)		\
		__ret =  -EINVAL;			\
	else if ((_arg) > (_max))			\
		__ret = -EINVAL;/*不得超过max*/			\
	else set_bit((_arg), udev->dev->_bit);/*将参数对应的位，置为1*/		\
	__ret;						\
})

static int uinput_str_to_user(void __user *dest, const char *str,
			      unsigned int maxlen)
{
	char __user *p = dest;
	int len, ret;

	if (!str)
		return -ENOENT;

	if (maxlen == 0)
		return -EINVAL;

	len = strlen(str) + 1;
	if (len > maxlen)
		len = maxlen;

	ret = copy_to_user(p, str, len);
	if (ret)
		return -EFAULT;

	/* force terminating '\0' */
	ret = put_user(0, p + len - 1);
	return ret ? -EFAULT : len;
}

static long uinput_ioctl_handler(struct file *file, unsigned int cmd,
				 unsigned long arg, void __user *p)
{
	int			retval;
	struct uinput_device	*udev = file->private_data;
	struct uinput_ff_upload ff_up;
	struct uinput_ff_erase  ff_erase;
	struct uinput_request   *req;
	char			*phys;
	const char		*name;
	unsigned int		size;

	retval = mutex_lock_interruptible(&udev->mutex);
	if (retval)
		return retval;

	if (!udev->dev) {
		/*如果dev还未设置，则申请input dev*/
		udev->dev = input_allocate_device();
		if (!udev->dev) {
			retval = -ENOMEM;
			goto out;
		}
	}

	switch (cmd) {
	case UI_GET_VERSION:
		/*取uinput版本号*/
		if (put_user(UINPUT_VERSION, (unsigned int __user *)p))
			retval = -EFAULT;
		goto out;

	case UI_DEV_CREATE:
		retval = uinput_create_device(udev);
		goto out;

	case UI_DEV_DESTROY:
		uinput_destroy_device(udev);
		goto out;

	case UI_DEV_SETUP:
		retval = uinput_dev_setup(udev, p);
		goto out;

	/* UI_ABS_SETUP is handled in the variable size ioctls */

	case UI_SET_EVBIT:
		/*指明udev->dev->evbit的arg位为'1'（用于指明设备支持的event)*/
		retval = uinput_set_bit(arg, evbit, EV_MAX);
		goto out;

	case UI_SET_KEYBIT:
		retval = uinput_set_bit(arg, keybit, KEY_MAX);
		goto out;

	case UI_SET_RELBIT:
		retval = uinput_set_bit(arg, relbit, REL_MAX);
		goto out;

	case UI_SET_ABSBIT:
		retval = uinput_set_bit(arg, absbit, ABS_MAX);
		goto out;

	case UI_SET_MSCBIT:
		retval = uinput_set_bit(arg, mscbit, MSC_MAX);
		goto out;

	case UI_SET_LEDBIT:
		retval = uinput_set_bit(arg, ledbit, LED_MAX);
		goto out;

	case UI_SET_SNDBIT:
		retval = uinput_set_bit(arg, sndbit, SND_MAX);
		goto out;

	case UI_SET_FFBIT:
		retval = uinput_set_bit(arg, ffbit, FF_MAX);
		goto out;

	case UI_SET_SWBIT:
		retval = uinput_set_bit(arg, swbit, SW_MAX);
		goto out;

	case UI_SET_PROPBIT:
		retval = uinput_set_bit(arg, propbit, INPUT_PROP_MAX);
		goto out;

	case UI_SET_PHYS:
		if (udev->state == UIST_CREATED) {
			retval = -EINVAL;/*已达created,报错*/
			goto out;
		}

		phys = strndup_user(p, 1024);
		if (IS_ERR(phys)) {
			retval = PTR_ERR(phys);
			goto out;
		}

		kfree(udev->dev->phys);
		udev->dev->phys = phys;
		goto out;

	case UI_BEGIN_FF_UPLOAD:
		retval = uinput_ff_upload_from_user(p, &ff_up);
		if (retval)
			goto out;

		req = uinput_request_find(udev, ff_up.request_id);
		if (!req || req->code != UI_FF_UPLOAD ||
		    !req->u.upload.effect) {
			retval = -EINVAL;
			goto out;
		}

		ff_up.retval = 0;
		ff_up.effect = *req->u.upload.effect;
		if (req->u.upload.old)
			ff_up.old = *req->u.upload.old;
		else
			memset(&ff_up.old, 0, sizeof(struct ff_effect));

		retval = uinput_ff_upload_to_user(p, &ff_up);
		goto out;

	case UI_BEGIN_FF_ERASE:
		if (copy_from_user(&ff_erase, p, sizeof(ff_erase))) {
			retval = -EFAULT;
			goto out;
		}

		req = uinput_request_find(udev, ff_erase.request_id);
		if (!req || req->code != UI_FF_ERASE) {
			retval = -EINVAL;
			goto out;
		}

		ff_erase.retval = 0;
		ff_erase.effect_id = req->u.effect_id;
		if (copy_to_user(p, &ff_erase, sizeof(ff_erase))) {
			retval = -EFAULT;
			goto out;
		}

		goto out;

	case UI_END_FF_UPLOAD:
		retval = uinput_ff_upload_from_user(p, &ff_up);
		if (retval)
			goto out;

		req = uinput_request_find(udev, ff_up.request_id);
		if (!req || req->code != UI_FF_UPLOAD ||
		    !req->u.upload.effect) {
			retval = -EINVAL;
			goto out;
		}

		req->retval = ff_up.retval;
		complete(&req->done);
		goto out;

	case UI_END_FF_ERASE:
		if (copy_from_user(&ff_erase, p, sizeof(ff_erase))) {
			retval = -EFAULT;
			goto out;
		}

		req = uinput_request_find(udev, ff_erase.request_id);
		if (!req || req->code != UI_FF_ERASE) {
			retval = -EINVAL;
			goto out;
		}

		req->retval = ff_erase.retval;
		complete(&req->done);
		goto out;
	}

	size = _IOC_SIZE(cmd);

	/* Now check variable-length commands */
	switch (cmd & ~IOCSIZE_MASK) {
	case UI_GET_SYSNAME(0):
		if (udev->state != UIST_CREATED) {
			retval = -ENOENT;
			goto out;
		}
		name = dev_name(&udev->dev->dev);
		retval = uinput_str_to_user(p, name, size);
		goto out;

	case UI_ABS_SETUP & ~IOCSIZE_MASK:
		retval = uinput_abs_setup(udev, p, size);
		goto out;
	}

	retval = -EINVAL;
 out:
	mutex_unlock(&udev->mutex);
	return retval;
}

static long uinput_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return uinput_ioctl_handler(file, cmd, arg, (void __user *)arg);
}

#ifdef CONFIG_COMPAT

/*
 * These IOCTLs change their size and thus their numbers between
 * 32 and 64 bits.
 */
#define UI_SET_PHYS_COMPAT		\
	_IOW(UINPUT_IOCTL_BASE, 108, compat_uptr_t)
#define UI_BEGIN_FF_UPLOAD_COMPAT	\
	_IOWR(UINPUT_IOCTL_BASE, 200, struct uinput_ff_upload_compat)
#define UI_END_FF_UPLOAD_COMPAT		\
	_IOW(UINPUT_IOCTL_BASE, 201, struct uinput_ff_upload_compat)

static long uinput_compat_ioctl(struct file *file,
				unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case UI_SET_PHYS_COMPAT:
		cmd = UI_SET_PHYS;
		break;
	case UI_BEGIN_FF_UPLOAD_COMPAT:
		cmd = UI_BEGIN_FF_UPLOAD;
		break;
	case UI_END_FF_UPLOAD_COMPAT:
		cmd = UI_END_FF_UPLOAD;
		break;
	}

	return uinput_ioctl_handler(file, cmd, arg, compat_ptr(arg));
}
#endif

static const struct file_operations uinput_fops = {
	.owner		= THIS_MODULE,
	.open		= uinput_open,
	.release	= uinput_release,
	.read		= uinput_read,/*读取event*/
	.write		= uinput_write,/*注入事件及用于初始化设备*/
	.poll		= uinput_poll,
	.unlocked_ioctl	= uinput_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= uinput_compat_ioctl,
#endif
};

static struct miscdevice uinput_misc = {
	.fops		= &uinput_fops,
	.minor		= UINPUT_MINOR,
	.name		= UINPUT_NAME,
};
module_misc_device(uinput_misc);/*注册uinput字符设备*/

MODULE_ALIAS_MISCDEV(UINPUT_MINOR);
MODULE_ALIAS("devname:" UINPUT_NAME);

MODULE_AUTHOR("Aristeu Sergio Rozanski Filho");
MODULE_DESCRIPTION("User level driver support for input subsystem");
MODULE_LICENSE("GPL");
