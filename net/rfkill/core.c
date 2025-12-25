// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2006 - 2007 Ivo van Doorn
 * Copyright (C) 2007 Dmitry Torokhov
 * Copyright 2009 Johannes Berg <johannes@sipsolutions.net>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rfkill.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "rfkill.h"

#define POLL_INTERVAL		(5 * HZ)

#define RFKILL_BLOCK_HW		BIT(0)
#define RFKILL_BLOCK_SW		BIT(1)
#define RFKILL_BLOCK_SW_PREV	BIT(2)
#define RFKILL_BLOCK_ANY	(RFKILL_BLOCK_HW |\
				 RFKILL_BLOCK_SW |\
				 RFKILL_BLOCK_SW_PREV)
#define RFKILL_BLOCK_SW_SETCALL	BIT(31)

struct rfkill {
	spinlock_t		lock;

	enum rfkill_type	type;/*无线电发射设备类型*/

	unsigned long		state;
	unsigned long		hard_block_reasons;

	u32			idx;/*编号*/

	bool			registered;/*是否已注册*/
	bool			persistent;
	bool			polling_paused;
	bool			suspended;
	bool			need_sync;

	const struct rfkill_ops	*ops;/*操作集，例如hci_rfkill_ops*/
	void			*data;

#ifdef CONFIG_RFKILL_LEDS
	struct led_trigger	led_trigger;
	const char		*ledtrigname;
#endif

	struct device		dev;/*对应的设备结构*/
	struct list_head	node;

	struct delayed_work	poll_work;
	struct work_struct	uevent_work;
	struct work_struct	sync_work;
	char			name[];/*无线电发射设备名称，例如hci0*/
};
#define to_rfkill(d)	container_of(d, struct rfkill, dev)

struct rfkill_int_event {
	struct list_head	list;
	struct rfkill_event_ext	ev;
};

struct rfkill_data {
	struct list_head	list;
	struct list_head	events;
	struct mutex		mtx;
	wait_queue_head_t	read_wait;
	bool			input_handler;
	u8			max_size;/*event大小不得超过此值*/
};


MODULE_AUTHOR("Ivo van Doorn <IvDoorn@gmail.com>");
MODULE_AUTHOR("Johannes Berg <johannes@sipsolutions.net>");
MODULE_DESCRIPTION("RF switch support");
MODULE_LICENSE("GPL");


/*
 * The locking here should be made much smarter, we currently have
 * a bit of a stupid situation because drivers might want to register
 * the rfkill struct under their own lock, and take this lock during
 * rfkill method calls -- which will cause an AB-BA deadlock situation.
 *
 * To fix that, we need to rework this code here to be mostly lock-free
 * and only use the mutex for list manipulations, not to protect the
 * various other global variables. Then we can avoid holding the mutex
 * around driver operations, and all is happy.
 */
/*串连所有struct rfkill结构体*/
static LIST_HEAD(rfkill_list);	/* list of registered rf switches */
static DEFINE_MUTEX(rfkill_global_mutex);
/*串连所有打开的fd,结构体为struct rfkill_data*/
static LIST_HEAD(rfkill_fds);	/* list of open fds of /dev/rfkill */

static unsigned int rfkill_default_state = 1;
module_param_named(default_state, rfkill_default_state, uint, 0444);
MODULE_PARM_DESC(default_state,
		 "Default initial state for all radio types, 0 = radio off");

static struct {
	bool cur, sav;
} rfkill_global_states[NUM_RFKILL_TYPES];

static bool rfkill_epo_lock_active;


#ifdef CONFIG_RFKILL_LEDS
static void rfkill_led_trigger_event(struct rfkill *rfkill)
{
	struct led_trigger *trigger;

	if (!rfkill->registered)
		return;

	trigger = &rfkill->led_trigger;

	if (rfkill->state & RFKILL_BLOCK_ANY)
		led_trigger_event(trigger, LED_OFF);
	else
		led_trigger_event(trigger, LED_FULL);
}

static int rfkill_led_trigger_activate(struct led_classdev *led)
{
	struct rfkill *rfkill;

	rfkill = container_of(led->trigger, struct rfkill, led_trigger);

	rfkill_led_trigger_event(rfkill);

	return 0;
}

const char *rfkill_get_led_trigger_name(struct rfkill *rfkill)
{
	return rfkill->led_trigger.name;
}
EXPORT_SYMBOL(rfkill_get_led_trigger_name);

void rfkill_set_led_trigger_name(struct rfkill *rfkill, const char *name)
{
	BUG_ON(!rfkill);

	rfkill->ledtrigname = name;
}
EXPORT_SYMBOL(rfkill_set_led_trigger_name);

static int rfkill_led_trigger_register(struct rfkill *rfkill)
{
	rfkill->led_trigger.name = rfkill->ledtrigname
					? : dev_name(&rfkill->dev);
	rfkill->led_trigger.activate = rfkill_led_trigger_activate;
	return led_trigger_register(&rfkill->led_trigger);
}

static void rfkill_led_trigger_unregister(struct rfkill *rfkill)
{
	led_trigger_unregister(&rfkill->led_trigger);
}

static struct led_trigger rfkill_any_led_trigger;
static struct led_trigger rfkill_none_led_trigger;
static struct work_struct rfkill_global_led_trigger_work;

static void rfkill_global_led_trigger_worker(struct work_struct *work)
{
	enum led_brightness brightness = LED_OFF;
	struct rfkill *rfkill;

	mutex_lock(&rfkill_global_mutex);
	list_for_each_entry(rfkill, &rfkill_list, node) {
		if (!(rfkill->state & RFKILL_BLOCK_ANY)) {
			brightness = LED_FULL;
			break;
		}
	}
	mutex_unlock(&rfkill_global_mutex);

	led_trigger_event(&rfkill_any_led_trigger, brightness);
	led_trigger_event(&rfkill_none_led_trigger,
			  brightness == LED_OFF ? LED_FULL : LED_OFF);
}

static void rfkill_global_led_trigger_event(void)
{
	schedule_work(&rfkill_global_led_trigger_work);
}

static int rfkill_global_led_trigger_register(void)
{
	int ret;

	INIT_WORK(&rfkill_global_led_trigger_work,
			rfkill_global_led_trigger_worker);

	rfkill_any_led_trigger.name = "rfkill-any";
	ret = led_trigger_register(&rfkill_any_led_trigger);
	if (ret)
		return ret;

	rfkill_none_led_trigger.name = "rfkill-none";
	ret = led_trigger_register(&rfkill_none_led_trigger);
	if (ret)
		led_trigger_unregister(&rfkill_any_led_trigger);
	else
		/* Delay activation until all global triggers are registered */
		rfkill_global_led_trigger_event();

	return ret;
}

static void rfkill_global_led_trigger_unregister(void)
{
	led_trigger_unregister(&rfkill_none_led_trigger);
	led_trigger_unregister(&rfkill_any_led_trigger);
	cancel_work_sync(&rfkill_global_led_trigger_work);
}
#else
static void rfkill_led_trigger_event(struct rfkill *rfkill)
{
}

static inline int rfkill_led_trigger_register(struct rfkill *rfkill)
{
	return 0;
}

static inline void rfkill_led_trigger_unregister(struct rfkill *rfkill)
{
}

static void rfkill_global_led_trigger_event(void)
{
}

static int rfkill_global_led_trigger_register(void)
{
	return 0;
}

static void rfkill_global_led_trigger_unregister(void)
{
}
#endif /* CONFIG_RFKILL_LEDS */

static void rfkill_fill_event(struct rfkill_event_ext *ev,
			      struct rfkill *rfkill,
			      enum rfkill_operation op)
{
	unsigned long flags;

	ev->idx = rfkill->idx;
	ev->type = rfkill->type;
	ev->op = op;/*事件类型*/

	spin_lock_irqsave(&rfkill->lock, flags);
	ev->hard = !!(rfkill->state & RFKILL_BLOCK_HW);
	ev->soft = !!(rfkill->state & (RFKILL_BLOCK_SW |
					RFKILL_BLOCK_SW_PREV));
	ev->hard_block_reasons = rfkill->hard_block_reasons;
	spin_unlock_irqrestore(&rfkill->lock, flags);
}

/*针对所有rfkill fd,按op产生event*/
static void rfkill_send_events(struct rfkill *rfkill, enum rfkill_operation op)
{
	struct rfkill_data *data;
	struct rfkill_int_event *ev;

	/*遍历所有rfkill fd,产生event*/
	list_for_each_entry(data, &rfkill_fds, list) {
		ev = kzalloc(sizeof(*ev), GFP_KERNEL);
		if (!ev)
			continue;
		rfkill_fill_event(&ev->ev, rfkill, op);
		mutex_lock(&data->mtx);
		/*添加event*/
		list_add_tail(&ev->list, &data->events);
		mutex_unlock(&data->mtx);
		/*知会read_wait,唤醒进程*/
		wake_up_interruptible(&data->read_wait);
	}
}

/*产生change事件给/dev/rfkill*/
static void rfkill_event(struct rfkill *rfkill)
{
	if (!rfkill->registered)
		return;

	kobject_uevent(&rfkill->dev.kobj, KOBJ_CHANGE);

	/* also send event to /dev/rfkill */
	rfkill_send_events(rfkill, RFKILL_OP_CHANGE);
}

/**
 * rfkill_set_block - wrapper for set_block method
 *
 * @rfkill: the rfkill struct to use
 * @blocked: the new software state
 *
 * Calls the set_block method (when applicable) and handles notifications
 * etc. as well.
 */
static void rfkill_set_block(struct rfkill *rfkill, bool blocked)
{
	unsigned long flags;
	bool prev, curr;
	int err;

	if (unlikely(rfkill->dev.power.power_state.event & PM_EVENT_SLEEP))
		return;

	/*
	 * Some platforms (...!) generate input events which affect the
	 * _hard_ kill state -- whenever something tries to change the
	 * current software state query the hardware state too.
	 */
	if (rfkill->ops->query)
		rfkill->ops->query(rfkill, rfkill->data);

	spin_lock_irqsave(&rfkill->lock, flags);
	prev = rfkill->state & RFKILL_BLOCK_SW;/*取之前的值*/

	if (prev)
		rfkill->state |= RFKILL_BLOCK_SW_PREV;
	else
		rfkill->state &= ~RFKILL_BLOCK_SW_PREV;

	if (blocked)
		rfkill->state |= RFKILL_BLOCK_SW;/*置sw block*/
	else
		rfkill->state &= ~RFKILL_BLOCK_SW;/*移除sw block*/

	rfkill->state |= RFKILL_BLOCK_SW_SETCALL;
	spin_unlock_irqrestore(&rfkill->lock, flags);

	err = rfkill->ops->set_block(rfkill->data, blocked);/*通过回调，设置block*/

	spin_lock_irqsave(&rfkill->lock, flags);
	if (err) {
		/*
		 * Failed -- reset status to _PREV, which may be different
		 * from what we have set _PREV to earlier in this function
		 * if rfkill_set_sw_state was invoked.
		 */
		if (rfkill->state & RFKILL_BLOCK_SW_PREV)
			rfkill->state |= RFKILL_BLOCK_SW;
		else
			rfkill->state &= ~RFKILL_BLOCK_SW;
	}
	rfkill->state &= ~RFKILL_BLOCK_SW_SETCALL;
	rfkill->state &= ~RFKILL_BLOCK_SW_PREV;
	curr = rfkill->state & RFKILL_BLOCK_SW;
	spin_unlock_irqrestore(&rfkill->lock, flags);

	rfkill_led_trigger_event(rfkill);
	rfkill_global_led_trigger_event();

	if (prev != curr)
		rfkill_event(rfkill);
}

static void rfkill_sync(struct rfkill *rfkill)
{
	lockdep_assert_held(&rfkill_global_mutex);

	if (!rfkill->need_sync)
		return;/*不需要同步，则不更新*/

	rfkill_set_block(rfkill, rfkill_global_states[rfkill->type].cur);
	rfkill->need_sync = false;/*已更新，指定不同步*/
}

static void rfkill_update_global_state(enum rfkill_type type/*类型*/, bool blocked)
{
	int i;

	if (type != RFKILL_TYPE_ALL) {
		/*针设置具体一个type的状态*/
		rfkill_global_states[type].cur = blocked;
		return;
	}

	/*设置所有type的状态*/
	for (i = 0; i < NUM_RFKILL_TYPES; i++)
		rfkill_global_states[i].cur = blocked;
}

#ifdef CONFIG_RFKILL_INPUT
static atomic_t rfkill_input_disabled = ATOMIC_INIT(0);

/**
 * __rfkill_switch_all - Toggle state of all switches of given type
 * @type: type of interfaces to be affected
 * @blocked: the new state
 *
 * This function sets the state of all switches of given type,
 * unless a specific switch is suspended.
 *
 * Caller must have acquired rfkill_global_mutex.
 */
static void __rfkill_switch_all(const enum rfkill_type type, bool blocked)
{
	struct rfkill *rfkill;

	rfkill_update_global_state(type, blocked);
	list_for_each_entry(rfkill, &rfkill_list, node) {
		if (rfkill->type != type && type != RFKILL_TYPE_ALL)
			continue;

		rfkill_set_block(rfkill, blocked);
	}
}

/**
 * rfkill_switch_all - Toggle state of all switches of given type
 * @type: type of interfaces to be affected
 * @blocked: the new state
 *
 * Acquires rfkill_global_mutex and calls __rfkill_switch_all(@type, @state).
 * Please refer to __rfkill_switch_all() for details.
 *
 * Does nothing if the EPO lock is active.
 */
void rfkill_switch_all(enum rfkill_type type, bool blocked)
{
	if (atomic_read(&rfkill_input_disabled))
		return;

	mutex_lock(&rfkill_global_mutex);

	if (!rfkill_epo_lock_active)
		__rfkill_switch_all(type, blocked);

	mutex_unlock(&rfkill_global_mutex);
}

/**
 * rfkill_epo - emergency power off all transmitters
 *
 * This kicks all non-suspended rfkill devices to RFKILL_STATE_SOFT_BLOCKED,
 * ignoring everything in its path but rfkill_global_mutex and rfkill->mutex.
 *
 * The global state before the EPO is saved and can be restored later
 * using rfkill_restore_states().
 */
void rfkill_epo(void)
{
	struct rfkill *rfkill;
	int i;

	if (atomic_read(&rfkill_input_disabled))
		return;

	mutex_lock(&rfkill_global_mutex);

	rfkill_epo_lock_active = true;
	list_for_each_entry(rfkill, &rfkill_list, node)
		rfkill_set_block(rfkill, true);

	for (i = 0; i < NUM_RFKILL_TYPES; i++) {
		rfkill_global_states[i].sav = rfkill_global_states[i].cur;
		rfkill_global_states[i].cur = true;
	}

	mutex_unlock(&rfkill_global_mutex);
}

/**
 * rfkill_restore_states - restore global states
 *
 * Restore (and sync switches to) the global state from the
 * states in rfkill_default_states.  This can undo the effects of
 * a call to rfkill_epo().
 */
void rfkill_restore_states(void)
{
	int i;

	if (atomic_read(&rfkill_input_disabled))
		return;

	mutex_lock(&rfkill_global_mutex);

	rfkill_epo_lock_active = false;
	for (i = 0; i < NUM_RFKILL_TYPES; i++)
		__rfkill_switch_all(i, rfkill_global_states[i].sav);
	mutex_unlock(&rfkill_global_mutex);
}

/**
 * rfkill_remove_epo_lock - unlock state changes
 *
 * Used by rfkill-input manually unlock state changes, when
 * the EPO switch is deactivated.
 */
void rfkill_remove_epo_lock(void)
{
	if (atomic_read(&rfkill_input_disabled))
		return;

	mutex_lock(&rfkill_global_mutex);
	rfkill_epo_lock_active = false;
	mutex_unlock(&rfkill_global_mutex);
}

/**
 * rfkill_is_epo_lock_active - returns true EPO is active
 *
 * Returns 0 (false) if there is NOT an active EPO condition,
 * and 1 (true) if there is an active EPO condition, which
 * locks all radios in one of the BLOCKED states.
 *
 * Can be called in atomic context.
 */
bool rfkill_is_epo_lock_active(void)
{
	return rfkill_epo_lock_active;
}

/**
 * rfkill_get_global_sw_state - returns global state for a type
 * @type: the type to get the global state of
 *
 * Returns the current global state for a given wireless
 * device type.
 */
bool rfkill_get_global_sw_state(const enum rfkill_type type)
{
	return rfkill_global_states[type].cur;
}
#endif

bool rfkill_set_hw_state_reason(struct rfkill *rfkill,
				bool blocked,
				enum rfkill_hard_block_reasons reason)
{
	unsigned long flags;
	bool ret, prev;

	BUG_ON(!rfkill);

	spin_lock_irqsave(&rfkill->lock, flags);
	prev = !!(rfkill->hard_block_reasons & reason);
	if (blocked) {
		rfkill->state |= RFKILL_BLOCK_HW;
		rfkill->hard_block_reasons |= reason;
	} else {
		rfkill->hard_block_reasons &= ~reason;
		if (!rfkill->hard_block_reasons)
			rfkill->state &= ~RFKILL_BLOCK_HW;
	}
	ret = !!(rfkill->state & RFKILL_BLOCK_ANY);
	spin_unlock_irqrestore(&rfkill->lock, flags);

	rfkill_led_trigger_event(rfkill);
	rfkill_global_led_trigger_event();

	if (rfkill->registered && prev != blocked)
		schedule_work(&rfkill->uevent_work);

	return ret;
}
EXPORT_SYMBOL(rfkill_set_hw_state_reason);

static void __rfkill_set_sw_state(struct rfkill *rfkill, bool blocked)
{
	u32 bit = RFKILL_BLOCK_SW;

	/* if in a ops->set_block right now, use other bit */
	if (rfkill->state & RFKILL_BLOCK_SW_SETCALL)
		bit = RFKILL_BLOCK_SW_PREV;

	if (blocked)
		rfkill->state |= bit;
	else
		rfkill->state &= ~bit;
}

bool rfkill_set_sw_state(struct rfkill *rfkill, bool blocked)
{
	unsigned long flags;
	bool prev, hwblock;

	BUG_ON(!rfkill);

	spin_lock_irqsave(&rfkill->lock, flags);
	prev = !!(rfkill->state & RFKILL_BLOCK_SW);
	__rfkill_set_sw_state(rfkill, blocked);
	hwblock = !!(rfkill->state & RFKILL_BLOCK_HW);
	blocked = blocked || hwblock;
	spin_unlock_irqrestore(&rfkill->lock, flags);

	if (!rfkill->registered)
		return blocked;

	if (prev != blocked && !hwblock)
		schedule_work(&rfkill->uevent_work);

	rfkill_led_trigger_event(rfkill);
	rfkill_global_led_trigger_event();

	return blocked;
}
EXPORT_SYMBOL(rfkill_set_sw_state);

void rfkill_init_sw_state(struct rfkill *rfkill, bool blocked)
{
	unsigned long flags;

	BUG_ON(!rfkill);
	BUG_ON(rfkill->registered);

	spin_lock_irqsave(&rfkill->lock, flags);
	__rfkill_set_sw_state(rfkill, blocked);
	rfkill->persistent = true;
	spin_unlock_irqrestore(&rfkill->lock, flags);
}
EXPORT_SYMBOL(rfkill_init_sw_state);

void rfkill_set_states(struct rfkill *rfkill, bool sw, bool hw)
{
	unsigned long flags;
	bool swprev, hwprev;

	BUG_ON(!rfkill);

	spin_lock_irqsave(&rfkill->lock, flags);

	/*
	 * No need to care about prev/setblock ... this is for uevent only
	 * and that will get triggered by rfkill_set_block anyway.
	 */
	swprev = !!(rfkill->state & RFKILL_BLOCK_SW);
	hwprev = !!(rfkill->state & RFKILL_BLOCK_HW);
	__rfkill_set_sw_state(rfkill, sw);
	if (hw)
		rfkill->state |= RFKILL_BLOCK_HW;
	else
		rfkill->state &= ~RFKILL_BLOCK_HW;

	spin_unlock_irqrestore(&rfkill->lock, flags);

	if (!rfkill->registered) {
		rfkill->persistent = true;
	} else {
		if (swprev != sw || hwprev != hw)
			schedule_work(&rfkill->uevent_work);

		rfkill_led_trigger_event(rfkill);
		rfkill_global_led_trigger_event();
	}
}
EXPORT_SYMBOL(rfkill_set_states);

static const char * const rfkill_types[] = {
	NULL, /* RFKILL_TYPE_ALL */
	"wlan",
	"bluetooth",
	"ultrawideband",
	"wimax",
	"wwan",
	"gps",
	"fm",
	"nfc",
};

/*依据名称转换rfkill_type*/
enum rfkill_type rfkill_find_type(const char *name)
{
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(rfkill_types) != NUM_RFKILL_TYPES);

	if (!name)
		return RFKILL_TYPE_ALL;

	for (i = 1; i < NUM_RFKILL_TYPES; i++)
		if (!strcmp(name, rfkill_types[i]))
			return i;
	return RFKILL_TYPE_ALL;
}
EXPORT_SYMBOL(rfkill_find_type);

/*显示设备名称*/
static ssize_t name_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	return sysfs_emit(buf, "%s\n", rfkill->name);
}
static DEVICE_ATTR_RO(name);

/*显示无线电发射设备类型*/
static ssize_t type_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	return sysfs_emit(buf, "%s\n", rfkill_types[rfkill->type]);
}
static DEVICE_ATTR_RO(type);

/*无线电发射设备编号*/
static ssize_t index_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	return sysfs_emit(buf, "%d\n", rfkill->idx);
}
static DEVICE_ATTR_RO(index);

static ssize_t persistent_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	return sysfs_emit(buf, "%d\n", rfkill->persistent);
}
static DEVICE_ATTR_RO(persistent);

static ssize_t hard_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	return sysfs_emit(buf, "%d\n", (rfkill->state & RFKILL_BLOCK_HW) ? 1 : 0);
}
static DEVICE_ATTR_RO(hard);

static ssize_t soft_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	mutex_lock(&rfkill_global_mutex);
	rfkill_sync(rfkill);
	mutex_unlock(&rfkill_global_mutex);

	return sysfs_emit(buf, "%d\n", (rfkill->state & RFKILL_BLOCK_SW) ? 1 : 0);
}

static ssize_t soft_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct rfkill *rfkill = to_rfkill(dev);
	unsigned long state;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	err = kstrtoul(buf, 0, &state);
	if (err)
		return err;

	if (state > 1 )
		return -EINVAL;

	mutex_lock(&rfkill_global_mutex);
	rfkill_sync(rfkill);
	rfkill_set_block(rfkill, state);
	mutex_unlock(&rfkill_global_mutex);

	return count;
}
static DEVICE_ATTR_RW(soft);

static ssize_t hard_block_reasons_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	return sysfs_emit(buf, "0x%lx\n", rfkill->hard_block_reasons);
}
static DEVICE_ATTR_RO(hard_block_reasons);

static u8 user_state_from_blocked(unsigned long state)
{
	if (state & RFKILL_BLOCK_HW)
		return RFKILL_USER_STATE_HARD_BLOCKED;
	if (state & RFKILL_BLOCK_SW)
		return RFKILL_USER_STATE_SOFT_BLOCKED;

	return RFKILL_USER_STATE_UNBLOCKED;
}

static ssize_t state_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct rfkill *rfkill = to_rfkill(dev);

	mutex_lock(&rfkill_global_mutex);
	rfkill_sync(rfkill);
	mutex_unlock(&rfkill_global_mutex);

	return sysfs_emit(buf, "%d\n", user_state_from_blocked(rfkill->state));
}

static ssize_t state_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct rfkill *rfkill = to_rfkill(dev);
	unsigned long state;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	err = kstrtoul(buf, 0, &state);
	if (err)
		return err;

	if (state != RFKILL_USER_STATE_SOFT_BLOCKED &&
	    state != RFKILL_USER_STATE_UNBLOCKED)
		return -EINVAL;

	mutex_lock(&rfkill_global_mutex);
	rfkill_sync(rfkill);
	rfkill_set_block(rfkill, state == RFKILL_USER_STATE_SOFT_BLOCKED);
	mutex_unlock(&rfkill_global_mutex);

	return count;
}
static DEVICE_ATTR_RW(state);

/*显示无线电发射设备属性*/
static struct attribute *rfkill_dev_attrs[] = {
	&dev_attr_name.attr,
	&dev_attr_type.attr,
	&dev_attr_index.attr,
	&dev_attr_persistent.attr,
	&dev_attr_state.attr,
	&dev_attr_soft.attr,
	&dev_attr_hard.attr,
	&dev_attr_hard_block_reasons.attr,
	NULL,
};
ATTRIBUTE_GROUPS(rfkill_dev);

static void rfkill_release(struct device *dev)
{
	struct rfkill *rfkill = to_rfkill(dev);

	kfree(rfkill);
}

static int rfkill_dev_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
	struct rfkill *rfkill = to_rfkill(dev);
	unsigned long flags;
	unsigned long reasons;
	u32 state;
	int error;

	error = add_uevent_var(env, "RFKILL_NAME=%s", rfkill->name);
	if (error)
		return error;
	error = add_uevent_var(env, "RFKILL_TYPE=%s",
			       rfkill_types[rfkill->type]);
	if (error)
		return error;
	spin_lock_irqsave(&rfkill->lock, flags);
	state = rfkill->state;
	reasons = rfkill->hard_block_reasons;
	spin_unlock_irqrestore(&rfkill->lock, flags);
	error = add_uevent_var(env, "RFKILL_STATE=%d",
			       user_state_from_blocked(state));
	if (error)
		return error;
	return add_uevent_var(env, "RFKILL_HW_BLOCK_REASON=0x%lx", reasons);
}

void rfkill_pause_polling(struct rfkill *rfkill)
{
	BUG_ON(!rfkill);

	if (!rfkill->ops->poll)
		return;

	rfkill->polling_paused = true;
	cancel_delayed_work_sync(&rfkill->poll_work);
}
EXPORT_SYMBOL(rfkill_pause_polling);

void rfkill_resume_polling(struct rfkill *rfkill)
{
	BUG_ON(!rfkill);

	if (!rfkill->ops->poll)
		return;

	rfkill->polling_paused = false;

	if (rfkill->suspended)
		return;

	queue_delayed_work(system_power_efficient_wq,
			   &rfkill->poll_work, 0);
}
EXPORT_SYMBOL(rfkill_resume_polling);

#ifdef CONFIG_PM_SLEEP
static int rfkill_suspend(struct device *dev)
{
	struct rfkill *rfkill = to_rfkill(dev);

	rfkill->suspended = true;
	cancel_delayed_work_sync(&rfkill->poll_work);

	return 0;
}

static int rfkill_resume(struct device *dev)
{
	struct rfkill *rfkill = to_rfkill(dev);
	bool cur;

	rfkill->suspended = false;

	if (!rfkill->registered)
		return 0;

	if (!rfkill->persistent) {
		cur = !!(rfkill->state & RFKILL_BLOCK_SW);
		rfkill_set_block(rfkill, cur);
	}

	if (rfkill->ops->poll && !rfkill->polling_paused)
		queue_delayed_work(system_power_efficient_wq,
				   &rfkill->poll_work, 0);

	return 0;
}

static SIMPLE_DEV_PM_OPS(rfkill_pm_ops, rfkill_suspend, rfkill_resume);
#define RFKILL_PM_OPS (&rfkill_pm_ops)
#else
#define RFKILL_PM_OPS NULL
#endif

static struct class rfkill_class = {
	.name		= "rfkill",
	.dev_release	= rfkill_release,
	.dev_groups	= rfkill_dev_groups,
	.dev_uevent	= rfkill_dev_uevent,
	.pm		= RFKILL_PM_OPS,
};

bool rfkill_blocked(struct rfkill *rfkill)
{
	unsigned long flags;
	u32 state;

	spin_lock_irqsave(&rfkill->lock, flags);
	state = rfkill->state;
	spin_unlock_irqrestore(&rfkill->lock, flags);

	return !!(state & RFKILL_BLOCK_ANY);
}
EXPORT_SYMBOL(rfkill_blocked);

bool rfkill_soft_blocked(struct rfkill *rfkill)
{
	unsigned long flags;
	u32 state;

	spin_lock_irqsave(&rfkill->lock, flags);
	state = rfkill->state;
	spin_unlock_irqrestore(&rfkill->lock, flags);

	return !!(state & RFKILL_BLOCK_SW);
}
EXPORT_SYMBOL(rfkill_soft_blocked);

struct rfkill * __must_check rfkill_alloc(const char *name/*无线电发射设备名称，例如hci0*/,
					  struct device *parent,
					  const enum rfkill_type type/*设备类型*/,
					  const struct rfkill_ops *ops,
					  void *ops_data)
{
	struct rfkill *rfkill;
	struct device *dev;

	if (WARN_ON(!ops))
		return NULL;

	if (WARN_ON(!ops->set_block))
		return NULL;/*ops必须提供set_block参数*/

	if (WARN_ON(!name))
		return NULL;/*必须提供设备名称*/

	if (WARN_ON(type == RFKILL_TYPE_ALL || type >= NUM_RFKILL_TYPES))
		return NULL;/*无线设备类型有误*/

	rfkill = kzalloc(sizeof(*rfkill) + strlen(name) + 1, GFP_KERNEL);
	if (!rfkill)
		return NULL;

	spin_lock_init(&rfkill->lock);
	INIT_LIST_HEAD(&rfkill->node);
	rfkill->type = type;
	strcpy(rfkill->name, name);/*设置设备名称*/
	rfkill->ops = ops;
	rfkill->data = ops_data;

	dev = &rfkill->dev;
	dev->class = &rfkill_class;/*指明其class*/
	dev->parent = parent;
	device_initialize(dev);

	return rfkill;
}
EXPORT_SYMBOL(rfkill_alloc);

static void rfkill_poll(struct work_struct *work)
{
	struct rfkill *rfkill;

	rfkill = container_of(work, struct rfkill, poll_work.work);

	/*
	 * Poll hardware state -- driver will use one of the
	 * rfkill_set{,_hw,_sw}_state functions and use its
	 * return value to update the current status.
	 */
	rfkill->ops->poll(rfkill, rfkill->data);

	queue_delayed_work(system_power_efficient_wq,
		&rfkill->poll_work,
		round_jiffies_relative(POLL_INTERVAL));
}

static void rfkill_uevent_work(struct work_struct *work)
{
	struct rfkill *rfkill;

	rfkill = container_of(work, struct rfkill, uevent_work);

	mutex_lock(&rfkill_global_mutex);
	rfkill_event(rfkill);
	mutex_unlock(&rfkill_global_mutex);
}

static void rfkill_sync_work(struct work_struct *work)
{
	struct rfkill *rfkill = container_of(work, struct rfkill, sync_work);

	mutex_lock(&rfkill_global_mutex);
	rfkill_sync(rfkill);
	mutex_unlock(&rfkill_global_mutex);
}

int __must_check rfkill_register(struct rfkill *rfkill)
{
	static unsigned long rfkill_no;/*负责分配rfkill设备名称编号*/
	struct device *dev;
	int error;

	if (!rfkill)
		return -EINVAL;

	dev = &rfkill->dev;

	mutex_lock(&rfkill_global_mutex);/*加锁*/

	if (rfkill->registered) {
		/*已注册*/
		error = -EALREADY;
		goto unlock;
	}

	rfkill->idx = rfkill_no;/*设置编号*/
	dev_set_name(dev, "rfkill%lu", rfkill_no);/*生成设备名称*/
	rfkill_no++;/*编号增加*/

	list_add_tail(&rfkill->node, &rfkill_list);/*加入链表*/

	error = device_add(dev);/*设备加入系统*/
	if (error)
		goto remove;

	error = rfkill_led_trigger_register(rfkill);
	if (error)
		goto devdel;

	rfkill->registered = true;/*标记已注册*/

	INIT_DELAYED_WORK(&rfkill->poll_work, rfkill_poll);
	INIT_WORK(&rfkill->uevent_work, rfkill_uevent_work);
	INIT_WORK(&rfkill->sync_work, rfkill_sync_work);

	if (rfkill->ops->poll)
		/*有poll回调，poll work入队*/
		queue_delayed_work(system_power_efficient_wq,
			&rfkill->poll_work,
			round_jiffies_relative(POLL_INTERVAL));

	if (!rfkill->persistent || rfkill_epo_lock_active) {
		rfkill->need_sync = true;
		schedule_work(&rfkill->sync_work);
	} else {
#ifdef CONFIG_RFKILL_INPUT
		bool soft_blocked = !!(rfkill->state & RFKILL_BLOCK_SW);

		if (!atomic_read(&rfkill_input_disabled))
			__rfkill_switch_all(rfkill->type, soft_blocked);
#endif
	}

	rfkill_global_led_trigger_event();
	/*触发add事件给rfkill*/
	rfkill_send_events(rfkill, RFKILL_OP_ADD);

	mutex_unlock(&rfkill_global_mutex);
	return 0;

 devdel:
	device_del(&rfkill->dev);
 remove:
	list_del_init(&rfkill->node);
 unlock:
	mutex_unlock(&rfkill_global_mutex);
	return error;
}
EXPORT_SYMBOL(rfkill_register);

void rfkill_unregister(struct rfkill *rfkill)
{
	BUG_ON(!rfkill);

	if (rfkill->ops->poll)
		cancel_delayed_work_sync(&rfkill->poll_work);

	cancel_work_sync(&rfkill->uevent_work);
	cancel_work_sync(&rfkill->sync_work);

	rfkill->registered = false;

	device_del(&rfkill->dev);

	mutex_lock(&rfkill_global_mutex);
	/*触发del事件*/
	rfkill_send_events(rfkill, RFKILL_OP_DEL);
	list_del_init(&rfkill->node);
	rfkill_global_led_trigger_event();
	mutex_unlock(&rfkill_global_mutex);

	rfkill_led_trigger_unregister(rfkill);
}
EXPORT_SYMBOL(rfkill_unregister);

void rfkill_destroy(struct rfkill *rfkill)
{
	if (rfkill)
		put_device(&rfkill->dev);
}
EXPORT_SYMBOL(rfkill_destroy);

static int rfkill_fop_open(struct inode *inode, struct file *file)
{
	struct rfkill_data *data;
	struct rfkill *rfkill;
	struct rfkill_int_event *ev, *tmp;

	/*申请rfkill_data结构体并初始化*/
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->max_size = RFKILL_EVENT_SIZE_V1;

	INIT_LIST_HEAD(&data->events);
	mutex_init(&data->mtx);
	init_waitqueue_head(&data->read_wait);

	mutex_lock(&rfkill_global_mutex);
	/*
	 * start getting events from elsewhere but hold mtx to get
	 * startup events added first
	 */

	list_for_each_entry(rfkill, &rfkill_list, node) {
		ev = kzalloc(sizeof(*ev), GFP_KERNEL);/*申请event*/
		if (!ev)
			goto free;
		rfkill_sync(rfkill);
		rfkill_fill_event(&ev->ev, rfkill, RFKILL_OP_ADD);/*构造add事件*/
		mutex_lock(&data->mtx);
		list_add_tail(&ev->list, &data->events);/*添加此event*/
		mutex_unlock(&data->mtx);
	}
	list_add(&data->list, &rfkill_fds);
	mutex_unlock(&rfkill_global_mutex);

	file->private_data = data;/*设置为文件的私有数据*/

	return stream_open(inode, file);

 free:
	mutex_unlock(&rfkill_global_mutex);
	mutex_destroy(&data->mtx);
	list_for_each_entry_safe(ev, tmp, &data->events, list)
		kfree(ev);
	kfree(data);
	return -ENOMEM;
}

static __poll_t rfkill_fop_poll(struct file *file, poll_table *wait)
{
	struct rfkill_data *data = file->private_data;
	__poll_t res = EPOLLOUT | EPOLLWRNORM;

	poll_wait(file, &data->read_wait, wait);

	mutex_lock(&data->mtx);
	if (!list_empty(&data->events))
		res = EPOLLIN | EPOLLRDNORM;/*events链表不为空，触发IN事件*/
	mutex_unlock(&data->mtx);

	return res;
}

/*读取data->events中下一个struct rfkill_int_event*/
static ssize_t rfkill_fop_read(struct file *file, char __user *buf,
			       size_t count, loff_t *pos)
{
	struct rfkill_data *data = file->private_data;
	struct rfkill_int_event *ev;
	unsigned long sz;
	int ret;

	mutex_lock(&data->mtx);

	while (list_empty(&data->events)) {
		/*events为空，且指明非阻塞，则返回EAGAIN*/
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}
		mutex_unlock(&data->mtx);
		/* since we re-check and it just compares pointers,
		 * using !list_empty() without locking isn't a problem
		 */
		ret = wait_event_interruptible(data->read_wait,
					       !list_empty(&data->events));/*等待data->events链表不为空*/
		mutex_lock(&data->mtx);

		if (ret)
			goto out;
	}

	/*取出event*/
	ev = list_first_entry(&data->events, struct rfkill_int_event,
				list);

	sz = min_t(unsigned long, sizeof(ev->ev), count);
	sz = min_t(unsigned long, sz, data->max_size);
	ret = sz;/*选择合适的大小*/
	if (copy_to_user(buf, &ev->ev, sz))/*复制到用户态*/
		ret = -EFAULT;

	list_del(&ev->list);/*将此event自链表上移除*/
	kfree(ev);
 out:
	mutex_unlock(&data->mtx);
	return ret;
}

static ssize_t rfkill_fop_write(struct file *file, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct rfkill_data *data = file->private_data;
	struct rfkill *rfkill;
	struct rfkill_event_ext ev;
	int ret;

	/* we don't need the 'hard' variable but accept it */
	if (count < RFKILL_EVENT_SIZE_V1 - 1)
		return -EINVAL;/*写和长度无效*/

	/*
	 * Copy as much data as we can accept into our 'ev' buffer,
	 * but tell userspace how much we've copied so it can determine
	 * our API version even in a write() call, if it cares.
	 */
	count = min(count, sizeof(ev));
	count = min_t(size_t, count, data->max_size);
	if (copy_from_user(&ev, buf, count))
		return -EFAULT;/*复制用户态内容出错*/

	if (ev.type >= NUM_RFKILL_TYPES)
		return -EINVAL;/*用户态给定的event type有误*/

	mutex_lock(&rfkill_global_mutex);

	switch (ev.op) {
	case RFKILL_OP_CHANGE_ALL:
		/*变更全局状态*/
		rfkill_update_global_state(ev.type, ev.soft);
		/*遍历所有rfkill,设置block*/
		list_for_each_entry(rfkill, &rfkill_list, node)
			if (rfkill->type == ev.type ||
			    ev.type == RFKILL_TYPE_ALL)
				rfkill_set_block(rfkill, ev.soft);
		ret = 0;
		break;
	case RFKILL_OP_CHANGE:
		/*遍历所有rfkill,针对index一致的，设置block*/
		list_for_each_entry(rfkill, &rfkill_list, node)
			if (rfkill->idx == ev.idx &&
			    (rfkill->type == ev.type ||
			     ev.type == RFKILL_TYPE_ALL))
				rfkill_set_block(rfkill, ev.soft);
		ret = 0;
		break;
	default:
		/*不支持其它op*/
		ret = -EINVAL;
		break;
	}

	mutex_unlock(&rfkill_global_mutex);

	return ret ?: count;
}

static int rfkill_fop_release(struct inode *inode, struct file *file)
{
	struct rfkill_data *data = file->private_data;
	struct rfkill_int_event *ev, *tmp;

	mutex_lock(&rfkill_global_mutex);
	list_del(&data->list);/*自链表中移除*/
	mutex_unlock(&rfkill_global_mutex);

	mutex_destroy(&data->mtx);
	/*释放未读取的所有events*/
	list_for_each_entry_safe(ev, tmp, &data->events, list)
		kfree(ev);

#ifdef CONFIG_RFKILL_INPUT
	if (data->input_handler)
		if (atomic_dec_return(&rfkill_input_disabled) == 0)
			printk(KERN_DEBUG "rfkill: input handler enabled\n");
#endif

	kfree(data);

	return 0;
}

/*rfkill ioctl实现*/
static long rfkill_fop_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct rfkill_data *data = file->private_data;
	int ret = -ENOTTY;
	u32 size;

	if (_IOC_TYPE(cmd) != RFKILL_IOC_MAGIC)
		return -ENOTTY;

	mutex_lock(&data->mtx);
	switch (_IOC_NR(cmd)) {
#ifdef CONFIG_RFKILL_INPUT
	case RFKILL_IOC_NOINPUT:
		if (!data->input_handler) {
			if (atomic_inc_return(&rfkill_input_disabled) == 1)
				printk(KERN_DEBUG "rfkill: input handler disabled\n");
			data->input_handler = true;
		}
		ret = 0;
		break;
#endif
	case RFKILL_IOC_MAX_SIZE:
		if (get_user(size, (__u32 __user *)arg)) {
			ret = -EFAULT;
			break;
		}
		if (size < RFKILL_EVENT_SIZE_V1 || size > U8_MAX) {
			ret = -EINVAL;
			break;
		}
		data->max_size = size;/*设置max size*/
		ret = 0;
		break;
	default:
		break;
	}
	mutex_unlock(&data->mtx);

	return ret;
}

static const struct file_operations rfkill_fops = {
	.owner		= THIS_MODULE,
	.open		= rfkill_fop_open,
	.read		= rfkill_fop_read,
	.write		= rfkill_fop_write,
	.poll		= rfkill_fop_poll,/*等待事件发生*/
	.release	= rfkill_fop_release,
	.unlocked_ioctl	= rfkill_fop_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

#define RFKILL_NAME "rfkill"

static struct miscdevice rfkill_miscdev = {
	.fops	= &rfkill_fops,
	.name	= RFKILL_NAME,/*指定名称*/
	.minor	= RFKILL_MINOR,
};

static int __init rfkill_init(void)
{
	int error;

	rfkill_update_global_state(RFKILL_TYPE_ALL, !rfkill_default_state);

	/*注册rfkill class*/
	error = class_register(&rfkill_class);
	if (error)
		goto error_class;

	/*注册misc设备*/
	error = misc_register(&rfkill_miscdev);
	if (error)
		goto error_misc;

	error = rfkill_global_led_trigger_register();
	if (error)
		goto error_led_trigger;

#ifdef CONFIG_RFKILL_INPUT
	error = rfkill_handler_init();
	if (error)
		goto error_input;
#endif

	return 0;

#ifdef CONFIG_RFKILL_INPUT
error_input:
	rfkill_global_led_trigger_unregister();
#endif
error_led_trigger:
	misc_deregister(&rfkill_miscdev);
error_misc:
	class_unregister(&rfkill_class);
error_class:
	return error;
}
subsys_initcall(rfkill_init);

static void __exit rfkill_exit(void)
{
#ifdef CONFIG_RFKILL_INPUT
	rfkill_handler_exit();
#endif
	rfkill_global_led_trigger_unregister();
	misc_deregister(&rfkill_miscdev);
	class_unregister(&rfkill_class);
}
module_exit(rfkill_exit);

MODULE_ALIAS_MISCDEV(RFKILL_MINOR);
MODULE_ALIAS("devname:" RFKILL_NAME);
