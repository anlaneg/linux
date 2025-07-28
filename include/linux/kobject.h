// SPDX-License-Identifier: GPL-2.0
/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2008 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2008 Novell Inc.
 *
 * Please read Documentation/core-api/kobject.rst before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors.
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/kobject_ns.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/uidgid.h>

#define UEVENT_HELPER_PATH_LEN		256
#define UEVENT_NUM_ENVP			64	/* number of env pointers */
#define UEVENT_BUFFER_SIZE		2048	/* buffer for the variables */

#ifdef CONFIG_UEVENT_HELPER
/* path to the userspace helper executed on an event */
extern char uevent_helper[];
#endif

/* counter to tag the uevent, read only except for the kobject core */
extern atomic64_t uevent_seqnum;

/*
 * The actions here must match the index to the string array
 * in lib/kobject_uevent.c
 *
 * Do not add new actions here without checking with the driver-core
 * maintainers. Action strings are not meant to express subsystem
 * or device specific properties. In most cases you want to send a
 * kobject_uevent_env(kobj, KOBJ_CHANGE, env) with additional event
 * specific variables added to the event environment.
 */
enum kobject_action {
	KOBJ_ADD,
	KOBJ_REMOVE,
	KOBJ_CHANGE,
	KOBJ_MOVE,
	KOBJ_ONLINE,
	KOBJ_OFFLINE,
	KOBJ_BIND,
	KOBJ_UNBIND,
};

struct kobject {
    /* kobject对象的名字，对应sysfs中的目录名 */
	const char		*name;
	//用于挂接成链，例如挂接给kset
	struct list_head	entry;
	/* 用于构建sysfs中kobjects的层次结构，指向父目录 */
	struct kobject		*parent;
	/*此kobject从属的kset*/
	struct kset		*kset;
	//kobj对应的ktype(可约定一组公共的attr,groups)
	const struct kobj_type	*ktype;
	//其在sysfs中对应的node
	struct kernfs_node	*sd; /* sysfs directory entry */
	struct kref		kref;/* kobject的引用计数，初始值为1 */

	unsigned int state_initialized:1;/* kobject是否初始化，由kobject_init()设置 */
	unsigned int state_in_sysfs:1;/* 是否已添加到sysfs层次结构中 */
	unsigned int state_add_uevent_sent:1;
	unsigned int state_remove_uevent_sent:1;
	unsigned int uevent_suppress:1;//此obj是否要求抑制uevent

#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	struct delayed_work	release;
#endif
};

__printf(2, 3) int kobject_set_name(struct kobject *kobj, const char *name, ...);
__printf(2, 0) int kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
	return kobj->name;
}

void kobject_init(struct kobject *kobj, const struct kobj_type *ktype);
__printf(3, 4) __must_check int kobject_add(struct kobject *kobj,
					    struct kobject *parent,
					    const char *fmt, ...);
__printf(4, 5) __must_check int kobject_init_and_add(struct kobject *kobj,
						     const struct kobj_type *ktype,
						     struct kobject *parent,
						     const char *fmt, ...);

void kobject_del(struct kobject *kobj);

struct kobject * __must_check kobject_create_and_add(const char *name, struct kobject *parent);

int __must_check kobject_rename(struct kobject *, const char *new_name);
int __must_check kobject_move(struct kobject *, struct kobject *);

struct kobject *kobject_get(struct kobject *kobj);
struct kobject * __must_check kobject_get_unless_zero(struct kobject *kobj);
void kobject_put(struct kobject *kobj);

const void *kobject_namespace(const struct kobject *kobj);
void kobject_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid);
char *kobject_get_path(const struct kobject *kobj, gfp_t flag);

//定义kobj的类型
struct kobj_type {
	void (*release)(struct kobject *kobj);
	//显示某个属性时，或者设置某个属性时的操作集
	const struct sysfs_ops *sysfs_ops;
	//所有默认group(会被处理成目录及子文件）
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations *(*child_ns_type)(const struct kobject *kobj);
	const void *(*namespace)(const struct kobject *kobj);
	//获取kobj对应uid,gid
	void (*get_ownership)(const struct kobject *kobj, kuid_t *uid, kgid_t *gid);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[UEVENT_NUM_ENVP];//记录环境变量各变量字符串起始位置
	int envp_idx;//记录环境变量总数
	//存放所有环境变量字符串
	char buf[UEVENT_BUFFER_SIZE];
	int buflen;//buffer的使用长度
};

struct kset_uevent_ops {
	//检查kobj对应的event是否可以不向userspace通告（返回0，不通告）
	int (* const filter)(const struct kobject *kobj);
	//返回kobject对应的subsystem
	const char *(* const name)(const struct kobject *kobj);
	//返回kobject特别需要的env添加
	int (* const uevent)(const struct kobject *kobj, struct kobj_uevent_env *env);
};

struct kobj_attribute {
	struct attribute attr;
	//显示函数
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf);
	//设置函数
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
};

extern const struct sysfs_ops kobj_sysfs_ops;

struct sock;

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
struct kset {
	struct list_head list;
	spinlock_t list_lock;//保护list成员
	struct kobject kobj;
	/*uevent操作集*/
	const struct kset_uevent_ops *uevent_ops;
} __randomize_layout;

void kset_init(struct kset *kset);
int __must_check kset_register(struct kset *kset);
void kset_unregister(struct kset *kset);
struct kset * __must_check kset_create_and_add(const char *name, const struct kset_uevent_ops *u,
					       struct kobject *parent_kobj);

static inline struct kset *to_kset(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

static inline struct kset *kset_get(struct kset *k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset *k)
{
	kobject_put(&k->kobj);
}

//kobj对应的类别（一组kobj具有相同的type)
static inline const struct kobj_type *get_ktype(const struct kobject *kobj)
{
	return kobj->ktype;
}

struct kobject *kset_find_obj(struct kset *, const char *);

/* The global /sys/kernel/ kobject for people to chain off of */
extern struct kobject *kernel_kobj;
/* The global /sys/kernel/mm/ kobject for people to chain off of */
extern struct kobject *mm_kobj;
/* The global /sys/hypervisor/ kobject for people to chain off of */
extern struct kobject *hypervisor_kobj;
/* The global /sys/power/ kobject for people to chain off of */
extern struct kobject *power_kobj;
/* The global /sys/firmware/ kobject for people to chain off of */
extern struct kobject *firmware_kobj;

int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
			char *envp[]);
int kobject_synth_uevent(struct kobject *kobj, const char *buf, size_t count);

__printf(2, 3)
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...);

#endif /* _KOBJECT_H_ */
