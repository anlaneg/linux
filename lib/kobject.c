// SPDX-License-Identifier: GPL-2.0
/*
 * kobject.c - library routines for handling generic kernel objects
 *
 * Copyright (c) 2002-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2006-2007 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2007 Novell Inc.
 *
 * Please see the file Documentation/core-api/kobject.rst for critical information
 * about using the kobject interface.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/random.h>

/**
 * kobject_namespace() - Return @kobj's namespace tag.
 * @kobj: kobject in question
 *
 * Returns namespace tag of @kobj if its parent has namespace ops enabled
 * and thus @kobj should have a namespace tag associated with it.  Returns
 * %NULL otherwise.
 */
const void *kobject_namespace(const struct kobject *kobj)
{
	const struct kobj_ns_type_operations *ns_ops = kobj_ns_ops(kobj);

	if (!ns_ops || ns_ops->type == KOBJ_NS_TYPE_NONE)
		return NULL;

	return kobj->ktype->namespace(kobj);
}

/**
 * kobject_get_ownership() - Get sysfs ownership data for @kobj.
 * @kobj: kobject in question
 * @uid: kernel user ID for sysfs objects
 * @gid: kernel group ID for sysfs objects
 *
 * Returns initial uid/gid pair that should be used when creating sysfs
 * representation of given kobject. Normally used to adjust ownership of
 * objects in a container.
 */
void kobject_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid)
{
	*uid = GLOBAL_ROOT_UID;
	*gid = GLOBAL_ROOT_GID;

	//取kobj对应的uid,gid
	if (kobj->ktype->get_ownership)
		kobj->ktype->get_ownership(kobj, uid, gid);
}

static bool kobj_ns_type_is_valid(enum kobj_ns_type type)
{
	if ((type <= KOBJ_NS_TYPE_NONE) || (type >= KOBJ_NS_TYPES))
		return false;

	return true;
}

//创建kobj对应的目录,kobj对应的ktype指明的属性及group
static int create_dir(struct kobject *kobj)
{
	const struct kobj_type *ktype = get_ktype(kobj);
	const struct kobj_ns_type_operations *ops;
	int error;

	//创建目录
	error = sysfs_create_dir_ns(kobj, kobject_namespace(kobj));
	if (error)
		return error;

	//创建ktype->default_groups对应的目录及属性
	error = sysfs_create_groups(kobj, ktype->default_groups);
	if (error) {
		sysfs_remove_dir(kobj);
		return error;
	}

	/*
	 * @kobj->sd may be deleted by an ancestor going away.  Hold an
	 * extra reference so that it stays until @kobj is gone.
	 */
	sysfs_get(kobj->sd);

	/*
	 * If @kobj has ns_ops, its children need to be filtered based on
	 * their namespace tags.  Enable namespace support on @kobj->sd.
	 */
	ops = kobj_child_ns_ops(kobj);
	if (ops) {
		BUG_ON(!kobj_ns_type_is_valid(ops->type));
		BUG_ON(!kobj_ns_type_registered(ops->type));

		sysfs_enable_ns(kobj->sd);
	}

	return 0;
}

//返回kobj到顶层目录的文件路径长度
static int get_kobj_path_length(const struct kobject *kobj)
{
	int length = 1;
	const struct kobject *parent = kobj;

	/* walk up the ancestors until we hit the one pointing to the
	 * root.
	 * Add 1 to strlen for leading '/' of each level.
	 */
	do {
        //通过递归调用kobject_name来计算从当前文件到
        //父节点的名称长度以（每过一次+1来表示'/')
		if (kobject_name(parent) == NULL)
			return 0;
		length += strlen(kobject_name(parent)) + 1;
		parent = parent->parent;
	} while (parent);
	return length;
}

//填充kobj的路径，这个函数要求path足够大
static int fill_kobj_path(const struct kobject *kobj, char *path, int length)
{
	const struct kobject *parent;

	--length;//跳过'\0'
    //由于自底向上遍历，故填充时，自尾向头填充字符串
	for (parent = kobj; parent; parent = parent->parent) {
		int cur = strlen(kobject_name(parent));
		/* back up enough to print this name with '/' */
		length -= cur;
		if (length <= 0)
			return -EINVAL;
		memcpy(path + length, kobject_name(parent), cur);
		*(path + --length) = '/';
	}

	pr_debug("'%s' (%p): %s: path = '%s'\n", kobject_name(kobj),
		 kobj, __func__, path);

	return 0;
}

/**
 * kobject_get_path() - Allocate memory and fill in the path for @kobj.
 * @kobj:	kobject in question, with which to build the path
 * @gfp_mask:	the allocation type used to allocate the path
 *
 * Return: The newly allocated memory, caller must free with kfree().
 */
char *kobject_get_path(const struct kobject *kobj, gfp_t gfp_mask)
{
	char *path;
	int len;

retry:
    	//取kobj路径长度
	len = get_kobj_path_length(kobj);
	if (len == 0)
		return NULL;
    //申请足够内存
	path = kzalloc(len, gfp_mask);
	if (!path)
		return NULL;
    	//填充kobj路径到path
	if (fill_kobj_path(kobj, path, len)) {
		kfree(path);
		goto retry;
	}

    //返回填充后结果
	return path;
}
EXPORT_SYMBOL_GPL(kobject_get_path);

/* add the kobject to its kset's list */
//将kobj加入到它所属的kset
static void kobj_kset_join(struct kobject *kobj)
{
	if (!kobj->kset)
		//不属于kset，跳出
		return;

	kset_get(kobj->kset);
	spin_lock(&kobj->kset->list_lock);
	//kobj挂接到kset
	list_add_tail(&kobj->entry, &kobj->kset->list);
	spin_unlock(&kobj->kset->list_lock);
}

/* remove the kobject from its kset's list */
//将kobj自其所属的kset上移除
static void kobj_kset_leave(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	spin_lock(&kobj->kset->list_lock);
	list_del_init(&kobj->entry);
	spin_unlock(&kobj->kset->list_lock);
	kset_put(kobj->kset);
}

//kobject初始化
static void kobject_init_internal(struct kobject *kobj)
{
	if (!kobj)
		return;
	kref_init(&kobj->kref);
	INIT_LIST_HEAD(&kobj->entry);
	kobj->state_in_sysfs = 0;
	kobj->state_add_uevent_sent = 0;
	kobj->state_remove_uevent_sent = 0;
	kobj->state_initialized = 1;//标记已初始化
}

//kobject加入sysfs系统时的内部实现（将为kobj创建目录）
static int kobject_add_internal(struct kobject *kobj)
{
	int error = 0;
	struct kobject *parent;

	if (!kobj)
		return -ENOENT;

    //kobj必须要有名称
	if (!kobj->name || !kobj->name[0]) {
		WARN(1,
		     "kobject: (%p): attempted to be registered with empty name!\n",
		     kobj);
		return -EINVAL;
	}

	//kobj对应的父节点
	parent = kobject_get(kobj->parent);

	/* join kset if set, use it as parent if we do not already have one */
	if (kobj->kset) {
		//如果kobj从属于kset,则其父节点为kobj->kset本身
		if (!parent)
			parent = kobject_get(&kobj->kset->kobj);
		kobj_kset_join(kobj);
		kobj->parent = parent;
	}

	pr_debug("'%s' (%p): %s: parent: '%s', set: '%s'\n",
		 kobject_name(kobj), kobj, __func__,
		 parent ? kobject_name(parent) : "<NULL>",
		 kobj->kset ? kobject_name(&kobj->kset->kobj) : "<NULL>");

    //创建kobj所属的目录
	error = create_dir(kobj);
	if (error) {
		//创建失败，告警
		kobj_kset_leave(kobj);
		kobject_put(parent);
		kobj->parent = NULL;

		/* be noisy on error issues */
		if (error == -EEXIST)
			pr_err("%s failed for %s with -EEXIST, don't try to register things with the same name in the same directory.\n",
			       __func__, kobject_name(kobj));
		else
			pr_err("%s failed for %s (error: %d parent: %s)\n",
			       __func__, kobject_name(kobj), error,
			       parent ? kobject_name(parent) : "'none'");
	} else
		//标明此kobj已被加入到sysfs中了
		kobj->state_in_sysfs = 1;

	return error;
}

/**
 * kobject_set_name_vargs() - Set the name of a kobject.
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 * @vargs: vargs to format the string.
 */
//设置kobj名称
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs)
{
	const char *s;

	if (kobj->name && !fmt)
		return 0;

    //格式化字符串
	s = kvasprintf_const(GFP_KERNEL, fmt, vargs);
	if (!s)
		return -ENOMEM;

	/*
	 * ewww... some of these buggers have '/' in the name ... If
	 * that's the case, we need to make sure we have an actual
	 * allocated copy to modify, since kvasprintf_const may have
	 * returned something from .rodata.
	 */
    //如果字符串含有'/',则将其更换为'!'
	if (strchr(s, '/')) {
		char *t;

		t = kstrdup(s, GFP_KERNEL);
		kfree_const(s);
		if (!t)
			return -ENOMEM;
		s = strreplace(t, '/', '!');
	}
	kfree_const(kobj->name);
	kobj->name = s;//设置kobj的名称

	return 0;
}

/**
 * kobject_set_name() - Set the name of a kobject.
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 *
 * This sets the name of the kobject.  If you have already added the
 * kobject to the system, you must call kobject_rename() in order to
 * change the name of the kobject.
 */
int kobject_set_name(struct kobject *kobj, const char *fmt, ...)
{
    //采用格式化串设置kobj->name
	va_list vargs;
	int retval;

	va_start(vargs, fmt);
	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	va_end(vargs);

	return retval;
}
EXPORT_SYMBOL(kobject_set_name);

/**
 * kobject_init() - Initialize a kobject structure.
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 *
 * This function will properly initialize a kobject such that it can then
 * be passed to the kobject_add() call.
 *
 * After this function is called, the kobject MUST be cleaned up by a call
 * to kobject_put(), not by a call to kfree directly to ensure that all of
 * the memory is cleaned up properly.
 */
//初始化一个kobj
void kobject_init(struct kobject *kobj, const struct kobj_type *ktype/*object对应的type*/)
{
	char *err_str;

    //参数检查
	if (!kobj) {
		err_str = "invalid kobject pointer!";
		goto error;
	}
	//必须指定type
	if (!ktype) {
		err_str = "must have a ktype to be initialized properly!\n";
		goto error;
	}

    //已执行过初始化，报错
	if (kobj->state_initialized) {
		/* do not error out as sometimes we can recover */
		pr_err("kobject (%p): tried to init an initialized object, something is seriously wrong.\n",
		       kobj);
		dump_stack_lvl(KERN_ERR);
	}

	//进行初始化
	kobject_init_internal(kobj);
	//指定kobj的ktype
	kobj->ktype = ktype;
	return;

error:
	pr_err("kobject (%p): %s\n", kobj, err_str);
	dump_stack_lvl(KERN_ERR);
}
EXPORT_SYMBOL(kobject_init);

//kobj添加，通过格式化名称及父节点填加
static __printf(3, 0) int kobject_add_varg(struct kobject *kobj,
					   struct kobject *parent,
					   const char *fmt, va_list vargs)
{
	int retval;

    //格式化kobj的name
	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	if (retval) {
		pr_err("can not set name properly!\n");
		return retval;
	}
	//设置obj对应的父节点
	kobj->parent = parent;
	//创建obj对应的目录
	return kobject_add_internal(kobj);
}

/**
 * kobject_add() - The main kobject add function.
 * @kobj: the kobject to add
 * @parent: pointer to the parent of the kobject.
 * @fmt: format to name the kobject with.
 *
 * The kobject name is set and added to the kobject hierarchy in this
 * function.
 *
 * If @parent is set, then the parent of the @kobj will be set to it.
 * If @parent is NULL, then the parent of the @kobj will be set to the
 * kobject associated with the kset assigned to this kobject.  If no kset
 * is assigned to the kobject, then the kobject will be located in the
 * root of the sysfs tree.
 *
 * Note, no "add" uevent will be created with this call, the caller should set
 * up all of the necessary sysfs files for the object and then call
 * kobject_uevent() with the UEVENT_ADD parameter to ensure that
 * userspace is properly notified of this kobject's creation.
 *
 * Return: If this function returns an error, kobject_put() must be
 *         called to properly clean up the memory associated with the
 *         object.  Under no instance should the kobject that is passed
 *         to this function be directly freed with a call to kfree(),
 *         that can leak memory.
 *
 *         If this function returns success, kobject_put() must also be called
 *         in order to properly clean up the memory associated with the object.
 *
 *         In short, once this function is called, kobject_put() MUST be called
 *         when the use of the object is finished in order to properly free
 *         everything.
 */
//初始化之后，通过kobject_add()将kobj添加到系统中
//这个函数给kobj指定一个名字，这个名字也就是其在sysfs中的目录名，
//parent用来指明kobj的父节点，即指定了kobj的目录在sysfs中创建的位置。
//如果这个kobj要加入到一个特定的kset中，则在kobject_add()必须给kobj->kset赋值，
//此时parent可以设置为NULL，这样kobj会自动将kobj->kset对应的对象作为自己的parent。
//如果parent设置为NULL，且没有加入到一个kset中，kobject会被创建到/sys顶层目录下。
int kobject_add(struct kobject *kobj, struct kobject *parent,
		const char *fmt, ...)
{
	va_list args;
	int retval;

	if (!kobj)
		return -EINVAL;

    //必须已初始化,否则报错
	if (!kobj->state_initialized) {
		pr_err("kobject '%s' (%p): tried to add an uninitialized object, something is seriously wrong.\n",
		       kobject_name(kobj), kobj);
		dump_stack_lvl(KERN_ERR);
		return -EINVAL;
	}

    //格式化kobj名称
	va_start(args, fmt);
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}
EXPORT_SYMBOL(kobject_add);

/**
 * kobject_init_and_add() - Initialize a kobject structure and add it to
 *                          the kobject hierarchy.
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 * @parent: pointer to the parent of this kobject.
 * @fmt: the name of the kobject.
 *
 * This function combines the call to kobject_init() and kobject_add().
 *
 * If this function returns an error, kobject_put() must be called to
 * properly clean up the memory associated with the object.  This is the
 * same type of error handling after a call to kobject_add() and kobject
 * lifetime rules are the same here.
 */
int kobject_init_and_add(struct kobject *kobj, const struct kobj_type *ktype/*obj类型*/,
			 struct kobject *parent/*obj父节点*/, const char *fmt/*obj名称格式串*/, ...)
{
	va_list args;
	int retval;

	kobject_init(kobj, ktype);

	va_start(args, fmt);
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}
EXPORT_SYMBOL_GPL(kobject_init_and_add);

/**
 * kobject_rename() - Change the name of an object.
 * @kobj: object in question.
 * @new_name: object's new name
 *
 * It is the responsibility of the caller to provide mutual
 * exclusion between two different calls of kobject_rename
 * on the same kobject and to ensure that new_name is valid and
 * won't conflict with other kobjects.
 */
int kobject_rename(struct kobject *kobj, const char *new_name)
{
	int error = 0;
	const char *devpath = NULL;
	const char *dup_name = NULL, *name;
	char *devpath_string = NULL;
	char *envp[2];

	kobj = kobject_get(kobj);
	if (!kobj)
		return -EINVAL;
	if (!kobj->parent) {
		kobject_put(kobj);
		return -EINVAL;
	}

	devpath = kobject_get_path(kobj, GFP_KERNEL);
	if (!devpath) {
		error = -ENOMEM;
		goto out;
	}
	devpath_string = kmalloc(strlen(devpath) + 15, GFP_KERNEL);
	if (!devpath_string) {
		error = -ENOMEM;
		goto out;
	}
	sprintf(devpath_string, "DEVPATH_OLD=%s", devpath);
	envp[0] = devpath_string;
	envp[1] = NULL;

	name = dup_name = kstrdup_const(new_name, GFP_KERNEL);
	if (!name) {
		error = -ENOMEM;
		goto out;
	}

	error = sysfs_rename_dir_ns(kobj, new_name, kobject_namespace(kobj));
	if (error)
		goto out;

	/* Install the new kobject name */
	dup_name = kobj->name;
	kobj->name = name;

	/* This function is mostly/only used for network interface.
	 * Some hotplug package track interfaces by their name and
	 * therefore want to know when the name is changed by the user. */
	kobject_uevent_env(kobj, KOBJ_MOVE, envp);

out:
	kfree_const(dup_name);
	kfree(devpath_string);
	kfree(devpath);
	kobject_put(kobj);

	return error;
}
EXPORT_SYMBOL_GPL(kobject_rename);

/**
 * kobject_move() - Move object to another parent.
 * @kobj: object in question.
 * @new_parent: object's new parent (can be NULL)
 */
int kobject_move(struct kobject *kobj, struct kobject *new_parent)
{
	int error;
	struct kobject *old_parent;
	const char *devpath = NULL;
	char *devpath_string = NULL;
	char *envp[2];

	kobj = kobject_get(kobj);
	if (!kobj)
		return -EINVAL;
	new_parent = kobject_get(new_parent);
	if (!new_parent) {
		if (kobj->kset)
			new_parent = kobject_get(&kobj->kset->kobj);
	}

	/* old object path */
	devpath = kobject_get_path(kobj, GFP_KERNEL);
	if (!devpath) {
		error = -ENOMEM;
		goto out;
	}
	devpath_string = kmalloc(strlen(devpath) + 15, GFP_KERNEL);
	if (!devpath_string) {
		error = -ENOMEM;
		goto out;
	}
	sprintf(devpath_string, "DEVPATH_OLD=%s", devpath);
	envp[0] = devpath_string;
	envp[1] = NULL;
	error = sysfs_move_dir_ns(kobj, new_parent, kobject_namespace(kobj));
	if (error)
		goto out;
	old_parent = kobj->parent;
	kobj->parent = new_parent;
	new_parent = NULL;
	kobject_put(old_parent);
	kobject_uevent_env(kobj, KOBJ_MOVE, envp);
out:
	kobject_put(new_parent);
	kobject_put(kobj);
	kfree(devpath_string);
	kfree(devpath);
	return error;
}
EXPORT_SYMBOL_GPL(kobject_move);

static void __kobject_del(struct kobject *kobj)
{
	struct kernfs_node *sd;
	const struct kobj_type *ktype;

	sd = kobj->sd;
	ktype = get_ktype(kobj);

	sysfs_remove_groups(kobj, ktype->default_groups);

	/* send "remove" if the caller did not do it but sent "add" */
	if (kobj->state_add_uevent_sent && !kobj->state_remove_uevent_sent) {
		pr_debug("'%s' (%p): auto cleanup 'remove' event\n",
			 kobject_name(kobj), kobj);
		kobject_uevent(kobj, KOBJ_REMOVE);
	}

	sysfs_remove_dir(kobj);
	sysfs_put(sd);

	kobj->state_in_sysfs = 0;
	kobj_kset_leave(kobj);
	kobj->parent = NULL;
}

/**
 * kobject_del() - Unlink kobject from hierarchy.
 * @kobj: object.
 *
 * This is the function that should be called to delete an object
 * successfully added via kobject_add().
 */
void kobject_del(struct kobject *kobj)
{
	struct kobject *parent;

	if (!kobj)
		return;

	parent = kobj->parent;
	__kobject_del(kobj);
	kobject_put(parent);
}
EXPORT_SYMBOL(kobject_del);

/**
 * kobject_get() - Increment refcount for object.
 * @kobj: object.
 */
//增加引用计数（如果kobj不为NULL时）
struct kobject *kobject_get(struct kobject *kobj)
{
	if (kobj) {
		if (!kobj->state_initialized)
			WARN(1, KERN_WARNING
				"kobject: '%s' (%p): is not initialized, yet kobject_get() is being called.\n",
			     kobject_name(kobj), kobj);
		//增加kobj的引用计数
		kref_get(&kobj->kref);
	}
	return kobj;
}
EXPORT_SYMBOL(kobject_get);

struct kobject * __must_check kobject_get_unless_zero(struct kobject *kobj)
{
	if (!kobj)
		return NULL;
	if (!kref_get_unless_zero(&kobj->kref))
		kobj = NULL;
	return kobj;
}
EXPORT_SYMBOL(kobject_get_unless_zero);

/*
 * kobject_cleanup - free kobject resources.
 * @kobj: object to cleanup
 */
static void kobject_cleanup(struct kobject *kobj)
{
	struct kobject *parent = kobj->parent;
	const struct kobj_type *t = get_ktype(kobj);
	const char *name = kobj->name;

	pr_debug("'%s' (%p): %s, parent %p\n",
		 kobject_name(kobj), kobj, __func__, kobj->parent);

	/* remove from sysfs if the caller did not do it */
	if (kobj->state_in_sysfs) {
		pr_debug("'%s' (%p): auto cleanup kobject_del\n",
			 kobject_name(kobj), kobj);
		__kobject_del(kobj);
	} else {
		/* avoid dropping the parent reference unnecessarily */
		parent = NULL;
	}

	if (t->release) {
		pr_debug("'%s' (%p): calling ktype release\n",
			 kobject_name(kobj), kobj);
		t->release(kobj);
	} else {
		pr_debug("'%s' (%p): does not have a release() function, it is broken and must be fixed. See Documentation/core-api/kobject.rst.\n",
			 kobject_name(kobj), kobj);
	}

	/* free name if we allocated it */
	if (name) {
		pr_debug("'%s': free name\n", name);
		kfree_const(name);
	}

	kobject_put(parent);
}

#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
static void kobject_delayed_cleanup(struct work_struct *work)
{
	kobject_cleanup(container_of(to_delayed_work(work),
				     struct kobject, release));
}
#endif

static void kobject_release(struct kref *kref)
{
	struct kobject *kobj = container_of(kref, struct kobject, kref);
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	unsigned long delay = HZ + HZ * get_random_u32_below(4);
	pr_info("'%s' (%p): %s, parent %p (delayed %ld)\n",
		kobject_name(kobj), kobj, __func__, kobj->parent, delay);
	INIT_DELAYED_WORK(&kobj->release, kobject_delayed_cleanup);

	schedule_delayed_work(&kobj->release, delay);
#else
	kobject_cleanup(kobj);
#endif
}

/**
 * kobject_put() - Decrement refcount for object.
 * @kobj: object.
 *
 * Decrement the refcount, and if 0, call kobject_cleanup().
 */
void kobject_put(struct kobject *kobj)
{
	if (kobj) {
		if (!kobj->state_initialized)
			WARN(1, KERN_WARNING
				"kobject: '%s' (%p): is not initialized, yet kobject_put() is being called.\n",
			     kobject_name(kobj), kobj);
		//如果引用计数减为0，则调用kobject_release完成对象释放
		kref_put(&kobj->kref, kobject_release);
	}
}
EXPORT_SYMBOL(kobject_put);

static void dynamic_kobj_release(struct kobject *kobj)
{
	pr_debug("(%p): %s\n", kobj, __func__);
	kfree(kobj);
}

static const struct kobj_type dynamic_kobj_ktype = {
	.release	= dynamic_kobj_release,
	.sysfs_ops	= &kobj_sysfs_ops,
};

/**
 * kobject_create() - Create a struct kobject dynamically.
 *
 * This function creates a kobject structure dynamically and sets it up
 * to be a "dynamic" kobject with a default release function set up.
 *
 * If the kobject was not able to be created, NULL will be returned.
 * The kobject structure returned from here must be cleaned up with a
 * call to kobject_put() and not kfree(), as kobject_init() has
 * already been called on this structure.
 */
static struct kobject *kobject_create(void)
{
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return NULL;

	kobject_init(kobj, &dynamic_kobj_ktype);
	return kobj;
}

/**
 * kobject_create_and_add() - Create a struct kobject dynamically and
 *                            register it with sysfs.
 * @name: the name for the kobject
 * @parent: the parent kobject of this kobject, if any.
 *
 * This function creates a kobject structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kobject_put() and the structure will be dynamically freed when
 * it is no longer being used.
 *
 * If the kobject was not able to be created, NULL will be returned.
 */
//创建一个新的kobj,并将其添加在parent下
struct kobject *kobject_create_and_add(const char *name, struct kobject *parent/*parent为NULL时,取sysfs_root_kn，常见为/sys/*/)
{
	struct kobject *kobj;
	int retval;

	kobj = kobject_create();
	if (!kobj)
		return NULL;

	retval = kobject_add(kobj, parent, "%s", name);
	if (retval) {
		pr_warn("%s: kobject_add error: %d\n", __func__, retval);
		kobject_put(kobj);
		kobj = NULL;
	}
	return kobj;
}
EXPORT_SYMBOL_GPL(kobject_create_and_add);

/**
 * kset_init() - Initialize a kset for use.
 * @k: kset
 */
void kset_init(struct kset *k)
{
	kobject_init_internal(&k->kobj);
	INIT_LIST_HEAD(&k->list);
	spin_lock_init(&k->list_lock);
}

//kobj属性显示函数
/* default kobject attribute operations */
static ssize_t kobj_attr_show(struct kobject *kobj/*kobj_attribute类型*/, struct attribute *attr/*访问的属性*/,
			      char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	//转为kobj_attrbute后，调用show函数完成显示
	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

//kobj属性设置函数
static ssize_t kobj_attr_store(struct kobject *kobj/*kobj_attribute类型*/, struct attribute *attr,
			       const char *buf, size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

/*定义kobj默认的sysfs操作符*/
const struct sysfs_ops kobj_sysfs_ops = {
	.show	= kobj_attr_show,
	.store	= kobj_attr_store,
};
EXPORT_SYMBOL_GPL(kobj_sysfs_ops);

/**
 * kset_register() - Initialize and add a kset.
 * @k: kset.
 *
 * NOTE: On error, the kset.kobj.name allocated by() kobj_set_name()
 * is freed, it can not be used any more.
 */
//会导致创建kset对应的目录，并通知kobj_add事件
int kset_register(struct kset *k)
{
	int err;

	if (!k)
		return -EINVAL;

	if (!k->kobj.ktype) {
		pr_err("must have a ktype to be initialized properly!\n");
		return -EINVAL;
	}

	kset_init(k);
	err = kobject_add_internal(&k->kobj);
	if (err) {
		kfree_const(k->kobj.name);
		/* Set it to NULL to avoid accessing bad pointer in callers. */
		k->kobj.name = NULL;
		return err;
	}
	kobject_uevent(&k->kobj, KOBJ_ADD);
	return 0;
}
EXPORT_SYMBOL(kset_register);

/**
 * kset_unregister() - Remove a kset.
 * @k: kset.
 */
void kset_unregister(struct kset *k)
{
	if (!k)
		return;
	kobject_del(&k->kobj);
	kobject_put(&k->kobj);
}
EXPORT_SYMBOL(kset_unregister);

/**
 * kset_find_obj() - Search for object in kset.
 * @kset: kset we're looking in.
 * @name: object's name.
 *
 * Lock kset via @kset->subsys, and iterate over @kset->list,
 * looking for a matching kobject. If matching object is found
 * take a reference and return the object.
 */
//实现kset中元素查找（通过名称查找）
struct kobject *kset_find_obj(struct kset *kset, const char *name)
{
	struct kobject *k;
	struct kobject *ret = NULL;

	spin_lock(&kset->list_lock);

	list_for_each_entry(k, &kset->list, entry) {
		if (kobject_name(k) && !strcmp(kobject_name(k), name)) {
			ret = kobject_get_unless_zero(k);
			break;//找到了对应的kobject,返回
		}
	}

	spin_unlock(&kset->list_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(kset_find_obj);

//kset节点释放函数
static void kset_release(struct kobject *kobj)
{
	struct kset *kset = container_of(kobj, struct kset, kobj);
	pr_debug("'%s' (%p): %s\n",
		 kobject_name(kobj), kobj, __func__);
	kfree(kset);
}

static void kset_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid)
{
	if (kobj->parent)
		kobject_get_ownership(kobj->parent, uid, gid);
}

//定义kset类型（的kobj)
static const struct kobj_type kset_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,//kset的sysfs操作集
	.release	= kset_release,
	.get_ownership	= kset_get_ownership,
};

/**
 * kset_create() - Create a struct kset dynamically.
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically.  This structure can
 * then be registered with the system and show up in sysfs with a call to
 * kset_register().  When you are finished with this structure, if
 * kset_register() has been called, call kset_unregister() and the
 * structure will be dynamically freed when it is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
static struct kset *kset_create(const char *name/*kset名称*/,
				const struct kset_uevent_ops *uevent_ops/*kset对应的uevent操作集*/,
				struct kobject *parent_kobj/*kset对应的父kobj*/)
{
	struct kset *kset;
	int retval;

	kset = kzalloc(sizeof(*kset), GFP_KERNEL);
	if (!kset)
		return NULL;

	//设置kset对应kobj名称
	retval = kobject_set_name(&kset->kobj, "%s", name);
	if (retval) {
		kfree(kset);
		return NULL;
	}

	//kset对应的udevent操作集
	kset->uevent_ops = uevent_ops;
	kset->kobj.parent = parent_kobj;

	/*
	 * The kobject of this kset will have a type of kset_ktype and belong to
	 * no kset itself.  That way we can properly free it when it is
	 * finished being used.
	 */
	kset->kobj.ktype = &kset_ktype;
	kset->kobj.kset = NULL;

	return kset;
}

/**
 * kset_create_and_add() - Create a struct kset dynamically and add it to sysfs.
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kset_unregister() and the structure will be dynamically freed when it
 * is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
//创建名称为$name的keyset
struct kset *kset_create_and_add(const char *name,
				 const struct kset_uevent_ops *uevent_ops,
				 struct kobject *parent_kobj/*kset对应的父kobject*/)
{
	struct kset *kset;
	int error;

	//创建名称为name的keyset,指明其父kobj
	kset = kset_create(name, uevent_ops, parent_kobj);
	if (!kset)
		return NULL;

	//创建$name的目录
	error = kset_register(kset);
	if (error) {
		kfree(kset);
		return NULL;
	}
	return kset;
}
EXPORT_SYMBOL_GPL(kset_create_and_add);


static DEFINE_SPINLOCK(kobj_ns_type_lock);
static const struct kobj_ns_type_operations *kobj_ns_ops_tbl[KOBJ_NS_TYPES];

int kobj_ns_type_register(const struct kobj_ns_type_operations *ops)
{
	enum kobj_ns_type type = ops->type;
	int error;

	spin_lock(&kobj_ns_type_lock);

	error = -EINVAL;
	if (!kobj_ns_type_is_valid(type))
		goto out;

	error = -EBUSY;
	if (kobj_ns_ops_tbl[type])
		goto out;

	error = 0;
	kobj_ns_ops_tbl[type] = ops;

out:
	spin_unlock(&kobj_ns_type_lock);
	return error;
}

int kobj_ns_type_registered(enum kobj_ns_type type)
{
	int registered = 0;

	spin_lock(&kobj_ns_type_lock);
	if (kobj_ns_type_is_valid(type))
		registered = kobj_ns_ops_tbl[type] != NULL;
	spin_unlock(&kobj_ns_type_lock);

	return registered;
}

const struct kobj_ns_type_operations *kobj_child_ns_ops(const struct kobject *parent)
{
	const struct kobj_ns_type_operations *ops = NULL;

	if (parent && parent->ktype->child_ns_type)
		ops = parent->ktype->child_ns_type(parent);

	return ops;
}

const struct kobj_ns_type_operations *kobj_ns_ops(const struct kobject *kobj)
{
	return kobj_child_ns_ops(kobj->parent);
}

bool kobj_ns_current_may_mount(enum kobj_ns_type type)
{
	bool may_mount = true;

	spin_lock(&kobj_ns_type_lock);
	if (kobj_ns_type_is_valid(type) && kobj_ns_ops_tbl[type])
		may_mount = kobj_ns_ops_tbl[type]->current_may_mount();
	spin_unlock(&kobj_ns_type_lock);

	return may_mount;
}

void *kobj_ns_grab_current(enum kobj_ns_type type)
{
	void *ns = NULL;

	spin_lock(&kobj_ns_type_lock);
	if (kobj_ns_type_is_valid(type) && kobj_ns_ops_tbl[type])
		ns = kobj_ns_ops_tbl[type]->grab_current_ns();
	spin_unlock(&kobj_ns_type_lock);

	return ns;
}
EXPORT_SYMBOL_GPL(kobj_ns_grab_current);

const void *kobj_ns_netlink(enum kobj_ns_type type, struct sock *sk)
{
	const void *ns = NULL;

	spin_lock(&kobj_ns_type_lock);
	if (kobj_ns_type_is_valid(type) && kobj_ns_ops_tbl[type])
		ns = kobj_ns_ops_tbl[type]->netlink_ns(sk);
	spin_unlock(&kobj_ns_type_lock);

	return ns;
}

const void *kobj_ns_initial(enum kobj_ns_type type)
{
	const void *ns = NULL;

	spin_lock(&kobj_ns_type_lock);
	if (kobj_ns_type_is_valid(type) && kobj_ns_ops_tbl[type])
		ns = kobj_ns_ops_tbl[type]->initial_ns();
	spin_unlock(&kobj_ns_type_lock);

	return ns;
}

void kobj_ns_drop(enum kobj_ns_type type, void *ns)
{
	spin_lock(&kobj_ns_type_lock);
	if (kobj_ns_type_is_valid(type) &&
	    kobj_ns_ops_tbl[type] && kobj_ns_ops_tbl[type]->drop_ns)
		kobj_ns_ops_tbl[type]->drop_ns(ns);
	spin_unlock(&kobj_ns_type_lock);
}
EXPORT_SYMBOL_GPL(kobj_ns_drop);
