// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/drivers/base/map.c
 *
 * (C) Copyright Al Viro 2002,2003
 *
 * NOTE: data structure needs to be changed.  It works, but for large dev_t
 * it will be too slow.  It is isolated, though, so these changes will be
 * local to that file.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kdev_t.h>
#include <linux/kobject.h>
#include <linux/kobj_map.h>

struct kobj_map {
	struct probe {
		struct probe *next;//挂接多个probe,各probe之前按range自小向大排列
		dev_t dev;
		unsigned long range;
		struct module *owner;//依赖的module
		kobj_probe_t *get;//获取kobj的回调函数
		int (*lock)(dev_t, void *);//加锁函数
		void *data;
	} *probes[255];
	struct mutex *lock;
};

//向domain中加入dev
int kobj_map(struct kobj_map *domain, dev_t dev, unsigned long range,
	     struct module *module, kobj_probe_t *probe,
	     int (*lock)(dev_t, void *), void *data)
{
	//需要占用多少个major
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	unsigned index = MAJOR(dev);//起始的major
	unsigned i;
	struct probe *p;

	if (n > 255)
		n = 255;//最多容许占用255个major

	//申请n个probe
	p = kmalloc_array(n, sizeof(struct probe), GFP_KERNEL);
	if (p == NULL)
		return -ENOMEM;

	//初始化n个probe
	for (i = 0; i < n; i++, p++) {
		p->owner = module;
		p->get = probe;
		p->lock = lock;
		p->dev = dev;
		p->range = range;
		p->data = data;
	}
	mutex_lock(domain->lock);
	for (i = 0, p -= n; i < n; i++, p++, index++) {
		struct probe **s = &domain->probes[index % 255];
		//插入p,使得probes链上按range自小向大排列
		while (*s && (*s)->range < range)
			s = &(*s)->next;
		//将p插入到s前面
		p->next = *s;
		*s = p;
	}
	mutex_unlock(domain->lock);
	return 0;
}

//自domain中删除dev及其range对应的段
void kobj_unmap(struct kobj_map *domain, dev_t dev, unsigned long range)
{
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	unsigned index = MAJOR(dev);
	unsigned i;
	struct probe *found = NULL;

	if (n > 255)
		n = 255;

	mutex_lock(domain->lock);
	for (i = 0; i < n; i++, index++) {
		struct probe **s;
		for (s = &domain->probes[index % 255]; *s; s = &(*s)->next) {
			struct probe *p = *s;
			if (p->dev == dev && p->range == range) {
				*s = p->next;
				if (!found)
					found = p;
				break;
			}
		}
	}
	mutex_unlock(domain->lock);
	kfree(found);
}

//通过domain->probes中查找dev,获取对应的probe,并调用相应的probe回调，产生kobj,并通过出参，返回对应的index
struct kobject *kobj_lookup(struct kobj_map *domain, dev_t dev, int *index)
{
	struct kobject *kobj;
	struct probe *p;
	unsigned long best = ~0UL;

retry:
	mutex_lock(domain->lock);
	//在domain的probes哈希表中查找dev
	for (p = domain->probes[MAJOR(dev) % 255]; p; p = p->next) {
		struct kobject *(*probe)(dev_t, int *, void *);
		struct module *owner;
		void *data;

		//p的设备编号大于查找的，或者p的设备编号小于dev(不要范围内）
		if (p->dev > dev || p->dev + p->range - 1 < dev)
			continue;

		//要查找的dev在p范围以内
		if (p->range - 1 >= best)
			break;//如果range为０或者其大于best，忽略

		//跳过无法引用对应module的
		if (!try_module_get(p->owner))
			continue;

		owner = p->owner;
		data = p->data;
		probe = p->get;
		best = p->range - 1;
		*index = dev - p->dev;//所查找的dev在其所属设备中的索引号

		//如果有lock函数，则进行加锁回调
		if (p->lock && p->lock(dev, data) < 0) {
			module_put(owner);
			continue;
		}
		mutex_unlock(domain->lock);
		//通过probe回调，获取对应的kobj
		kobj = probe(dev, index, data);
		/* Currently ->owner protects _only_ ->probe() itself. */
		module_put(owner);
		if (kobj)
			return kobj;
		goto retry;
	}
	mutex_unlock(domain->lock);
	return NULL;
}

struct kobj_map *kobj_map_init(kobj_probe_t *base_probe, struct mutex *lock)
{
	struct kobj_map *p = kmalloc(sizeof(struct kobj_map), GFP_KERNEL);
	struct probe *base = kzalloc(sizeof(*base), GFP_KERNEL);
	int i;

	if ((p == NULL) || (base == NULL)) {
		kfree(p);
		kfree(base);
		return NULL;
	}

	//初始每个probes为base
	base->dev = 1;
	base->range = ~0;
	base->get = base_probe;
	for (i = 0; i < 255; i++)
		p->probes[i] = base;
	p->lock = lock;
	return p;
}
