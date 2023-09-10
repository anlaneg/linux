/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_POOL_H
#define RXE_POOL_H

enum rxe_elem_type {
	RXE_TYPE_UC,
	RXE_TYPE_PD,
	RXE_TYPE_AH,
	RXE_TYPE_SRQ,
	RXE_TYPE_QP,
	RXE_TYPE_CQ,
	RXE_TYPE_MR,
	RXE_TYPE_MW,
	RXE_NUM_TYPES,		/* keep me last */
};

struct rxe_pool_elem {
	/*所属的pool*/
	struct rxe_pool		*pool;
	void			*obj;
	/*此entry的引用计数*/
	struct kref		ref_cnt;
	struct list_head	list;
	struct completion	complete;
	/*elem对应的在pool里的index*/
	u32			index;
};

struct rxe_pool {
    /*pool所属的rxe设备*/
	struct rxe_dev		*rxe;
	/*pool名称，例如pd,ucontext，ah等*/
	const char		*name;
	/*各entry的清理函数,来源看rxe_type_info*/
	void			(*cleanup)(struct rxe_pool_elem *elem);
	/*pool对应的类型*/
	enum rxe_elem_type	type;

	/*最大元素数*/
	unsigned int		max_elem;
	/*已使用元素数*/
	atomic_t		num_elem;
	/*单个元素size*/
	size_t			elem_size;
	/*obj指针位置到rxe_pool_entry位置的offset，可据此推算出elem结构体
	 * 例如结构体struct rxe_ucontext的elem_offset = offsetof(struct rxe_ucontext, elem)
	 * 则增加此偏移可推出rxe_ucontext->elem成员
	 * */
	size_t			elem_offset;

	/*存放元素的xarray*/
	struct xarray		xa;
	/*元素的最大，最小索引*/
	struct xa_limit		limit;
	u32			next;
};

/* initialize a pool of objects with given limit on
 * number of elements. gets parameters from rxe_type_info
 * pool elements will be allocated out of a slab cache
 */
void rxe_pool_init(struct rxe_dev *rxe, struct rxe_pool *pool,
		  enum rxe_elem_type type);

/* free resources from object pool */
void rxe_pool_cleanup(struct rxe_pool *pool);

/* connect already allocated object to pool */
int __rxe_add_to_pool(struct rxe_pool *pool, struct rxe_pool_elem *elem,
				bool sleepable);
/*将obj添加进pool*/
#define rxe_add_to_pool(pool, obj) __rxe_add_to_pool(pool, &(obj)->elem, true)
#define rxe_add_to_pool_ah(pool, obj, sleepable) __rxe_add_to_pool(pool, \
				&(obj)->elem, sleepable)

/* lookup an indexed object from index. takes a reference on object */
void *rxe_pool_get_index(struct rxe_pool *pool, u32 index);

int __rxe_get(struct rxe_pool_elem *elem);
#define rxe_get(obj) __rxe_get(&(obj)->elem)

int __rxe_put(struct rxe_pool_elem *elem);
#define rxe_put(obj) __rxe_put(&(obj)->elem)

int __rxe_cleanup(struct rxe_pool_elem *elem, bool sleepable);
#define rxe_cleanup(obj) __rxe_cleanup(&(obj)->elem, true)
#define rxe_cleanup_ah(obj, sleepable) __rxe_cleanup(&(obj)->elem, sleepable)

#define rxe_read(obj) kref_read(&(obj)->elem.ref_cnt)

void __rxe_finalize(struct rxe_pool_elem *elem);
#define rxe_finalize(obj) __rxe_finalize(&(obj)->elem)

#endif /* RXE_POOL_H */
