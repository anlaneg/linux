/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bvec iterator
 *
 * Copyright (C) 2001 Ming Lei <ming.lei@canonical.com>
 */
#ifndef __LINUX_BVEC_H
#define __LINUX_BVEC_H

#include <linux/highmem.h>
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/types.h>

struct page;

/**
 * struct bio_vec - a contiguous range of physical memory addresses
 * @bv_page:   First page associated with the address range.
 * @bv_len:    Number of bytes in the address range.
 * @bv_offset: Start of the address range relative to the start of @bv_page.
 *
 * The following holds for a bvec if n * PAGE_SIZE < bv_offset + bv_len:
 *
 *   nth_page(@bv_page, n) == @bv_page + n
 *
 * This holds because page_is_mergeable() checks the above property.
 */
struct bio_vec {
	struct page	*bv_page;/*页指针*/
	unsigned int	bv_len;/*可转换长度*/
	unsigned int	bv_offset;/*有效起始地址在页内的offset*/
};

/**
 * bvec_set_page - initialize a bvec based off a struct page
 * @bv:		bvec to initialize
 * @page:	page the bvec should point to
 * @len:	length of the bvec
 * @offset:	offset into the page
 */
static inline void bvec_set_page(struct bio_vec *bv, struct page *page,
		unsigned int len, unsigned int offset)
{
	bv->bv_page = page;/*要填充的页*/
	bv->bv_len = len;
	bv->bv_offset = offset;
}

/**
 * bvec_set_folio - initialize a bvec based off a struct folio
 * @bv:		bvec to initialize
 * @folio:	folio the bvec should point to
 * @len:	length of the bvec
 * @offset:	offset into the folio
 */
static inline void bvec_set_folio(struct bio_vec *bv, struct folio *folio,
		unsigned int len, unsigned int offset)
{
	bvec_set_page(bv, &folio->page, len, offset);
}

/**
 * bvec_set_virt - initialize a bvec based on a virtual address
 * @bv:		bvec to initialize
 * @vaddr:	virtual address to set the bvec to
 * @len:	length of the bvec
 */
static inline void bvec_set_virt(struct bio_vec *bv, void *vaddr,
		unsigned int len)
{
	bvec_set_page(bv, virt_to_page(vaddr), len, offset_in_page(vaddr));
}

struct bvec_iter {
	/*设备对应的扇区数*/
	sector_t		bi_sector;	/* device address in 512 byte
						   sectors */
	/*剩余的io的字节数*/
	unsigned int		bi_size;	/* residual I/O count */

	/*当前遍历位置（即bvl_vec数组索引）*/
	unsigned int		bi_idx;		/* current index into bvl_vec */

	/*此iter中已完成的数目（本bi已完成访问的字节数）*/
	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
} __packed;

struct bvec_iter_all {
	struct bio_vec	bv;
	int		idx;
	unsigned	done;
};

/*
 * various member access, note that bio_data should of course not be used
 * on highmem page vectors
 */
/*取bvec数据的iter.bi_idx号下标元素（即当前遍历位置对应的struct bio_vec结构，注意取了地址）*/
#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])

/* multi-page (mp_bvec) helpers */
/*取bvec数组的bi_idx号元素，并返回其对应的bv_page（即当前遍历位置对应的page)*/
#define mp_bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)

#define mp_bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)

/*多页中的offset(当前遍历位置的struct bio_vec结构指明了
 * 本页有效位置的offset,再合上已经完成的长度，即为本轮关心的真实offset)*/
#define mp_bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)

/*多页的第几个页(由于mp_bvec_iter_offset是支持多页的，此宏解决多页中跳几页的问题）*/
#define mp_bvec_iter_page_idx(bvec, iter)			\
	(mp_bvec_iter_offset((bvec), (iter)) / PAGE_SIZE)

#define mp_bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= mp_bvec_iter_page((bvec), (iter)),	\
	.bv_len		= mp_bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= mp_bvec_iter_offset((bvec), (iter)),	\
})

/* For building single-page bvec in flight */
/*在一个页中的偏移量（与mp_bvec_iter_page_idx函数配对，考虑多页后在具体一页中的偏移量)*/
 #define bvec_iter_offset(bvec, iter)				\
	(mp_bvec_iter_offset((bvec), (iter)) % PAGE_SIZE)

/*获得本页可提供的数据最大长度
 * （是一个选择问题。一种是当前bvc可提供的未遍历的内容长度；
 * 另一种是在当前页，未遍历的内容长度；两者中找最小的）
 * */
#define bvec_iter_len(bvec, iter)				\
	min_t(unsigned, mp_bvec_iter_len((bvec), (iter)),		\
	      PAGE_SIZE - bvec_iter_offset((bvec), (iter)))

/*获取当前遍历位置对应的页指针（先取基页，再考虑当前遍历的偏移量导致的页数偏移）*/
#define bvec_iter_page(bvec, iter)				\
	(mp_bvec_iter_page((bvec), (iter)) +			\
	 mp_bvec_iter_page_idx((bvec), (iter)))

/*填充并返回bio_vec结构体bvec，用于指出本轮的访问内容。
 * （考虑了多页情况。返回需要访问的页，可以访问的页长度，访问的起始偏移量）
 * */
#define bvec_iter_bvec(bvec/*当前要遍历的内容*/, iter/*枚举器（枚举用状态变量)*/)				\
((struct bio_vec) {						\
	.bv_page	= bvec_iter_page((bvec), (iter)),	\
	.bv_len		= bvec_iter_len((bvec), (iter)),/*本页可遍历的最大长度*/	\
	.bv_offset	= bvec_iter_offset((bvec), (iter)),	\
})

static inline bool bvec_iter_advance(const struct bio_vec *bv,
		struct bvec_iter *iter, unsigned bytes)
{
	unsigned int idx = iter->bi_idx;

	if (WARN_ONCE(bytes > iter->bi_size,
		     "Attempted to advance past end of bvec iter\n")) {
		iter->bi_size = 0;
		return false;
	}

	iter->bi_size -= bytes;
	bytes += iter->bi_bvec_done;

	while (bytes && bytes >= bv[idx].bv_len) {
		bytes -= bv[idx].bv_len;
		idx++;
	}

	iter->bi_idx = idx;
	iter->bi_bvec_done = bytes;
	return true;
}

/*
 * A simpler version of bvec_iter_advance(), @bytes should not span
 * across multiple bvec entries, i.e. bytes <= bv[i->bi_idx].bv_len
 */
static inline void bvec_iter_advance_single(const struct bio_vec *bv,
				struct bvec_iter *iter, unsigned int bytes)
{
	unsigned int done = iter->bi_bvec_done + bytes;/*枚举器已完成访问的内容增加*/

	if (done == bv[iter->bi_idx].bv_len) {
		/*此索引的bv均已访问完成*/
		done = 0;/*要切索引了，done清零*/
		iter->bi_idx++;/*索引切换*/
	}
	iter->bi_bvec_done = done;/*本bi已完成访问的字节数*/
	iter->bi_size -= bytes;
}

#define for_each_bvec(bvl, bio_vec, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bvec_iter_bvec((bio_vec), (iter))), 1);	\
	     bvec_iter_advance_single((bio_vec), &(iter), (bvl).bv_len))

/* for iterating one bio from start to end */
#define BVEC_ITER_ALL_INIT (struct bvec_iter)				\
{									\
	.bi_sector	= 0,						\
	.bi_size	= UINT_MAX,					\
	.bi_idx		= 0,						\
	.bi_bvec_done	= 0,						\
}

static inline struct bio_vec *bvec_init_iter_all(struct bvec_iter_all *iter_all)
{
	iter_all->done = 0;
	iter_all->idx = 0;

	return &iter_all->bv;
}

static inline void bvec_advance(const struct bio_vec *bvec,
				struct bvec_iter_all *iter_all)
{
	struct bio_vec *bv = &iter_all->bv;

	if (iter_all->done) {
		bv->bv_page++;
		bv->bv_offset = 0;
	} else {
		bv->bv_page = bvec->bv_page + (bvec->bv_offset >> PAGE_SHIFT);
		bv->bv_offset = bvec->bv_offset & ~PAGE_MASK;
	}
	bv->bv_len = min_t(unsigned int, PAGE_SIZE - bv->bv_offset,
			   bvec->bv_len - iter_all->done);
	iter_all->done += bv->bv_len;

	if (iter_all->done == bvec->bv_len) {
		iter_all->idx++;
		iter_all->done = 0;
	}
}

/**
 * bvec_kmap_local - map a bvec into the kernel virtual address space
 * @bvec: bvec to map
 *
 * Must be called on single-page bvecs only.  Call kunmap_local on the returned
 * address to unmap.
 */
static inline void *bvec_kmap_local(struct bio_vec *bvec)
{
	return kmap_local_page(bvec->bv_page) + bvec->bv_offset;
}

/**
 * memcpy_from_bvec - copy data from a bvec
 * @bvec: bvec to copy from
 *
 * Must be called on single-page bvecs only.
 */
static inline void memcpy_from_bvec(char *to, struct bio_vec *bvec)
{
	memcpy_from_page(to, bvec->bv_page, bvec->bv_offset, bvec->bv_len);
}

/**
 * memcpy_to_bvec - copy data to a bvec
 * @bvec: bvec to copy to
 *
 * Must be called on single-page bvecs only.
 */
static inline void memcpy_to_bvec(struct bio_vec *bvec, const char *from)
{
	memcpy_to_page(bvec->bv_page, bvec->bv_offset, from, bvec->bv_len);
}

/**
 * memzero_bvec - zero all data in a bvec
 * @bvec: bvec to zero
 *
 * Must be called on single-page bvecs only.
 */
static inline void memzero_bvec(struct bio_vec *bvec)
{
	memzero_page(bvec->bv_page, bvec->bv_offset, bvec->bv_len);
}

/**
 * bvec_virt - return the virtual address for a bvec
 * @bvec: bvec to return the virtual address for
 *
 * Note: the caller must ensure that @bvec->bv_page is not a highmem page.
 */
static inline void *bvec_virt(struct bio_vec *bvec)
{
	WARN_ON_ONCE(PageHighMem(bvec->bv_page));
	return page_address(bvec->bv_page) + bvec->bv_offset;
}

#endif /* __LINUX_BVEC_H */
