/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_COUNTER_H
#define _LINUX_PAGE_COUNTER_H

#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <asm/page.h>

struct page_counter {
	/*
	 * Make sure 'usage' does not share cacheline with any other field. The
	 * memcg->memory.usage is a hot member of struct mem_cgroup.
	 */
	atomic_long_t usage;/*此counter当前用量*/
	CACHELINE_PADDING(_pad1_);

	/* effective memory.min and memory.min usage tracking */
	unsigned long emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;

	/* effective memory.low and memory.low usage tracking */
	unsigned long elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;

	unsigned long watermark;
	unsigned long failcnt;/*统计此counter超限次数*/

	/* Keep all the read most fields in a separete cacheline. */
	CACHELINE_PADDING(_pad2_);

	unsigned long min;
	unsigned long low;
	unsigned long high;
	unsigned long max;/*此couter当前用量（usage)容许的最大值*/
	struct page_counter *parent;/*设置此counter,对应的parnet counter*/
} ____cacheline_internodealigned_in_smp;

#if BITS_PER_LONG == 32
#define PAGE_COUNTER_MAX LONG_MAX
#else
#define PAGE_COUNTER_MAX (LONG_MAX / PAGE_SIZE)
#endif

static inline void page_counter_init(struct page_counter *counter,
				     struct page_counter *parent)
{
	atomic_long_set(&counter->usage, 0);/*用量置为0*/
	counter->max = PAGE_COUNTER_MAX;/*默认无限量*/
	counter->parent = parent;/*设置此counter对应的parent*/
}

/*取此counter的当前用量*/
static inline unsigned long page_counter_read(struct page_counter *counter)
{
	return atomic_long_read(&counter->usage);
}

void page_counter_cancel(struct page_counter *counter, unsigned long nr_pages);
void page_counter_charge(struct page_counter *counter, unsigned long nr_pages);
bool page_counter_try_charge(struct page_counter *counter,
			     unsigned long nr_pages,
			     struct page_counter **fail);
void page_counter_uncharge(struct page_counter *counter, unsigned long nr_pages);
void page_counter_set_min(struct page_counter *counter, unsigned long nr_pages);
void page_counter_set_low(struct page_counter *counter, unsigned long nr_pages);

static inline void page_counter_set_high(struct page_counter *counter,
					 unsigned long nr_pages)
{
	WRITE_ONCE(counter->high, nr_pages);
}

int page_counter_set_max(struct page_counter *counter, unsigned long nr_pages);
int page_counter_memparse(const char *buf, const char *max,
			  unsigned long *nr_pages);

static inline void page_counter_reset_watermark(struct page_counter *counter)
{
	counter->watermark = page_counter_read(counter);
}

#endif /* _LINUX_PAGE_COUNTER_H */
