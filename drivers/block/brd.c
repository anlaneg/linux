// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/xarray.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/debugfs.h>

#include <linux/uaccess.h>

/*
 * Each block ramdisk device has a xarray brd_pages of pages that stores
 * the pages containing the block device's contents. A brd page's ->index is
 * its offset in PAGE_SIZE units. This is similar to, but in no way connected
 * with, the kernel's pagecache or buffer cache (which sit above our block
 * device).
 */
struct brd_device {
	int			brd_number;/*brd设备唯一编号*/
	struct gendisk		*brd_disk;
	struct list_head	brd_list;/*用于串连其它的brd_device*/

	/*
	 * Backing store of pages. This is the contents of the block device.
	 */
	struct xarray	        brd_pages;/*用于保存内存page*/
	u64			brd_nr_pages;/*当前占用多少个page*/
};

/*
 * Look up and return a brd's page for a given sector.
 */
static struct page *brd_lookup_page(struct brd_device *brd, sector_t sector)
{
	pgoff_t idx;
	struct page *page;

	/*扇区数向右移PAGE_SECTORS_SHIFT，即可换算为page数*/
	idx = sector >> PAGE_SECTORS_SHIFT; /* sector to page index */
	page = xa_load(&brd->brd_pages, idx);/*加载idx号page*/

	BUG_ON(page && page->index != idx);/*索引必须相等*/

	return page;/*返回此扇区对应的page*/
}

/*
 * Insert a new page for a given sector, if one does not already exist.
 */
static int brd_insert_page(struct brd_device *brd, sector_t sector, gfp_t gfp)
{
	pgoff_t idx;
	struct page *page, *cur;
	int ret = 0;

	page = brd_lookup_page(brd, sector);
	if (page)
		/*此page存在，返回0*/
		return 0;

	/*申请一个page*/
	page = alloc_page(gfp | __GFP_ZERO | __GFP_HIGHMEM);
	if (!page)
		return -ENOMEM;

	xa_lock(&brd->brd_pages);

	idx = sector >> PAGE_SECTORS_SHIFT;/*记录此page的索引*/
	page->index = idx;/*设置此page的索引*/

	/*在index位置存储此page*/
	cur = __xa_cmpxchg(&brd->brd_pages, idx, NULL, page, gfp);

	if (unlikely(cur)) {
		/*此位置原page指针不为空，新内容释放，复用旧内容*/
		__free_page(page);
		ret = xa_err(cur);
		if (!ret && (cur->index != idx))
			ret = -EIO;
	} else {
		brd->brd_nr_pages++;/*brd占用的内存数增加*/
	}

	xa_unlock(&brd->brd_pages);

	return ret;
}

/*
 * Free all backing store pages and xarray. This must only be called when
 * there are no other users of the device.
 */
static void brd_free_pages(struct brd_device *brd)
{
	struct page *page;
	pgoff_t idx;

	/*释放brd中保存的所有page(设备释放时资源回收）*/
	xa_for_each(&brd->brd_pages, idx, page) {
		__free_page(page);
		cond_resched();
	}

	xa_destroy(&brd->brd_pages);
}

/*
 * copy_to_brd_setup must be called before copy_to_brd. It may sleep.
 */
static int copy_to_brd_setup(struct brd_device *brd, sector_t sector, size_t n,
			     gfp_t gfp)
{
	/*此扇区在page中的偏移量*/
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;
	int ret;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	ret = brd_insert_page(brd, sector, gfp);
	if (ret)
		/*添加page失败，返回*/
		return ret;
	if (copy < n) {
		/*要写的内容过长，再增加一个page*/
		sector += copy >> SECTOR_SHIFT;
		ret = brd_insert_page(brd, sector, gfp);
	}
	return ret;
}

/*
 * Copy n bytes from src to the brd starting at sector. Does not sleep.
 */
static void copy_to_brd(struct brd_device *brd, const void *src,
			sector_t sector, size_t n)
{
	struct page *page;
	void *dst;
	/*扇区在page中的偏移*/
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	/*在此页中需复制的内容长度*/
	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = brd_lookup_page(brd, sector);
	BUG_ON(!page);

	dst = kmap_atomic(page);
	memcpy(dst + offset, src, copy);/*写入page*/
	kunmap_atomic(dst);

	if (copy < n) {
		src += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = brd_lookup_page(brd, sector);/*数据没写完，再写剩余的*/
		BUG_ON(!page);

		dst = kmap_atomic(page);
		memcpy(dst, src, copy);
		kunmap_atomic(dst);
	}
}

/*
 * Copy n bytes to dst from the brd starting at sector. Does not sleep.
 */
static void copy_from_brd(void *dst, struct brd_device *brd,
			sector_t sector, size_t n)
{
	struct page *page;
	void *src;
	/*扇区在page中的偏移*/
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	/*在此页中需复制的内容长度*/
	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = brd_lookup_page(brd, sector);/*查询扇区对应的page*/
	if (page) {
		src = kmap_atomic(page);
		memcpy(dst, src + offset, copy);/*读取数据，写入到dst*/
		kunmap_atomic(src);
	} else
		memset(dst, 0, copy);/*这一页之前没有写，直接返回0*/

	if (copy < n) {
		/*仍存在一些数据没有读取，再取一个页将剩余数据复制进来*/
		dst += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = brd_lookup_page(brd, sector);
		if (page) {
			src = kmap_atomic(page);
			memcpy(dst, src, copy);
			kunmap_atomic(src);
		} else
			memset(dst, 0, copy);
	}
}

/*
 * Process a single bvec of a bio.
 */
static int brd_do_bvec(struct brd_device *brd, struct page *page/*要写入/读取的内容*/,
			unsigned int len/*要写入/写入的内容长度*/, unsigned int off/*要写入/读取内容在page中的偏移量*/, blk_opf_t opf,
			sector_t sector/*写入位置对应的起始扇区*/)
{
	void *mem;
	int err = 0;

	if (op_is_write(opf)) {
		/*写操作*/
		/*
		 * Must use NOIO because we don't want to recurse back into the
		 * block or filesystem layers from page reclaim.
		 */
		gfp_t gfp = opf & REQ_NOWAIT ? GFP_NOWAIT : GFP_NOIO;

		err = copy_to_brd_setup(brd, sector, len, gfp);
		if (err)
			/*准备page失败，跳出*/
			goto out;
	}

	mem = kmap_atomic(page);
	if (!op_is_write(opf)) {
		/*读操作，自brd中读取并写入到mem对应的page*/
		copy_from_brd(mem + off, brd, sector, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		/*写操作，将mem对应的page的内容写入brd*/
		copy_to_brd(brd, mem + off, sector, len);
	}
	kunmap_atomic(mem);

out:
	return err;
}

/*响应bio操作*/
static void brd_submit_bio(struct bio *bio)
{
	/*取要操作的brd设备*/
	struct brd_device *brd = bio->bi_bdev->bd_disk->private_data;
	sector_t sector = bio->bi_iter.bi_sector;
	struct bio_vec bvec;
	struct bvec_iter iter;

	/*遍历bio对应的所有bio_vec(bi_io_vec),针对每一个执行相应的读写操作*/
	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		int err;

		/* Don't support un-aligned buffer */
		WARN_ON_ONCE((bvec.bv_offset & (SECTOR_SIZE - 1)) ||
				(len & (SECTOR_SIZE - 1)));

		err = brd_do_bvec(brd, bvec.bv_page, len, bvec.bv_offset,
				  bio->bi_opf, sector);
		if (err) {
			if (err == -ENOMEM && bio->bi_opf & REQ_NOWAIT) {
				bio_wouldblock_error(bio);
				return;
			}
			bio_io_error(bio);
			return;
		}
		sector += len >> SECTOR_SHIFT;
	}

	bio_endio(bio);
}

static const struct block_device_operations brd_fops = {
	.owner =		THIS_MODULE,
	.submit_bio =		brd_submit_bio,
};

/*
 * And now the modules code and kernel interface.
 */
static int rd_nr = CONFIG_BLK_DEV_RAM_COUNT;
module_param(rd_nr, int, 0444);/*brd设备的数目*/
MODULE_PARM_DESC(rd_nr, "Maximum number of brd devices");

unsigned long rd_size = CONFIG_BLK_DEV_RAM_SIZE;/*brd设备默认大小为16k*1024=16m*/
module_param(rd_size, ulong, 0444);
MODULE_PARM_DESC(rd_size, "Size of each RAM disk in kbytes.");

static int max_part = 1;
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Num Minors to reserve between devices");

MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(RAMDISK_MAJOR);
MODULE_ALIAS("rd");

#ifndef MODULE
/* Legacy boot options - nonmodular */
static int __init ramdisk_size(char *str)
{
	rd_size = simple_strtol(str, NULL, 0);/*调整brd设备大小*/
	return 1;
}
__setup("ramdisk_size=", ramdisk_size);
#endif

/*
 * The device scheme is derived from loop.c. Keep them in synch where possible
 * (should share code eventually).
 */
static LIST_HEAD(brd_devices);/*用于记录系统中所有brd设备*/
static struct dentry *brd_debugfs_dir;

static int brd_alloc(int i/*要创建的brd设备编号*/)
{
	struct brd_device *brd;
	struct gendisk *disk;
	char buf[DISK_NAME_LEN];
	int err = -ENOMEM;

	list_for_each_entry(brd, &brd_devices, brd_list)
		if (brd->brd_number == i)
			/*此设备已存在*/
			return -EEXIST;

	/*申请brd设备*/
	brd = kzalloc(sizeof(*brd), GFP_KERNEL);
	if (!brd)
		return -ENOMEM;
	brd->brd_number		= i;
	list_add_tail(&brd->brd_list, &brd_devices);

	xa_init(&brd->brd_pages);

	snprintf(buf, DISK_NAME_LEN, "ram%d", i);
	if (!IS_ERR_OR_NULL(brd_debugfs_dir))
		debugfs_create_u64(buf, 0444, brd_debugfs_dir,
				&brd->brd_nr_pages);

	/*申请一个disk*/
	disk = brd->brd_disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk)
		goto out_free_dev;

	disk->major		= RAMDISK_MAJOR;
	disk->first_minor	= i * max_part;
	disk->minors		= max_part;
	disk->fops		= &brd_fops;/*指定设备操作集*/
	disk->private_data	= brd;
	/*设置brd设备名称为ramX*/
	strscpy(disk->disk_name, buf, DISK_NAME_LEN);
	/*设置此块设备sectors总数，这里乘了2，即换算为disk的总字节数大小（单位为k)*/
	set_capacity(disk, rd_size * 2);
	
	/*
	 * This is so fdisk will align partitions on 4k, because of
	 * direct_access API needing 4k alignment, returning a PFN
	 * (This is only a problem on very small devices <= 4M,
	 *  otherwise fdisk will align on 1M. Regardless this call
	 *  is harmless)
	 */
	blk_queue_physical_block_size(disk->queue, PAGE_SIZE);

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_SYNCHRONOUS, disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_NOWAIT, disk->queue);
	err = add_disk(disk);/*添加此disk到系统*/
	if (err)
		goto out_cleanup_disk;

	return 0;

out_cleanup_disk:
	put_disk(disk);
out_free_dev:
	list_del(&brd->brd_list);
	kfree(brd);
	return err;
}

static void brd_probe(dev_t dev)
{
	brd_alloc(MINOR(dev) / max_part);
}

static void brd_cleanup(void)
{
	struct brd_device *brd, *next;

	debugfs_remove_recursive(brd_debugfs_dir);

	list_for_each_entry_safe(brd, next, &brd_devices, brd_list) {
		del_gendisk(brd->brd_disk);
		put_disk(brd->brd_disk);
		brd_free_pages(brd);
		list_del(&brd->brd_list);
		kfree(brd);
	}
}

static inline void brd_check_and_reset_par(void)
{
	if (unlikely(!max_part))
		max_part = 1;

	/*
	 * make sure 'max_part' can be divided exactly by (1U << MINORBITS),
	 * otherwise, it is possiable to get same dev_t when adding partitions.
	 */
	if ((1U << MINORBITS) % max_part != 0)
		max_part = 1UL << fls(max_part);

	if (max_part > DISK_MAX_PARTS) {
		pr_info("brd: max_part can't be larger than %d, reset max_part = %d.\n",
			DISK_MAX_PARTS, DISK_MAX_PARTS);
		max_part = DISK_MAX_PARTS;
	}
}

/*此驱动提供了ram block设备，可以将内存做为一个block设备*/
static int __init brd_init(void)
{
	int err, i;

	brd_check_and_reset_par();

	brd_debugfs_dir = debugfs_create_dir("ramdisk_pages", NULL);

	/*申请rd_nr块block设备*/
	for (i = 0; i < rd_nr; i++) {
		err = brd_alloc(i);
		if (err)
			goto out_free;
	}

	/*
	 * brd module now has a feature to instantiate underlying device
	 * structure on-demand, provided that there is an access dev node.
	 *
	 * (1) if rd_nr is specified, create that many upfront. else
	 *     it defaults to CONFIG_BLK_DEV_RAM_COUNT
	 * (2) User can further extend brd devices by create dev node themselves
	 *     and have kernel automatically instantiate actual device
	 *     on-demand. Example:
	 *		mknod /path/devnod_name b 1 X	# 1 is the rd major
	 *		fdisk -l /path/devnod_name
	 *	If (X / max_part) was not already created it will be created
	 *	dynamically.
	 */

	if (__register_blkdev(RAMDISK_MAJOR, "ramdisk", brd_probe)) {
		err = -EIO;
		goto out_free;
	}

	pr_info("brd: module loaded\n");
	return 0;

out_free:
	brd_cleanup();

	pr_info("brd: module NOT loaded !!!\n");
	return err;
}

static void __exit brd_exit(void)
{

	unregister_blkdev(RAMDISK_MAJOR, "ramdisk");
	brd_cleanup();

	pr_info("brd: module unloaded\n");
}

module_init(brd_init);
module_exit(brd_exit);

