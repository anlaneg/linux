// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright (C) 2016 - 2020 Christoph Hellwig
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/device_cgroup.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/backing-dev.h>
#include <linux/module.h>
#include <linux/blkpg.h>
#include <linux/magic.h>
#include <linux/buffer_head.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/part_stat.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include "../fs/internal.h"
#include "blk.h"

/* Should we allow writing to mounted block devices? */
static bool bdev_allow_write_mounted = IS_ENABLED(CONFIG_BLK_DEV_WRITE_MOUNTED);

/*系统块设备对应的inode*/
struct bdev_inode {
	struct block_device bdev;/*块设备*/
	struct inode vfs_inode;/*块设备对应的inode基础信息*/
};

/*由inode获得bdev_inode*/
static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
	return container_of(inode, struct bdev_inode, vfs_inode);
}

/*由inode获得block_device*/
struct block_device *I_BDEV(struct inode *inode)
{
	return &BDEV_I(inode)->bdev;
}
EXPORT_SYMBOL(I_BDEV);

static void bdev_write_inode(struct block_device *bdev)
{
	struct inode *inode = bdev->bd_inode;
	int ret;

	spin_lock(&inode->i_lock);
	while (inode->i_state & I_DIRTY) {
		spin_unlock(&inode->i_lock);
		/*将此inode信息写到磁盘*/
		ret = write_inode_now(inode, true);
		if (ret)
			pr_warn_ratelimited(
	"VFS: Dirty inode writeback failed for block device %pg (err=%d).\n",
				bdev, ret);
		spin_lock(&inode->i_lock);
	}
	spin_unlock(&inode->i_lock);
}

/* Kill _all_ buffers and pagecache , dirty or not.. */
static void kill_bdev(struct block_device *bdev)
{
	struct address_space *mapping = bdev->bd_inode->i_mapping;

	if (mapping_empty(mapping))
		return;

	invalidate_bh_lrus();
	truncate_inode_pages(mapping, 0);
}

/* Invalidate clean unused buffers and pagecache. */
void invalidate_bdev(struct block_device *bdev)
{
	struct address_space *mapping = bdev->bd_inode->i_mapping;

	if (mapping->nrpages) {
		invalidate_bh_lrus();
		lru_add_drain_all();	/* make sure all lru add caches are flushed */
		invalidate_mapping_pages(mapping, 0, -1);
	}
}
EXPORT_SYMBOL(invalidate_bdev);

/*
 * Drop all buffers & page cache for given bdev range. This function bails
 * with error if bdev has other exclusive owner (such as filesystem).
 */
int truncate_bdev_range(struct block_device *bdev, blk_mode_t mode,
			loff_t lstart, loff_t lend)
{
	/*
	 * If we don't hold exclusive handle for the device, upgrade to it
	 * while we discard the buffer cache to avoid discarding buffers
	 * under live filesystem.
	 */
	if (!(mode & BLK_OPEN_EXCL)) {
		int err = bd_prepare_to_claim(bdev, truncate_bdev_range, NULL);
		if (err)
			goto invalidate;
	}

	truncate_inode_pages_range(bdev->bd_inode->i_mapping, lstart, lend);
	if (!(mode & BLK_OPEN_EXCL))
		bd_abort_claiming(bdev, truncate_bdev_range);
	return 0;

invalidate:
	/*
	 * Someone else has handle exclusively open. Try invalidating instead.
	 * The 'end' argument is inclusive so the rounding is safe.
	 */
	return invalidate_inode_pages2_range(bdev->bd_inode->i_mapping,
					     lstart >> PAGE_SHIFT,
					     lend >> PAGE_SHIFT);
}

static void set_init_blocksize(struct block_device *bdev)
{
	unsigned int bsize = bdev_logical_block_size(bdev);
	loff_t size = i_size_read(bdev->bd_inode);

	while (bsize < PAGE_SIZE) {
		if (size & bsize)
			break;
		bsize <<= 1;
	}
	bdev->bd_inode->i_blkbits = blksize_bits(bsize);
}

int set_blocksize(struct block_device *bdev, int size)
{
	/* Size must be a power of two, and between 512 and PAGE_SIZE */
	if (size > PAGE_SIZE || size < 512 || !is_power_of_2(size))
		return -EINVAL;

	/* Size cannot be smaller than the size supported by the device */
	if (size < bdev_logical_block_size(bdev))
		return -EINVAL;

	/* Don't change the size if it is same as current */
	if (bdev->bd_inode->i_blkbits != blksize_bits(size)) {
		sync_blockdev(bdev);
		bdev->bd_inode->i_blkbits = blksize_bits(size);
		kill_bdev(bdev);
	}
	return 0;
}

EXPORT_SYMBOL(set_blocksize);

//设置sb对应的块大小
int sb_set_blocksize(struct super_block *sb, int size)
{
	if (set_blocksize(sb->s_bdev, size))
		return 0;
	/* If we get here, we know size is power of two
	 * and it's value is between 512 and PAGE_SIZE */
	sb->s_blocksize = size;
	sb->s_blocksize_bits = blksize_bits(size);
	return sb->s_blocksize;
}

EXPORT_SYMBOL(sb_set_blocksize);

int sb_min_blocksize(struct super_block *sb, int size)
{
	int minsize = bdev_logical_block_size(sb->s_bdev);
	if (size < minsize)
		size = minsize;
	return sb_set_blocksize(sb, size);
}

EXPORT_SYMBOL(sb_min_blocksize);

int sync_blockdev_nowait(struct block_device *bdev)
{
	if (!bdev)
		return 0;
	return filemap_flush(bdev->bd_inode->i_mapping);
}
EXPORT_SYMBOL_GPL(sync_blockdev_nowait);

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
	if (!bdev)
		return 0;
	return filemap_write_and_wait(bdev->bd_inode->i_mapping);
}
EXPORT_SYMBOL(sync_blockdev);

int sync_blockdev_range(struct block_device *bdev, loff_t lstart, loff_t lend)
{
	return filemap_write_and_wait_range(bdev->bd_inode->i_mapping,
			lstart, lend);
}
EXPORT_SYMBOL(sync_blockdev_range);

/**
 * bdev_freeze - lock a filesystem and force it into a consistent state
 * @bdev:	blockdevice to lock
 *
 * If a superblock is found on this device, we take the s_umount semaphore
 * on it to make sure nobody unmounts until the snapshot creation is done.
 * The reference counter (bd_fsfreeze_count) guarantees that only the last
 * unfreeze process can unfreeze the frozen filesystem actually when multiple
 * freeze requests arrive simultaneously. It counts up in bdev_freeze() and
 * count down in bdev_thaw(). When it becomes 0, thaw_bdev() will unfreeze
 * actually.
 *
 * Return: On success zero is returned, negative error code on failure.
 */
int bdev_freeze(struct block_device *bdev)
{
	int error = 0;

	mutex_lock(&bdev->bd_fsfreeze_mutex);

	if (atomic_inc_return(&bdev->bd_fsfreeze_count) > 1) {
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		return 0;
	}

	mutex_lock(&bdev->bd_holder_lock);
	if (bdev->bd_holder_ops && bdev->bd_holder_ops->freeze) {
		error = bdev->bd_holder_ops->freeze(bdev);
		lockdep_assert_not_held(&bdev->bd_holder_lock);
	} else {
		mutex_unlock(&bdev->bd_holder_lock);
		error = sync_blockdev(bdev);
	}

	if (error)
		atomic_dec(&bdev->bd_fsfreeze_count);

	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	return error;
}
EXPORT_SYMBOL(bdev_freeze);

/**
 * bdev_thaw - unlock filesystem
 * @bdev:	blockdevice to unlock
 *
 * Unlocks the filesystem and marks it writeable again after bdev_freeze().
 *
 * Return: On success zero is returned, negative error code on failure.
 */
int bdev_thaw(struct block_device *bdev)
{
	int error = -EINVAL, nr_freeze;

	mutex_lock(&bdev->bd_fsfreeze_mutex);

	/*
	 * If this returns < 0 it means that @bd_fsfreeze_count was
	 * already 0 and no decrement was performed.
	 */
	nr_freeze = atomic_dec_if_positive(&bdev->bd_fsfreeze_count);
	if (nr_freeze < 0)
		goto out;

	error = 0;
	if (nr_freeze > 0)
		goto out;

	mutex_lock(&bdev->bd_holder_lock);
	if (bdev->bd_holder_ops && bdev->bd_holder_ops->thaw) {
		error = bdev->bd_holder_ops->thaw(bdev);
		lockdep_assert_not_held(&bdev->bd_holder_lock);
	} else {
		mutex_unlock(&bdev->bd_holder_lock);
	}

	if (error)
		atomic_inc(&bdev->bd_fsfreeze_count);
out:
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	return error;
}
EXPORT_SYMBOL(bdev_thaw);

/*
 * pseudo-fs
 */

static  __cacheline_aligned_in_smp DEFINE_MUTEX(bdev_lock);
/*负责系统中bdev_inode申请，此inode对应一个block设备*/
static struct kmem_cache *bdev_cachep __ro_after_init;

/*申请bdev_inode，块设备自bdev_cachep中申请inode(此ei->bdev为全零）*/
static struct inode *bdev_alloc_inode(struct super_block *sb)
{
	/*自bdev_cachep中申请inode*/
	struct bdev_inode *ei = alloc_inode_sb(sb, bdev_cachep, GFP_KERNEL);

	if (!ei)
		return NULL;
	/*将块设备对应的成员清零（bdev_alloc负责初始化ei->bdev）*/
	memset(&ei->bdev, 0, sizeof(ei->bdev));
	return &ei->vfs_inode;
}

/*释放bdev_inode*/
static void bdev_free_inode(struct inode *inode)
{
	struct block_device *bdev = I_BDEV(inode);

	free_percpu(bdev->bd_stats);
	kfree(bdev->bd_meta_info);

	if (!bdev_is_partition(bdev)) {
		if (bdev->bd_disk && bdev->bd_disk->bdi)
			bdi_put(bdev->bd_disk->bdi);
		kfree(bdev->bd_disk);
	}

	if (MAJOR(bdev->bd_dev) == BLOCK_EXT_MAJOR)
		/*块设备是blkext，释放minor*/
		blk_free_ext_minor(MINOR(bdev->bd_dev));

	/*存回到cache*/
	kmem_cache_free(bdev_cachep, BDEV_I(inode));
}

/*inode cache初始化*/
static void init_once(void *data)
{
	struct bdev_inode *ei = data;

	inode_init_once(&ei->vfs_inode);
}

static void bdev_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	invalidate_inode_buffers(inode); /* is it needed here? */
	clear_inode(inode);
}

static const struct super_operations bdev_sops = {
	.statfs = simple_statfs,
	.alloc_inode = bdev_alloc_inode,/*申请bdev对应的inode*/
	.free_inode = bdev_free_inode,/*释放bdev对应的inode*/
	.drop_inode = generic_delete_inode,
	.evict_inode = bdev_evict_inode,
};

//块设备挂载fc初始化回调
static int bd_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, BDEVFS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	fc->s_iflags |= SB_I_CGROUPWB;
	ctx->ops = &bdev_sops;/*指明super block操作集*/
	return 0;
}

//块设备对应的文件系统
static struct file_system_type bd_type = {
	.name		= "bdev",
	.init_fs_context = bd_init_fs_context,
	.kill_sb	= kill_anon_super,
};

//块设备（bdev)文件系统的super_block（所有块设备均在此文件系统中有记录）
struct super_block *blockdev_superblock __ro_after_init;
EXPORT_SYMBOL_GPL(blockdev_superblock);

/*块设备cache初始化*/
void __init bdev_cache_init(void)
{
	int err;
	static struct vfsmount *bd_mnt __ro_after_init;

	//构造bdev_inode cache，负责分配bdev_inode结构体
	bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
			0, (SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|
				SLAB_MEM_SPREAD|SLAB_ACCOUNT|SLAB_PANIC),
			init_once);

	//注册块设备文件系统
	err = register_filesystem(&bd_type);
	if (err)
		panic("Cannot register bdev pseudo-fs");

	//挂载块设备文件系统，并获得挂载点(促使bd_mount函数被调用）
	bd_mnt = kern_mount(&bd_type);
	if (IS_ERR(bd_mnt))
		panic("Cannot create bdev pseudo-fs");

	/*记录bdev设备的超级块*/
	blockdev_superblock = bd_mnt->mnt_sb;   /* For writeback */
}

/*针对gendisk,分区号创建block_device*/
struct block_device *bdev_alloc(struct gendisk *disk, u8 partno/*分区号*/)
{
	struct block_device *bdev;
	struct inode *inode;

	/*申请块设备(blockdev_superblock)对应的inode，申请的类型为（struct bdev_inode）*/
	inode = new_inode(blockdev_superblock);
	if (!inode)
		return NULL;
	inode->i_mode = S_IFBLK;/*指明为block设备*/
	inode->i_rdev = 0;
	inode->i_data.a_ops = &def_blk_aops;
	mapping_set_gfp_mask(&inode->i_data, GFP_USER);

	/*取此bdev对应的block device结构体，并开始初始化它*/
	bdev = I_BDEV(inode);
	mutex_init(&bdev->bd_fsfreeze_mutex);
	spin_lock_init(&bdev->bd_size_lock);
	mutex_init(&bdev->bd_holder_lock);
	bdev->bd_partno = partno;
	bdev->bd_inode = inode;/*设置它关联的inode*/
	bdev->bd_queue = disk->queue;/*block设备queue复用disk->queue*/
	if (partno)
		bdev->bd_has_submit_bio = disk->part0->bd_has_submit_bio;
	else
		bdev->bd_has_submit_bio = false;
	bdev->bd_stats = alloc_percpu(struct disk_stats);
	if (!bdev->bd_stats) {
		iput(inode);
		return NULL;
	}
	bdev->bd_disk = disk;/*为此块设备关联gendisk*/
	return bdev;
}

void bdev_set_nr_sectors(struct block_device *bdev, sector_t sectors)
{
	spin_lock(&bdev->bd_size_lock);
	/*设置此块设备文件大小（即总扇区的字节总数）*/
	i_size_write(bdev->bd_inode, (loff_t)sectors << SECTOR_SHIFT);
	/*设置此块设备总扇区数*/
	bdev->bd_nr_sectors = sectors;
	spin_unlock(&bdev->bd_size_lock);
}

/*将block设备对应的inode加入到inode_hashtable中(后续可以通过ilookup查找到）*/
void bdev_add(struct block_device *bdev, dev_t dev)
{
	if (bdev_stable_writes(bdev))
		mapping_set_stable_writes(bdev->bd_inode->i_mapping);
	bdev->bd_dev = dev;
	/*如下示，块设备inode number即为设备编号*/
	bdev->bd_inode->i_rdev = dev;
	bdev->bd_inode->i_ino = dev;
	/*将块设备对应的inode,加入到inode hash表中*/
	insert_inode_hash(bdev->bd_inode);
}

long nr_blockdev_pages(void)
{
	struct inode *inode;
	long ret = 0;

	spin_lock(&blockdev_superblock->s_inode_list_lock);
	list_for_each_entry(inode, &blockdev_superblock->s_inodes, i_sb_list)
		ret += inode->i_mapping->nrpages;
	spin_unlock(&blockdev_superblock->s_inode_list_lock);

	return ret;
}

/**
 * bd_may_claim - test whether a block device can be claimed
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 * @hops: holder ops
 *
 * Test whether @bdev can be claimed by @holder.
 *
 * RETURNS:
 * %true if @bdev can be claimed, %false otherwise.
 */
static bool bd_may_claim(struct block_device *bdev, void *holder,
		const struct blk_holder_ops *hops)
{
	struct block_device *whole = bdev_whole(bdev);

	lockdep_assert_held(&bdev_lock);

	if (bdev->bd_holder) {
		/*
		 * The same holder can always re-claim.
		 */
		if (bdev->bd_holder == holder) {
			if (WARN_ON_ONCE(bdev->bd_holder_ops != hops))
				return false;
			return true;
		}
		return false;
	}

	/*
	 * If the whole devices holder is set to bd_may_claim, a partition on
	 * the device is claimed, but not the whole device.
	 */
	if (whole != bdev &&
	    whole->bd_holder && whole->bd_holder != bd_may_claim)
		return false;
	return true;
}

/**
 * bd_prepare_to_claim - claim a block device
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 * @hops: holder ops.
 *
 * Claim @bdev.  This function fails if @bdev is already claimed by another
 * holder and waits if another claiming is in progress. return, the caller
 * has ownership of bd_claiming and bd_holder[s].
 *
 * RETURNS:
 * 0 if @bdev can be claimed, -EBUSY otherwise.
 */
int bd_prepare_to_claim(struct block_device *bdev, void *holder,
		const struct blk_holder_ops *hops)
{
	struct block_device *whole = bdev_whole(bdev);

	if (WARN_ON_ONCE(!holder))
		return -EINVAL;
retry:
	mutex_lock(&bdev_lock);
	/* if someone else claimed, fail */
	if (!bd_may_claim(bdev, holder, hops)) {
		mutex_unlock(&bdev_lock);
		return -EBUSY;
	}

	/* if claiming is already in progress, wait for it to finish */
	if (whole->bd_claiming) {
		wait_queue_head_t *wq = bit_waitqueue(&whole->bd_claiming, 0);
		DEFINE_WAIT(wait);

		prepare_to_wait(wq, &wait, TASK_UNINTERRUPTIBLE);
		mutex_unlock(&bdev_lock);
		schedule();
		finish_wait(wq, &wait);
		goto retry;
	}

	/* yay, all mine */
	whole->bd_claiming = holder;
	mutex_unlock(&bdev_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(bd_prepare_to_claim); /* only for the loop driver */

static void bd_clear_claiming(struct block_device *whole, void *holder)
{
	lockdep_assert_held(&bdev_lock);
	/* tell others that we're done */
	BUG_ON(whole->bd_claiming != holder);
	whole->bd_claiming = NULL;
	wake_up_bit(&whole->bd_claiming, 0);
}

/**
 * bd_finish_claiming - finish claiming of a block device
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 * @hops: block device holder operations
 *
 * Finish exclusive open of a block device. Mark the device as exlusively
 * open by the holder and wake up all waiters for exclusive open to finish.
 */
static void bd_finish_claiming(struct block_device *bdev, void *holder,
		const struct blk_holder_ops *hops)
{
	struct block_device *whole = bdev_whole(bdev);

	mutex_lock(&bdev_lock);
	BUG_ON(!bd_may_claim(bdev, holder, hops));
	/*
	 * Note that for a whole device bd_holders will be incremented twice,
	 * and bd_holder will be set to bd_may_claim before being set to holder
	 */
	whole->bd_holders++;
	whole->bd_holder = bd_may_claim;
	bdev->bd_holders++;
	mutex_lock(&bdev->bd_holder_lock);
	bdev->bd_holder = holder;
	bdev->bd_holder_ops = hops;
	mutex_unlock(&bdev->bd_holder_lock);
	bd_clear_claiming(whole, holder);
	mutex_unlock(&bdev_lock);
}

/**
 * bd_abort_claiming - abort claiming of a block device
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 *
 * Abort claiming of a block device when the exclusive open failed. This can be
 * also used when exclusive open is not actually desired and we just needed
 * to block other exclusive openers for a while.
 */
void bd_abort_claiming(struct block_device *bdev, void *holder)
{
	mutex_lock(&bdev_lock);
	bd_clear_claiming(bdev_whole(bdev), holder);
	mutex_unlock(&bdev_lock);
}
EXPORT_SYMBOL(bd_abort_claiming);

static void bd_end_claim(struct block_device *bdev, void *holder)
{
	struct block_device *whole = bdev_whole(bdev);
	bool unblock = false;

	/*
	 * Release a claim on the device.  The holder fields are protected with
	 * bdev_lock.  open_mutex is used to synchronize disk_holder unlinking.
	 */
	mutex_lock(&bdev_lock);
	WARN_ON_ONCE(bdev->bd_holder != holder);
	WARN_ON_ONCE(--bdev->bd_holders < 0);
	WARN_ON_ONCE(--whole->bd_holders < 0);
	if (!bdev->bd_holders) {
		mutex_lock(&bdev->bd_holder_lock);
		bdev->bd_holder = NULL;
		bdev->bd_holder_ops = NULL;
		mutex_unlock(&bdev->bd_holder_lock);
		if (bdev->bd_write_holder)
			unblock = true;
	}
	if (!whole->bd_holders)
		whole->bd_holder = NULL;
	mutex_unlock(&bdev_lock);

	/*
	 * If this was the last claim, remove holder link and unblock evpoll if
	 * it was a write holder.
	 */
	if (unblock) {
		disk_unblock_events(bdev->bd_disk);
		bdev->bd_write_holder = false;
	}
}

static void blkdev_flush_mapping(struct block_device *bdev)
{
	WARN_ON_ONCE(bdev->bd_holders);
	sync_blockdev(bdev);
	kill_bdev(bdev);
	bdev_write_inode(bdev);
}

static int blkdev_get_whole(struct block_device *bdev, blk_mode_t mode)
{
	struct gendisk *disk = bdev->bd_disk;
	int ret;

	if (disk->fops->open) {
		ret = disk->fops->open(disk, mode);
		if (ret) {
			/* avoid ghost partitions on a removed medium */
			if (ret == -ENOMEDIUM &&
			     test_bit(GD_NEED_PART_SCAN, &disk->state))
				bdev_disk_changed(disk, true);
			return ret;
		}
	}

	if (!atomic_read(&bdev->bd_openers))
		set_init_blocksize(bdev);
	if (test_bit(GD_NEED_PART_SCAN, &disk->state))
		bdev_disk_changed(disk, false);
	atomic_inc(&bdev->bd_openers);
	return 0;
}

static void blkdev_put_whole(struct block_device *bdev)
{
	if (atomic_dec_and_test(&bdev->bd_openers))
		blkdev_flush_mapping(bdev);
	if (bdev->bd_disk->fops->release)
		bdev->bd_disk->fops->release(bdev->bd_disk);
}

static int blkdev_get_part(struct block_device *part, blk_mode_t mode)
{
	struct gendisk *disk = part->bd_disk;
	int ret;

	ret = blkdev_get_whole(bdev_whole(part), mode);
	if (ret)
		return ret;

	ret = -ENXIO;
	if (!bdev_nr_sectors(part))
		/*此分区扇区数为零*/
		goto out_blkdev_put;

	if (!atomic_read(&part->bd_openers)) {
		disk->open_partitions++;
		set_init_blocksize(part);
	}
	atomic_inc(&part->bd_openers);
	return 0;

out_blkdev_put:
	blkdev_put_whole(bdev_whole(part));
	return ret;
}

static void blkdev_put_part(struct block_device *part)
{
	struct block_device *whole = bdev_whole(part);

	if (atomic_dec_and_test(&part->bd_openers)) {
		blkdev_flush_mapping(part);
		whole->bd_disk->open_partitions--;
	}
	blkdev_put_whole(whole);
}

/*由dev获得块设备*/
struct block_device *blkdev_get_no_open(dev_t dev)
{
	struct block_device *bdev;
	struct inode *inode;

	/*查找inode id为dev,且super blok为blockdev_superblock的inode,此即为dev对应的块设备
	 * 添加位置见bdev_add*/
	inode = ilookup(blockdev_superblock, dev);
	if (!inode && IS_ENABLED(CONFIG_BLOCK_LEGACY_AUTOLOAD)) {
		/*inode不存在，但开启了autoload,先尝试做module的probe回调，再查一次inode*/
		blk_request_module(dev);
		inode = ilookup(blockdev_superblock, dev);
		if (inode)
			pr_warn_ratelimited(
"block device autoloading is deprecated and will be removed.\n");
	}

	/*没有查找到块设备*/
	if (!inode)
		return NULL;

	/* switch from the inode reference to a device mode one: */
	bdev = &BDEV_I(inode)->bdev;/*取此inode对应的块设备*/
	if (!kobject_get_unless_zero(&bdev->bd_device.kobj))
		bdev = NULL;
	iput(inode);
	return bdev;
}

void blkdev_put_no_open(struct block_device *bdev)
{
	put_device(&bdev->bd_device);
}

static bool bdev_writes_blocked(struct block_device *bdev)
{
	return bdev->bd_writers == -1;
}

static void bdev_block_writes(struct block_device *bdev)
{
	bdev->bd_writers = -1;
}

static void bdev_unblock_writes(struct block_device *bdev)
{
	bdev->bd_writers = 0;
}

static bool bdev_may_open(struct block_device *bdev, blk_mode_t mode)
{
	if (bdev_allow_write_mounted)
		return true;
	/* Writes blocked? */
	if (mode & BLK_OPEN_WRITE && bdev_writes_blocked(bdev))
		return false;
	if (mode & BLK_OPEN_RESTRICT_WRITES && bdev->bd_writers > 0)
		return false;
	return true;
}

static void bdev_claim_write_access(struct block_device *bdev, blk_mode_t mode)
{
	if (bdev_allow_write_mounted)
		return;

	/* Claim exclusive or shared write access. */
	if (mode & BLK_OPEN_RESTRICT_WRITES)
		bdev_block_writes(bdev);
	else if (mode & BLK_OPEN_WRITE)
		bdev->bd_writers++;
}

static void bdev_yield_write_access(struct block_device *bdev, blk_mode_t mode)
{
	if (bdev_allow_write_mounted)
		return;

	/* Yield exclusive or shared write access. */
	if (mode & BLK_OPEN_RESTRICT_WRITES)
		bdev_unblock_writes(bdev);
	else if (mode & BLK_OPEN_WRITE)
		bdev->bd_writers--;
}

/**
 * bdev_open_by_dev - open a block device by device number
 * @dev: device number of block device to open
 * @mode: open mode (BLK_OPEN_*)
 * @holder: exclusive holder identifier
 * @hops: holder operations
 *
 * Open the block device described by device number @dev. If @holder is not
 * %NULL, the block device is opened with exclusive access.  Exclusive opens may
 * nest for the same @holder.
 *
 * Use this interface ONLY if you really do not have anything better - i.e. when
 * you are behind a truly sucky interface and all you are given is a device
 * number.  Everything else should use bdev_open_by_path().
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Handle with a reference to the block_device on success, ERR_PTR(-errno) on
 * failure.
 */
struct bdev_handle *bdev_open_by_dev(dev_t dev/*设备编号*/, blk_mode_t mode, void *holder,
				     const struct blk_holder_ops *hops)
{
	/*申请结构体*/
	struct bdev_handle *handle = kmalloc(sizeof(struct bdev_handle),
					     GFP_KERNEL);
	struct block_device *bdev;
	bool unblock_events = true;
	struct gendisk *disk;
	int ret;

	if (!handle)
		return ERR_PTR(-ENOMEM);

	ret = devcgroup_check_permission(DEVCG_DEV_BLOCK,
			MAJOR(dev), MINOR(dev),
			((mode & BLK_OPEN_READ) ? DEVCG_ACC_READ : 0) |
			((mode & BLK_OPEN_WRITE) ? DEVCG_ACC_WRITE : 0));
	if (ret)
		goto free_handle;

	/* Blocking writes requires exclusive opener */
	if (mode & BLK_OPEN_RESTRICT_WRITES && !holder) {
		ret = -EINVAL;
		goto free_handle;
	}

	/*取dev_t对应的块设备*/
	bdev = blkdev_get_no_open(dev);
	if (!bdev) {
		ret = -ENXIO;
		goto free_handle;
	}
	disk = bdev->bd_disk;/*取此块设备的gernal disk*/

	if (holder) {
		mode |= BLK_OPEN_EXCL;
		ret = bd_prepare_to_claim(bdev, holder, hops);
		if (ret)
			goto put_blkdev;
	} else {
		if (WARN_ON_ONCE(mode & BLK_OPEN_EXCL)) {
			ret = -EIO;
			goto put_blkdev;
		}
	}

	disk_block_events(disk);

	mutex_lock(&disk->open_mutex);
	ret = -ENXIO;
	if (!disk_live(disk))
		goto abort_claiming;
	if (!try_module_get(disk->fops->owner))
		goto abort_claiming;
	ret = -EBUSY;
	if (!bdev_may_open(bdev, mode))
		goto abort_claiming;
	if (bdev_is_partition(bdev))
		/*块设备分区号不为0，取分区*/
		ret = blkdev_get_part(bdev, mode);
	else
		ret = blkdev_get_whole(bdev, mode);
	if (ret)
		goto put_module;
	bdev_claim_write_access(bdev, mode);
	if (holder) {
		bd_finish_claiming(bdev, holder, hops);

		/*
		 * Block event polling for write claims if requested.  Any write
		 * holder makes the write_holder state stick until all are
		 * released.  This is good enough and tracking individual
		 * writeable reference is too fragile given the way @mode is
		 * used in blkdev_get/put().
		 */
		if ((mode & BLK_OPEN_WRITE) && !bdev->bd_write_holder &&
		    (disk->event_flags & DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE)) {
			bdev->bd_write_holder = true;
			unblock_events = false;
		}
	}
	mutex_unlock(&disk->open_mutex);

	if (unblock_events)
		disk_unblock_events(disk);
	handle->bdev = bdev;
	handle->holder = holder;
	handle->mode = mode;
	return handle;
put_module:
	module_put(disk->fops->owner);
abort_claiming:
	if (holder)
		bd_abort_claiming(bdev, holder);
	mutex_unlock(&disk->open_mutex);
	disk_unblock_events(disk);
put_blkdev:
	blkdev_put_no_open(bdev);
free_handle:
	kfree(handle);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(bdev_open_by_dev);

/**
 * bdev_open_by_path - open a block device by name
 * @path: path to the block device to open
 * @mode: open mode (BLK_OPEN_*)
 * @holder: exclusive holder identifier
 * @hops: holder operations
 *
 * Open the block device described by the device file at @path.  If @holder is
 * not %NULL, the block device is opened with exclusive access.  Exclusive opens
 * may nest for the same @holder.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Handle with a reference to the block_device on success, ERR_PTR(-errno) on
 * failure.
 */
struct bdev_handle *bdev_open_by_path(const char *path/*块设备名称*/, blk_mode_t mode,
		void *holder, const struct blk_holder_ops *hops)
{
	struct bdev_handle *handle;
	dev_t dev;
	int error;

	//取path对应的块设备的dev_t
	error = lookup_bdev(path, &dev);
	if (error)
		return ERR_PTR(error);

	/*通过dev_t取对应的块设备*/
	handle = bdev_open_by_dev(dev, mode, holder, hops);
	if (!IS_ERR(handle) && (mode & BLK_OPEN_WRITE) &&
	    bdev_read_only(handle->bdev)) {
		bdev_release(handle);
		return ERR_PTR(-EACCES);
	}

	return handle;
}
EXPORT_SYMBOL(bdev_open_by_path);

void bdev_release(struct bdev_handle *handle)
{
	struct block_device *bdev = handle->bdev;
	struct gendisk *disk = bdev->bd_disk;

	/*
	 * Sync early if it looks like we're the last one.  If someone else
	 * opens the block device between now and the decrement of bd_openers
	 * then we did a sync that we didn't need to, but that's not the end
	 * of the world and we want to avoid long (could be several minute)
	 * syncs while holding the mutex.
	 */
	if (atomic_read(&bdev->bd_openers) == 1)
		sync_blockdev(bdev);

	mutex_lock(&disk->open_mutex);
	bdev_yield_write_access(bdev, handle->mode);

	if (handle->holder)
		bd_end_claim(bdev, handle->holder);

	/*
	 * Trigger event checking and tell drivers to flush MEDIA_CHANGE
	 * event.  This is to ensure detection of media removal commanded
	 * from userland - e.g. eject(1).
	 */
	disk_flush_events(disk, DISK_EVENT_MEDIA_CHANGE);

	if (bdev_is_partition(bdev))
		blkdev_put_part(bdev);
	else
		blkdev_put_whole(bdev);
	mutex_unlock(&disk->open_mutex);

	module_put(disk->fops->owner);
	blkdev_put_no_open(bdev);
	kfree(handle);
}
EXPORT_SYMBOL(bdev_release);

/**
 * lookup_bdev() - Look up a struct block_device by name.
 * @pathname: Name of the block device in the filesystem.
 * @dev: Pointer to the block device's dev_t, if found.
 *
 * Lookup the block device's dev_t at @pathname in the current
 * namespace if possible and return it in @dev.
 *
 * Context: May sleep.
 * Return: 0 if succeeded, negative errno otherwise.
 */
//通过pathname查找其对应的块设备
int lookup_bdev(const char *pathname, dev_t *dev/*出参，确认pathname对应的块设备*/)
{
	struct inode *inode;
	struct path path;
	int error;

	//pathname为空时，无法查询到对应的bdev
	if (!pathname || !*pathname)
		return -EINVAL;

	//将pathname转换为path
	error = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (error)
		return error;

	//取此dentry所对应的inode
	inode = d_backing_inode(path.dentry);
	error = -ENOTBLK;
	if (!S_ISBLK(inode->i_mode))
		//inode如果非块设备，则跳出
		goto out_path_put;

	/*path指定的是一个块设备*/
	error = -EACCES;
	if (!may_open_dev(&path))
		goto out_path_put;

	*dev = inode->i_rdev;
	error = 0;
out_path_put:
	path_put(&path);
	return error;
}
EXPORT_SYMBOL(lookup_bdev);

/**
 * bdev_mark_dead - mark a block device as dead
 * @bdev: block device to operate on
 * @surprise: indicate a surprise removal
 *
 * Tell the file system that this devices or media is dead.  If @surprise is set
 * to %true the device or media is already gone, if not we are preparing for an
 * orderly removal.
 *
 * This calls into the file system, which then typicall syncs out all dirty data
 * and writes back inodes and then invalidates any cached data in the inodes on
 * the file system.  In addition we also invalidate the block device mapping.
 */
void bdev_mark_dead(struct block_device *bdev, bool surprise)
{
	mutex_lock(&bdev->bd_holder_lock);
	if (bdev->bd_holder_ops && bdev->bd_holder_ops->mark_dead)
		bdev->bd_holder_ops->mark_dead(bdev, surprise);
	else {
		mutex_unlock(&bdev->bd_holder_lock);
		sync_blockdev(bdev);
	}

	invalidate_bdev(bdev);
}
/*
 * New drivers should not use this directly.  There are some drivers however
 * that needs this for historical reasons. For example, the DASD driver has
 * historically had a shutdown to offline mode that doesn't actually remove the
 * gendisk that otherwise looks a lot like a safe device removal.
 */
EXPORT_SYMBOL_GPL(bdev_mark_dead);

void sync_bdevs(bool wait)
{
	struct inode *inode, *old_inode = NULL;

	spin_lock(&blockdev_superblock->s_inode_list_lock);
	list_for_each_entry(inode, &blockdev_superblock->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;
		struct block_device *bdev;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW) ||
		    mapping->nrpages == 0) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&blockdev_superblock->s_inode_list_lock);
		/*
		 * We hold a reference to 'inode' so it couldn't have been
		 * removed from s_inodes list while we dropped the
		 * s_inode_list_lock  We cannot iput the inode now as we can
		 * be holding the last reference and we cannot iput it under
		 * s_inode_list_lock. So we keep the reference and iput it
		 * later.
		 */
		iput(old_inode);
		old_inode = inode;
		bdev = I_BDEV(inode);

		mutex_lock(&bdev->bd_disk->open_mutex);
		if (!atomic_read(&bdev->bd_openers)) {
			; /* skip */
		} else if (wait) {
			/*
			 * We keep the error status of individual mapping so
			 * that applications can catch the writeback error using
			 * fsync(2). See filemap_fdatawait_keep_errors() for
			 * details.
			 */
			filemap_fdatawait_keep_errors(inode->i_mapping);
		} else {
			filemap_fdatawrite(inode->i_mapping);
		}
		mutex_unlock(&bdev->bd_disk->open_mutex);

		spin_lock(&blockdev_superblock->s_inode_list_lock);
	}
	spin_unlock(&blockdev_superblock->s_inode_list_lock);
	iput(old_inode);
}

/*
 * Handle STATX_DIOALIGN for block devices.
 *
 * Note that the inode passed to this is the inode of a block device node file,
 * not the block device's internal inode.  Therefore it is *not* valid to use
 * I_BDEV() here; the block device has to be looked up by i_rdev instead.
 */
void bdev_statx_dioalign(struct inode *inode, struct kstat *stat)
{
	struct block_device *bdev;

	bdev = blkdev_get_no_open(inode->i_rdev);
	if (!bdev)
		return;

	stat->dio_mem_align = bdev_dma_alignment(bdev) + 1;
	stat->dio_offset_align = bdev_logical_block_size(bdev);
	stat->result_mask |= STATX_DIOALIGN;

	blkdev_put_no_open(bdev);
}

static int __init setup_bdev_allow_write_mounted(char *str)
{
	if (kstrtobool(str, &bdev_allow_write_mounted))
		/*解析bdev_allow_write_mounted配置失败*/
		pr_warn("Invalid option string for bdev_allow_write_mounted:"
			" '%s'\n", str);
	return 1;
}
__setup("bdev_allow_write_mounted=", setup_bdev_allow_write_mounted);
