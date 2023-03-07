// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/bitmap.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Modified for 680x0 by Hamish Macdonald
 * Fixed for 680x0 by Andreas Schwab
 */

/* bitmap.c contains the code that handles the inode and block bitmaps */

#include "minix.h"
#include <linux/buffer_head.h>
#include <linux/bitops.h>
#include <linux/sched.h>

static DEFINE_SPINLOCK(bitmap_lock);

/*
 * bitmap consists of blocks filled with 16bit words
 * bit set == busy, bit clear == free
 * endianness is a mess, but for counting zero bits it really doesn't matter...
 */
static __u32 count_free(struct buffer_head *map[], unsigned blocksize, __u32 numbits)
{
    /*计算map的空闲bit的数目*/
	__u32 sum = 0;
	/*numbits使其为blocks的整数倍，从而得出block总数量（*8）*/
	unsigned blocks = DIV_ROUND_UP(numbits, blocksize * 8);

	while (blocks--) {
	    /*每个map指向一个blocksize页，故外层循环每次变更一个buffer head*/
		unsigned words = blocksize / 2;/*由于采用u16进行遍历，故words数为除二*/
		__u16 *p = (__u16 *)(*map++)->b_data;
		/*计算此map中空闲数目*/
		while (words--)
		    /*hweight16用于计算p指针指向的内容中'1'的数目，
		     * 采用16减后，得到p指向内容中'0'的数目，即可用空间数量*/
			sum += 16 - hweight16(*p++);
	}

	return sum;
}

/*归还给定的block,指明其不再占用*/
void minix_free_block(struct inode *inode, unsigned long block/*block编号*/)
{
	struct super_block *sb = inode->i_sb;
	struct minix_sb_info *sbi = minix_sb(sb);
	struct buffer_head *bh;
	/*等价于将block_size*8,获得一个block中可提供多少bit*/
	int k = sb->s_blocksize_bits + 3;
	unsigned long bit, zone;

	if (block < sbi->s_firstdatazone || block >= sbi->s_nzones) {
		printk("Trying to free block not in datazone\n");
		return;
	}
	/*移除block中的firstdatazone偏移量*/
	zone = block - sbi->s_firstdatazone + 1;
	bit = zone & ((1<<k) - 1);
	zone >>= k;
	if (zone >= sbi->s_zmap_blocks) {
		printk("minix_free_block: nonexistent bitmap buffer\n");
		return;
	}
	bh = sbi->s_zmap[zone];/*定位到相应zmap*/
	spin_lock(&bitmap_lock);
	/*清除掉此block对应的bit位*/
	if (!minix_test_and_clear_bit(bit, bh->b_data))
		printk("minix_free_block (%s:%lu): bit already cleared\n",
		       sb->s_id, block);
	/*注意：其对应的内容未进行清除，故申请block时需要清零*/
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(bh);
	return;
}

/*申请一个可用的block*/
int minix_new_block(struct inode * inode)
{
	struct minix_sb_info *sbi = minix_sb(inode->i_sb);
	int bits_per_zone = 8 * inode->i_sb->s_blocksize;
	int i;

	for (i = 0; i < sbi->s_zmap_blocks; i++) {
		struct buffer_head *bh = sbi->s_zmap[i];
		int j;

		spin_lock(&bitmap_lock);
		/*在bh中找一个空闲的bit*/
		j = minix_find_first_zero_bit(bh->b_data, bits_per_zone);
		if (j < bits_per_zone) {
		    /*占用此bit*/
			minix_set_bit(j, bh->b_data);
			spin_unlock(&bitmap_lock);
			mark_buffer_dirty(bh);/*此bh为dirty*/
			/*更新j，使其位于其对应逻辑值（增加了sbi->s_firstdatazone的偏移量）*/
			j += i * bits_per_zone + sbi->s_firstdatazone-1;
			if (j < sbi->s_firstdatazone || j >= sbi->s_nzones)
				break;
			return j;
		}
		spin_unlock(&bitmap_lock);
	}
	return 0;
}

unsigned long minix_count_free_blocks(struct super_block *sb)
{
	struct minix_sb_info *sbi = minix_sb(sb);
	/*有效bits数*/
	u32 bits = sbi->s_nzones - sbi->s_firstdatazone + 1;

	/*计算zone block空闲的字节数*/
	return (count_free(sbi->s_zmap/*指明block占用情况的buffer header*/, sb->s_blocksize, bits)
		<< sbi->s_log_zone_size);
}

struct minix_inode *
minix_V1_raw_inode(struct super_block *sb, ino_t ino, struct buffer_head **bh)
{
	int block;
	struct minix_sb_info *sbi = minix_sb(sb);
	struct minix_inode *p;

	if (!ino || ino > sbi->s_ninodes) {
		printk("Bad inode number on dev %s: %ld is out of range\n",
		       sb->s_id, (long)ino);
		return NULL;
	}
	ino--;
	block = 2 + sbi->s_imap_blocks + sbi->s_zmap_blocks +
		 ino / MINIX_INODES_PER_BLOCK;
	*bh = sb_bread(sb, block);
	if (!*bh) {
		printk("Unable to read inode block\n");
		return NULL;
	}
	p = (void *)(*bh)->b_data;
	return p + ino % MINIX_INODES_PER_BLOCK;
}

struct minix2_inode *
minix_V2_raw_inode(struct super_block *sb, ino_t ino, struct buffer_head **bh)
{
	int block;
	struct minix_sb_info *sbi = minix_sb(sb);
	struct minix2_inode *p;
	/*一个blocksize，包含多少个minix2_inode结构体*/
	int minix2_inodes_per_block = sb->s_blocksize / sizeof(struct minix2_inode);

	*bh = NULL;
	if (!ino || ino > sbi->s_ninodes) {
	    /*inode编号有误*/
		printk("Bad inode number on dev %s: %ld is out of range\n",
		       sb->s_id, (long)ino);
		return NULL;
	}
	ino--;
	/*由ino换算到block*/
	block = 2 + sbi->s_imap_blocks + sbi->s_zmap_blocks +
		 ino / minix2_inodes_per_block;
	/*加载block内容*/
	*bh = sb_bread(sb, block);
	if (!*bh) {
		printk("Unable to read inode block\n");
		return NULL;
	}
	/*取block内容的起始地址*/
	p = (void *)(*bh)->b_data;

	/*取ino内容对应的地址，此内容为minix2_inode结构体*/
	return p + ino % minix2_inodes_per_block;
}

/* Clear the link count and mode of a deleted inode on disk. */

static void minix_clear_inode(struct inode *inode)
{
	struct buffer_head *bh = NULL;

	if (INODE_VERSION(inode) == MINIX_V1) {
		struct minix_inode *raw_inode;
		raw_inode = minix_V1_raw_inode(inode->i_sb, inode->i_ino, &bh);
		if (raw_inode) {
			raw_inode->i_nlinks = 0;
			raw_inode->i_mode = 0;
		}
	} else {
		struct minix2_inode *raw_inode;
		raw_inode = minix_V2_raw_inode(inode->i_sb, inode->i_ino, &bh);
		if (raw_inode) {
			raw_inode->i_nlinks = 0;
			raw_inode->i_mode = 0;
		}
	}
	if (bh) {
		mark_buffer_dirty(bh);
		brelse (bh);
	}
}

void minix_free_inode(struct inode * inode)
{
	struct super_block *sb = inode->i_sb;
	struct minix_sb_info *sbi = minix_sb(inode->i_sb);
	struct buffer_head *bh;
	int k = sb->s_blocksize_bits + 3;
	unsigned long ino, bit;

	ino = inode->i_ino;
	if (ino < 1 || ino > sbi->s_ninodes) {
		printk("minix_free_inode: inode 0 or nonexistent inode\n");
		return;
	}
	bit = ino & ((1<<k) - 1);
	ino >>= k;
	if (ino >= sbi->s_imap_blocks) {
		printk("minix_free_inode: nonexistent imap in superblock\n");
		return;
	}

	minix_clear_inode(inode);	/* clear on-disk copy */

	bh = sbi->s_imap[ino];
	spin_lock(&bitmap_lock);
	if (!minix_test_and_clear_bit(bit, bh->b_data))
		printk("minix_free_inode: bit %lu already cleared\n", bit);
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(bh);
}

struct inode *minix_new_inode(const struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct minix_sb_info *sbi = minix_sb(sb);
	/*新申请一个inode*/
	struct inode *inode = new_inode(sb);
	struct buffer_head * bh;
	/*按bit占用block,故block有效位数为bits_per_zone*/
	int bits_per_zone = 8 * sb->s_blocksize;
	unsigned long j;
	int i;

	if (!inode)
	    	/*申请inode失败*/
		return ERR_PTR(-ENOMEM);
	j = bits_per_zone;
	bh = NULL;
	spin_lock(&bitmap_lock);
	/*查找空闲的inode编号*/
	for (i = 0; i < sbi->s_imap_blocks; i++) {
		bh = sbi->s_imap[i];
		/*在bh->b_data中查找首个0 bit*/
		j = minix_find_first_zero_bit(bh->b_data, bits_per_zone/*bits长度*/);
		if (j < bits_per_zone)
		    /*找到了，跳出*/
			break;
	}
	if (!bh || j >= bits_per_zone) {
	    /*没有找到空闲的bit*/
		spin_unlock(&bitmap_lock);
		iput(inode);
		return ERR_PTR(-ENOSPC);
	}

	/*占用此bit*/
	if (minix_test_and_set_bit(j, bh->b_data)) {	/* shouldn't happen */
		spin_unlock(&bitmap_lock);
		printk("minix_new_inode: bit already set\n");
		iput(inode);
		return ERR_PTR(-ENOSPC);
	}
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(bh);/*此buffer已被更改，置dirty*/
	j += i * bits_per_zone;/*更新j到逻辑位置*/
	if (!j || j > sbi->s_ninodes) {
		iput(inode);
		return ERR_PTR(-ENOSPC);
	}
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	inode->i_ino = j;/*指明inode编号*/
	/*更新inode修改时间，访问时间，更新时间*/
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;
	memset(&minix_i(inode)->u, 0, sizeof(minix_i(inode)->u));
	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	return inode;
}

unsigned long minix_count_free_inodes(struct super_block *sb)
{
	struct minix_sb_info *sbi = minix_sb(sb);
	u32 bits = sbi->s_ninodes + 1;

	return count_free(sbi->s_imap, sb->s_blocksize, bits);
}
