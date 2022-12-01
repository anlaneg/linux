// SPDX-License-Identifier: GPL-2.0
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include "minix.h"

enum {DEPTH = 3, DIRECT = 7};	/* Only double indirect */

typedef u16 block_t;	/* 16 bit, host order */

static inline unsigned long block_to_cpu(block_t n)
{
	return n;
}

static inline block_t cpu_to_block(unsigned long n)
{
	return n;
}

static inline block_t *i_data(struct inode *inode)
{
	return (block_t *)minix_i(inode)->u.i1_data;
}

/*依据block的编号值，按布局填充offsets*/
static int block_to_path(struct inode * inode, long block, int offsets[DEPTH])
{
	int n = 0;

	if (block < 0) {
	    /*block编号为负，参数有误*/
		printk("MINIX-fs: block_to_path: block %ld < 0 on dev %pg\n",
			block, inode->i_sb->s_bdev);
		return 0;
	}
	if ((u64)block * BLOCK_SIZE >= inode->i_sb->s_maxbytes)
	    /*block超过了super block的文件最大字节数，block编号有误*/
		return 0;

	if (block < 7) {
	    /*block编号小于7，则offsets为block本身*/
		offsets[n++] = block;
	} else if ((block -= 7) < 512) {
		offsets[n++] = 7;/*标记为减去7*/
		offsets[n++] = block;/*减去7的偏移量*/
	} else {
		block -= 512;
		offsets[n++] = 8;/*标记为减去512*/
		offsets[n++] = block>>9;/*除以512的商*/
		offsets[n++] = block & 511;/*除以512的余数*/
	}
	return n;
}

#include "itree_common.c"

int V1_minix_get_block(struct inode * inode, long block,
			struct buffer_head *bh_result, int create)
{
	return get_block(inode, block, bh_result, create);
}

void V1_minix_truncate(struct inode * inode)
{
	truncate(inode);
}

unsigned V1_minix_blocks(loff_t size, struct super_block *sb)
{
	return nblocks(size, sb);
}
