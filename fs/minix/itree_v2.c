// SPDX-License-Identifier: GPL-2.0
#include <linux/buffer_head.h>
#include "minix.h"

enum {DIRECT = 7, DEPTH = 4};	/* Have triple indirect */

typedef u32 block_t;	/* 32 bit, host order */

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
	return (block_t *)minix_i(inode)->u.i2_data;
}

#define DIRCOUNT 7
#define INDIRCOUNT(sb) (1 << ((sb)->s_blocksize_bits - 2))

static int block_to_path(struct inode * inode, long block, int offsets[DEPTH])
{
	int n = 0;
	struct super_block *sb = inode->i_sb;

	if (block < 0) {
	    /*block需要大于等于0，返回0*/
		printk("MINIX-fs: block_to_path: block %ld < 0 on dev %pg\n",
			block, sb->s_bdev);
		return 0;
	}
	/*要求的内容超过文件系统可提供的最大file尺寸，返回0*/
	if ((u64)block * (u64)sb->s_blocksize >= sb->s_maxbytes)
		return 0;

	if (block < DIRCOUNT) {
	    /*将block直接填充到offsets数组,样式1*/
		offsets[n++] = block;
	} else if ((block -= DIRCOUNT) < INDIRCOUNT(sb)) {
	    /*先填充DIRCOUNT,再填充减掉DIRCOUNT后的block,样式2*/
		offsets[n++] = DIRCOUNT;
		offsets[n++] = block;
	} else if ((block -= INDIRCOUNT(sb)) < INDIRCOUNT(sb) * INDIRCOUNT(sb)) {
	    /*样式3*/
		offsets[n++] = DIRCOUNT + 1;
		offsets[n++] = block / INDIRCOUNT(sb);
		offsets[n++] = block % INDIRCOUNT(sb);
	} else {
	    /*样式4*/
		block -= INDIRCOUNT(sb) * INDIRCOUNT(sb);
		offsets[n++] = DIRCOUNT + 2;
		offsets[n++] = (block / INDIRCOUNT(sb)) / INDIRCOUNT(sb);
		offsets[n++] = (block / INDIRCOUNT(sb)) % INDIRCOUNT(sb);
		offsets[n++] = block % INDIRCOUNT(sb);
	}
	return n;
}

#include "itree_common.c"

int V2_minix_get_block(struct inode * inode, long block,
			struct buffer_head *bh_result, int create)
{
	return get_block(inode, block, bh_result, create);
}

void V2_minix_truncate(struct inode * inode)
{
	truncate(inode);
}

unsigned V2_minix_blocks(loff_t size, struct super_block *sb)
{
	return nblocks(size, sb);
}
