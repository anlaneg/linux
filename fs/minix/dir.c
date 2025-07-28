// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix directory handling functions
 *
 *  Updated to filesystem version 3 by Daniel Aragones
 */

#include "minix.h"
#include <linux/buffer_head.h>
#include <linux/highmem.h>
#include <linux/swap.h>

typedef struct minix_dir_entry minix_dirent;
typedef struct minix3_dir_entry minix3_dirent;

static int minix_readdir(struct file *, struct dir_context *);

const struct file_operations minix_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= minix_readdir,
	.fsync		= generic_file_fsync,
};

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
minix_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = PAGE_SIZE;

	if (page_nr == (inode->i_size >> PAGE_SHIFT))
		last_byte = inode->i_size & (PAGE_SIZE - 1);
	return last_byte;
}

static void dir_commit_chunk(struct folio *folio, loff_t pos, unsigned len)
{
	struct address_space *mapping = folio->mapping;
	struct inode *dir = mapping->host;

	block_write_end(NULL, mapping, pos, len, len, folio, NULL);

	if (pos+len > dir->i_size) {
		i_size_write(dir, pos+len);
		mark_inode_dirty(dir);
	}
	folio_unlock(folio);
}

static int minix_handle_dirsync(struct inode *dir)
{
	int err;

	err = filemap_write_and_wait(dir->i_mapping);
	if (!err)
		err = sync_inode_metadata(dir, 1);
	return err;
}

/*读取目录对应的inode的第n号页，并返回其对应的内容*/
static void *dir_get_folio(struct inode *dir, unsigned long n/*页序号*/,
		struct folio **foliop)
{
	struct folio *folio = read_mapping_folio(dir->i_mapping, n, NULL);

	if (IS_ERR(folio))
		return ERR_CAST(folio);
	*foliop = folio;
	return kmap_local_folio(folio, 0);
}

static inline void *minix_next_entry(void *de, struct minix_sb_info *sbi)
{
	return (void*)((char*)de + sbi->s_dirsize);
}

static int minix_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct minix_sb_info *sbi = minix_sb(sb);
	unsigned chunk_size = sbi->s_dirsize;
	unsigned long npages = dir_pages(inode);/*目录占有多少page*/
	unsigned long pos = ctx->pos;
	unsigned offset;
	unsigned long n;

	ctx->pos = pos = ALIGN(pos, chunk_size);
	if (pos >= inode->i_size)
	    /*pos超过了inode大小，返回0*/
		return 0;

	offset = pos & ~PAGE_MASK;/*pos在页中的偏移*/
	n = pos >> PAGE_SHIFT;/*pos对应的页号*/

	for ( ; n < npages; n++, offset = 0) {
		char *p, *kaddr, *limit;
		struct folio *folio;

		kaddr = dir_get_folio(inode, n, &folio);
		if (IS_ERR(kaddr))
			continue;
		p = kaddr+offset;/*指向对应的dirent*/
		limit = kaddr + minix_last_byte(inode, n) - chunk_size;
		for ( ; p <= limit; p = minix_next_entry(p, sbi)) {
			const char *name;
			__u32 inumber;
			if (sbi->s_version == MINIX_V3) {
				minix3_dirent *de3 = (minix3_dirent *)p;
				name = de3->name;
				inumber = de3->inode;
	 		} else {
				minix_dirent *de = (minix_dirent *)p;
				name = de->name;
				inumber = de->inode;
			}
			if (inumber) {
				unsigned l = strnlen(name, sbi->s_namelen);
				/*调用ctx->actor函数*/
				if (!dir_emit(ctx, name, l,
					      inumber, DT_UNKNOWN)) {
					folio_release_kmap(folio, p);
					return 0;
				}
			}
			ctx->pos += chunk_size;/*增加pos*/
		}
		folio_release_kmap(folio, kaddr);
	}
	return 0;
}

static inline int namecompare(int len, int maxlen,
	const char * name, const char * buffer)
{
	if (len < maxlen && buffer[len])
	    /*长度在范围，但内容不匹配*/
		return 0;
	/*内容匹配成功*/
	return !memcmp(name, buffer, len);
}

/*
 *	minix_find_entry()
 *
 * finds an entry in the specified directory with the wanted name.
 * It does NOT read the inode of the
 * entry - you'll have to do that yourself if you want to.
 * 
 * On Success folio_release_kmap() should be called on *foliop.
 */
minix_dirent *minix_find_entry(struct dentry *dentry, struct folio **foliop)
{
    /*dentry名称*/
	const char * name = dentry->d_name.name;
	/*dentry名称长度*/
	int namelen = dentry->d_name.len;
	/*取父目录对应的inode*/
	struct inode * dir = d_inode(dentry->d_parent);
	/*取它对应的super_block*/
	struct super_block * sb = dir->i_sb;
	struct minix_sb_info * sbi = minix_sb(sb);
	unsigned long n;
	/*取目录大小需要多少个页*/
	unsigned long npages = dir_pages(dir);
	char *p;

	char *namx;
	__u32 inumber;

	for (n = 0; n < npages; n++) {
		char *kaddr, *limit;

		/*取此目录的n号页*/
		kaddr = dir_get_folio(dir, n, foliop);
		if (IS_ERR(kaddr))
			continue;

		limit = kaddr + minix_last_byte(dir, n) - sbi->s_dirsize;
		for (p = kaddr; p <= limit; p = minix_next_entry(p, sbi)) {
		    /*取目录下成员名称及inumber*/
			if (sbi->s_version == MINIX_V3) {
				minix3_dirent *de3 = (minix3_dirent *)p;
				namx = de3->name;
				inumber = de3->inode;
 			} else {
				minix_dirent *de = (minix_dirent *)p;
				namx = de->name;
				inumber = de->inode;
			}
			if (!inumber)
			    /*忽略没有ino的节点*/
				continue;
			/*要查询的namx与此目录下的文件de->name匹配，跳found*/
			if (namecompare(namelen, sbi->s_namelen, name, namx))
				goto found;
		}
		folio_release_kmap(*foliop, kaddr);
	}
	return NULL;

found:
	return (minix_dirent *)p;/*返回对应的dirent指针*/
}

int minix_add_link(struct dentry *dentry, struct inode *inode)
{
    /*取dentry父节点*/
	struct inode *dir = d_inode(dentry->d_parent);
	/*dentry节点名称*/
	const char * name = dentry->d_name.name;
	/*本节点名称长度*/
	int namelen = dentry->d_name.len;
	/*取super block*/
	struct super_block * sb = dir->i_sb;
	/*由super block取得minix super block info*/
	struct minix_sb_info * sbi = minix_sb(sb);
	struct folio *folio = NULL;
	/*父目录中占用了多少page*/
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr, *p;
	minix_dirent *de;
	minix3_dirent *de3;
	loff_t pos;
	int err;
	char *namx = NULL;
	__u32 inumber;

	/*
	 * We take care of directory expansion in the same loop
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	for (n = 0; n <= npages; n++) {
		char *limit, *dir_end;

		/*读取父目录的第n个页*/
		kaddr = dir_get_folio(dir, n, &folio);
		if (IS_ERR(kaddr))
			return PTR_ERR(kaddr);
		folio_lock(folio);
		dir_end = kaddr + minix_last_byte(dir, n);
		limit = kaddr + PAGE_SIZE - sbi->s_dirsize;
		/*遍历记录在此页的direntry*/
		for (p = kaddr; p <= limit; p = minix_next_entry(p, sbi)) {
			de = (minix_dirent *)p;
			de3 = (minix3_dirent *)p;
			/*取当前访问的dir entry对应的name,inode*/
			if (sbi->s_version == MINIX_V3) {
				namx = de3->name;
				inumber = de3->inode;
		 	} else {
  				namx = de->name;
				inumber = de->inode;
			}
			if (p == dir_end) {
				/* We hit i_size */
				if (sbi->s_version == MINIX_V3)
					de3->inode = 0;
		 		else
					de->inode = 0;
				goto got_it;
			}
			if (!inumber)
				goto got_it;

			/*文件已存在*/
			err = -EEXIST;
			if (namecompare(namelen, sbi->s_namelen, name, namx))
				goto out_unlock;
		}
		folio_unlock(folio);
		folio_release_kmap(folio, kaddr);
	}
	BUG();
	return -EINVAL;

got_it:
	pos = folio_pos(folio) + offset_in_folio(folio, p);
	err = minix_prepare_chunk(folio, pos, sbi->s_dirsize);
	if (err)
		goto out_unlock;
	/*设置文件名称*/
	memcpy (namx, name, namelen);
	/*设置dir entry对应的inode编号*/
	if (sbi->s_version == MINIX_V3) {
		memset (namx + namelen, 0, sbi->s_dirsize - namelen - 4);
		de3->inode = inode->i_ino;
	} else {
		memset (namx + namelen, 0, sbi->s_dirsize - namelen - 2);
		de->inode = inode->i_ino;
	}
	/*落盘*/
	dir_commit_chunk(folio, pos, sbi->s_dirsize);
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	mark_inode_dirty(dir);
	err = minix_handle_dirsync(dir);
out_put:
	folio_release_kmap(folio, kaddr);
	return err;
out_unlock:
	folio_unlock(folio);
	goto out_put;
}

int minix_delete_entry(struct minix_dir_entry *de, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	loff_t pos = folio_pos(folio) + offset_in_folio(folio, de);
	struct minix_sb_info *sbi = minix_sb(inode->i_sb);
	unsigned len = sbi->s_dirsize;
	int err;

	folio_lock(folio);
	err = minix_prepare_chunk(folio, pos, len);
	if (err) {
		folio_unlock(folio);
		return err;
	}
	if (sbi->s_version == MINIX_V3)
		((minix3_dirent *)de)->inode = 0;
	else
		de->inode = 0;
	dir_commit_chunk(folio, pos, len);
	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	mark_inode_dirty(inode);
	return minix_handle_dirsync(inode);
}

int minix_make_empty(struct inode *inode, struct inode *dir)
{
	struct folio *folio = filemap_grab_folio(inode->i_mapping, 0);
	struct minix_sb_info *sbi = minix_sb(inode->i_sb);
	char *kaddr;
	int err;

	if (IS_ERR(folio))
		return PTR_ERR(folio);
	err = minix_prepare_chunk(folio, 0, 2 * sbi->s_dirsize);
	if (err) {
		folio_unlock(folio);
		goto fail;
	}

	kaddr = kmap_local_folio(folio, 0);
	memset(kaddr, 0, folio_size(folio));

	if (sbi->s_version == MINIX_V3) {
		minix3_dirent *de3 = (minix3_dirent *)kaddr;

		de3->inode = inode->i_ino;
		strcpy(de3->name, ".");
		de3 = minix_next_entry(de3, sbi);
		de3->inode = dir->i_ino;
		strcpy(de3->name, "..");
	} else {
		minix_dirent *de = (minix_dirent *)kaddr;

		de->inode = inode->i_ino;
		strcpy(de->name, ".");
		de = minix_next_entry(de, sbi);
		de->inode = dir->i_ino;
		strcpy(de->name, "..");
	}
	kunmap_local(kaddr);

	dir_commit_chunk(folio, 0, 2 * sbi->s_dirsize);
	err = minix_handle_dirsync(inode);
fail:
	folio_put(folio);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int minix_empty_dir(struct inode * inode)
{
	struct folio *folio = NULL;
	unsigned long i, npages = dir_pages(inode);
	struct minix_sb_info *sbi = minix_sb(inode->i_sb);
	char *name, *kaddr;
	__u32 inumber;

	for (i = 0; i < npages; i++) {
		char *p, *limit;

		kaddr = dir_get_folio(inode, i, &folio);
		if (IS_ERR(kaddr))
			continue;

		limit = kaddr + minix_last_byte(inode, i) - sbi->s_dirsize;
		/*遍历dirent*/
		for (p = kaddr; p <= limit; p = minix_next_entry(p, sbi)) {
			if (sbi->s_version == MINIX_V3) {
				minix3_dirent *de3 = (minix3_dirent *)p;
				name = de3->name;
				inumber = de3->inode;
			} else {
				minix_dirent *de = (minix_dirent *)p;
				name = de->name;
				inumber = de->inode;
			}

			/*dirent的inode不为0*/
			if (inumber != 0) {
				/* check for . and .. */
				if (name[0] != '.')
				    /*内容名称为以'.'开头*/
					goto not_empty;
				if (!name[1]) {
				    /*遇到名称为'.'的文件，inumber不为自身，则为非空*/
					if (inumber != inode->i_ino)
						goto not_empty;
				} else if (name[1] != '.')
				    /*遇到隐藏文件，则为非空*/
					goto not_empty;
				else if (name[2])
				    /*遇到'..??'文件，则为非空*/
					goto not_empty;
			}
		}
		folio_release_kmap(folio, kaddr);
	}
	return 1;

not_empty:
	folio_release_kmap(folio, kaddr);
	return 0;
}

/* Releases the page */
int minix_set_link(struct minix_dir_entry *de, struct folio *folio,
		struct inode *inode)
{
	struct inode *dir = folio->mapping->host;
	struct minix_sb_info *sbi = minix_sb(dir->i_sb);
	loff_t pos = folio_pos(folio) + offset_in_folio(folio, de);
	int err;

	folio_lock(folio);
	err = minix_prepare_chunk(folio, pos, sbi->s_dirsize);
	if (err) {
		folio_unlock(folio);
		return err;
	}
	if (sbi->s_version == MINIX_V3)
		((minix3_dirent *)de)->inode = inode->i_ino;
	else
		de->inode = inode->i_ino;
	dir_commit_chunk(folio, pos, sbi->s_dirsize);
	inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
	mark_inode_dirty(dir);
	return minix_handle_dirsync(dir);
}

struct minix_dir_entry *minix_dotdot(struct inode *dir, struct folio **foliop)
{
	struct minix_sb_info *sbi = minix_sb(dir->i_sb);
	struct minix_dir_entry *de = dir_get_folio(dir, 0, foliop);

	if (!IS_ERR(de))
		return minix_next_entry(de, sbi);
	return NULL;
}

ino_t minix_inode_by_name(struct dentry *dentry)
{
	struct folio *folio;
	/*取dentry对应的dir_entry，并返回对应指针*/
	struct minix_dir_entry *de = minix_find_entry(dentry, &folio);
	ino_t res = 0;

	if (de) {
		struct inode *inode = folio->mapping->host;
		struct minix_sb_info *sbi = minix_sb(inode->i_sb);

		/*取此dentry对应的inode编号*/
		if (sbi->s_version == MINIX_V3)
			res = ((minix3_dirent *) de)->inode;
		else
			res = de->inode;
		folio_release_kmap(folio, de);
	}
	return res;
}
