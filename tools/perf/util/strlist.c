// SPDX-License-Identifier: GPL-2.0-only
/*
 * (c) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>
 */

#include "strlist.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/zalloc.h>

static
struct rb_node *strlist__node_new(struct rblist *rblist, const void *entry)
{
	const char *s = entry;
	struct rb_node *rc = NULL;
	struct strlist *strlist = container_of(rblist, struct strlist, rblist);
	struct str_node *snode = malloc(sizeof(*snode));

	if (snode != NULL) {
		if (strlist->dupstr) {
			s = strdup(s);
			if (s == NULL)
				goto out_delete;
		}
		/*设置string*/
		snode->s = s;
		rc = &snode->rb_node;
	}

	return rc;

out_delete:
	free(snode);
	return NULL;
}

static void str_node__delete(struct str_node *snode, bool dupstr)
{
	if (dupstr)
		zfree((char **)&snode->s);
	free(snode);
}

static
void strlist__node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
	struct strlist *slist = container_of(rblist, struct strlist, rblist);
	struct str_node *snode = container_of(rb_node, struct str_node, rb_node);

	str_node__delete(snode, slist->dupstr);
}

/*string list节点比对函数*/
static int strlist__node_cmp(struct rb_node *rb_node, const void *entry)
{
	const char *str = entry;
	struct str_node *snode = container_of(rb_node, struct str_node, rb_node);

	return strcmp(snode->s, str);
}

int strlist__add(struct strlist *slist, const char *new_entry)
{
	return rblist__add_node(&slist->rblist, new_entry);
}

int strlist__load(struct strlist *slist, const char *filename)
{
	char entry[1024];
	int err;
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
		return -errno;

	/*自文件中读取一行数据*/
	while (fgets(entry, sizeof(entry), fp) != NULL) {
		const size_t len = strlen(entry);

		if (len == 0)
			continue;
		entry[len - 1] = '\0';

		/*添加元素到slist*/
		err = strlist__add(slist, entry);
		if (err != 0)
			goto out;
	}

	err = 0;
out:
	fclose(fp);
	return err;
}

void strlist__remove(struct strlist *slist, struct str_node *snode)
{
	rblist__remove_node(&slist->rblist, &snode->rb_node);
}

struct str_node *strlist__find(struct strlist *slist, const char *entry)
{
	struct str_node *snode = NULL;
	struct rb_node *rb_node = rblist__find(&slist->rblist, entry);

	if (rb_node)
		snode = container_of(rb_node, struct str_node, rb_node);

	return snode;
}

static int strlist__parse_list_entry(struct strlist *slist, const char *s,
				     const char *subst_dir)
{
	int err;
	char *subst = NULL;

	/*s以file://开头,打开给定的文件，构造slist*/
	if (strncmp(s, "file://", 7) == 0)
		return strlist__load(slist, s + 7);

	if (subst_dir) {
	    /*指定了目录名称，添加目录构成路径，加载此文件，构造slist*/
		err = -ENOMEM;
		if (asprintf(&subst, "%s/%s", subst_dir, s) < 0)
			goto out;

		if (access(subst, F_OK) == 0) {
			err = strlist__load(slist, subst);
			goto out;
		}

		if (slist->file_only) {
			err = -ENOENT;
			goto out;
		}
	}

	/*在slist中添加s*/
	err = strlist__add(slist, s);
out:
	free(subst);
	return err;
}

/*加载文件内容或字符串内容到slist*/
static int strlist__parse_list(struct strlist *slist, const char *s, const char *subst_dir)
{
	char *sep;
	int err;

	while ((sep = strchr(s, ',')) != NULL) {
	    /*置字符串结束符*/
		*sep = '\0';
		/*添加s到slist*/
		err = strlist__parse_list_entry(slist, s/*分隔的一部分内容*/, subst_dir);
		/*还原字符串内容*/
		*sep = ',';
		if (err != 0)
			return err;
		s = sep + 1;
	}

	/*直接添加s到slist*/
	return *s ? strlist__parse_list_entry(slist, s, subst_dir) : 0;
}

struct strlist *strlist__new(const char *list, const struct strlist_config *config)
{
	struct strlist *slist = malloc(sizeof(*slist));

	if (slist != NULL) {
		bool dupstr = true;
		bool file_only = false;
		const char *dirname = NULL;

		if (config) {
			dupstr = !config->dont_dupstr;
			/*文件目录名称*/
			dirname = config->dirname;
			file_only = config->file_only;
		}

		rblist__init(&slist->rblist);
		slist->rblist.node_cmp    = strlist__node_cmp;
		slist->rblist.node_new    = strlist__node_new;
		slist->rblist.node_delete = strlist__node_delete;

		slist->dupstr	 = dupstr;
		slist->file_only = file_only;

		/*指定了list,将list内容（字符串或者文件中的字符串）添加到slist中*/
		if (list && strlist__parse_list(slist, list, dirname) != 0)
			goto out_error;
	}

	return slist;
out_error:
	free(slist);
	return NULL;
}

void strlist__delete(struct strlist *slist)
{
	if (slist != NULL)
		rblist__delete(&slist->rblist);
}

struct str_node *strlist__entry(const struct strlist *slist, unsigned int idx)
{
	struct str_node *snode = NULL;
	struct rb_node *rb_node;

	rb_node = rblist__entry(&slist->rblist, idx);
	if (rb_node)
		snode = container_of(rb_node, struct str_node, rb_node);

	return snode;
}
