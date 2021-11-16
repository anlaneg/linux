/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Today's hack: quantum tunneling in structs
 *
 * 'entries' and 'term' are never anywhere referenced by word in code. In fact,
 * they serve as the hanging-off data accessed through repl.data[].
 */

/* tbl has the following structure equivalent, but is C99 compliant:
 * 通过此宏产生如下所示的结构体
 * struct {
 *	struct type##_replace repl;
 *	struct type##_standard entries[nhooks];
 *	struct type##_error term;
 * } *tbl;
 * 例如看struct ipt_replace ,struct ipt_error结构
 */
//注：宏要求在其可见区有info存在
#define xt_alloc_initial_table(type, typ2) ({ \
	/*要注册的hook mask*/\
	unsigned int hook_mask = info->valid_hooks; \
	/*注册了多少hook,自0开始计*/\
	unsigned int nhooks = hweight32(hook_mask); \
	unsigned int bytes = 0, hooknum = 0, i = 0; \
	struct { \
		struct type##_replace repl; \
		struct type##_standard entries[]; \
	} *tbl; \
	/*指向结构体中term成员*/\
	struct type##_error *term; \
	/*我们将在最后一个待注册的hook位置后存放term,这里获得term成员的offset，考虑typeof(*term）成员对齐*/\
	size_t term_offset = (offsetof(typeof(*tbl), entries[nhooks]) + \
		__alignof__(*term) - 1) & ~(__alignof__(*term) - 1); \
	/*申请对应的结构体{repl,entries[nhooks],term}*/\
	tbl = kzalloc(term_offset + sizeof(*term), GFP_KERNEL); \
	if (tbl == NULL) \
		return NULL; \
	/*使term指向上文term成员的位置（已对齐）*/\
	term = (struct type##_error *)&(((char *)tbl)[term_offset]); \
	/*设置表名*/\
	strncpy(tbl->repl.name, info->name, sizeof(tbl->repl.name)); \
	/*填充term*/                                      \
	*term = (struct type##_error)typ2##_ERROR_INIT;  \
	/*设置需要挂接的hook点掩码*/\
	tbl->repl.valid_hooks = hook_mask; \
	/*nhooks是一个自0开始计的数，故hook的数目为nhooks+1*/\
	tbl->repl.num_entries = nhooks + 1; \
	tbl->repl.size = nhooks * sizeof(struct type##_standard) + \
			 sizeof(struct type##_error); \
	for (; hook_mask != 0; hook_mask >>= 1, ++hooknum) { \
		if (!(hook_mask & 1)) \
			continue; /*跳过未指明的hook*/\
		tbl->repl.hook_entry[hooknum] = bytes; \
		tbl->repl.underflow[hooknum]  = bytes; \
		/*填充entries*/\
		tbl->entries[i++] = (struct type##_standard) \
			typ2##_STANDARD_INIT(NF_ACCEPT); \
		bytes += sizeof(struct type##_standard); \
	} \
	tbl; \
})
