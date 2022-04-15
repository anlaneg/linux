/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Module internals
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/elf.h>
#include <asm/module.h>

struct load_info {
	const char *name;/*来源于modinfo段中的name tag对应value*/
	/* pointer to module in temporary copy, freed at end of load_module() */
	struct module *mod;
	Elf_Ehdr *hdr;/*文件头指针*/
	unsigned long len;/*文件长度*/
	Elf_Shdr *sechdrs;/*section header*/
	char *secstrings/*section name起始地址*/, *strtab;
	unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;
	struct _ddebug *debug;
	unsigned int num_debug;
	bool sig_ok;
#ifdef CONFIG_KALLSYMS
	unsigned long mod_kallsyms_init_off;
#endif
	struct {
		unsigned int sym, str, mod, vers/*__version段index*/, info/*modinfo段index*/, pcpu/*per cpu段index*/;
	} index;
};

extern int mod_verify_sig(const void *mod, struct load_info *info);
