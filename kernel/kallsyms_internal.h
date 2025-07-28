/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_KALLSYMS_INTERNAL_H_
#define LINUX_KALLSYMS_INTERNAL_H_

#include <linux/types.h>

extern const int kallsyms_offsets[];
extern const u8 kallsyms_names[];/*记录kernel内置的符号*/

extern const unsigned int kallsyms_num_syms;/*记录kernel内置符号总数*/
extern const unsigned long kallsyms_relative_base;

extern const char kallsyms_token_table[];/*能过token编号获得token*/
extern const u16 kallsyms_token_index[];/*通过token索引得到token编号*/

extern const unsigned int kallsyms_markers[];
extern const u8 kallsyms_seqs_of_names[];

#endif // LINUX_KALLSYMS_INTERNAL_H_
