/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_KALLSYMS_INTERNAL_H_
#define LINUX_KALLSYMS_INTERNAL_H_

#include <linux/types.h>

/*
 * These will be re-linked against their real values
 * during the second link stage.
 */
extern const unsigned long kallsyms_addresses[] __weak;
extern const int kallsyms_offsets[] __weak;
extern const u8 kallsyms_names[] __weak;/*记录kernel内置的符号*/

/*
 * Tell the compiler that the count isn't in the small data section if the arch
 * has one (eg: FRV).
 */
extern const unsigned int kallsyms_num_syms
__section(".rodata") __attribute__((weak));/*记录kernel内置符号总数*/

extern const unsigned long kallsyms_relative_base
__section(".rodata") __attribute__((weak));

extern const char kallsyms_token_table[] __weak;/*能过token编号获得token*/
extern const u16 kallsyms_token_index[] __weak;/*通过token索引得到token编号*/

extern const unsigned int kallsyms_markers[] __weak;
extern const u8 kallsyms_seqs_of_names[] __weak;

#endif // LINUX_KALLSYMS_INTERNAL_H_
