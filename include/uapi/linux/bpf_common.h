/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BPF_COMMON_H__
#define _UAPI__LINUX_BPF_COMMON_H__

/* Instruction classes */
//指令类别(0b111，共8种)
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
//装载类指令操作位宽(0b11000，共4种)
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
/* eBPF		BPF_DW		0x18    64-bit */

//指令访问模式（0b11100000，共8种)
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0
/* eBPF     BPF_XADD    0xc0    exclusive add */

/* alu/jmp fields */
//数值运算类指令(0b11110000,共16种)
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60 //左移
#define		BPF_RSH		0x70 //右移
#define		BPF_NEG		0x80 //取负数
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0
/* eBPF     BPF_MOV     0xb0  mov reg to reg */
/* eBPF BPF_ARSH        0xc0  sign extending arithmetic shift right */

//跳转类指令
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08 //按顺序跳转下一条指令

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#endif /* _UAPI__LINUX_BPF_COMMON_H__ */
