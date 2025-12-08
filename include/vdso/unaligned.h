/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSO_UNALIGNED_H
#define __VDSO_UNALIGNED_H

#define __get_unaligned_t(type, ptr) ({							\
	const struct { type x; } __packed * __get_pptr = (typeof(__get_pptr))(ptr);	\
	__get_pptr->x;									\
})

#define __put_unaligned_t(type, val, ptr) do {						\
	/*指向ptr*/\
	struct { type x; } __packed * __put_pptr = (typeof(__put_pptr))(ptr);		\
	__put_pptr->x = (val);/*填充ptr指向的内存*/								\
} while (0)

#endif /* __VDSO_UNALIGNED_H */
