// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IP/TCP/UDP checksumming routines
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Tom May, <ftom@netcom.com>
 *		Andreas Schwab, <schwab@issan.informatik.uni-dortmund.de>
 *		Lots of code moved from tcp.c and ip.c; see those files
 *		for more names.
 *
 * 03/02/96	Jes Sorensen, Andreas Schwab, Roman Hodek:
 *		Fixed some nasty bugs, causing some horrible crashes.
 *		A: At some points, the sum (%0) was used as
 *		length-counter instead of the length counter
 *		(%1). Thanks to Roman Hodek for pointing this out.
 *		B: GCC seems to mess up if one uses too many
 *		data-registers to hold input values and one tries to
 *		specify d0 and d1 as scratch registers. Letting gcc
 *		choose these registers itself solves the problem.
 */

/* Revised by Kenneth Albanowski for m68knommu. Basic problem: unaligned access
 kills, so most of the assembly has to go. */

#include <linux/export.h>
#include <net/checksum.h>

#include <asm/byteorder.h>

#ifndef do_csum
//将checksum由32bits拆叠后更新为16bits(见checksum计算第4步）
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

//1、 先将需要计算checksum数据中的checksum设为0； 
//2、 计算checksum的数据按2byte划分开来，每2byte组成一个16bit的值，如果最后有单个byte的数据，补一个byte的0组成2byte； 
//3、 将所有的16bit值累加到一个32bit的值中； 
//4、 将32bit值的高16bit与低16bit相加到一个新的32bit值中，若新的32bit值大于0Xffff, 
//再将新值的高16bit与低16bit相加； 
//5、 将上一步计算所得的16bit值按位取反，即得到checksum值，存入数据的checksum字段即可。
// 总的来看，此加法是一个需要将16bit的进位加回的算法，故采用32位加时，将多出的进位加回即可。
//此函数计算checksum,完成2,3,4步运算
static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;

    //不对齐处理
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}

	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}

        //按4字节方式计算(将进位加回来即可与原算法一致）
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);//检查当前是否已定位
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
    //解决odd处理导致的问题
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}
#endif

#ifndef ip_fast_csum
/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 */
__sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
    //完成ipv4头部checksum计算（计合，拆叠，取反）
    //此函数要求iph中checksum字段已清零
	return (__force __sum16)~do_csum(iph, ihl*4);
}
EXPORT_SYMBOL(ip_fast_csum);
#endif

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
__wsum csum_partial(const void *buff, int len, __wsum wsum)
{
	unsigned int sum = (__force unsigned int)wsum;
    //计算buff的checksum(计合，拆叠）
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
    //加上旧值，并将进位加回（完成计合，折叠）
	result += sum;
	if (sum > result)
		result += 1;
	return (__force __wsum)result;
}
EXPORT_SYMBOL(csum_partial);

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
__sum16 ip_compute_csum(const void *buff, int len)
{
    /*完成buff的checksum计算*/
	return (__force __sum16)~do_csum(buff, len);
}
EXPORT_SYMBOL(ip_compute_csum);

/*
 * copy from ds while checksumming, otherwise like csum_partial
 */
__wsum
csum_partial_copy(const void *src, void *dst, int len, __wsum sum)
{
	memcpy(dst, src, len);
	return csum_partial(dst, len, sum);
}
EXPORT_SYMBOL(csum_partial_copy);

#ifndef csum_tcpudp_nofold
static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (__force u32)sum;

	s += (__force u32)saddr;
	s += (__force u32)daddr;
#ifdef __BIG_ENDIAN
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__force __wsum)from64to32(s);
}
EXPORT_SYMBOL(csum_tcpudp_nofold);
#endif
