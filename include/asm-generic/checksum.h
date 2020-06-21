/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_CHECKSUM_H
#define __ASM_GENERIC_CHECKSUM_H

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
extern __wsum csum_partial(const void *buff, int len, __wsum sum);

/*
 * the same as csum_partial, but copies from src while it
 * checksums
 *
 * here even more important to align src and dst on a 32-bit (or even
 * better 64-bit) boundary
 */
extern __wsum csum_partial_copy(const void *src, void *dst, int len, __wsum sum);

#ifndef csum_partial_copy_nocheck
#define csum_partial_copy_nocheck(src, dst, len, sum)	\
	csum_partial_copy((src), (dst), (len), (sum))
#endif

#ifndef ip_fast_csum
/*
 * This is a version of ip_compute_csum() optimized for IP headers,
 * which always checksum on 4 octet boundaries.
 */
extern __sum16 ip_fast_csum(const void *iph, unsigned int ihl);
#endif

#ifndef csum_fold
/*
 * Fold a partial checksum
 */
//1、 先将需要计算checksum数据中的checksum设为0； 
//2、 计算checksum的数据按2byte划分开来，每2byte组成一个16bit的值，如果最后有单个byte的数据，补一个byte的0组成2byte； 
//3、 将所有的16bit值累加到一个32bit的值中； 
//4、 将32bit值的高16bit与低16bit相加到一个新的32bit值中，若新的32bit值大于0Xffff, 
//再将新值的高16bit与低16bit相加； 
//5、 将上一步计算所得的16bit值按位取反，即得到checksum值，存入数据的checksum字段即可。
//此函数完成4,5步
static inline __sum16 csum_fold(__wsum csum)
{
    //考虑任意的csum,(sum & 0xffff) <= 0xffff
    //且 (sum >> 16) <= 0xffff
    //所以 (sum & 0xffff) + (sum >>16) <= 0x1fffe
    //此时，如果其<= 0xffff,则其再计算一次合结果不变
    //      如果其>0xffff && <=0x1fffe,则其值最大为0xffff
    //故下面的代码通过两次计算获得16位的sum
	u32 sum = (__force u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
    //按checksum计算方法，其最终结果需要取反
	return (__force __sum16)~sum;
}
#endif

#ifndef csum_tcpudp_nofold
/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
extern __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len,
		   __u8 proto, __wsum sum);
#endif

#ifndef csum_tcpudp_magic
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}
#endif

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
extern __sum16 ip_compute_csum(const void *buff, int len);

#endif /* __ASM_GENERIC_CHECKSUM_H */
