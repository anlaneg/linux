// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * AF_XDP user-space access library.
 *
 * Copyright(c) 2018 - 2019 Intel Corporation.
 *
 * Author(s): Magnus Karlsson <magnus.karlsson@intel.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <asm/barrier.h>
#include <linux/compiler.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "xsk.h"
#include "bpf_util.h"

#ifndef SOL_XDP
 #define SOL_XDP 283
#endif

#ifndef AF_XDP
 #define AF_XDP 44
#endif

#ifndef PF_XDP
 #define PF_XDP AF_XDP
#endif

#define pr_warn(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define XSKMAP_SIZE 1

struct xsk_umem {
	struct xsk_ring_prod *fill_save;/*指向fill队列*/
	struct xsk_ring_cons *comp_save;/*指向complete队列*/
	char *umem_area;/*用户态内存起始地址,按页对齐*/
	struct xsk_umem_config config;/*umem_area内存配置情况*/
	int fd;/*afxdp socket*/
	int refcount;
	struct list_head ctx_list;
	bool rx_ring_setup_done;/*标记rx创建完成*/
	bool tx_ring_setup_done;/*标记tx创建完成*/
};

struct xsk_ctx {
	struct xsk_ring_prod *fill;/*指明fill队列*/
	struct xsk_ring_cons *comp;/*指明comp队列*/
	__u32 queue_id;
	struct xsk_umem *umem;
	int refcount;
	int ifindex;
	struct list_head list;
};

struct xsk_socket {
	struct xsk_ring_cons *rx;//rx信息
	struct xsk_ring_prod *tx;//tx信息
	struct xsk_ctx *ctx;/*此socket对应的context*/
	struct xsk_socket_config config;//rx,tx配置信息
	int fd;
};

struct nl_mtu_req {
	struct nlmsghdr nh;
	struct ifinfomsg msg;
	char             buf[512];
};

int xsk_umem__fd(const struct xsk_umem *umem)
{
	return umem ? umem->fd : -EINVAL;
}

int xsk_socket__fd(const struct xsk_socket *xsk)
{
	return xsk ? xsk->fd : -EINVAL;
}

static bool xsk_page_aligned(void *buffer)
{
	unsigned long addr = (unsigned long)buffer;

	return !(addr & (getpagesize() - 1));
}

static void xsk_set_umem_config(struct xsk_umem_config *cfg,
				const struct xsk_umem_config *usr_cfg)
{
	if (!usr_cfg) {
	    /*用户未提供配置时，使用默认值*/
		cfg->fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
		cfg->comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
		cfg->frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
		cfg->frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
		cfg->flags = XSK_UMEM__DEFAULT_FLAGS;
		cfg->tx_metadata_len = 0;
		return;
	}

	cfg->fill_size = usr_cfg->fill_size;
	cfg->comp_size = usr_cfg->comp_size;
	cfg->frame_size = usr_cfg->frame_size;
	cfg->frame_headroom = usr_cfg->frame_headroom;
	cfg->flags = usr_cfg->flags;
	cfg->tx_metadata_len = usr_cfg->tx_metadata_len;
}

static int xsk_set_xdp_socket_config(struct xsk_socket_config *cfg,
				     const struct xsk_socket_config *usr_cfg)
{
	/*如果未提供cfg,则使用默认配置，初始化rx_size,tx_size*/
	if (!usr_cfg) {
		cfg->rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
		cfg->tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
		cfg->bind_flags = 0;
		return 0;
	}

	cfg->rx_size = usr_cfg->rx_size;
	cfg->tx_size = usr_cfg->tx_size;
	cfg->bind_flags = usr_cfg->bind_flags;

	return 0;
}

static int xsk_get_mmap_offsets(int fd, struct xdp_mmap_offsets *off)
{
	socklen_t optlen;
	int err;

	optlen = sizeof(*off);
	/*取各ring, rx,tx,cr,fr结构体成员在内存中位置的偏移量*/
	err = getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, off, &optlen);
	if (err)
		return err;

	if (optlen == sizeof(*off))
		return 0;

	return -EINVAL;
}

/*要求kernel创建umem ring(cr,fr)并将其映射到用户态，填充fill,comp*/
static int xsk_create_umem_rings(struct xsk_umem *umem, int fd,
				 struct xsk_ring_prod *fill,
				 struct xsk_ring_cons *comp)
{
	struct xdp_mmap_offsets off;
	void *map;
	int err;

	//要求kernel创建fill队列，队列长度为fill_size
	err = setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING,
			 &umem->config.fill_size,
			 sizeof(umem->config.fill_size));
	if (err)
		return -errno;

	//要求kernel创建complete队列，队列长度为comp_size
	err = setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
			 &umem->config.comp_size,
			 sizeof(umem->config.comp_size));
	if (err)
		return -errno;

	//获取各ring结构体成员在内存中位置的offset，用于与kernel对齐数据结构
	err = xsk_get_mmap_offsets(fd, &off);
	if (err)
		return -errno;

	//针对af_xdp socket，调用mmap,将kernel创建的fill队列映射到用户态
	map = mmap(NULL, off.fr.desc + umem->config.fill_size * sizeof(__u64)/*描述符指针起始位置 + 标识符数组总长度*/,
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		   XDP_UMEM_PGOFF_FILL_RING/*通过此offset指明为fill队列映射*/);
	if (map == MAP_FAILED)
		return -errno;

	//初始化fill队列
	fill->mask = umem->config.fill_size - 1;
	fill->size = umem->config.fill_size;
	fill->producer = map + off.fr.producer;
	fill->consumer = map + off.fr.consumer;
	fill->flags = map + off.fr.flags;
	fill->ring = map + off.fr.desc;
	//????
	fill->cached_cons = umem->config.fill_size;

	//针对af_xdp socket，调用mmap,将kernel创建的complete队列映射到用户态
	map = mmap(NULL, off.cr.desc + umem->config.comp_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		   XDP_UMEM_PGOFF_COMPLETION_RING);
	if (map == MAP_FAILED) {
		err = -errno;
		goto out_mmap;
	}

	//初始化complete队列
	comp->mask = umem->config.comp_size - 1;
	comp->size = umem->config.comp_size;
	comp->producer = map + off.cr.producer;
	comp->consumer = map + off.cr.consumer;
	comp->flags = map + off.cr.flags;
	comp->ring = map + off.cr.desc;

	return 0;

out_mmap:
	/*遇射cr失败，释放映射的fr*/
	munmap(map, off.fr.desc + umem->config.fill_size * sizeof(__u64));
	return err;
}

int xsk_umem__create(struct xsk_umem **umem_ptr/*出参，xsk用户态内存信息*/, void *umem_area/*要注册的内存区域*/,
		     __u64 size/*umem_area内存长度*/, struct xsk_ring_prod *fill/*出参，fill ring信息*/,
		     struct xsk_ring_cons *comp/*出参，comp ring信息*/,
		     const struct xsk_umem_config *usr_config/*umem配置，可以为空*/)
{
	struct xdp_umem_reg mr;
	struct xsk_umem *umem;
	int err;

	/*参数不能为空*/
	if (!umem_area || !umem_ptr || !fill || !comp)
		return -EFAULT;

	/*size不得为0，且申请的umem_area必须以页对齐*/
	if (!size && !xsk_page_aligned(umem_area))
		return -EINVAL;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return -ENOMEM;

	/*创建af_xdp socket*/
	umem->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (umem->fd < 0) {
		err = -errno;
		goto out_umem_alloc;
	}

	umem->umem_area = umem_area;
	INIT_LIST_HEAD(&umem->ctx_list);
	xsk_set_umem_config(&umem->config, usr_config);

	/*注册长度为size的用户态地址umem_area*/
	memset(&mr, 0, sizeof(mr));
	mr.addr = (uintptr_t)umem_area;
	mr.len = size;
	//chunk的大小为每个帧的大小
	mr.chunk_size = umem->config.frame_size;
	//每个帧前headroom空间大小
	mr.headroom = umem->config.frame_headroom;
	mr.flags = umem->config.flags;
	mr.tx_metadata_len = umem->config.tx_metadata_len;

	//通过sockopt向kernel注册用户态的内存
	err = setsockopt(umem->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
	if (err) {
		err = -errno;
		goto out_socket;
	}

	/*创建并映射fill,comp两个队列*/
	err = xsk_create_umem_rings(umem, umem->fd, fill, comp);
	if (err)
		goto out_socket;

	umem->fill_save = fill;
	umem->comp_save = comp;
	*umem_ptr = umem;
	return 0;

out_socket:
	close(umem->fd);
out_umem_alloc:
	free(umem);
	return err;
}

bool xsk_is_in_mode(u32 ifindex, int mode)
{
	LIBBPF_OPTS(bpf_xdp_query_opts, opts);
	int ret;

	ret = bpf_xdp_query(ifindex, mode, &opts);
	if (ret) {
		printf("XDP mode query returned error %s\n", strerror(errno));
		return false;
	}

	if (mode == XDP_FLAGS_DRV_MODE)
		return opts.attach_mode == XDP_ATTACHED_DRV;
	else if (mode == XDP_FLAGS_SKB_MODE)
		return opts.attach_mode == XDP_ATTACHED_SKB;

	return false;
}

/* Lifted from netlink.c in tools/lib/bpf */
static int netlink_recvmsg(int sock, struct msghdr *mhdr, int flags)
{
	int len;

	do {
		len = recvmsg(sock, mhdr, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));

	if (len < 0)
		return -errno;
	return len;
}

/* Lifted from netlink.c in tools/lib/bpf */
static int alloc_iov(struct iovec *iov, int len)
{
	void *nbuf;

	nbuf = realloc(iov->iov_base, len);
	if (!nbuf)
		return -ENOMEM;

	iov->iov_base = nbuf;
	iov->iov_len = len;
	return 0;
}

/* Original version lifted from netlink.c in tools/lib/bpf */
static int netlink_recv(int sock)
{
	struct iovec iov = {};
	struct msghdr mhdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	bool multipart = true;
	struct nlmsgerr *err;
	struct nlmsghdr *nh;
	int len, ret;

	ret = alloc_iov(&iov, 4096);
	if (ret)
		goto done;

	while (multipart) {
		multipart = false;
		len = netlink_recvmsg(sock, &mhdr, MSG_PEEK | MSG_TRUNC);
		if (len < 0) {
			ret = len;
			goto done;
		}

		if (len > iov.iov_len) {
			ret = alloc_iov(&iov, len);
			if (ret)
				goto done;
		}

		len = netlink_recvmsg(sock, &mhdr, 0);
		if (len < 0) {
			ret = len;
			goto done;
		}

		if (len == 0)
			break;

		for (nh = (struct nlmsghdr *)iov.iov_base; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_flags & NLM_F_MULTI)
				multipart = true;
			switch (nh->nlmsg_type) {
			case NLMSG_ERROR:
				err = (struct nlmsgerr *)NLMSG_DATA(nh);
				if (!err->error)
					continue;
				ret = err->error;
				goto done;
			case NLMSG_DONE:
				ret = 0;
				goto done;
			default:
				break;
			}
		}
	}
	ret = 0;
done:
	free(iov.iov_base);
	return ret;
}

int xsk_set_mtu(int ifindex, int mtu)
{
	struct nl_mtu_req req;
	struct rtattr *rta;
	int fd, ret;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0)
		return fd;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_NEWLINK;
	req.msg.ifi_family = AF_UNSPEC;
	req.msg.ifi_index = ifindex;
	rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = IFLA_MTU;
	rta->rta_len = RTA_LENGTH(sizeof(unsigned int));
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(sizeof(mtu));
	memcpy(RTA_DATA(rta), &mtu, sizeof(mtu));

	ret = send(fd, &req, req.nh.nlmsg_len, 0);
	if (ret < 0) {
		close(fd);
		return errno;
	}

	ret = netlink_recv(fd);
	close(fd);
	return ret;
}

//加载xdp程序到对应的接口
//通过queue_id查询xsks_map,并直接送给AF_XDP socket对应的fd
int xsk_attach_xdp_program(struct bpf_program *prog, int ifindex, u32 xdp_flags)
{
	int prog_fd;

	prog_fd = bpf_program__fd(prog);
	return bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
}

void xsk_detach_xdp_program(int ifindex, u32 xdp_flags)
{
	bpf_xdp_detach(ifindex, xdp_flags, NULL);
}

void xsk_clear_xskmap(struct bpf_map *map)
{
	u32 index = 0;
	int map_fd;

	map_fd = bpf_map__fd(map);
	bpf_map_delete_elem(map_fd, &index);
}

/*通过ioctl获取channel数*/
int xsk_update_xskmap(struct bpf_map *map, struct xsk_socket *xsk, u32 index)
{
	int map_fd, sock_fd;

	map_fd = bpf_map__fd(map);
	sock_fd = xsk_socket__fd(xsk);

	return bpf_map_update_elem(map_fd, &index, &sock_fd, 0);
}

static struct xsk_ctx *xsk_get_ctx(struct xsk_umem *umem, int ifindex,
				   __u32 queue_id)
{
	struct xsk_ctx *ctx;

	if (list_empty(&umem->ctx_list))
		return NULL;

	/*查找是否已存在xsk_ctx*/
	list_for_each_entry(ctx, &umem->ctx_list, list) {
		if (ctx->ifindex == ifindex && ctx->queue_id == queue_id) {
			ctx->refcount++;
			return ctx;
		}
	}

	return NULL;
}

static void xsk_put_ctx(struct xsk_ctx *ctx, bool unmap)
{
	struct xsk_umem *umem = ctx->umem;
	struct xdp_mmap_offsets off;
	int err;

	if (--ctx->refcount)
		return;

	if (!unmap)
		goto out_free;

	err = xsk_get_mmap_offsets(umem->fd, &off);
	if (err)
		goto out_free;

	munmap(ctx->fill->ring - off.fr.desc, off.fr.desc + umem->config.fill_size *
	       sizeof(__u64));
	munmap(ctx->comp->ring - off.cr.desc, off.cr.desc + umem->config.comp_size *
	       sizeof(__u64));

out_free:
	list_del(&ctx->list);
	free(ctx);
}

static struct xsk_ctx *xsk_create_ctx(struct xsk_socket *xsk,
				      struct xsk_umem *umem, int ifindex,
				      __u32 queue_id,
				      struct xsk_ring_prod *fill,
				      struct xsk_ring_cons *comp)
{
	struct xsk_ctx *ctx;
	int err;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (!umem->fill_save) {
		/*未设置fill_save,映射fill,comp*/
		err = xsk_create_umem_rings(umem, xsk->fd, fill, comp);
		if (err) {
			free(ctx);
			return NULL;
		}
	} else if (umem->fill_save != fill || umem->comp_save != comp) {
		/* Copy over rings to new structs. */
		memcpy(fill, umem->fill_save, sizeof(*fill));
		memcpy(comp, umem->comp_save, sizeof(*comp));
	}

	ctx->ifindex = ifindex;
	ctx->refcount = 1;
	ctx->umem = umem;
	ctx->queue_id = queue_id;

	ctx->fill = fill;
	ctx->comp = comp;
	list_add(&ctx->list, &umem->ctx_list);/*加入链表*/
	return ctx;
}

int xsk_socket__create_shared(struct xsk_socket **xsk_ptr,
			      int ifindex,
			      __u32 queue_id, struct xsk_umem *umem,
			      struct xsk_ring_cons *rx,
			      struct xsk_ring_prod *tx,
			      struct xsk_ring_prod *fill,
			      struct xsk_ring_cons *comp,
			      const struct xsk_socket_config *usr_config)
{
	bool unmap, rx_setup_done = false, tx_setup_done = false;
	void *rx_map = NULL, *tx_map = NULL;
	struct sockaddr_xdp sxdp = {};
	struct xdp_mmap_offsets off;
	struct xsk_socket *xsk;
	struct xsk_ctx *ctx;
	int err;

	if (!umem || !xsk_ptr || !(rx || tx))
		return -EFAULT;

	unmap = umem->fill_save != fill;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return -ENOMEM;

	err = xsk_set_xdp_socket_config(&xsk->config, usr_config);
	if (err)
		goto out_xsk_alloc;

	if (umem->refcount++ > 0) {
		/*umem原引用计数不为0时，创建新的af_xdp socket*/
		xsk->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
		if (xsk->fd < 0) {
			err = -errno;
			goto out_xsk_alloc;
		}
	} else {
		xsk->fd = umem->fd;
		rx_setup_done = umem->rx_ring_setup_done;
		tx_setup_done = umem->tx_ring_setup_done;
	}

	ctx = xsk_get_ctx(umem, ifindex, queue_id);
	if (!ctx) {
		if (!fill || !comp) {
			/*ctx未创建，且未给定fill,comp,报错退出*/
			err = -EFAULT;
			goto out_socket;
		}

		/*创建xsk context*/
		ctx = xsk_create_ctx(xsk, umem, ifindex, queue_id, fill, comp);
		if (!ctx) {
			err = -ENOMEM;
			goto out_socket;
		}
	}
	xsk->ctx = ctx;

	if (rx && !rx_setup_done) {
	    //rx未创建，要求kernel创建rx队列
		err = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING,
				 &xsk->config.rx_size,
				 sizeof(xsk->config.rx_size));
		if (err) {
			err = -errno;
			goto out_put_ctx;
		}
		if (xsk->fd == umem->fd)
			umem->rx_ring_setup_done = true;
	}
	if (tx && !tx_setup_done) {
	    //tx未创建，要求kernel创建tx队列
		err = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING,
				 &xsk->config.tx_size,
				 sizeof(xsk->config.tx_size));
		if (err) {
			err = -errno;
			goto out_put_ctx;
		}
		if (xsk->fd == umem->fd)
			umem->tx_ring_setup_done = true;
	}

	//取af_xdp所有ring结构体成员在内存中的位置信息
	err = xsk_get_mmap_offsets(xsk->fd, &off);
	if (err) {
		err = -errno;
		goto out_put_ctx;
	}

	if (rx) {
		//映射rx队列
		rx_map = mmap(NULL, off.rx.desc +
			      xsk->config.rx_size * sizeof(struct xdp_desc),
			      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
			      xsk->fd, XDP_PGOFF_RX_RING/*指明映射rx ring*/);
		if (rx_map == MAP_FAILED) {
			err = -errno;
			goto out_put_ctx;
		}

		rx->mask = xsk->config.rx_size - 1;
		rx->size = xsk->config.rx_size;
		rx->producer = rx_map + off.rx.producer;
		rx->consumer = rx_map + off.rx.consumer;
		rx->flags = rx_map + off.rx.flags;
		rx->ring = rx_map + off.rx.desc;
		rx->cached_prod = *rx->producer;
		rx->cached_cons = *rx->consumer;
	}
	xsk->rx = rx;

	if (tx) {
		//映射tx队列
		tx_map = mmap(NULL, off.tx.desc +
			      xsk->config.tx_size * sizeof(struct xdp_desc),
			      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
			      xsk->fd, XDP_PGOFF_TX_RING/*指明映射tx ring*/);
		if (tx_map == MAP_FAILED) {
			err = -errno;
			goto out_mmap_rx;
		}

		tx->mask = xsk->config.tx_size - 1;
		tx->size = xsk->config.tx_size;
		tx->producer = tx_map + off.tx.producer;
		tx->consumer = tx_map + off.tx.consumer;
		tx->flags = tx_map + off.tx.flags;
		tx->ring = tx_map + off.tx.desc;
		tx->cached_prod = *tx->producer;
		/* cached_cons is r->size bigger than the real consumer pointer
		 * See xsk_prod_nb_free
		 */
		tx->cached_cons = *tx->consumer + xsk->config.tx_size;
	}
	xsk->tx = tx;

	//xdp socket绑定
	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_ifindex = ctx->ifindex;/*接口ifindex*/
	sxdp.sxdp_queue_id = ctx->queue_id;/*队列编号*/
	if (umem->refcount > 1) {
		sxdp.sxdp_flags |= XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = umem->fd;
	} else {
		sxdp.sxdp_flags = xsk->config.bind_flags;
	}

	//将队列xsk->queueu_id，设备xsk->ifindex关联到此socket
	err = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	if (err) {
		err = -errno;
		goto out_mmap_tx;
	}

	*xsk_ptr = xsk;
	umem->fill_save = NULL;
	umem->comp_save = NULL;
	return 0;

out_mmap_tx:
	if (tx)
		munmap(tx_map, off.tx.desc +
		       xsk->config.tx_size * sizeof(struct xdp_desc));
out_mmap_rx:
	if (rx)
		munmap(rx_map, off.rx.desc +
		       xsk->config.rx_size * sizeof(struct xdp_desc));
out_put_ctx:
	xsk_put_ctx(ctx, unmap);
out_socket:
	if (--umem->refcount)
		close(xsk->fd);
out_xsk_alloc:
	free(xsk);
	return err;
}

int xsk_socket__create(struct xsk_socket **xsk_ptr, int ifindex,
		       __u32 queue_id, struct xsk_umem *umem,
		       struct xsk_ring_cons *rx, struct xsk_ring_prod *tx,
		       const struct xsk_socket_config *usr_config)
{
	if (!umem)
		/*umem必须已初始化*/
		return -EFAULT;

	/*创建rx,tx ring,为netdev使能xsk pool*/
	return xsk_socket__create_shared(xsk_ptr, ifindex, queue_id, umem,
					 rx, tx, umem->fill_save,
					 umem->comp_save, usr_config);
}

int xsk_umem__delete(struct xsk_umem *umem)
{
	struct xdp_mmap_offsets off;
	int err;

	if (!umem)
		return 0;

	if (umem->refcount)
		return -EBUSY;

	err = xsk_get_mmap_offsets(umem->fd, &off);
	if (!err && umem->fill_save && umem->comp_save) {
		munmap(umem->fill_save->ring - off.fr.desc,
		       off.fr.desc + umem->config.fill_size * sizeof(__u64));
		munmap(umem->comp_save->ring - off.cr.desc,
		       off.cr.desc + umem->config.comp_size * sizeof(__u64));
	}

	close(umem->fd);
	free(umem);

	return 0;
}

void xsk_socket__delete(struct xsk_socket *xsk)
{
	size_t desc_sz = sizeof(struct xdp_desc);
	struct xdp_mmap_offsets off;
	struct xsk_umem *umem;
	struct xsk_ctx *ctx;
	int err;

	if (!xsk)
		return;

	ctx = xsk->ctx;
	umem = ctx->umem;

	xsk_put_ctx(ctx, true);

	err = xsk_get_mmap_offsets(xsk->fd, &off);
	if (!err) {
		if (xsk->rx) {
			munmap(xsk->rx->ring - off.rx.desc,
			       off.rx.desc + xsk->config.rx_size * desc_sz);
		}
		if (xsk->tx) {
			munmap(xsk->tx->ring - off.tx.desc,
			       off.tx.desc + xsk->config.tx_size * desc_sz);
		}
	}

	umem->refcount--;
	/* Do not close an fd that also has an associated umem connected
	 * to it.
	 */
	if (xsk->fd != umem->fd)
		close(xsk->fd);
	free(xsk);
}
