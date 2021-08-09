// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2011 Instituto Nokia de Tecnologia
 *
 * Authors:
 *    Aloisio Almeida Jr <aloisio.almeida@openbossa.org>
 *    Lauro Ramos Venancio <lauro.venancio@openbossa.org>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": %s: " fmt, __func__

#include <net/tcp_states.h>
#include <linux/nfc.h>
#include <linux/export.h>

#include "nfc.h"

/*记录系统中的raw socket*/
static struct nfc_sock_list raw_sk_list = {
	.lock = __RW_LOCK_UNLOCKED(raw_sk_list.lock)
};

/*sk加入到l对应的链表中*/
static void nfc_sock_link(struct nfc_sock_list *l, struct sock *sk)
{
	write_lock(&l->lock);
	sk_add_node(sk, &l->head);
	write_unlock(&l->lock);
}

/*将sk自l对应的链表中移除*/
static void nfc_sock_unlink(struct nfc_sock_list *l, struct sock *sk)
{
	write_lock(&l->lock);
	sk_del_node_init(sk);
	write_unlock(&l->lock);
}

/*清空sock队列中的内容*/
static void rawsock_write_queue_purge(struct sock *sk)
{
	pr_debug("sk=%p\n", sk);

	spin_lock_bh(&sk->sk_write_queue.lock);
	/*清空写队列中的内容*/
	__skb_queue_purge(&sk->sk_write_queue);
	/*指明tx队列不再调度*/
	nfc_rawsock(sk)->tx_work_scheduled = false;
	spin_unlock_bh(&sk->sk_write_queue.lock);
}

/*指明sock出错*/
static void rawsock_report_error(struct sock *sk, int err)
{
	pr_debug("sk=%p err=%d\n", sk, err);

	sk->sk_shutdown = SHUTDOWN_MASK;
	sk->sk_err = -err;
	/*触发此sk的错误report，例如唤醒等待进程*/
	sk_error_report(sk);

	/*清空此sock上的发送队列*/
	rawsock_write_queue_purge(sk);
}

static int rawsock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	pr_debug("sock=%p sk=%p\n", sock, sk);

	if (!sk)
		return 0;

	/*如果此sock为raw,则将其自raw_sk_list上移除*/
	if (sock->type == SOCK_RAW)
		nfc_sock_unlink(&raw_sk_list, sk);

	sock_orphan(sk);
	sock_put(sk);

	return 0;
}

static int rawsock_connect(struct socket *sock, struct sockaddr *_addr,
			   int len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_nfc *addr = (struct sockaddr_nfc *)_addr;
	struct nfc_dev *dev;
	int rc = 0;

	pr_debug("sock=%p sk=%p flags=%d\n", sock, sk, flags);

	if (!addr || len < sizeof(struct sockaddr_nfc) ||
	    addr->sa_family != AF_NFC)
		return -EINVAL;

	pr_debug("addr dev_idx=%u target_idx=%u protocol=%u\n",
		 addr->dev_idx, addr->target_idx, addr->nfc_protocol);

	lock_sock(sk);

	//已连接,报错
	if (sock->state == SS_CONNECTED) {
		rc = -EISCONN;
		goto error;
	}

	//查找对端设备
	dev = nfc_get_device(addr->dev_idx);
	if (!dev) {
		rc = -ENODEV;
		goto error;
	}

	if (addr->target_idx > dev->target_next_idx - 1 ||
	    addr->target_idx < dev->target_next_idx - dev->n_targets) {
		rc = -EINVAL;
		goto put_dev;
	}

	rc = nfc_activate_target(dev, addr->target_idx, addr->nfc_protocol);
	if (rc)
		goto put_dev;

	/*此sock对应的dev设备*/
	nfc_rawsock(sk)->dev = dev;
	/*对应的对端设备*/
	nfc_rawsock(sk)->target_idx = addr->target_idx;
	//指明socket完成连接
	sock->state = SS_CONNECTED;
	sk->sk_state = TCP_ESTABLISHED;
	sk->sk_state_change(sk);

	release_sock(sk);
	return 0;

put_dev:
	nfc_put_device(dev);
error:
	release_sock(sk);
	return rc;
}

//为skb增加NFC_HEADER,并初始化为0（一个字节）
static int rawsock_add_header(struct sk_buff *skb)
{
	*(u8 *)skb_push(skb, NFC_HEADER_SIZE) = 0;

	return 0;
}

static void rawsock_data_exchange_complete(void *context, struct sk_buff *skb,
					   int err)
{
	struct sock *sk = (struct sock *) context;

	BUG_ON(in_irq());

	pr_debug("sk=%p err=%d\n", sk, err);

	if (err)
		goto error;

	err = rawsock_add_header(skb);
	if (err)
		goto error_skb;

	err = sock_queue_rcv_skb(sk, skb);
	if (err)
		goto error_skb;

	spin_lock_bh(&sk->sk_write_queue.lock);
	if (!skb_queue_empty(&sk->sk_write_queue))
		schedule_work(&nfc_rawsock(sk)->tx_work);
	else
		nfc_rawsock(sk)->tx_work_scheduled = false;
	spin_unlock_bh(&sk->sk_write_queue.lock);

	sock_put(sk);
	return;

error_skb:
	kfree_skb(skb);

error:
	rawsock_report_error(sk, err);
	sock_put(sk);
}

/*nfc socket的发送work,每个socket一个work*/
static void rawsock_tx_work(struct work_struct *work)
{
	struct sock *sk = to_rawsock_sk(work);
	struct nfc_dev *dev = nfc_rawsock(sk)->dev;
	u32 target_idx = nfc_rawsock(sk)->target_idx;
	struct sk_buff *skb;
	int rc;

	pr_debug("sk=%p target_idx=%u\n", sk, target_idx);

	/*socket关闭处理*/
	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		rawsock_write_queue_purge(sk);
		return;
	}

	/*自写队列中提取一个skb*/
	skb = skb_dequeue(&sk->sk_write_queue);

	sock_hold(sk);
	/*交付给驱动，完成数据交换*/
	rc = nfc_data_exchange(dev, target_idx, skb,
			       rawsock_data_exchange_complete, sk);
	if (rc) {
	    /*交换时出错，错误处理*/
		rawsock_report_error(sk, rc);
		sock_put(sk);
	}
}

static int rawsock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct nfc_dev *dev = nfc_rawsock(sk)->dev;
	struct sk_buff *skb;
	int rc;

	pr_debug("sock=%p sk=%p len=%zu\n", sock, sk, len);

	if (msg->msg_namelen)
		return -EOPNOTSUPP;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;

	/*申请skb,为消息发送做准备*/
	skb = nfc_alloc_send_skb(dev, sk, msg->msg_flags, len, &rc);
	if (skb == NULL)
		return rc;

	/*将消息内容填充到skb*/
	rc = memcpy_from_msg(skb_put(skb, len), msg, len);
	if (rc < 0) {
		kfree_skb(skb);
		return rc;
	}

	spin_lock_bh(&sk->sk_write_queue.lock);
	/*将报文放入到写队列*/
	__skb_queue_tail(&sk->sk_write_queue, skb);
	if (!nfc_rawsock(sk)->tx_work_scheduled) {
	    /*指明调度tx_work*/
		schedule_work(&nfc_rawsock(sk)->tx_work);
		nfc_rawsock(sk)->tx_work_scheduled = true;
	}
	spin_unlock_bh(&sk->sk_write_queue.lock);

	return len;
}

//nfc socket,收取报文
static int rawsock_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
			   int flags)
{
	int noblock = flags & MSG_DONTWAIT;/*是否非阻塞收取*/
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int copied;
	int rc;

	pr_debug("sock=%p sk=%p len=%zu flags=%d\n", sock, sk, len, flags);

	//自sk_receive_queue中摘取一个skb
	skb = skb_recv_datagram(sk, flags, noblock, &rc);
	if (!skb)
		return rc;

	copied = skb->len;/*报文可复制长度*/
	if (len < copied) {
	    /*buffer内容过小，指明trunc*/
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	//利用skb填充msg,并返回
	rc = skb_copy_datagram_msg(skb, 0, msg, copied);

	/*释放此skb*/
	skb_free_datagram(sk, skb);

	return rc ? : copied;
}

//SOCK_SEQPACKET类型socket对应的ops
static const struct proto_ops rawsock_ops = {
	.family         = PF_NFC,
	.owner          = THIS_MODULE,
	.release        = rawsock_release,
	.bind           = sock_no_bind,//不支持bind
	.connect        = rawsock_connect,
	.socketpair     = sock_no_socketpair,//不支持socketpair
	.accept         = sock_no_accept,//不支持accept
	.getname        = sock_no_getname,//不支持getname
	.poll           = datagram_poll,
	.ioctl          = sock_no_ioctl,//不支持ioctl
	.listen         = sock_no_listen,//不支持listen
	.shutdown       = sock_no_shutdown,//不支持shutdown
	.sendmsg        = rawsock_sendmsg,
	.recvmsg        = rawsock_recvmsg,
	.mmap           = sock_no_mmap,//不支持mmap
};

/*SOCK_RAW类型socket对应的ops（其不支持write操作，由其它socket在读取或者发送时，将其报文送一份给
 * raw socket,以便raw socket可以嗅探到报文，故其只需要read操作即可）*/
static const struct proto_ops rawsock_raw_ops = {
	.family         = PF_NFC,
	.owner          = THIS_MODULE,
	.release        = rawsock_release,/*释放sock*/
	.bind           = sock_no_bind,//不支持bind
	.connect        = sock_no_connect,//不支持connect
	.socketpair     = sock_no_socketpair,//不支持socketpair
	.accept         = sock_no_accept,//不支持accept
	.getname        = sock_no_getname,//不支持getname
	.poll           = datagram_poll,/*支持poll接口*/
	.ioctl          = sock_no_ioctl,//不支持ioctl
	.listen         = sock_no_listen,//不支持listen
	.shutdown       = sock_no_shutdown,//不支持shutdown
	.sendmsg        = sock_no_sendmsg,//不支持sendmsg
	.recvmsg        = rawsock_recvmsg,/*nfc rawsock消息接收*/
	.mmap           = sock_no_mmap,//不支持mmap
};

static void rawsock_destruct(struct sock *sk)
{
	pr_debug("sk=%p\n", sk);

	if (sk->sk_state == TCP_ESTABLISHED) {
		nfc_deactivate_target(nfc_rawsock(sk)->dev,
				      nfc_rawsock(sk)->target_idx,
				      NFC_TARGET_MODE_IDLE);
		nfc_put_device(nfc_rawsock(sk)->dev);
	}

	skb_queue_purge(&sk->sk_receive_queue);

	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Freeing alive NFC raw socket %p\n", sk);
		return;
	}
}

//af_nfc rawsocket 创建
static int rawsock_create(struct net *net, struct socket *sock,
			  const struct nfc_protocol *nfc_proto, int kern)
{
	struct sock *sk;

	pr_debug("sock=%p\n", sock);

	//当前仅支持SOCK_RAW及SOCK_SEQPACKET两种类型
	if ((sock->type != SOCK_SEQPACKET) && (sock->type != SOCK_RAW))
		return -ESOCKTNOSUPPORT;

	//不同类型指向不同的ops
	if (sock->type == SOCK_RAW) {
		if (!ns_capable(net->user_ns, CAP_NET_RAW))
			return -EPERM;
		sock->ops = &rawsock_raw_ops;/*raw sock只能读取，不能发送*/
	} else {
		sock->ops = &rawsock_ops;/*可发送，可读取*/
	}

	sk = sk_alloc(net, PF_NFC, GFP_ATOMIC, nfc_proto->proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sk->sk_protocol = nfc_proto->id;
	sk->sk_destruct = rawsock_destruct;
	sock->state = SS_UNCONNECTED;
	if (sock->type == SOCK_RAW)
	    /*此sock为raw sock,则挂接在raw_sk_list链表上*/
		nfc_sock_link(&raw_sk_list, sk);
	else {
	    /*指明socket的tx work函数*/
		INIT_WORK(&nfc_rawsock(sk)->tx_work, rawsock_tx_work);
		nfc_rawsock(sk)->tx_work_scheduled = false;
	}

	return 0;
}

/*将skb送给发送给所有的raw socket（raw socket用于sniffer)*/
void nfc_send_to_raw_sock(struct nfc_dev *dev, struct sk_buff *skb,
			  u8 payload_type, u8 direction/*用0/1来表示方向*/)
{
	struct sk_buff *skb_copy = NULL, *nskb;
	struct sock *sk;
	u8 *data;

	read_lock(&raw_sk_list.lock);

	/*遍历挂接在raw_sk_list上所有的raw sock*/
	sk_for_each(sk, &raw_sk_list.head) {
		if (!skb_copy) {
			//制作skb的一个副本
			skb_copy = __pskb_copy_fclone(skb, NFC_RAW_HEADER_SIZE,
						      GFP_ATOMIC, true);
			if (!skb_copy)
				continue;

			/*在原始报文前面添加raw_header*/
			data = skb_push(skb_copy, NFC_RAW_HEADER_SIZE);

			/*如果有设备，则第一字节填充dev的index,否则为0xff*/
			data[0] = dev ? dev->idx : 0xFF;
			/*在第二个字节，填充payload_type及方向*/
			data[1] = direction & 0x01;
			data[1] |= (payload_type << 1);
		}

		//制作skb_copy的副本，并交给当前处理的socket
		nskb = skb_clone(skb_copy, GFP_ATOMIC);
		if (!nskb)
			continue;

		//将报文nskb递交给socket
		if (sock_queue_rcv_skb(sk, nskb))
			kfree_skb(nskb);
	}

	read_unlock(&raw_sk_list.lock);

	//释放skb_copy
	kfree_skb(skb_copy);
}
EXPORT_SYMBOL(nfc_send_to_raw_sock);

static struct proto rawsock_proto = {
	.name     = "NFC_RAW",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct nfc_rawsock),
};

//注册raw协议(用于nfc报文嗅探）
static const struct nfc_protocol rawsock_nfc_proto = {
	.id	  = NFC_SOCKPROTO_RAW,
	.proto    = &rawsock_proto,
	.owner    = THIS_MODULE,
	//raw方式socket创建
	.create   = rawsock_create
};

int __init rawsock_init(void)
{
	int rc;

	//为af_nfc注册nfc_raw协议
	rc = nfc_proto_register(&rawsock_nfc_proto);

	return rc;
}

void rawsock_exit(void)
{
    /*移除nfc_raw协议*/
	nfc_proto_unregister(&rawsock_nfc_proto);
}
