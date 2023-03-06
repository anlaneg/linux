/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol sk_state field.
 */
#ifndef _LINUX_TCP_STATES_H
#define _LINUX_TCP_STATES_H

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,/*本机已发syn*/
	TCP_SYN_RECV,/*本机收到syn*/
	TCP_FIN_WAIT1,/*本机想关闭，已向对端发送了fin*/
	TCP_FIN_WAIT2,/*本机向对端发送了fin,且对端针对此fin已回复ack*/
	/*本机收到fin,关且本机已针对此fin回复ack*/
	TCP_TIME_WAIT,
	/*socket首个状态*/
	TCP_CLOSE,
	/*本机收到对端发送过来的fin,且本端针对此fin回复了actk*/
	TCP_CLOSE_WAIT,
	/*之前已确认了对端的fin,当前状态本端关闭，发送了fin,等待对端响应ack*/
	TCP_LAST_ACK,
	//socket监听后首个注册状态
	TCP_LISTEN,
	/*本机向对端发送了fin,但对端没有针以此fin回复ack,而是发送了fin,此时认定两端同时关闭*/
	TCP_CLOSING,	/* Now a valid state */
	TCP_NEW_SYN_RECV,//收到syn报文，创建req_socket

	TCP_MAX_STATES	/* Leave at the end! */
};

#define TCP_STATE_MASK	0xF

#define TCP_ACTION_FIN	(1 << TCP_CLOSE)

enum {
	TCPF_ESTABLISHED = (1 << TCP_ESTABLISHED),
	TCPF_SYN_SENT	 = (1 << TCP_SYN_SENT),
	TCPF_SYN_RECV	 = (1 << TCP_SYN_RECV),
	TCPF_FIN_WAIT1	 = (1 << TCP_FIN_WAIT1),
	TCPF_FIN_WAIT2	 = (1 << TCP_FIN_WAIT2),
	TCPF_TIME_WAIT	 = (1 << TCP_TIME_WAIT),
	TCPF_CLOSE	 = (1 << TCP_CLOSE),
	TCPF_CLOSE_WAIT	 = (1 << TCP_CLOSE_WAIT),
	TCPF_LAST_ACK	 = (1 << TCP_LAST_ACK),
	TCPF_LISTEN	 = (1 << TCP_LISTEN),
	TCPF_CLOSING	 = (1 << TCP_CLOSING),
	TCPF_NEW_SYN_RECV = (1 << TCP_NEW_SYN_RECV),
};

#endif	/* _LINUX_TCP_STATES_H */
