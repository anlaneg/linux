// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2011 Instituto Nokia de Tecnologia
 *
 * Authors:
 *    Aloisio Almeida Jr <aloisio.almeida@openbossa.org>
 *    Lauro Ramos Venancio <lauro.venancio@openbossa.org>
 */

#include <linux/nfc.h>
#include <linux/module.h>

#include "nfc.h"

static DEFINE_RWLOCK(proto_tab_lock);
//提取PF_NFC支持的proto
static const struct nfc_protocol *proto_tab[NFC_SOCKPROTO_MAX];

//nfc socket创建
static int nfc_sock_create(struct net *net, struct socket *sock, int proto/*协议号*/,
			   int kern)
{
	int rc = -EPROTONOSUPPORT;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	if (proto < 0 || proto >= NFC_SOCKPROTO_MAX)
		return -EINVAL;

	read_lock(&proto_tab_lock);
	if (proto_tab[proto] &&	try_module_get(proto_tab[proto]->owner)) {
		rc = proto_tab[proto]->create(net, sock, proto_tab[proto], kern);
		module_put(proto_tab[proto]->owner);
	}
	read_unlock(&proto_tab_lock);

	return rc;
}

//注册PF_NFC协议族
static const struct net_proto_family nfc_sock_family_ops = {
	.owner  = THIS_MODULE,
	.family = PF_NFC,
	.create = nfc_sock_create,
};

//为af_nfc注册协议
int nfc_proto_register(const struct nfc_protocol *nfc_proto)
{
	int rc;

	if (nfc_proto->id < 0 || nfc_proto->id >= NFC_SOCKPROTO_MAX)
		return -EINVAL;

	rc = proto_register(nfc_proto->proto, 0);
	if (rc)
		return rc;

	write_lock(&proto_tab_lock);
	if (proto_tab[nfc_proto->id])
		rc = -EBUSY;
	else
		proto_tab[nfc_proto->id] = nfc_proto;
	write_unlock(&proto_tab_lock);

	return rc;
}
EXPORT_SYMBOL(nfc_proto_register);

void nfc_proto_unregister(const struct nfc_protocol *nfc_proto)
{
	write_lock(&proto_tab_lock);
	proto_tab[nfc_proto->id] = NULL;
	write_unlock(&proto_tab_lock);

	proto_unregister(nfc_proto->proto);
}
EXPORT_SYMBOL(nfc_proto_unregister);

int __init af_nfc_init(void)
{
	//注册af_nfc对应的socket协议族
	return sock_register(&nfc_sock_family_ops);
}

void af_nfc_exit(void)
{
	sock_unregister(PF_NFC);
}
