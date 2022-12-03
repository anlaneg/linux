// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>

#include <net/ipv6.h>
#include <net/protocol.h>

#include <net/seg6.h>
#include <net/genetlink.h>
#include <linux/seg6.h>
#include <linux/seg6_genl.h>
#ifdef CONFIG_IPV6_SEG6_HMAC
#include <net/seg6_hmac.h>
#endif

/*对srh进行校验*/
bool seg6_validate_srh(struct ipv6_sr_hdr *srh, int len/*srh长度*/,
        bool reduced/*reduce情况下，segments中不包含当前目的地址*/)
{
	unsigned int tlv_offset;
	int max_last_entry;
	int trailing;

	if (srh->type != IPV6_SRCRT_TYPE_4)
	    /*type必须为segment routing*/
		return false;

	/*头部长度不足，报错*/
	if (((srh->hdrlen + 1) << 3) != len)
		return false;

	if (!reduced && srh->segments_left > srh->first_segment) {
	    /*reduce为false情况下，segments_left不得大于first_segment位置*/
		return false;
	} else {
	    /*srh中最大entry数目*/
		max_last_entry = (srh->hdrlen / 2) - 1;

		if (srh->first_segment > max_last_entry)
		    /*first segment不得大于max last entry*/
			return false;

		/*????*/
		if (srh->segments_left > srh->first_segment + 1)
			return false;
	}

	/*srh结构体后面，frist_segment的最后一个字段为ipv6地址故 <<4 即*16*/
	tlv_offset = sizeof(*srh) + ((srh->first_segment + 1) << 4);

	/*hmac长度检查*/
	trailing = len - tlv_offset;
	if (trailing < 0)
		return false;

	while (trailing) {
		struct sr6_tlv *tlv;
		unsigned int tlv_len;

		if (trailing < sizeof(*tlv))
			return false;

		/*取此tlv*/
		tlv = (struct sr6_tlv *)((unsigned char *)srh + tlv_offset);
		tlv_len = sizeof(*tlv) + tlv->len;

		/*检查其长度*/
		trailing -= tlv_len;
		if (trailing < 0)
			return false;

		tlv_offset += tlv_len;
	}

	return true;
}

/*获取报文中的srv6头*/
struct ipv6_sr_hdr *seg6_get_srh(struct sk_buff *skb, int flags)
{
	struct ipv6_sr_hdr *srh;
	int len, srhoff = 0;

	/*查找srv6头*/
	if (ipv6_find_hdr(skb, &srhoff, IPPROTO_ROUTING, NULL, &flags) < 0)
		return NULL;

	/*buffer必须足够*/
	if (!pskb_may_pull(skb, srhoff + sizeof(*srh)))
		return NULL;

	/*指向srv6头*/
	srh = (struct ipv6_sr_hdr *)(skb->data + srhoff);

	len = (srh->hdrlen + 1) << 3;

	/*buffer必须足够完整的srv6头*/
	if (!pskb_may_pull(skb, srhoff + len))
		return NULL;

	/* note that pskb_may_pull may change pointers in header;
	 * for this reason it is necessary to reload them when needed.
	 */
	srh = (struct ipv6_sr_hdr *)(skb->data + srhoff);

	/*srv6头校验*/
	if (!seg6_validate_srh(srh, len, true))
		return NULL;

	return srh;
}

/* Determine if an ICMP invoking packet contains a segment routing
 * header.  If it does, extract the offset to the true destination
 * address, which is in the first segment address.
 */
void seg6_icmp_srh(struct sk_buff *skb, struct inet6_skb_parm *opt)
{
	__u16 network_header = skb->network_header;
	struct ipv6_sr_hdr *srh;

	/* Update network header to point to the invoking packet
	 * inside the ICMP packet, so we can use the seg6_get_srh()
	 * helper.
	 */
	skb_reset_network_header(skb);

	srh = seg6_get_srh(skb, 0);
	if (!srh)
		goto out;

	if (srh->type != IPV6_SRCRT_TYPE_4)
		goto out;

	opt->flags |= IP6SKB_SEG6;
	opt->srhoff = (unsigned char *)srh - skb->data;

out:
	/* Restore the network header back to the ICMP packet */
	skb->network_header = network_header;
}

static struct genl_family seg6_genl_family;

static const struct nla_policy seg6_genl_policy[SEG6_ATTR_MAX + 1] = {
	[SEG6_ATTR_DST]				= { .type = NLA_BINARY,
		.len = sizeof(struct in6_addr) },
	[SEG6_ATTR_DSTLEN]			= { .type = NLA_S32, },
	[SEG6_ATTR_HMACKEYID]		= { .type = NLA_U32, },
	[SEG6_ATTR_SECRET]			= { .type = NLA_BINARY, },
	[SEG6_ATTR_SECRETLEN]		= { .type = NLA_U8, },
	[SEG6_ATTR_ALGID]			= { .type = NLA_U8, },
	[SEG6_ATTR_HMACINFO]		= { .type = NLA_NESTED, },
};

#ifdef CONFIG_IPV6_SEG6_HMAC

/*删除或者修改，创建hmac_info*/
static int seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct seg6_pernet_data *sdata;
	struct seg6_hmac_info *hinfo;
	u32 hmackeyid;
	char *secret;
	int err = 0;
	u8 algid;
	u8 slen;

	/*取此net namespace中的seg6*/
	sdata = seg6_pernet(net);

	if (!info->attrs[SEG6_ATTR_HMACKEYID] ||
	    !info->attrs[SEG6_ATTR_SECRETLEN] ||
	    !info->attrs[SEG6_ATTR_ALGID])
		return -EINVAL;

	hmackeyid = nla_get_u32(info->attrs[SEG6_ATTR_HMACKEYID]);
	slen = nla_get_u8(info->attrs[SEG6_ATTR_SECRETLEN]);
	algid = nla_get_u8(info->attrs[SEG6_ATTR_ALGID]);

	if (hmackeyid == 0)
		return -EINVAL;

	if (slen > SEG6_HMAC_SECRET_LEN)
		return -EINVAL;

	/*由于设置的前提是加锁先删除，故获取时，需要先加锁，才能读取*/
	mutex_lock(&sdata->lock);
	/*查询hmackeyid*/
	hinfo = seg6_hmac_info_lookup(net, hmackeyid);

	if (!slen) {
	    /*未指定长度，执行删除*/
		err = seg6_hmac_info_del(net, hmackeyid);

		goto out_unlock;
	}

	if (!info->attrs[SEG6_ATTR_SECRET]) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (slen > nla_len(info->attrs[SEG6_ATTR_SECRET])) {
		err = -EINVAL;
		goto out_unlock;
	}

	/*之前已有hinfo,先执行删除*/
	if (hinfo) {
		err = seg6_hmac_info_del(net, hmackeyid);
		if (err)
			goto out_unlock;
	}

	secret = (char *)nla_data(info->attrs[SEG6_ATTR_SECRET]);

	hinfo = kzalloc(sizeof(*hinfo), GFP_KERNEL);
	if (!hinfo) {
		err = -ENOMEM;
		goto out_unlock;
	}

	/*填充hinfo*/
	memcpy(hinfo->secret, secret, slen);
	hinfo->slen = slen;
	hinfo->alg_id = algid;
	hinfo->hmackeyid = hmackeyid;

	/*以hmackeyid进行映射，加入到net namesapce中*/
	err = seg6_hmac_info_add(net, hmackeyid, hinfo);
	if (err)
		kfree(hinfo);

out_unlock:
	mutex_unlock(&sdata->lock);
	return err;
}

#else

static int seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info)
{
	return -ENOTSUPP;
}

#endif

static int seg6_genl_set_tunsrc(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *val, *t_old, *t_new;
	struct seg6_pernet_data *sdata;

	sdata = seg6_pernet(net);

	if (!info->attrs[SEG6_ATTR_DST])
	    /*必须填充dst地址*/
		return -EINVAL;

	/*取地址*/
	val = nla_data(info->attrs[SEG6_ATTR_DST]);
	t_new = kmemdup(val, sizeof(*val), GFP_KERNEL);
	if (!t_new)
		return -ENOMEM;

	mutex_lock(&sdata->lock);

	/*设置tunnel源地址*/
	t_old = sdata->tun_src;
	rcu_assign_pointer(sdata->tun_src, t_new);

	mutex_unlock(&sdata->lock);

	synchronize_net();
	kfree(t_old);

	return 0;
}

static int seg6_genl_get_tunsrc(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *tun_src;
	struct sk_buff *msg;
	void *hdr;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &seg6_genl_family, 0, SEG6_CMD_GET_TUNSRC);
	if (!hdr)
		goto free_msg;

	rcu_read_lock();
	/*取此network中对应的tunnel src*/
	tun_src = rcu_dereference(seg6_pernet(net)->tun_src);

	/*填充并返回*/
	if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), tun_src))
		goto nla_put_failure;

	rcu_read_unlock();

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	rcu_read_unlock();
free_msg:
	nlmsg_free(msg);
	return -ENOMEM;
}

#ifdef CONFIG_IPV6_SEG6_HMAC

/*填充hmac_info到msg中*/
static int __seg6_hmac_fill_info(struct seg6_hmac_info *hinfo,
				 struct sk_buff *msg)
{
	if (nla_put_u32(msg, SEG6_ATTR_HMACKEYID, hinfo->hmackeyid) ||
	    nla_put_u8(msg, SEG6_ATTR_SECRETLEN, hinfo->slen) ||
	    nla_put(msg, SEG6_ATTR_SECRET, hinfo->slen, hinfo->secret) ||
	    nla_put_u8(msg, SEG6_ATTR_ALGID, hinfo->alg_id))
		return -1;

	return 0;
}

static int __seg6_genl_dumphmac_element(struct seg6_hmac_info *hinfo,
					u32 portid, u32 seq, u32 flags,
					struct sk_buff *skb, u8 cmd)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &seg6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	/*填充hinfo到skb中*/
	if (__seg6_hmac_fill_info(hinfo, skb) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int seg6_genl_dumphmac_start(struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	struct seg6_pernet_data *sdata;
	struct rhashtable_iter *iter;

	sdata = seg6_pernet(net);
	iter = (struct rhashtable_iter *)cb->args[0];

	if (!iter) {
		iter = kmalloc(sizeof(*iter), GFP_KERNEL);
		if (!iter)
			return -ENOMEM;

		cb->args[0] = (long)iter;
	}

	/*填充hmac*/
	rhashtable_walk_enter(&sdata->hmac_infos, iter);

	return 0;
}

static int seg6_genl_dumphmac_done(struct netlink_callback *cb)
{
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];

	rhashtable_walk_exit(iter);

	kfree(iter);

	return 0;
}

static int seg6_genl_dumphmac(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct rhashtable_iter *iter = (struct rhashtable_iter *)cb->args[0];
	struct seg6_hmac_info *hinfo;
	int ret;

	rhashtable_walk_start(iter);

	for (;;) {
		hinfo = rhashtable_walk_next(iter);

		if (IS_ERR(hinfo)) {
			if (PTR_ERR(hinfo) == -EAGAIN)
				continue;
			ret = PTR_ERR(hinfo);
			goto done;
		} else if (!hinfo) {
			break;
		}

		ret = __seg6_genl_dumphmac_element(hinfo,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI,
						   skb, SEG6_CMD_DUMPHMAC);
		if (ret)
			goto done;
	}

	ret = skb->len;

done:
	rhashtable_walk_stop(iter);
	return ret;
}

#else

static int seg6_genl_dumphmac_start(struct netlink_callback *cb)
{
	return 0;
}

static int seg6_genl_dumphmac_done(struct netlink_callback *cb)
{
	return 0;
}

static int seg6_genl_dumphmac(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -ENOTSUPP;
}

#endif

static int __net_init seg6_net_init(struct net *net)
{
	struct seg6_pernet_data *sdata;

	sdata = kzalloc(sizeof(*sdata), GFP_KERNEL);
	if (!sdata)
		return -ENOMEM;

	mutex_init(&sdata->lock);

	/*初始化tunnel src*/
	sdata->tun_src = kzalloc(sizeof(*sdata->tun_src), GFP_KERNEL);
	if (!sdata->tun_src) {
		kfree(sdata);
		return -ENOMEM;
	}

	net->ipv6.seg6_data = sdata;

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (seg6_hmac_net_init(net)) {
		kfree(rcu_dereference_raw(sdata->tun_src));
		kfree(sdata);
		return -ENOMEM;
	}
#endif

	return 0;
}

static void __net_exit seg6_net_exit(struct net *net)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);

#ifdef CONFIG_IPV6_SEG6_HMAC
	seg6_hmac_net_exit(net);
#endif

	kfree(rcu_dereference_raw(sdata->tun_src));
	kfree(sdata);
}

static struct pernet_operations ip6_segments_ops = {
	.init = seg6_net_init,
	.exit = seg6_net_exit,
};

static const struct genl_ops seg6_genl_ops[] = {
	{
	    /*设置hmac*/
		.cmd	= SEG6_CMD_SETHMAC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= seg6_genl_sethmac,
		.flags	= GENL_ADMIN_PERM,
	},
	{
	    /*显示hmac*/
		.cmd	= SEG6_CMD_DUMPHMAC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.start	= seg6_genl_dumphmac_start,/*设置iter*/
		.dumpit	= seg6_genl_dumphmac,
		.done	= seg6_genl_dumphmac_done,
		.flags	= GENL_ADMIN_PERM,
	},
	{
	    /*设置tunnel src*/
		.cmd	= SEG6_CMD_SET_TUNSRC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= seg6_genl_set_tunsrc,
		.flags	= GENL_ADMIN_PERM,
	},
	{
	    /*显示tunnel src*/
		.cmd	= SEG6_CMD_GET_TUNSRC,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit	= seg6_genl_get_tunsrc,
		.flags	= GENL_ADMIN_PERM,
	},
};

static struct genl_family seg6_genl_family __ro_after_init = {
	.hdrsize	= 0,
	.name		= SEG6_GENL_NAME,
	.version	= SEG6_GENL_VERSION,
	.maxattr	= SEG6_ATTR_MAX,
	.policy = seg6_genl_policy,
	.netnsok	= true,
	.parallel_ops	= true,
	.ops		= seg6_genl_ops,
	.n_ops		= ARRAY_SIZE(seg6_genl_ops),
	.resv_start_op	= SEG6_CMD_GET_TUNSRC + 1,
	.module		= THIS_MODULE,
};

int __init seg6_init(void)
{
	int err;

	/*注册seg6 netlink消息，用于hmac,tunnel src设置显示*/
	err = genl_register_family(&seg6_genl_family);
	if (err)
		goto out;

	/*hmac,tunnel src针对每个net namespace进行填充，故每个netns需要单独初始化*/
	err = register_pernet_subsys(&ip6_segments_ops);
	if (err)
		goto out_unregister_genl;

#ifdef CONFIG_IPV6_SEG6_LWTUNNEL
	err = seg6_iptunnel_init();
	if (err)
		goto out_unregister_pernet;

	err = seg6_local_init();
	if (err)
		goto out_unregister_pernet;
#endif

#ifdef CONFIG_IPV6_SEG6_HMAC
	err = seg6_hmac_init();
	if (err)
		goto out_unregister_iptun;
#endif

	pr_info("Segment Routing with IPv6\n");

out:
	return err;
#ifdef CONFIG_IPV6_SEG6_HMAC
out_unregister_iptun:
#ifdef CONFIG_IPV6_SEG6_LWTUNNEL
	seg6_local_exit();
	seg6_iptunnel_exit();
#endif
#endif
#ifdef CONFIG_IPV6_SEG6_LWTUNNEL
out_unregister_pernet:
	unregister_pernet_subsys(&ip6_segments_ops);
#endif
out_unregister_genl:
	genl_unregister_family(&seg6_genl_family);
	goto out;
}

void seg6_exit(void)
{
#ifdef CONFIG_IPV6_SEG6_HMAC
	seg6_hmac_exit();
#endif
#ifdef CONFIG_IPV6_SEG6_LWTUNNEL
	seg6_iptunnel_exit();
#endif
	unregister_pernet_subsys(&ip6_segments_ops);
	genl_unregister_family(&seg6_genl_family);
}
