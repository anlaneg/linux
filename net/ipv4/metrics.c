// SPDX-License-Identifier: GPL-2.0-only
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/tcp.h>

/*将fc_mx中的配置解析出来，校验后，填充到metrics中，对应的type进行了减一处理*/
static int ip_metrics_convert(struct net *net, struct nlattr *fc_mx,
			      int fc_mx_len, u32 *metrics,
			      struct netlink_ext_ack *extack)
{
	bool ecn_ca = false;
	struct nlattr *nla;
	int remaining;

	if (!fc_mx)
		return 0;

	nla_for_each_attr(nla, fc_mx, fc_mx_len, remaining) {
		int type = nla_type(nla);
		u32 val;

		/*无效metrics type排除*/
		if (!type)
			continue;
		if (type > RTAX_MAX) {
			NL_SET_ERR_MSG(extack, "Invalid metric type");
			return -EINVAL;
		}

		if (type == RTAX_CC_ALGO) {
		    /*处理拥塞算法，其为字符串，长度非u32*/
			char tmp[TCP_CA_NAME_MAX];

			nla_strscpy(tmp, nla, sizeof(tmp));
			val = tcp_ca_get_key_by_name(net, tmp, &ecn_ca);
			if (val == TCP_CA_UNSPEC) {
			    /*遇到未注册的拥塞算法*/
				NL_SET_ERR_MSG(extack, "Unknown tcp congestion algorithm");
				return -EINVAL;
			}
		} else {
		    /*处理其它杂项，这些配置值长度均为u32*/
			if (nla_len(nla) != sizeof(u32)) {
				NL_SET_ERR_MSG_ATTR(extack, nla,
						    "Invalid attribute in metrics");
				return -EINVAL;
			}
			val = nla_get_u32(nla);
		}
		/*建议的mss值*/
		if (type == RTAX_ADVMSS && val > 65535 - 40)
			val = 65535 - 40;
		/*mtu值，mtu这里为何是减去15?*/
		if (type == RTAX_MTU && val > 65535 - 15)
			val = 65535 - 15;
		if (type == RTAX_HOPLIMIT && val > 255)
			val = 255;
		/*features相关的掩码须保证是认识的feature*/
		if (type == RTAX_FEATURES && (val & ~RTAX_FEATURE_MASK)) {
			NL_SET_ERR_MSG(extack, "Unknown flag set in feature mask in metrics attribute");
			return -EINVAL;
		}
		/*记录各杂项的配置值（注：type进行了减一处理）*/
		metrics[type - 1] = val;
	}

	if (ecn_ca)
	    /*支持ecn拥塞*/
		metrics[RTAX_FEATURES - 1] |= DST_FEATURE_ECN_CA;

	return 0;
}

struct dst_metrics *ip_fib_metrics_init(struct net *net, struct nlattr *fc_mx,
					int fc_mx_len,
					struct netlink_ext_ack *extack)
{
	struct dst_metrics *fib_metrics;
	int err;

	if (!fc_mx)
	    /*没有配置metric，使用default metric*/
		return (struct dst_metrics *)&dst_default_metrics;

	/*申请dst_metrics*/
	fib_metrics = kzalloc(sizeof(*fib_metrics), GFP_KERNEL);
	if (unlikely(!fib_metrics))
		return ERR_PTR(-ENOMEM);

	/*利用fc_mx配置，填充fib_metrics->metrics*/
	err = ip_metrics_convert(net, fc_mx, fc_mx_len, fib_metrics->metrics/*出参，填充此结构*/,
				 extack);
	if (!err) {
		refcount_set(&fib_metrics->refcnt, 1);
	} else {
		kfree(fib_metrics);
		fib_metrics = ERR_PTR(err);
	}

	return fib_metrics;
}
EXPORT_SYMBOL_GPL(ip_fib_metrics_init);
