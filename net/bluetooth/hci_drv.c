// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Google Corporation
 */

#include <linux/skbuff.h>
#include <linux/types.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci.h>
#include <net/bluetooth/hci_core.h>
#include <net/bluetooth/hci_drv.h>

int hci_drv_cmd_status(struct hci_dev *hdev, u16 cmd, u8 status)
{
	struct hci_drv_ev_hdr *hdr;
	struct hci_drv_ev_cmd_status *ev;
	struct sk_buff *skb;

	skb = bt_skb_alloc(sizeof(*hdr) + sizeof(*ev), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	hdr = skb_put(skb, sizeof(*hdr));
	hdr->opcode = __cpu_to_le16(HCI_DRV_EV_CMD_STATUS);
	hdr->len = __cpu_to_le16(sizeof(*ev));

	ev = skb_put(skb, sizeof(*ev));
	ev->opcode = __cpu_to_le16(cmd);/*指明原请求的opcode*/
	ev->status = status;

	hci_skb_pkt_type(skb) = HCI_DRV_PKT;/*指明为driver类packet*/

	return hci_recv_frame(hdev, skb);
}
EXPORT_SYMBOL(hci_drv_cmd_status);

int hci_drv_cmd_complete(struct hci_dev *hdev, u16 cmd, u8 status, void *rp,
			 size_t rp_len)
{
	struct hci_drv_ev_hdr *hdr;
	struct hci_drv_ev_cmd_complete *ev;
	struct sk_buff *skb;

	skb = bt_skb_alloc(sizeof(*hdr) + sizeof(*ev) + rp_len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	hdr = skb_put(skb, sizeof(*hdr));
	hdr->opcode = __cpu_to_le16(HCI_DRV_EV_CMD_COMPLETE);/*指明command完成*/
	hdr->len = __cpu_to_le16(sizeof(*ev) + rp_len);/*指明消息长度*/

	ev = skb_put(skb, sizeof(*ev));
	ev->opcode = __cpu_to_le16(cmd);/*指明原请求opcode*/
	ev->status = status;/*指明原请求的执行结果*/

	skb_put_data(skb, rp, rp_len);/*放入响应内容*/

	hci_skb_pkt_type(skb) = HCI_DRV_PKT;/*指明为driver command*/

	return hci_recv_frame(hdev, skb);/*手动调用收包函数*/
}
EXPORT_SYMBOL(hci_drv_cmd_complete);

int hci_drv_process_cmd(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_drv_cmd_hdr *hdr;
	const struct hci_drv_handler *handler = NULL;
	u16 opcode, len, ogf, ocf;

	hdr = skb_pull_data(skb, sizeof(*hdr));/*取driver cmd header*/
	if (!hdr)
		return -EILSEQ;

	opcode = __le16_to_cpu(hdr->opcode);
	len = __le16_to_cpu(hdr->len);
	if (len != skb->len)
		return -EILSEQ;/*与skb长度不相等*/

	ogf = hci_opcode_ogf(opcode);
	ocf = hci_opcode_ocf(opcode);

	if (!hdev->hci_drv)
		/*未提供driver command实现*/
		return hci_drv_cmd_status(hdev, opcode,
					  HCI_DRV_STATUS_UNKNOWN_COMMAND);

	if (ogf != HCI_DRV_OGF_DRIVER_SPECIFIC) {
		if (opcode < hdev->hci_drv->common_handler_count)
			handler = &hdev->hci_drv->common_handlers[opcode];
	} else {
		/*当ogf为HCI_DRV_OGF_DRIVER_SPECIFIC时，按ocf要求执行specific handler*/
		if (ocf < hdev->hci_drv->specific_handler_count)
			handler = &hdev->hci_drv->specific_handlers[ocf];
	}

	if (!handler || !handler->func)
		/*无handler或者无相应处理func,按未知的command处理*/
		return hci_drv_cmd_status(hdev, opcode,
					  HCI_DRV_STATUS_UNKNOWN_COMMAND);

	if (len != handler->data_len)
		/*报文长度与handler要求的参数长度不符*/
		return hci_drv_cmd_status(hdev, opcode,
					  HCI_DRV_STATUS_INVALID_PARAMETERS);

	/*按回调处理*/
	return handler->func(hdev, skb->data, len);
}
EXPORT_SYMBOL(hci_drv_process_cmd);
