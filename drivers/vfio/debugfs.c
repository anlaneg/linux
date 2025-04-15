// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, HiSilicon Ltd.
 */

#include <linux/device.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/vfio.h>
#include "vfio.h"

static struct dentry *vfio_debugfs_root;

/*state文件内容显示*/
static int vfio_device_state_read(struct seq_file *seq, void *data)
{
	struct device *vf_dev = seq->private;
	struct vfio_device *vdev = container_of(vf_dev,
						struct vfio_device, device);
	enum vfio_device_mig_state state;
	int ret;

	BUILD_BUG_ON(VFIO_DEVICE_STATE_NR !=
		     VFIO_DEVICE_STATE_PRE_COPY_P2P + 1);

	/*获得vdev对应的状态*/
	ret = vdev->mig_ops->migration_get_state(vdev, &state);
	if (ret)
		return -EINVAL;

	/*转换state为字符串形式*/
	switch (state) {
	case VFIO_DEVICE_STATE_ERROR:
		/*错误状态*/
		seq_puts(seq, "ERROR\n");
		break;
	case VFIO_DEVICE_STATE_STOP:
		seq_puts(seq, "STOP\n");
		break;
	case VFIO_DEVICE_STATE_RUNNING:
		seq_puts(seq, "RUNNING\n");
		break;
	case VFIO_DEVICE_STATE_STOP_COPY:
		seq_puts(seq, "STOP_COPY\n");
		break;
	case VFIO_DEVICE_STATE_RESUMING:
		seq_puts(seq, "RESUMING\n");
		break;
	case VFIO_DEVICE_STATE_RUNNING_P2P:
		seq_puts(seq, "RUNNING_P2P\n");
		break;
	case VFIO_DEVICE_STATE_PRE_COPY:
		seq_puts(seq, "PRE_COPY\n");
		break;
	case VFIO_DEVICE_STATE_PRE_COPY_P2P:
		seq_puts(seq, "PRE_COPY_P2P\n");
		break;
	default:
		seq_puts(seq, "Invalid\n");
	}

	return 0;
}

void vfio_device_debugfs_init(struct vfio_device *vdev)
{
	struct device *dev = &vdev->device;

	/*在根目录下创建vdev设备（名称）对应的目录*/
	vdev->debug_root = debugfs_create_dir(dev_name(vdev->dev),
					      vfio_debugfs_root);

	if (vdev->mig_ops) {
		struct dentry *vfio_dev_migration = NULL;

		vfio_dev_migration = debugfs_create_dir("migration",
							vdev->debug_root);/*每个vdev有一个migration目录*/
		debugfs_create_devm_seqfile(dev, "state", vfio_dev_migration,
					    vfio_device_state_read/*state文件读操作实现*/);/*migration目录有一个state文件*/
	}
}

void vfio_device_debugfs_exit(struct vfio_device *vdev)
{
	/*vdev设备对应的根目录移除*/
	debugfs_remove_recursive(vdev->debug_root);
}

void vfio_debugfs_create_root(void)
{
	/*创建vfio-debugfs根目录*/
	vfio_debugfs_root = debugfs_create_dir("vfio", NULL);
}

void vfio_debugfs_remove_root(void)
{
	/*删除根目录*/
	debugfs_remove_recursive(vfio_debugfs_root);
	vfio_debugfs_root = NULL;
}
