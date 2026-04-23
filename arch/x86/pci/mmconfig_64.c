// SPDX-License-Identifier: GPL-2.0
/*
 * mmconfig.c - Low-level direct PCI config space access via MMCONFIG
 *
 * This is an 64bit optimized version that always keeps the full mmconfig
 * space mapped. This allows lockless config space operation.
 */

#define pr_fmt(fmt) "PCI: " fmt

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/bitmap.h>
#include <linux/rcupdate.h>
#include <asm/e820/api.h>
#include <asm/pci_x86.h>

/*取此设备对应的base地址*/
static char __iomem *pci_dev_base(unsigned int seg, unsigned int bus, unsigned int devfn)
{
	struct pci_mmcfg_region *cfg = pci_mmconfig_lookup(seg, bus);

	if (cfg && cfg->virt)
		/*每个devfn只对应了4096的空间。每个bus只对应了1M空间，两个devfn之间内存是连续的*/
		return cfg->virt + (PCI_MMCFG_BUS_OFFSET(bus) | (devfn << 12));
	return NULL;
}

static int pci_mmcfg_read(unsigned int seg/*domain编号*/, unsigned int bus,
			  unsigned int devfn, int reg/*偏移量*/, int len/*读取的内容长度*/, u32 *value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095))) {
err:		*value = -1;
		return -EINVAL;/*参数有误*/
	}

	rcu_read_lock();
	/*拿到此设备对应的配置base地址*/
	addr = pci_dev_base(seg, bus, devfn);
	if (!addr) {
		rcu_read_unlock();
		goto err;
	}

	/*读取指定位置*/
	switch (len) {
	case 1:
		*value = mmio_config_readb(addr + reg);
		break;
	case 2:
		*value = mmio_config_readw(addr + reg);
		break;
	case 4:
		*value = mmio_config_readl(addr + reg);
		break;
	}
	rcu_read_unlock();

	return 0;
}

static int pci_mmcfg_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095)))
		return -EINVAL;

	rcu_read_lock();
	/*取得此dev对应的配置空间base地址*/
	addr = pci_dev_base(seg, bus, devfn);
	if (!addr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	/*为此位置写入值（addr+reg）这个地址将由根桥转发给子bus,子bus传递并最终转给对应的设备*/
	switch (len) {
	case 1:
		mmio_config_writeb(addr + reg, value);
		break;
	case 2:
		mmio_config_writew(addr + reg, value);
		break;
	case 4:
		mmio_config_writel(addr + reg, value);
		break;
	}
	rcu_read_unlock();

	return 0;
}

/*对pci设备针对某个位置进行读写
 * root@server:/sys/kernel/debug/# /usr/share/bcc/tools/trace -K '::pci_mmcfg_read'
PID     TID     COMM            FUNC
52888   52888   lspci           pci_mmcfg_read
        pci_mmcfg_read+0x1 [kernel]
        pci_user_read_config_dword+0x69 [kernel]
        pci_read_config+0x1fd [kernel]
        kernfs_fop_read_iter+0xa4 [kernel]
        new_sync_read+0x112 [kernel]
        vfs_read+0xee [kernel]
        ksys_pread64+0x61 [kernel]
        do_syscall_64+0x34 [kernel]
        entry_SYSCALL_64_after_hwframe+0x61 [kernel]
 * */
const struct pci_raw_ops pci_mmcfg = {
	.read =		pci_mmcfg_read,
	.write =	pci_mmcfg_write,
};

static void __iomem *mcfg_ioremap(struct pci_mmcfg_region *cfg)
{
	void __iomem *addr;
	u64 start, size;
	int num_buses;

	start = cfg->address + PCI_MMCFG_BUS_OFFSET(cfg->start_bus);
	num_buses = cfg->end_bus - cfg->start_bus + 1;
	size = PCI_MMCFG_BUS_OFFSET(num_buses);
	addr = ioremap(start, size);
	if (addr)
		addr -= PCI_MMCFG_BUS_OFFSET(cfg->start_bus);
	return addr;
}

int pci_mmcfg_arch_map(struct pci_mmcfg_region *cfg)
{
	cfg->virt = mcfg_ioremap(cfg);
	if (!cfg->virt) {
		pr_err("can't map ECAM at %pR\n", &cfg->res);
		return -ENOMEM;
	}

	return 0;
}

void pci_mmcfg_arch_unmap(struct pci_mmcfg_region *cfg)
{
	if (cfg && cfg->virt) {
		iounmap(cfg->virt + PCI_MMCFG_BUS_OFFSET(cfg->start_bus));
		cfg->virt = NULL;
	}
}

int __init pci_mmcfg_arch_init(void)
{
	struct pci_mmcfg_region *cfg;

	list_for_each_entry(cfg, &pci_mmcfg_list, list)
		if (pci_mmcfg_arch_map(cfg)) {
			pci_mmcfg_arch_free();
			return 0;
		}

	raw_pci_ext_ops = &pci_mmcfg;

	return 1;
}

void __init pci_mmcfg_arch_free(void)
{
	struct pci_mmcfg_region *cfg;

	list_for_each_entry(cfg, &pci_mmcfg_list, list)
		pci_mmcfg_arch_unmap(cfg);
}
