// SPDX-License-Identifier: GPL-2.0
/*
 * MSI[X} related functions which are available unconditionally.
 */
#include "../pci.h"

/*
 * Disable the MSI[X] hardware to avoid screaming interrupts during boot.
 * This is the power on reset default so usually this should be a noop.
 */

void pci_msi_init(struct pci_dev *dev)
{
	u16 ctrl;

	dev->msi_cap = pci_find_capability(dev, PCI_CAP_ID_MSI);
	if (!dev->msi_cap)
		return;

	pci_read_config_word(dev, dev->msi_cap + PCI_MSI_FLAGS, &ctrl);
	if (ctrl & PCI_MSI_FLAGS_ENABLE) {
		pci_write_config_word(dev, dev->msi_cap + PCI_MSI_FLAGS,
				      ctrl & ~PCI_MSI_FLAGS_ENABLE);
	}

	if (!(ctrl & PCI_MSI_FLAGS_64BIT))
		dev->no_64bit_msi = 1;
}

void pci_msix_init(struct pci_dev *dev)
{
	u16 ctrl;

	dev->msix_cap = pci_find_capability(dev, PCI_CAP_ID_MSIX);
	if (!dev->msix_cap)
		/*此设备没有msix cap*/
		return;

	/*读取msix-cap结构体中的flags成员（16bits)*/
	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &ctrl);
	if (ctrl & PCI_MSIX_FLAGS_ENABLE) {
		/*此时是开启状态，配置为禁用状态*/
		pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS,
				      ctrl & ~PCI_MSIX_FLAGS_ENABLE);
	}
}
