// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_H_
#define CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_H_

#include "cmd_interface/cmd_interface.h"


/**
 * Protocol handler for MCTP Vendor Defined - PCI messages, as defined in section 13.1 of the MCTP
 * base specification (DSP0236).
 */
struct cmd_interface_protocol_mctp_vdm_pci {
	struct cmd_interface_protocol base;	/**< Base protocol handling API. */
};


int cmd_interface_protocol_mctp_vdm_pci_init (struct cmd_interface_protocol_mctp_vdm_pci *mctp);
void cmd_interface_protocol_mctp_vdm_pci_release (
	const struct cmd_interface_protocol_mctp_vdm_pci *mctp);


#endif	/* CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_H_ */
