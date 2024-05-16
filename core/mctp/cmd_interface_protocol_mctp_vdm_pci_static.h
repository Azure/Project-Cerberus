// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_STATIC_H_
#define CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_STATIC_H_

#include "cmd_interface_protocol_mctp_vdm_pci.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_protocol_mctp_vdm_pci_parse_message (
	const struct cmd_interface_protocol *protocol, struct cmd_interface_msg *message,
	uint32_t *message_type);


/**
 * Constant initializer for the protocol handler API.
 */
#define	CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_API_INIT { \
		.parse_message = cmd_interface_protocol_mctp_vdm_pci_parse_message, \
		.handle_request_result = NULL, \
	}


/**
 * Initialize a static protocol handler for MCTP Vendor Defined - PCI messages.
 */
#define	cmd_interface_protocol_mctp_vdm_pci_static_init { \
		.base = CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_API_INIT, \
	}


#endif	/* CMD_INTERFACE_PROTOCOL_MCTP_VDM_PCI_STATIC_H_ */
