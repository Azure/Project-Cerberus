// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_MCTP_VDM_PCI_H_
#define MSG_TRANSPORT_MCTP_VDM_PCI_H_

#include <stdint.h>
#include "cmd_interface/msg_transport_intermediate.h"
#include "mctp/cmd_interface_protocol_mctp_vdm_pci.h"


/**
 * Defines a transport for sending MCTP Vendor Defined - PCI messages, irrespective of the physical
 * transport layer used to transmit the message.
 *
 * This is intended to be connected directly to an MCTP transport layer without needing to be passed
 * through further MCTP message layer handling.
 */
struct msg_transport_mctp_vdm_pci {
	struct msg_transport_intermediate base;						/**< Base transport API. */
	const struct cmd_interface_protocol_mctp_vdm_pci *protocol;	/**< Protocol handler for MCTP VDMs. */
	uint16_t vendor_id;											/**< PCI vendor ID for the VDM protocol. */
};


int msg_transport_mctp_vdm_pci_init (struct msg_transport_mctp_vdm_pci *mctp_vdm_pci,
	const struct msg_transport *mctp_transport,
	const struct cmd_interface_protocol_mctp_vdm_pci *protocol, uint16_t vendor_id);
void msg_transport_mctp_vdm_pci_release (const struct msg_transport_mctp_vdm_pci *mctp_vdm_pci);


#endif	/* MSG_TRANSPORT_MCTP_VDM_PCI_H_ */
