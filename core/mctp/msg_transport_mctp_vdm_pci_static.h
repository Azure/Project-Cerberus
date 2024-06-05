// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_MCTP_VDM_PCI_STATIC_H_
#define MSG_TRANSPORT_MCTP_VDM_PCI_STATIC_H_

#include "mctp_base_protocol.h"
#include "msg_transport_mctp_vdm_pci.h"
#include "cmd_interface/msg_transport_intermediate_static.h"


/* Internal functions declared to allow for static initialization. */
int msg_transport_mctp_vdm_pci_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response);


/**
 * Initialize a static transport for MCTP Vendor Defined - PCI messages. This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param mctp_transport_ptr The MCTP transport layer used to send the messages.
 * @param protocol_ptr Protocol handler for MCTP messages.
 * @param vendor_id_arg Identifier for the vendor defined protocol sent through this transport.
 */
#define	msg_transport_mctp_vdm_pci_static_init(mctp_transport_ptr, protocol_ptr, vendor_id_arg) { \
		.base = msg_transport_intermediate_static_init ( \
			msg_transport_mctp_vdm_pci_send_request_message, mctp_transport_ptr, \
			sizeof (struct mctp_base_protocol_vdm_pci_header)), \
		.protocol = protocol_ptr, \
		.vendor_id = vendor_id_arg, \
	}


#endif /* MSG_TRANSPORT_MCTP_VDM_PCI_STATIC_H_ */
