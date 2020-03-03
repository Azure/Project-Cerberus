// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stddef.h>
#include "mctp/mctp_protocol.h"
#include "cerberus_protocol.h"
#include "cmd_interface.h"


/**
 * Pre-process received request.
 *
 * @param intf The command interface that will process the request.
 * @param request The request being processed.
 * @param command_id Pointer to hold command ID of incoming request.
 * @param command_set Pointer to hold command set of incoming request.
 * 
 * @return 0 if the request was successfully processed or an error code.
 */
int cmd_interface_process_request (struct cmd_interface *intf, 
	struct cmd_interface_request *request, uint8_t *command_id, uint8_t *command_set)
{
	struct cerberus_protocol_header *header;
	
	if (request == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	request->new_request = false;
	request->crypto_timeout = false;

	if (intf == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	header = (struct cerberus_protocol_header*) request->data;

	if (request->length < CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_PAYLOAD_TOO_SHORT;
	}

	if ((header->msg_type != (MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF)) || 
		(header->pci_vendor_id != CERBERUS_PROTOCOL_MSFT_PCI_VID) || 
		(header->crypt != 0)) {
		return CMD_HANDLER_UNSUPPORTED_MSG;
	}

	*command_id = header->command;
	*command_set = header->rq;

	if (header->command == CERBERUS_PROTOCOL_ERROR) {
		return CMD_ERROR_MESSAGE_ESCAPE_SEQ;
	}

	return 0;
}
