// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "mctp/mctp_protocol.h"
#include "cerberus_protocol.h"
#include "session_manager.h"
#include "cmd_interface.h"


/**
 * Determine if received request is encrypted from Cerberus protocol header.
 *
 * @param intf The command interface that will process the request.
 * @param request The request being processed.
 * 
 * @return 0 if the request is not encrypted, 1 if request is encrypted or an error code.
 */
int cmd_interface_is_request_encrypted (struct cmd_interface *intf, 
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_header *header;
	
	if ((intf == NULL) || (request == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	header = (struct cerberus_protocol_header*) request->data;

	if ((request->length < CERBERUS_PROTOCOL_MIN_MSG_LEN) ||
		(header->msg_type != MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) || 
		(header->pci_vendor_id != CERBERUS_PROTOCOL_MSFT_PCI_VID)) {
		return 0;
	}

	return header->crypt;
}

/**
 * Pre-process received request.
 *
 * @param intf The command interface that will process the request.
 * @param request The request being processed.
 * @param command_id Pointer to hold command ID of incoming request.
 * @param command_set Pointer to hold command set of incoming request.
 * @param decrypt Flag indicating whether to decrypt incoming request if encrypted
 * 
 * @return 0 if the request was successfully processed or an error code.
 */
int cmd_interface_process_request (struct cmd_interface *intf, 
	struct cmd_interface_request *request, uint8_t *command_id, uint8_t *command_set, bool decrypt)
{
	struct cerberus_protocol_header *header;
	int status;
	
	if (request == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}
		
	request->new_request = false;
	request->crypto_timeout = false;

	if (intf == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	intf->curr_txn_encrypted = false;

	header = (struct cerberus_protocol_header*) request->data;

	if (request->length < CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_PAYLOAD_TOO_SHORT;
	}

	if ((header->msg_type != (MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF)) || 
		(header->pci_vendor_id != CERBERUS_PROTOCOL_MSFT_PCI_VID)) {
		return CMD_HANDLER_UNSUPPORTED_MSG;
	}

	*command_id = header->command;
	*command_set = header->rq;

	if (header->crypt && decrypt) {
		if (intf->session) {
			status = intf->session->decrypt_message (intf->session, request);
			if (status != 0) {
				return status;
			}

			request->max_response -= SESSION_MANAGER_TRAILER_LEN;
			intf->curr_txn_encrypted = true;
		}
		else {
			return CMD_HANDLER_ENCRYPTION_UNSUPPORTED;
		}
	}

	if (header->command == CERBERUS_PROTOCOL_ERROR) {
		return CMD_ERROR_MESSAGE_ESCAPE_SEQ;
	}

	return 0;
}

/**
 * Process generated response.
 *
 * @param intf The command interface that will process the response.
 * @param response The response being processed.
 * 
 * @return 0 if the response was successfully processed or an error code.
 */
int cmd_interface_process_response (struct cmd_interface *intf, 
	struct cmd_interface_request *response)
{
	int status = 0;
	
	if (response == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}
		
	if (intf->curr_txn_encrypted) {
		response->max_response += SESSION_MANAGER_TRAILER_LEN;

		status = cmd_interface_is_request_encrypted (intf, response);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		if (!status) {
			return 0;
		}

		if (intf->session == NULL) {
			return CMD_HANDLER_ENCRYPTION_UNSUPPORTED;
		}
		
		status = intf->session->encrypt_message (intf->session, response);
		if (status == 0) {
			intf->curr_txn_encrypted = false;
		}
	}

	return status;
}

/**
 * Generate a packet containing error message.
 *
 * @param intf The command interface to utilize.
 * @param request The request container to utilize.
 * @param error_code Identifier for the error.
 * @param error_data Data for the error condition.
 * @param cmd_set Command set to respond on.
 * 
 * @return 0 if the error was successfully generated or an error code.
 */
int cmd_interface_generate_error_packet (struct cmd_interface *intf, 
	struct cmd_interface_request *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	struct cerberus_protocol_error *error_msg = (struct cerberus_protocol_error*) request->data;
	int status;

	if ((intf == NULL) || (request == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (error_msg, 0, sizeof (struct cerberus_protocol_error));

	error_msg->header.rq = cmd_set;
	error_msg->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error_msg->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	error_msg->header.command = CERBERUS_PROTOCOL_ERROR;

	error_msg->error_code = error_code;
	error_msg->error_data = error_data;

	request->length = sizeof (struct cerberus_protocol_error);

	if (intf->curr_txn_encrypted) {
		status = intf->session->encrypt_message (intf->session, request);	
		if (status != 0) {
			return status;
		}

		intf->curr_txn_encrypted = false;
	}

	return 0;
}
