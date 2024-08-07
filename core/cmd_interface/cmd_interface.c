// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "cerberus_protocol.h"
#include "cmd_interface.h"
#include "mctp/mctp_base_protocol.h"


/**
 * Configure the message structure to support receiving a new message in the data buffer.  The data
 * pointer is not modified, but the descriptor for that buffer is reset.
 *
 * @param message The message instance to initialize.
 * @param source_eid EID to assign as the message source.
 * @param source_addr Bus address to assign as the message source.
 * @param target_eid EID to assign as the message target.
 * @param channel_id Identifier for the command channel receiving the message.
 */
void cmd_interface_msg_new_message (struct cmd_interface_msg *message, uint8_t source_eid,
	uint8_t source_addr, uint8_t target_eid, int channel_id)
{
	if (message != NULL) {
		message->length = 0;
		message->payload = message->data;
		message->payload_length = 0;
		message->source_eid = source_eid;
		message->source_addr = source_addr;
		message->target_eid = target_eid;
		message->is_encrypted = false;
		message->crypto_timeout = false;
		message->channel_id = channel_id;
	}
}

/**
 * Add new payload data to the message buffer.  The new data will be appended to the existing
 * payload location.
 *
 * The data will be copied and the message length updated.  There are no length checks performed
 * before the copy, so the caller must ensure there is sufficient space in the message buffer for
 * the additional payload data.
 *
 * @param message The message to update.
 * @param data The payload data to copy into the message buffer.
 * @param length Length of the payload data.
 */
void cmd_interface_msg_add_payload_data (struct cmd_interface_msg *message, const uint8_t *data,
	size_t length)
{
	if ((message == NULL) || (data == NULL) || (length == 0)) {
		return;
	}

	memcpy (&message->payload[message->payload_length], data, length);
	message->length += length;
	message->payload_length += length;
}

/**
 * Set the length of a message payload without any additional protocol headers.  Protocol headers
 * will need to be added using {@link cmd_interface_msg_add_protocol_header}.
 *
 * The length provided is not validated in any way.  The caller must ensure the length is valid for
 * the data in the message buffer.
 *
 * @param message The message to update.
 * @param length Length of the message.
 */
void cmd_interface_msg_set_message_payload_length (struct cmd_interface_msg *message, size_t length)
{
	if (message != NULL) {
		message->length = length;
		message->payload_length = length;
	}
}

/**
 * Update the message payload to remove a layer of protocol headers.  The message structure must
 * have been properly initialized with {@link cmd_interface_msg_new_message} and have message data
 * in the buffer before making this call.
 *
 * @param message The message to update.
 * @param header_length Size of the protocol header.
 */
void cmd_interface_msg_remove_protocol_header (struct cmd_interface_msg *message,
	size_t header_length)
{
	if (message != NULL) {
		if (header_length > message->payload_length) {
			header_length = message->payload_length;
		}

		message->payload += header_length;
		message->payload_length -= header_length;
	}
}

/**
 * Update the message payload to add a layer of protocol headers.  The message structure must have
 * been properly initialized with {@link cmd_interface_msg_new_message}.
 *
 * When adding protocol headers, both the payload and overall data lengths will be increased, unless
 * these lengths are different from each other.
 *
 * @param message The message to update.
 * @param header_length Size of the protocol header.
 */
void cmd_interface_msg_add_protocol_header (struct cmd_interface_msg *message, size_t header_length)
{
	size_t hdr_space;

	if (message != NULL) {
		hdr_space = message->payload - message->data;
		if (hdr_space < header_length) {
			header_length = hdr_space;
		}

		message->payload -= header_length;

		/* If both lengths are the same, keep them in sync with each other.  If they start off
		 * different, don't update the raw message length. */
		if (message->length == message->payload_length) {
			message->length += header_length;
		}
		message->payload_length += header_length;
	}
}

/**
 * Determine the length of protocol header data added to the message.
 *
 * @param message The message to query.
 *
 * @return Length of the protocol header on the message data.
 */
size_t cmd_interface_msg_get_protocol_length (const struct cmd_interface_msg *message)
{
	if (message == NULL) {
		return 0;
	}

	if (message->payload < message->data) {
		return 0;
	}

	return (message->payload - message->data);
}

/**
 * Determine the maximum data length allowed for response messages when building the response in the
 * message payload buffer.  This will be the maximum message payload length, excluding protocol
 * headers.
 *
 * @param message The message to query.
 *
 * @return Maximum allowed length of payload response data.
 */
size_t cmd_interface_msg_get_max_response (const struct cmd_interface_msg *message)
{
	size_t length;

	if (message == NULL) {
		return 0;
	}

	length = cmd_interface_msg_get_protocol_length (message);
	if (message->max_response >= length) {
		length = message->max_response - length;
	}
	else {
		/* This should never happen.  This condition represents an improperly constructed message
		 * descriptor, since there should always at least be room for the protocol headers in the
		 * response message. */
		length = 0;
	}

	return length;
}

/**
 * Set the maximum data length allowed for responses messages that can be constructed in the message
 * payload buffer.
 *
 * This will only reduce the maximum response length for the message.  If the current maximum
 * response length is less than the requested setting, the length will not be changed.
 *
 * @param message The message to update.
 * @param max_response The maximum message response payload to set.  This value represents the
 * maximum payload that can be added, so it must exclude the length of any protocol headers
 * preceding the payload data in the message buffer.
 */
void cmd_interface_msg_set_max_response (struct cmd_interface_msg *message, size_t max_response)
{
	if (message != NULL) {
		max_response += cmd_interface_msg_get_protocol_length (message);
		if (max_response < message->max_response) {
			message->max_response = max_response;
		}
	}
}

#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
/**
 * Determine if received request is encrypted from header.
 *
 * @param intf The command interface that will process the request.
 * @param request The request being processed.
 *
 * @return 0 if the request is not encrypted, 1 if request is encrypted or an error code.
 */
static int cmd_interface_is_request_encrypted (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_header *header;

	if ((intf == NULL) || (request == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	header = (struct cerberus_protocol_header*) request->data;

	if ((request->length < CERBERUS_PROTOCOL_MIN_MSG_LEN) ||
		(header->msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF) ||
		(header->pci_vendor_id != CERBERUS_PROTOCOL_MSFT_PCI_VID)) {
		return 0;
	}

	return header->crypt;
}
#endif

/**
 * Pre-process received Cerberus protocol message.
 *
 * TODO:  Deprecate use of this function and remove it.  Use the cmd_interface_protocol handlers
 * for processing Cerberus messages instead.
 *
 * @param intf The command interface that will process the message.
 * @param message The message being processed.
 * @param command_id Pointer to hold command ID of incoming message.
 * @param command_set Pointer to hold command set of incoming message.
 * @param decrypt Flag indicating whether to decrypt incoming message if encrypted.
 * @param rsvd_zero Flag indicating if the reserved bits must be set to zero.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
int cmd_interface_process_cerberus_protocol_message (const struct cmd_interface *intf,
	struct cmd_interface_msg *message, uint8_t *command_id, uint8_t *command_set, bool decrypt,
	bool rsvd_zero)
{
	struct cerberus_protocol_header *header;

	if (message == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	message->crypto_timeout = false;

	if ((intf == NULL) || (command_id == NULL) || (command_set == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	message->is_encrypted = false;

	header = (struct cerberus_protocol_header*) message->data;

	if (message->length < CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_PAYLOAD_TOO_SHORT;
	}

	if ((header->msg_type != (MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF)) ||
		(header->integrity_check == 1) ||
		(header->pci_vendor_id != CERBERUS_PROTOCOL_MSFT_PCI_VID)) {
		return CMD_HANDLER_UNSUPPORTED_MSG;
	}

	if (rsvd_zero) {
		if ((header->reserved1 != 0) || (header->reserved2 != 0)) {
			return CMD_HANDLER_RSVD_NOT_ZERO;
		}
	}

	*command_id = header->command;
	*command_set = header->rq;

	if (header->crypt && decrypt) {
#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
		if (intf->session) {
			int status = intf->session->decrypt_message (intf->session, message);

			if (status != 0) {
				return status;
			}

			*command_id = header->command;
			message->max_response -= SESSION_MANAGER_TRAILER_LEN;
			message->is_encrypted = true;
		}
		else
#endif
		{
			return CMD_HANDLER_ENCRYPTION_UNSUPPORTED;
		}
	}

	return 0;
}

/**
 * Process generated response.
 *
 * TODO:  Deprecate use of this function and remove it.  Use the cmd_interface_protocol handlers
 * for processing Cerberus messages instead.
 *
 * @param intf The command interface that will process the response.
 * @param response The response being processed.
 *
 * @return 0 if the response was successfully processed or an error code.
 */
int cmd_interface_prepare_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	int status = 0;

	if ((response == NULL) || (intf == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
	if (response->is_encrypted) {
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
	}
#endif

	return status;
}
