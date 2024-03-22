// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface_multi_handler.h"
#include "common/unused.h"


/**
 * Find the command handler for a specified message type.
 *
 * @param handler The multi-message handler to search for the message type.
 * @param message_type Identifier for the message type that needs a handler.
 *
 * @return The command handler for the message type or null if the message type is not supported.
 */
static const struct cmd_interface* cmd_interface_multi_handler_find_message_type (
	const struct cmd_interface_multi_handler *handler, uint32_t message_type)
{
	size_t i;

	for (i = 0; i < handler->type_count; i++) {
		if (handler->msg_types[i].type_id == message_type) {
			return handler->msg_types[i].handler;
		}
	}

	return NULL;
}

int cmd_interface_multi_handler_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_multi_handler *handler =
		(const struct cmd_interface_multi_handler*) intf;
	uint32_t message_type;
	const struct cmd_interface *msg_handler = NULL;
	int status;

	if ((handler == NULL) || (request == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	status = handler->protocol->parse_message (handler->protocol, request, &message_type);
	if (status != 0) {
		/* Return success if an error response has already been generated for the request. */
		if (status == CMD_HANDLER_PROTO_ERROR_RESPONSE) {
			status = 0;
		}

		/* Since the message could not be parsed or handled here, return the error for handling at
		 * a different protocol layer. */
		return status;
	}

	msg_handler = cmd_interface_multi_handler_find_message_type (handler, message_type);
	if (msg_handler != NULL) {
		status = msg_handler->process_request (msg_handler, request);
	}
	else {
		status = CMD_HANDLER_UNKNOWN_MESSAGE_TYPE;
	}

	/* Post-processing the response is optional, based on the the requirements of the protocol. */
	if (handler->protocol->handle_request_result != NULL) {
		status = handler->protocol->handle_request_result (handler->protocol, status, message_type,
			request);
	}

	return status;
}

int cmd_interface_multi_handler_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	UNUSED (intf);
	UNUSED (response);

	/* No need to support response processing through this interface, as this functionality will
	 * likely be handled differently and removed from the command handler interface. */
	return CMD_HANDLER_UNSUPPORTED_OPERATION;
}

int cmd_interface_multi_handler_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	UNUSED (intf);
	UNUSED (request);
	UNUSED (error_code);
	UNUSED (error_data);
	UNUSED (cmd_set);

	/* TODO:  Perhaps add an API to the protocol handler to generate an error message?  But really,
	 * this API should probably be removed from the command handler interface. */
	return CMD_HANDLER_UNSUPPORTED_OPERATION;
}

int cmd_interface_multi_handler_is_message_type_supported (
	const struct cmd_interface_multi_handler *intf, uint32_t message_type)
{
	if (intf == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (cmd_interface_multi_handler_find_message_type (intf, message_type) != NULL) {
		return 0;
	}
	else {
		return CMD_HANDLER_UNKNOWN_MESSAGE_TYPE;
	}
}

/**
 * Initialize the handler descriptor for a single message type.
 *
 * @param msg_type The descriptor to initialize.
 * @param type_id Identifier for the message type.  This must match the message type output from the
 * {@link cmd_interface_protocol.parse_message} call.
 * @param handler The command handler to use for processing this type of message.
 *
 * @return 0 if the descriptor was initialized successfully or an error code.
 */
int cmd_interface_multi_handler_msg_type_init (
	struct cmd_interface_multi_handler_msg_type *msg_type, uint32_t type_id,
	const struct cmd_interface *handler)
{
	if ((msg_type == NULL) || (handler == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (msg_type, 0, sizeof (struct cmd_interface_multi_handler_msg_type));

	msg_type->type_id = type_id;
	msg_type->handler = handler;

	return 0;
}

/**
 * Initialize a command handler for a protocol that wraps multiple different types of messages
 * that have different processing requirements.
 *
 * @param intf The multi-message command handler to initialize.
 * @param protocol Handler for protocol specific details common to all message types.
 * @param msg_types A list of command handlers for the different message types that are supported.
 * @param type_count The number of supported message types in the list.
 *
 * @return 0 if the command handler was successfully initialized or an error code.
 */
int cmd_interface_multi_handler_init (struct cmd_interface_multi_handler *intf,
	const struct cmd_interface_protocol *protocol,
	const struct cmd_interface_multi_handler_msg_type *msg_types, size_t type_count)
{
	if ((intf == NULL) || (protocol == NULL) || (msg_types == NULL) || (type_count == 0)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_multi_handler));

	intf->base.process_request = cmd_interface_multi_handler_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_multi_handler_process_response;
#endif
	intf->base.generate_error_packet = cmd_interface_multi_handler_generate_error_packet;

	intf->is_message_type_supported = cmd_interface_multi_handler_is_message_type_supported;

	intf->protocol = protocol;
	intf->msg_types = msg_types;
	intf->type_count = type_count;

	return 0;
}

/**
 * Release the resources used by a multi-message type command handler.
 *
 * @param intf The command handler to release.
 */
void cmd_interface_multi_handler_release (const struct cmd_interface_multi_handler *intf)
{
	UNUSED (intf);
}
