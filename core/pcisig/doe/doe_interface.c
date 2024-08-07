// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "doe_interface.h"
#include "common/array_size.h"
#include "common/unused.h"


/**
 * DOE interface initialization
 *
 * @param doe The DOE interface to initialize.
 * @param cmd_spdm_responder The command interface to use for processing and generating
 * SPDM protocol messages.
 * @param data_object_protocol The supported DOE data object protocol(s).
 * @param data_object_protocol_count The number of supported data object protocols.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int doe_interface_init (struct doe_interface *doe, struct cmd_interface *cmd_spdm_responder,
	const struct doe_data_object_protocol *data_object_protocol, uint8_t data_object_protocol_count)
{
	int status = 0;

	if ((doe == NULL) || (cmd_spdm_responder == NULL) || (data_object_protocol == NULL) ||
		(data_object_protocol_count == 0) ||
		(data_object_protocol[0].vendor_id != DOE_VENDOR_ID_PCISIG) ||
		(data_object_protocol[0].data_object_type != DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY)) {
		status = DOE_INTERFACE_INVALID_ARGUMENT;
		goto exit;
	}

	memset (doe, 0, sizeof (struct doe_interface));

	doe->cmd_spdm_responder = cmd_spdm_responder;
	doe->data_object_protocol = data_object_protocol;
	doe->data_object_protocol_count = data_object_protocol_count;

exit:

	return status;
}

/**
 * Deinitialize the DOE interface
 *
 * @param doe The DOE interface to deinitialize.
 */
void doe_interface_release (const struct doe_interface *doe)
{
	UNUSED (doe);
}

/**
 * Encode a DOE message.
 *
 * @param doe_message A message to encode.
 * @param message_size The size of the message to encode.
 *
 * @return 0 if the message was successfully encoded or an error code.
 */
static int doe_interface_encode_message (struct doe_cmd_message *doe_message, size_t message_size)
{
	int status = 0;
	struct doe_base_protocol_transport_header *doe_header;
	size_t aligned_message_size;
	size_t transport_message_size;

	/* Align the message to a dword boundary. */
	aligned_message_size = (message_size + (DOE_ALIGNMENT - 1)) & ~(DOE_ALIGNMENT - 1);
	transport_message_size =
		aligned_message_size + sizeof (struct doe_base_protocol_transport_header);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message->message;

	if (transport_message_size > DOE_MESSAGE_MAX_SIZE_IN_BYTES) {
		status = DOE_INTERFACE_INVALID_MSG_SIZE;
		goto exit;
	}
	else if (transport_message_size == DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES) {
		doe_header->length = DOE_MESSAGE_MAX_SIZE_INDICATOR;
	}
	else {
		doe_header->length = (transport_message_size / sizeof (uint32_t));
	}
	doe_header->reserved = 0;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;

exit:

	return status;
}

/**
 * Process a DOE Discovery Request message.
 *
 * @param doe_interface The DOE interface to use for processing the message.
 * @param data_obj_message The DOE message to process.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
static int doe_interface_process_doe_discovery_request (const struct doe_interface *doe_interface,
	struct cmd_interface_msg *data_obj_message)
{
	int status = 0;
	uint8_t index;
	struct doe_base_protocol_discovery_response *discovery_response;

	index = ((struct doe_base_protocol_discovery_request*) data_obj_message->payload)->index;
	discovery_response = (struct doe_base_protocol_discovery_response*) data_obj_message->payload;

	if (index >= doe_interface->data_object_protocol_count) {
		status = DOE_INTERFACE_INVALID_DISCOVERY_INDEX;
		goto exit;
	}

	discovery_response->vendor_id = doe_interface->data_object_protocol[index].vendor_id;
	discovery_response->data_object_protocol =
		doe_interface->data_object_protocol[index].data_object_type;

	/* For the last data object protocol, the next_index is 0. */
	discovery_response->next_index =
		(index == (doe_interface->data_object_protocol_count - 1)) ? 0 : (index + 1);

	cmd_interface_msg_set_message_payload_length (data_obj_message,
		sizeof (struct doe_base_protocol_discovery_response));

exit:

	return status;
}

/**
 * Initialize a DOE command interface message.
 *
 * @param data_obj_message A cmd interface message to initialize.
 * @param doe_message_size The size of the DOE message in bytes.
 * @param doe_message A DOE message to initialize from.
 */
static void doe_interface_msg_init (struct cmd_interface_msg *data_obj_message,
	size_t doe_message_size, struct doe_cmd_message *doe_message)
{
	/* Initialize the data object message. */
	data_obj_message->data = doe_message->message;
	data_obj_message->payload = doe_message->message;
	data_obj_message->length = doe_message_size;
	data_obj_message->payload_length = doe_message_size;
	data_obj_message->max_response = ARRAY_SIZE (doe_message->message);

	/* Move the payload ptr. past the DOE transport header. Also update the payload length. */
	cmd_interface_msg_remove_protocol_header (data_obj_message,
		sizeof (struct doe_base_protocol_transport_header));
}

/**
 * Decode a DOE message.
 *
 * @param doe_message A DOE message to decode.
 * @param data_obj_message Decoded message.
 *
 * @return 0 if the doe_message was successfully decoded or an error code.
 */
static int doe_interface_decode_message (struct doe_cmd_message *doe_message,
	struct cmd_interface_msg *data_obj_message)
{
	int status = 0;
	const struct doe_base_protocol_transport_header *doe_header;
	size_t doe_message_size;

	doe_header = (struct doe_base_protocol_transport_header*) doe_message->message;
	if (doe_header->length != 0) {
		if ((doe_header->length < DOE_MESSAGE_MIN_SIZE_IN_DWORDS) ||
			(doe_header->length >= DOE_MESSAGE_SPEC_MAX_SIZE_IN_DWORDS)) {
			status = DOE_INTERFACE_INVALID_MSG_SIZE;
			goto exit;
		}
		doe_message_size = (doe_header->length * sizeof (uint32_t));
	}
	else {
		doe_message_size = DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES;
	}

	/* [TODO] This needs to be tested by configuring the DOE_MESSAGE_MAX_SIZE_IN_BYTES
	 * to a value less than DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES and creating a message
	 * that is larger than DOE_MESSAGE_MAX_SIZE_IN_BYTES. */
	if (doe_message_size > ARRAY_SIZE (doe_message->message)) {
		status = DOE_INTERFACE_INVALID_MSG_SIZE;
		goto exit;
	}

	if (doe_header->vendor_id != DOE_VENDOR_ID_PCISIG) {
		status = DOE_INTERFACE_INVALID_VENDOR_ID;
		goto exit;
	}

	memset (data_obj_message, 0, sizeof (struct cmd_interface_msg));

	switch (doe_header->data_object_type) {
		case DOE_DATA_OBJECT_TYPE_SECURED_SPDM:
			if (doe_message_size <=
				(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t))) {
				status = DOE_INTERFACE_INVALID_MSG_SIZE;
				goto exit;
			}
			data_obj_message->is_encrypted = true;
			break;

		case DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY:
		case DOE_DATA_OBJECT_TYPE_SPDM:
			data_obj_message->is_encrypted = false;
			break;

		default:
			break;
	}

	/* Initialize the data object message. */
	doe_interface_msg_init (data_obj_message, doe_message_size, doe_message);

exit:

	return status;
}

/**
 * DOE message processor.
 *
 * @param doe The DOE interface.
 * @param doe_message The DOE message to process.
 *
 * @return 0 if success or an error code.
 */
int doe_interface_process_message (const struct doe_interface *doe,
	struct doe_cmd_message *doe_message)
{
	int status = 0;
	struct cmd_interface_msg data_obj_message;
	uint8_t data_object_type;

	if ((doe == NULL) || (doe_message == NULL)) {
		status = DOE_INTERFACE_INVALID_ARGUMENT;
		goto exit;
	}

	status = doe_interface_decode_message (doe_message, &data_obj_message);
	if (status != 0) {
		goto exit;
	}

	data_object_type = DOE_DATA_OBJECT_TYPE (doe_message->message);
	switch (data_object_type) {
		case DOE_DATA_OBJECT_TYPE_SPDM:
		case DOE_DATA_OBJECT_TYPE_SECURED_SPDM:
			status = doe->cmd_spdm_responder->process_request (doe->cmd_spdm_responder,
				&data_obj_message);
			break;

		case DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY:
			status = doe_interface_process_doe_discovery_request (doe, &data_obj_message);
			break;

		default:
			status = DOE_INTERFACE_UNSUPPORTED_DATA_OBJECT_TYPE;
			break;
	}
	if (status != 0) {
		goto exit;
	}

	status = doe_interface_encode_message (doe_message, data_obj_message.payload_length);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}
