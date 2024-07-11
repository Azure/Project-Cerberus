// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface_protocol_spdm_pcisig.h"
#include "spdm_protocol_pcisig.h"
#include "common/buffer_util.h"
#include "common/unused.h"


int cmd_interface_protocol_spdm_pcisig_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type)
{
	struct spdm_protocol_pcisig_header header;

	if ((protocol == NULL) || (message == NULL) || (message_type == NULL)) {
		return SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT;
	}

	if (message->payload_length < sizeof (header)) {
		return SPDM_PCISIG_PROTOCOL_MSG_TOO_SHORT;
	}

	/* to avoid unaligned access */
	memcpy (&header, message->payload, sizeof (header));

	if ((header.vendor_id_len != sizeof (uint16_t)) ||
		(header.vendor_id != SPDM_PCISIG_VENDOR_ID)) {
		return SPDM_PCISIG_PROTOCOL_INVALID_HEADER;
	}

	*message_type = header.protocol_id;
	cmd_interface_msg_remove_protocol_header (message, sizeof (header));

	return 0;
}

int cmd_interface_protocol_spdm_pcisig_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	struct spdm_protocol_pcisig_header *header_ptr = 0;
	uint32_t payload_length;

	UNUSED (message_type);

	if ((protocol == NULL) || (message == NULL)) {
		return SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT;
	}

	payload_length = message->payload_length;

	if (cmd_interface_msg_get_protocol_length (message) < sizeof (*header_ptr)) {
		return SPDM_PCISIG_PROTOCOL_INVALID_RESPONSE;
	}

	cmd_interface_msg_add_protocol_header (message, sizeof (*header_ptr));

	if (result == 0) {
		header_ptr = (struct spdm_protocol_pcisig_header*) message->payload;

		/* account for protocol_id as it should be part of response */
		buffer_unaligned_write16 (&header_ptr->payload_length, payload_length + sizeof (uint8_t));
	}

	return result;
}

/**
 * Initialize a protocol handler for SPDM PCISIG messages.
 *
 * @param spdm_pcisig The SPDM PCISIG protocol handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_spdm_pcisig_init (struct cmd_interface_protocol_spdm_pcisig *spdm_pcisig)
{
	if (spdm_pcisig == NULL) {
		return SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (spdm_pcisig, 0, sizeof (*spdm_pcisig));

	spdm_pcisig->base.parse_message = cmd_interface_protocol_spdm_pcisig_parse_message;
	spdm_pcisig->base.handle_request_result =
		cmd_interface_protocol_spdm_pcisig_handle_request_result;

	return 0;
}

/**
 * Release the resources used by an SPDM PCISIG message protocol handler.
 *
 * @param spdm_pcisig The SPDM PCISIG handler to release.
 */
void cmd_interface_protocol_spdm_pcisig_release (
	const struct cmd_interface_protocol_spdm_pcisig *spdm_pcisig)
{
	UNUSED (spdm_pcisig);
}
