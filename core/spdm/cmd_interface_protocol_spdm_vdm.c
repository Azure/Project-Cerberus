// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface_protocol_spdm_vdm.h"
#include "spdm_commands.h"
#include "common/unused.h"


int cmd_interface_protocol_spdm_vdm_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type)
{
	struct spdm_protocol_vdm_header *header;

	if ((protocol == NULL) || (message == NULL) || (message_type == NULL)) {
		return SPDM_VDM_PROTOCOL_INVALID_ARGUMENT;
	}

	if (message->payload_length < sizeof (header)) {
		return SPDM_VDM_PROTOCOL_MSG_TOO_SHORT;
	}

	header = (struct spdm_protocol_vdm_header*) message->payload;
	*message_type = buffer_unaligned_read16 (&header->standard_id);
	cmd_interface_msg_remove_protocol_header (message, sizeof (*header));

	return 0;
}

int cmd_interface_protocol_spdm_vdm_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	UNUSED (message_type);

	if ((protocol == NULL) || (message == NULL)) {
		return SPDM_VDM_PROTOCOL_INVALID_ARGUMENT;
	}

	if (cmd_interface_msg_get_protocol_length (message) <
		sizeof (struct spdm_protocol_vdm_header)) {
		return SPDM_VDM_PROTOCOL_INVALID_RESPONSE;
	}

	cmd_interface_msg_add_protocol_header (message, sizeof (struct spdm_protocol_vdm_header));

	return result;
}

/**
 * Initialize a protocol handler for SPDM VDM messages.
 *
 * @param spdm_vdm The SPDM VDM protocol handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_spdm_vdm_init (struct cmd_interface_protocol_spdm_vdm *spdm_vdm)
{
	if (spdm_vdm == NULL) {
		return SPDM_VDM_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (spdm_vdm, 0, sizeof (*spdm_vdm));

	spdm_vdm->base.parse_message = cmd_interface_protocol_spdm_vdm_parse_message;
	spdm_vdm->base.handle_request_result = cmd_interface_protocol_spdm_vdm_handle_request_result;

	return 0;
}

/**
 * Release the resources used by an MCTP message protocol handler.
 *
 * @param mctp The MCTP handler to release.
 */
void cmd_interface_protocol_spdm_vdm_release (
	const struct cmd_interface_protocol_spdm_vdm *spdm_vdm)
{
	UNUSED (spdm_vdm);
}
