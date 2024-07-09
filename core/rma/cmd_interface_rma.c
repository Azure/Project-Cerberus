// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_rma.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "common/unused.h"


int cmd_interface_rma_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_rma *rma = (const struct cmd_interface_rma*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (&rma->base, request, &command_id,
		&command_set, false, true);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES:
			status = cerberus_protocol_get_device_capabilities (rma->device_manager, request);
			break;

		default:
			return CMD_HANDLER_UNKNOWN_REQUEST;
	}

	return status;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_rma_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	if ((intf == NULL) || (response == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	return CMD_HANDLER_UNSUPPORTED_OPERATION;
}
#endif

/**
 * Initialize a minimal command handler to support RMA workflows.
 *
 * @param intf The command handler to initialize.
 * @param device_manager Manager for known devices.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_rma_init (struct cmd_interface_rma *intf, struct device_manager *device_manager)
{
	if ((intf == NULL) || (device_manager == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_rma));

	intf->base.process_request = cmd_interface_rma_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_rma_process_response;
#endif

	intf->device_manager = device_manager;

	return 0;
}

/**
 * Release the resources used by an RMA command handler.
 *
 * @param intf The handler to release.
 */
void cmd_interface_rma_release (const struct cmd_interface_rma *intf)
{
	UNUSED (intf);
}
