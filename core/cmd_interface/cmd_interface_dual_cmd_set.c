// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface.h"
#include "cmd_interface_dual_cmd_set.h"
#include "common/unused.h"


int cmd_interface_dual_cmd_set_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_dual_cmd_set *interface =
		(const struct cmd_interface_dual_cmd_set*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (intf, request, &command_id,
		&command_set, false, false);
	if (status != 0) {
		return status;
	}

	if (command_set == 0) {
		return interface->intf_0->process_request (interface->intf_0, request);
	}
	else {
		return interface->intf_1->process_request (interface->intf_1, request);
	}
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_dual_cmd_set_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	const struct cmd_interface_dual_cmd_set *interface =
		(const struct cmd_interface_dual_cmd_set*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (intf, response, &command_id,
		&command_set, false, false);
	if (status != 0) {
		return status;
	}

	if (command_set == 0) {
		return interface->intf_0->process_response (interface->intf_0, response);
	}
	else {
		return interface->intf_1->process_response (interface->intf_1, response);
	}
}
#endif

/**
 * Initialize a command interface instance with two command sets supported. Requests from each
 * command set get routed to the appropiate command interface. Issuing requests from this interface
 * defaults to the first command set.
 *
 * @param intf The dual command set interface instance to initialize
 * @param intf_0 The command interface to utilize for command set 0
 * @param intf_1 The command interface to utilize for command set 1
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_dual_cmd_set_init (struct cmd_interface_dual_cmd_set *intf,
	const struct cmd_interface *intf_0, const struct cmd_interface *intf_1)
{
	if ((intf == 0)	|| (intf_0 == NULL) || (intf_1 == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_dual_cmd_set));

	intf->intf_0 = intf_0;
	intf->intf_1 = intf_1;

	intf->base.process_request = cmd_interface_dual_cmd_set_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_dual_cmd_set_process_response;
#endif

	return 0;
}

/**
 * Deinitialize command interface instance
 *
 * @param intf The dual command set command interface instance to deinitialize
 */
void cmd_interface_dual_cmd_set_deinit (const struct cmd_interface_dual_cmd_set *intf)
{
	UNUSED (intf);
}
