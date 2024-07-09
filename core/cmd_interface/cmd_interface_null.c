// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_null.h"
#include "common/unused.h"


int cmd_interface_null_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	if ((intf == NULL) || (request == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	/* Always indicate that the received request message is unsupported. */
	return CMD_HANDLER_UNSUPPORTED_MSG;
}

int cmd_interface_null_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	if ((intf == NULL) || (response == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	/* No processing is required for the response.  Just return success. */
	return 0;
}

/**
 * Initialize a command handler that will drop any received request/response messages while
 * providing the ability to generate valid error messages.
 *
 * @param intf The command handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_null_init (struct cmd_interface_null *intf)
{
	if (intf == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_null));

	intf->base.process_request = cmd_interface_null_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_null_process_response;
#endif

	return 0;
}

/**
 * Release the resources used by a null command handler.
 *
 * @param intf The command handler to release.
 */
void cmd_interface_null_release (const struct cmd_interface_null *intf)
{
	UNUSED (intf);
}
