// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_spdm.h"
#include "spdm_commands.h"
#include "spdm_protocol.h"
#include "cmd_interface/cmd_logging.h"
#include "common/unused.h"
#include "logging/debug_log.h"


static int cmd_interface_spdm_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	UNUSED (intf);
	UNUSED (request);

	return CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION;
}

/**
 * Initialize SPDM command interface instance
 *
 * @param intf The SPDM command interface instance to initialize
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_spdm_init (struct cmd_interface_spdm *intf)
{
	int status;

	if (intf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_spdm));

	status = observable_init (&intf->observable);
	if (status != 0) {
		return status;
	}

	intf->base.process_request = cmd_interface_spdm_process_request;

	return 0;
}

/**
 * Deinitialize SPDM command interface instance
 *
 * @param intf The SPDM command interface instance to deinitialize
 */
void cmd_interface_spdm_deinit (struct cmd_interface_spdm *intf)
{
	if (intf != NULL) {
		observable_release (&intf->observable);
	}
}
