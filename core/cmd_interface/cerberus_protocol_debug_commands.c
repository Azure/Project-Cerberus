// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cerberus_protocol_debug_commands.h"


#ifdef CMD_SUPPORT_DEBUG_COMMANDS
/**
 * Process log fill request
 *
 * @param background Command background instance to utilize
 * @param request Log fill request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_debug_fill_log (struct cmd_background *background,
	struct cmd_interface_msg *request)
{
	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;

	return background->debug_log_fill (background);
}

/**
 * Process get attestation state request
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Attestation state request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_attestation_state (struct device_manager *device_mgr,
	struct cmd_interface_msg *request)
{
	uint8_t device_num;
	int status;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	device_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	status = device_manager_get_device_state (device_mgr, device_num);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = (uint8_t) status;
	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint8_t);
	return 0;
}
#endif
