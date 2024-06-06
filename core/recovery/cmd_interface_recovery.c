// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_recovery.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_debug_commands.h"
#include "cmd_interface/cerberus_protocol_diagnostic_commands.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_logging.h"
#include "common/unused.h"


int cmd_interface_recovery_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_recovery *interface = (const struct cmd_interface_recovery*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (&interface->base, request,
		&command_id, &command_set, true, true);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case CERBERUS_PROTOCOL_GET_FW_VERSION:
			status = cerberus_protocol_get_fw_version (interface->fw_version, request);
			break;

		case CERBERUS_PROTOCOL_GET_LOG_INFO:
			status = cerberus_protocol_get_log_info (NULL, request);
			break;

		case CERBERUS_PROTOCOL_READ_LOG:
			status = cerberus_protocol_log_read (NULL, NULL, request);
			break;

		case CERBERUS_PROTOCOL_INIT_FW_UPDATE:
			status = cerberus_protocol_fw_update_init (interface->control, request);
			break;

		case CERBERUS_PROTOCOL_FW_UPDATE:
			status = cerberus_protocol_fw_update (interface->control, request);
			break;

		case CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE:
			status = cerberus_protocol_fw_update_start (interface->control, request);
			break;

		case CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS:
			status = cerberus_protocol_get_extended_update_status (interface->control, NULL, NULL,
				NULL, NULL, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES:
			status = cerberus_protocol_get_device_capabilities (interface->device_manager, request);
			break;

		default:
			return CMD_HANDLER_UNKNOWN_REQUEST;
	}

	if (status == 0) {
		status = cmd_interface_prepare_response (&interface->base, request);
	}

	return status;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_recovery_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	if ((intf == NULL) || (response == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	return CMD_HANDLER_UNSUPPORTED_OPERATION;
}
#endif

/**
 * Initialize Recovery command interface instance
 *
 * @param intf The Recovery command interface instance to initialize
 * @param control The FW update control instance to use
 * @param device_manager Device manager
 * @param store PCR storage
 * @param hash Hash engine to to use for PCR operations
 * @param fw_version The FW version strings
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_recovery_init (struct cmd_interface_recovery *intf,
	const struct firmware_update_control *control, struct device_manager *device_manager,
	const struct cmd_interface_fw_version *fw_version)
{
	if ((intf == NULL) || (control == NULL) || (device_manager == NULL) || (fw_version == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_recovery));

	intf->control = control;
	intf->device_manager = device_manager;
	intf->fw_version = fw_version;

	intf->base.process_request = cmd_interface_recovery_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_recovery_process_response;
#endif
	intf->base.generate_error_packet = cmd_interface_generate_error_packet;

	return 0;
}

/**
 * Deinitialize Recovery command interface instance
 *
 * @param intf The Recovery command interface instance to deinitialize
 */
void cmd_interface_recovery_deinit (const struct cmd_interface_recovery *intf)
{
	UNUSED (intf);
}
