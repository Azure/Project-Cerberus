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
#include "common/type_cast.h"
#include "common/unused.h"


int cmd_interface_recovery_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_recovery *interface =
		TO_DERIVED_TYPE (intf, const struct cmd_interface_recovery, base);
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (intf, request, &command_id,
		&command_set, true, true);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case CERBERUS_PROTOCOL_GET_FW_VERSION:
			status = cerberus_protocol_get_fw_version (interface->fw_version, request);
			break;

		case CERBERUS_PROTOCOL_GET_DIGEST:
			status = cerberus_protocol_get_certificate_digest (interface->attestation, NULL,
				request);
			break;

		case CERBERUS_PROTOCOL_GET_CERTIFICATE:
			status = cerberus_protocol_get_certificate (interface->attestation, request);
			break;

		case CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE:
			status = cerberus_protocol_get_challenge_response (interface->attestation, NULL,
				request);
			break;

		case CERBERUS_PROTOCOL_EXPORT_CSR:
			status = cerberus_protocol_export_csr (interface->riot, request);
			break;

		case CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT:
			status = cerberus_protocol_import_ca_signed_cert (interface->riot,
				interface->background, request);
			break;

		case CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE:
			status = cerberus_protocol_get_signed_cert_state (interface->background, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_INFO:
			status = cerberus_protocol_get_device_info (interface->cmd_device, request);
			break;

		case CERBERUS_PROTOCOL_RESET_COUNTER:
			status = cerberus_protocol_reset_counter (interface->cmd_device, request);
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

		case CERBERUS_PROTOCOL_GET_DEVICE_ID:
			status = cerberus_protocol_get_device_id (&interface->device_id, request);
			break;

#ifdef CMD_ENABLE_STACK_STATS
		case CERBERUS_PROTOCOL_DIAG_STACK_USAGE:
			status = cerberus_protocol_stack_stats (interface->cmd_device, request);
			break;
#endif

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
 * @param attestation Handler for attestation requests.
 * @param control The FW update control instance to use.
 * @param device_manager Manager for known devices.
 * @param background Context for executing long-running operations in the background.
 * @param riot Manager for device identity keys.
 * @param fw_version The FW version strings reported by the device.
 * @param vendor_id Device vendor identifier for the platform.
 * @param device_id Device identifier for the platform.
 * @param subsystem_vid Subsystem vendor identifier for the platform.
 * @param subsystem_id Subsystem identifier for the platform.
 * @param cmd_device Handler for commands that depend on platform details.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_recovery_init (struct cmd_interface_recovery *intf,
	struct attestation_responder *attestation, const struct firmware_update_control *control,
	struct device_manager *device_manager, const struct cmd_background *background,
	const struct riot_key_manager *riot, const struct cmd_interface_fw_version *fw_version,
	uint16_t vendor_id, uint16_t device_id,	uint16_t subsystem_vid,	uint16_t subsystem_id,
	const struct cmd_device *cmd_device)
{
	if ((intf == NULL) || (control == NULL) || (device_manager == NULL) || (fw_version == NULL) ||
		(attestation == NULL) || (riot == NULL) || (background == NULL) || (cmd_device == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_recovery));

	intf->control = control;
	intf->device_manager = device_manager;
	intf->fw_version = fw_version;
	intf->riot = riot;
	intf->background = background;
	intf->attestation = attestation;
	intf->cmd_device = cmd_device;

	intf->device_id.vendor_id = vendor_id;
	intf->device_id.device_id = device_id;
	intf->device_id.subsystem_vid = subsystem_vid;
	intf->device_id.subsystem_id = subsystem_id;

	intf->base.process_request = cmd_interface_recovery_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_recovery_process_response;
#endif

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
