// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cerberus_protocol.h"
#include "cerberus_protocol_required_commands.h"
#include "cmd_interface_ac_rot.h"
#include "common/unused.h"


int cmd_interface_ac_rot_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_ac_rot *ac_rot = (const struct cmd_interface_ac_rot*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (&ac_rot->base, request, &command_id,
		&command_set, true, true);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case CERBERUS_PROTOCOL_GET_FW_VERSION:
			status = cerberus_protocol_get_fw_version (ac_rot->fw_version, request);
			break;

		case CERBERUS_PROTOCOL_GET_DIGEST:
			status = cerberus_protocol_get_certificate_digest (ac_rot->attestation,
				ac_rot->base.session, request);
			break;

		case CERBERUS_PROTOCOL_GET_CERTIFICATE:
			status = cerberus_protocol_get_certificate (ac_rot->attestation, request);
			break;

		case CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE:
			status = cerberus_protocol_get_challenge_response (ac_rot->attestation,
				ac_rot->base.session, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES:
			status = cerberus_protocol_get_device_capabilities (ac_rot->device_manager,	request);
			break;

		case CERBERUS_PROTOCOL_EXPORT_CSR:
			status = cerberus_protocol_export_csr (ac_rot->riot, request);
			break;

		case CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT:
			status = cerberus_protocol_import_ca_signed_cert (ac_rot->riot,	ac_rot->background,
				request);
			break;

		case CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE:
			status = cerberus_protocol_get_signed_cert_state (ac_rot->background, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_INFO:
			status = cerberus_protocol_get_device_info (ac_rot->cmd_device, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_ID:
			status = cerberus_protocol_get_device_id (&ac_rot->device_id, request);
			break;

		case CERBERUS_PROTOCOL_RESET_COUNTER:
			status = cerberus_protocol_reset_counter (ac_rot->cmd_device, request);
			break;

#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
		case CERBERUS_PROTOCOL_EXCHANGE_KEYS:
			status = cerberus_protocol_key_exchange (ac_rot->base.session, request,
				request->is_encrypted);
			break;

		case CERBERUS_PROTOCOL_SESSION_SYNC:
			status = cerberus_protocol_session_sync (ac_rot->base.session, request,
				request->is_encrypted);
			break;
#endif

		default:
			return CMD_HANDLER_UNKNOWN_REQUEST;
	}

	if (status == 0) {
		status = cmd_interface_prepare_response (&ac_rot->base, request);
	}

	return status;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_ac_rot_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	return CMD_HANDLER_UNSUPPORTED_OPERATION;
}
#endif

/**
 * Initialize a minimal AC-RoT command handler.
 *
 * @param intf The handler to initialize.
 * @param attestation Handler for attestation requests.
 * @param device_manager Manager for known devices.
 * @param background Context for executing long-running operations in the background.
 * @param fw_version The FW version strings reported by the device.
 * @param riot Manager for device identity keys.
 * @param cmd_device Handler for commands that depend on platform details.
 * @param vendor_id Device vendor identifier for the platform.
 * @param device_id Device identifier for the platform.
 * @param subsystem_vid Subsystem vendor identifier for the platform.
 * @param subsystem_id Subsystem identifier for the platform.
 * @param session Optional handler for channel encryption.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_ac_rot_init (struct cmd_interface_ac_rot *intf,
	struct attestation_responder *attestation, struct device_manager *device_manager,
	const struct cmd_background *background, const struct cmd_interface_fw_version *fw_version,
	const struct riot_key_manager *riot, const struct cmd_device *cmd_device, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager *session)
{
	if ((intf == NULL) || (background == NULL) || (riot == NULL) || (attestation == NULL) ||
		(device_manager == NULL) || (fw_version == NULL) || (cmd_device == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_ac_rot));

	intf->riot = riot;
	intf->background = background;
	intf->attestation = attestation;
	intf->device_manager = device_manager;
	intf->fw_version = fw_version;
	intf->cmd_device = cmd_device;

	intf->device_id.vendor_id = vendor_id;
	intf->device_id.device_id = device_id;
	intf->device_id.subsystem_vid = subsystem_vid;
	intf->device_id.subsystem_id = subsystem_id;

	intf->base.process_request = cmd_interface_ac_rot_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_ac_rot_process_response;
#endif

#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
	intf->base.session = session;
#endif

	return 0;
}

/**
 * Deinitialize AC-RoT command handler.
 *
 * @param intf The AC-RoT command handler to deinitialize.
 */
void cmd_interface_ac_rot_deinit (const struct cmd_interface_ac_rot *intf)
{
	UNUSED (intf);
}
