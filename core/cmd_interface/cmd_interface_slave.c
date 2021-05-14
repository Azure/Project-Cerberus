// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "cmd_interface.h"
#include "cerberus_protocol.h"
#include "cerberus_protocol_required_commands.h"
#include "cmd_interface_slave.h"


static int cmd_interface_slave_process_request (struct cmd_interface *intf,
	struct cmd_interface_request *request)
{
	struct cmd_interface_slave *interface = (struct cmd_interface_slave*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int device_num;
	int status;

	status = cmd_interface_process_request (&interface->base, request, &command_id, &command_set,
		true, true);
	if (status == CMD_HANDLER_ERROR_MESSAGE) {
		return CMD_HANDLER_UNKNOWN_COMMAND;
	}
	if (status != 0) {
		return status;
	}

	device_num = device_manager_get_device_num (interface->device_manager, request->source_eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	switch (command_id) {
		case CERBERUS_PROTOCOL_GET_FW_VERSION:
			status = cerberus_protocol_get_fw_version (interface->fw_version, request);
			break;

		case CERBERUS_PROTOCOL_GET_DIGEST:
			status = cerberus_protocol_get_certificate_digest (interface->slave_attestation,
				interface->base.session, request);
			break;

		case CERBERUS_PROTOCOL_GET_CERTIFICATE:
			status = cerberus_protocol_get_certificate (interface->slave_attestation, request);
			break;

		case CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE:
			status = cerberus_protocol_get_challenge_response (interface->slave_attestation,
				interface->base.session, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES:
			status = cerberus_protocol_get_device_capabilities (interface->device_manager,
				request, device_num);
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

		case CERBERUS_PROTOCOL_GET_DEVICE_ID:
			status = cerberus_protocol_get_device_id (&interface->device_id, request);
			break;

		case CERBERUS_PROTOCOL_RESET_COUNTER:
			status = cerberus_protocol_reset_counter (interface->cmd_device, request);
			break;

		case CERBERUS_PROTOCOL_EXCHANGE_KEYS:
			status = cerberus_protocol_key_exchange (interface->base.session, request,
				intf->curr_txn_encrypted);
			break;

		case CERBERUS_PROTOCOL_SESSION_SYNC:
			status = cerberus_protocol_session_sync (interface->base.session, request,
				intf->curr_txn_encrypted);
			break;

		default:
			return CMD_HANDLER_UNKNOWN_COMMAND;
	}

	if (status == 0) {
		status = cmd_interface_process_response (&interface->base, request);
	}

	return status;
}

int cmd_interface_slave_issue_request (struct cmd_interface *intf, uint8_t command_id,
	void *request_params, uint8_t *buf, size_t buf_len)
{
	return CMD_HANDLER_UNSUPPORTED_OPERATION;
}

/**
 * Initialize System command interface instance
 *
 * @param intf The System command interface instance to initialize
 * @param slave_attestation Slave attestation manager
 * @param device_manager Device manager
 * @param background Context for executing long-running operations in the background.
 * @param fw_version The FW version strings
 * @param riot RIoT keys manager
 * @param cmd_device Device command handler instance
 * @param vendor_id Device vendor ID
 * @param device_id Device ID
 * @param subsystem_vid Subsystem vendor ID
 * @param subsystem_id Subsystem ID
 * @param session Session manager for channel encryption
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_slave_init (struct cmd_interface_slave *intf,
	struct attestation_slave *slave_attestation, struct device_manager *device_manager,
	struct cmd_background *background, struct cmd_interface_fw_version *fw_version,
	struct riot_key_manager *riot, struct cmd_device *cmd_device, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager *session)
{
	if ((intf == NULL) || (background == NULL) || (riot == NULL) || (slave_attestation == NULL) ||
		(device_manager == NULL) || (fw_version == NULL) || (cmd_device == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_slave));

	intf->riot = riot;
	intf->background = background;
	intf->slave_attestation = slave_attestation;
	intf->device_manager = device_manager;
	intf->fw_version = fw_version;
	intf->cmd_device = cmd_device;

	intf->device_id.vendor_id = vendor_id;
	intf->device_id.device_id = device_id;
	intf->device_id.subsystem_vid = subsystem_vid;
	intf->device_id.subsystem_id = subsystem_id;

	intf->base.process_request = cmd_interface_slave_process_request;
	intf->base.issue_request = cmd_interface_slave_issue_request;
	intf->base.generate_error_packet = cmd_interface_generate_error_packet;

#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
	intf->base.session = session;
#endif

	return 0;
}

/**
 * Deinitialize slave system command interface instance
 *
 * @param intf The slave system command interface instance to deinitialize
 */
void cmd_interface_slave_deinit (struct cmd_interface_slave *intf)
{
	if (intf != NULL) {
		memset (intf, 0, sizeof (struct cmd_interface_slave));
	}
}
