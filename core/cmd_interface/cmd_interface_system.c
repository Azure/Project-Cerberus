// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "cmd_logging.h"
#include "cmd_interface.h"
#include "cerberus_protocol.h"
#include "cerberus_protocol_required_commands.h"
#include "cerberus_protocol_master_commands.h"
#include "cerberus_protocol_optional_commands.h"
#include "cerberus_protocol_debug_commands.h"
#include "cmd_interface_system.h"


int cmd_interface_system_process_request (struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct cmd_interface_system *interface = (struct cmd_interface_system*) intf;
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

		case CERBERUS_PROTOCOL_GET_LOG_INFO:
			status = cerberus_protocol_get_log_info (interface->pcr_store, request);
			break;

		case CERBERUS_PROTOCOL_READ_LOG:
			status = cerberus_protocol_log_read (interface->pcr_store, interface->hash, request);
			break;

		case CERBERUS_PROTOCOL_CLEAR_LOG:
			status = cerberus_protocol_log_clear (interface->background, request);
			break;

		case CERBERUS_PROTOCOL_GET_PFM_ID:{
			struct pfm_manager* pfm_mgr[2] = {interface->pfm_manager_0, interface->pfm_manager_1};
			status = cerberus_protocol_get_pfm_id (pfm_mgr, 2, request);
			break;
		}

		case CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW: {
			struct pfm_manager* pfm_mgr[2] = {interface->pfm_manager_0, interface->pfm_manager_1};
			status = cerberus_protocol_get_pfm_fw (pfm_mgr, 2, request);
			break;
		}

		case CERBERUS_PROTOCOL_INIT_PFM_UPDATE: {
			struct manifest_cmd_interface* pfm_cmd[2] = {interface->pfm_0, interface->pfm_1};
			status = cerberus_protocol_pfm_update_init (pfm_cmd, 2, request);
			break;
		}

		case CERBERUS_PROTOCOL_PFM_UPDATE: {
			struct manifest_cmd_interface* pfm_cmd[2] = {interface->pfm_0, interface->pfm_1};
			status = cerberus_protocol_pfm_update (pfm_cmd, 2, request);
			break;
		}

		case CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE: {
			struct manifest_cmd_interface* pfm_cmd[2] = {interface->pfm_0, interface->pfm_1};
			status = cerberus_protocol_pfm_update_complete (pfm_cmd, 2,	request);
			break;
		}

		case CERBERUS_PROTOCOL_GET_CFM_ID:
			status = cerberus_protocol_get_cfm_id (interface->cfm_manager, request);
			break;

		case CERBERUS_PROTOCOL_INIT_CFM_UPDATE:
			status = cerberus_protocol_cfm_update_init (interface->cfm, request);
			break;

		case CERBERUS_PROTOCOL_CFM_UPDATE:
			status = cerberus_protocol_cfm_update (interface->cfm, request);
			break;

		case CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE:
			status = cerberus_protocol_cfm_update_complete (interface->cfm, request);
			break;

		case CERBERUS_PROTOCOL_GET_PCD_ID:
			status = cerberus_protocol_get_pcd_id (interface->pcd_manager, request);
			break;

		case CERBERUS_PROTOCOL_INIT_PCD_UPDATE:
			status = cerberus_protocol_pcd_update_init (interface->pcd, request);
			break;

		case CERBERUS_PROTOCOL_PCD_UPDATE:
			status = cerberus_protocol_pcd_update (interface->pcd, request);
			break;

		case CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE:
			status = cerberus_protocol_pcd_update_complete (interface->pcd, request);
			break;

		case CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS:
			status = cerberus_protocol_get_cfm_component_ids (interface->cfm_manager, request);
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

		case CERBERUS_PROTOCOL_GET_UPDATE_STATUS: {
			struct manifest_cmd_interface* pfm_cmd[2] = {interface->pfm_0, interface->pfm_1};
			struct host_processor* host[2] = {interface->host_0, interface->host_1};
			status = cerberus_protocol_get_update_status (interface->control, 2, pfm_cmd,
				interface->cfm, interface->pcd, host, interface->recovery_cmd_0,
				interface->recovery_cmd_1, interface->background, request);
			break;
		}

		case CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS:
			status = cerberus_protocol_get_extended_update_status (interface->control,
				interface->recovery_manager_0, interface->recovery_manager_1,
				interface->recovery_cmd_0, interface->recovery_cmd_1, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES:
			status = cerberus_protocol_get_device_capabilities (interface->device_manager,
				request);
			break;

		case CERBERUS_PROTOCOL_RESET_COUNTER:
			status = cerberus_protocol_reset_counter (interface->cmd_device, request);
			break;

		case CERBERUS_PROTOCOL_UNSEAL_MESSAGE:
			status = cerberus_protocol_unseal_message (interface->background, request);
			break;

		case CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT:
			status = cerberus_protocol_unseal_message_result (interface->background, request);
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

		case CERBERUS_PROTOCOL_RESET_CONFIG:
			status = cerberus_protocol_reset_config (interface->auth, interface->background,
				request);
			break;

		case CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE:
			status = cerberus_protocol_prepare_recovery_image (interface->recovery_cmd_0,
				interface->recovery_cmd_1, request);
			break;

		case CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE:
			status = cerberus_protocol_update_recovery_image (interface->recovery_cmd_0,
				interface->recovery_cmd_1, request);
			break;

		case CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE:
			status = cerberus_protocol_activate_recovery_image (interface->recovery_cmd_0,
				interface->recovery_cmd_1, request);
			break;

		case CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION:
			status = cerberus_protocol_get_recovery_image_id (interface->recovery_manager_0,
				interface->recovery_manager_1, request);
			break;

		case CERBERUS_PROTOCOL_GET_HOST_STATE:
			status = cerberus_protocol_get_host_reset_status (interface->host_0_ctrl,
				interface->host_1_ctrl, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_INFO:
			status = cerberus_protocol_get_device_info (interface->cmd_device, request);
			break;

		case CERBERUS_PROTOCOL_GET_DEVICE_ID:
			status = cerberus_protocol_get_device_id (&interface->device_id, request);
			break;

		case CERBERUS_PROTOCOL_GET_ATTESTATION_DATA:
			status = cerberus_protocol_get_attestation_data (interface->pcr_store, request);
			break;

#ifdef CMD_SUPPORT_ENCRYPTED_SESSIONS
		case CERBERUS_PROTOCOL_EXCHANGE_KEYS:
			status = cerberus_protocol_key_exchange (interface->base.session, request,
				intf->curr_txn_encrypted);
			break;

		case CERBERUS_PROTOCOL_SESSION_SYNC:
			status = cerberus_protocol_session_sync (interface->base.session, request,
				intf->curr_txn_encrypted);
			break;
#endif

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
		case CERBERUS_PROTOCOL_DEBUG_GET_ATTESTATION_STATE:
			status = cerberus_protocol_get_attestation_state (interface->device_manager, request);
			break;

		case CERBERUS_PROTOCOL_DEBUG_FILL_LOG:
			status = cerberus_protocol_debug_fill_log (interface->background, request);
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

int cmd_interface_system_process_response (struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	struct cmd_interface_system *interface = (struct cmd_interface_system*) intf;
	uint8_t command_id;
	uint8_t command_set;
	int status;

	status = cmd_interface_process_cerberus_protocol_message (&interface->base, response,
		&command_id, &command_set, true, true);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case CERBERUS_PROTOCOL_GET_DIGEST:
			status = cerberus_protocol_process_certificate_digest_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct cerberus_protocol_observer, on_get_digest_response),
					response);
			}

		case CERBERUS_PROTOCOL_GET_CERTIFICATE:
			status = cerberus_protocol_process_certificate_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct cerberus_protocol_observer, on_get_certificate_response),
					response);
			}

		case CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE:
			status = cerberus_protocol_process_challenge_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct cerberus_protocol_observer, on_challenge_response),
					response);
			}

		case CERBERUS_PROTOCOL_ERROR:
			return cerberus_protocol_process_error_response (response);

		default:
			return CMD_HANDLER_UNKNOWN_RESPONSE;
	}
}

/**
 * Initialize System command interface instance
 *
 * @param intf The System command interface instance to initialize
 * @param control The FW update control instance to use
 * @param pfm_0 Command interface to PFM for port 0
 * @param pfm_1 Command interface to PFM for port 1
 * @param cfm Command interface to CFM
 * @param pcd Command interface to PCD
 * @param pfm_manager_0 PFM manager for port 0
 * @param pfm_manager_1 PFM manager for port 1
 * @param cfm_manager CFM manager
 * @param pcd_manager PCD manager
 * @param master_attestation Master attestation manager
 * @param slave_attestation Slave attestation manager
 * @param device_manager Device manager
 * @param store PCR storage
 * @param hash Hash engine to to use for PCR operations
 * @param background Context for executing long-running operations in the background.
 * @param host_0 Host interface for port 0
 * @param host_1 Host interface for port 1
 * @param fw_version The FW version strings
 * @param riot RIoT keys manager
 * @param auth Handler for authorizing protected commands
 * @param host_0_ctrl The host control instance for port 0
 * @param host_1_ctrl The host control instance for port 1
 * @param recovery_cmd_0 Command interface to a recovery image for port 0
 * @param recovery_cmd_1 Command interface to a recovery image for port 1
 * @param recovery_manager_0 Recovery image manager for port 0
 * @param recovery_manager_1 Recovery image manager for port 1
 * @param cmd_device Device command handler instance
 * @param vendor_id Device vendor ID
 * @param device_id Device ID
 * @param subsystem_vid Subsystem vendor ID
 * @param subsystem_id Subsystem ID
 * @param session Session manager for channel encryption
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_system_init (struct cmd_interface_system *intf,
	struct firmware_update_control *control, struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct manifest_cmd_interface *cfm,
	struct manifest_cmd_interface *pcd, struct pfm_manager *pfm_manager_0,
	struct pfm_manager *pfm_manager_1, struct cfm_manager *cfm_manager,
	struct pcd_manager *pcd_manager, struct attestation_master *master_attestation,
	struct attestation_slave *slave_attestation, struct device_manager *device_manager,
	struct pcr_store *store, struct hash_engine *hash, struct cmd_background *background,
	struct host_processor *host_0, struct host_processor *host_1,
	struct cmd_interface_fw_version *fw_version, struct riot_key_manager *riot,
	struct cmd_authorization *auth, struct host_control *host_ctrl_0,
	struct host_control *host_ctrl_1, struct recovery_image_cmd_interface *recovery_cmd_0,
	struct recovery_image_cmd_interface *recovery_cmd_1,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1, struct cmd_device *cmd_device,
	uint16_t vendor_id, uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager *session)
{
	int status;

	if ((intf == NULL) || (control == NULL) || (store == NULL) || (background == NULL) ||
		(riot == NULL) || (auth == NULL) || (master_attestation == NULL) ||
		(slave_attestation == NULL) || (hash == NULL) || (device_manager == NULL) ||
		(fw_version == NULL) || (cmd_device == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_system));

	status = observable_init (&intf->observable);
	if (status != 0) {
		return status;
	}

	intf->control = control;
	intf->pfm_0 = pfm_0;
	intf->pfm_1 = pfm_1;
	intf->cfm = cfm;
	intf->pcd = pcd;
	intf->pfm_manager_0 = pfm_manager_0;
	intf->pfm_manager_1 = pfm_manager_1;
	intf->cfm_manager = cfm_manager;
	intf->pcd_manager = pcd_manager;
	intf->host_0 = host_0;
	intf->host_1 = host_1;
	intf->pcr_store = store;
	intf->riot = riot;
	intf->background = background;
	intf->auth = auth;
	intf->master_attestation = master_attestation;
	intf->slave_attestation = slave_attestation;
	intf->hash = hash;
	intf->host_0_ctrl = host_ctrl_0;
	intf->host_1_ctrl = host_ctrl_1;
	intf->device_manager = device_manager;
	intf->recovery_cmd_0 = recovery_cmd_0;
	intf->recovery_cmd_1 = recovery_cmd_1;
	intf->recovery_manager_0 = recovery_manager_0;
	intf->recovery_manager_1 = recovery_manager_1;
	intf->fw_version = fw_version;
	intf->cmd_device = cmd_device;

	intf->device_id.vendor_id = vendor_id;
	intf->device_id.device_id = device_id;
	intf->device_id.subsystem_vid = subsystem_vid;
	intf->device_id.subsystem_id = subsystem_id;

	intf->base.process_request = cmd_interface_system_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_system_process_response;
#endif 
	intf->base.generate_error_packet = cmd_interface_generate_error_packet;

#if CMD_SUPPORT_ENCRYPTED_SESSIONS
	intf->base.session = session;
#endif

	return 0;
}

/**
 * Deinitialize System command interface instance
 *
 * @param intf The System command interface instance to deinitialize
 */
void cmd_interface_system_deinit (struct cmd_interface_system *intf)
{
	if (intf != NULL) {
		observable_release (&intf->observable);
		memset (intf, 0, sizeof (struct cmd_interface_system));
	}
}

/**
 * Add an observer for system notifications.
 *
 * @param system The system instance to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int cmd_interface_system_add_cerberus_protocol_observer (struct cmd_interface_system *intf,
	struct cerberus_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&intf->observable, observer);
}

/**
 * Remove an observer from system notifications.
 *
 * @param system The system instance to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int cmd_interface_system_remove_cerberus_protocol_observer (struct cmd_interface_system *intf,
	struct cerberus_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&intf->observable, observer);
}
