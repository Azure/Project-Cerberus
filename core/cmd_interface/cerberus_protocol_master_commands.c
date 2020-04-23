// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "common/certificate.h"
#include "common/common_math.h"
#include "manifest/cfm/cfm_manager.h"
#include "manifest/pcd/pcd_manager.h"
#include "attestation_cmd_interface.h"
#include "cerberus_protocol_required_commands.h"
#include "cerberus_protocol_master_commands.h"
#include "cerberus_protocol_optional_commands.h"


/**
 * Get CFM interface for a specified CFM location.
 *
 * @param manager The cfm managing responsible for cfm.
 * @param region The cfm region to query. 0 for active, 1 for pending.
 * @param cfm Output for the CFM
 *
 * @return 0 if the operation was successful or an error code.
 */
int cerberus_protocol_get_curr_cfm (struct cfm_manager *manager, uint8_t region, struct cfm **cfm)
{
	if (manager == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	if (region == 0) {
		*cfm = manager->get_active_cfm (manager);
	}
	else if (region == 1) {
		*cfm = manager->get_pending_cfm (manager);
	}
	else {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	return 0;
}

/**
 * Release a cfm instance.
 *
 * @param manager The cfm manager releasing the cfm.
 * @param cfm The cfm to release.
 */
static void cerberus_protocol_free_cfm (struct cfm_manager *manager, struct cfm *cfm)
{
	if (manager != NULL) {
		manager->free_cfm (manager, cfm);
	}
}

/**
 * Release a PCD instance.
 *
 * @param manager The PCD manager releasing the PCD.
 * @param pcd The PCD to release.
 */
static void cerberus_protocol_free_pcd (struct pcd_manager *manager, struct pcd *pcd)
{
	if (manager != NULL) {
		manager->free_pcd (manager, pcd);
	}
}

/**
 * Construct get certificate digest request.
 *
 * @param attestation Attestation manager instance to utilize.
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_issue_get_certificate_digest (struct attestation_master *attestation,
	uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_digest_info *rq = (struct cerberus_protocol_digest_info*) buf;

	if (buf_len < sizeof (struct cerberus_protocol_digest_info)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	rq->slot_num = 0;
	rq->key_alg = attestation->encryption_algorithm;

	return (sizeof (struct cerberus_protocol_digest_info));
}

/**
 * Construct get certificate request.
 *
 * @param params Parameters needed to construct request.
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_issue_get_certificate (struct cerberus_protocol_cert_req_params *params,
	uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_cert_info *rq = (struct cerberus_protocol_cert_info*) buf;

	if (params == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct cerberus_protocol_cert_info)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	rq->slot_num = params->slot_num;
	rq->cert_num = params->cert_num;
	rq->offset = 0;
	rq->length = 0;

	return (sizeof (struct cerberus_protocol_cert_info));
}

/**
 * Construct challenge request.
 *
 * @param attestation Attestation manager instance to utilize.
 * @param params Parameters needed to construct request.
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_issue_challenge (struct attestation_master *attestation,
	struct cerberus_protocol_challenge_req_params *params, uint8_t *buf, size_t buf_len)
{
	if (params == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	return attestation->issue_challenge (attestation, params->eid, params->slot_num,
		buf, buf_len);
}

/**
 * Process manifest update init packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_manifest_update_init (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request)
{
	struct cerberus_protocol_prepare_cfm_update *rq =
		(struct cerberus_protocol_prepare_cfm_update*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_prepare_cfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (manifest_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	request->length = 0;
	return manifest_interface->prepare_manifest (manifest_interface, rq->total_size);
}

/**
 * Process manifest update packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_manifest_update (struct manifest_cmd_interface *manifest_interface,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_cfm_update *rq = (struct cerberus_protocol_cfm_update*) request->data;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_cfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (manifest_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	status = manifest_interface->store_manifest (manifest_interface, &rq->payload,
		cerberus_protocol_cfm_update_length (request));

	request->length = 0;
	return status;
}

/**
 * Process manifest update complete packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update complete request to process
 * @param delayed_activation_allowed Boolean indicating whether delayed activation is allowed
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_manifest_update_complete (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	bool delayed_activation_allowed)
{
	struct cerberus_protocol_complete_cfm_update *rq =
		(struct cerberus_protocol_complete_cfm_update*) request->data;

	if (request->length !=
		(sizeof (struct cerberus_protocol_complete_pcd_update) + delayed_activation_allowed)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (manifest_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	request->length = 0;
	if (delayed_activation_allowed) {
		return manifest_interface->finish_manifest (manifest_interface, rq->activation);
	}
	else {
		return manifest_interface->finish_manifest (manifest_interface, true);
	}
}

/**
 * Process a request to initialize a CFM update.
 *
 * @param cfm_interface Command interface for CFM processing
 * @param request Request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_cfm_update_init (struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_manifest_update_init (cfm_interface, request);
}

/**
 * Process a request to write CFM update data.
 *
 * @param cfm_interface Command interface for CFM processing
 * @param request Request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_cfm_update (struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_manifest_update (cfm_interface, request);
}

/**
 * Process a request to complete a CFM update.
 *
 * @param cfm_interface Command interface for CFM processing
 * @param request Request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_cfm_update_complete (struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_manifest_update_complete (cfm_interface, request, true);
}

/**
 * Process CFM ID packet
 *
 * @param cfm_mgr CFM manager instance to utilize
 * @param request CFM ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_cfm_id (struct cfm_manager *cfm_mgr,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_get_cfm_id *rq = (struct cerberus_protocol_get_cfm_id*) request->data;
	struct cerberus_protocol_get_cfm_id_version_response *rsp =
		(struct cerberus_protocol_get_cfm_id_version_response*) request->data;
	struct cfm *curr_cfm;
	int status = 0;

	if (request->length == (sizeof (struct cerberus_protocol_get_cfm_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_cfm_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = cerberus_protocol_get_curr_cfm (cfm_mgr, rq->region, &curr_cfm);
	if (status != 0) {
		return status;
	}

	if (curr_cfm != NULL) {
		status = curr_cfm->base.get_id (&curr_cfm->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		rsp->valid = 1;
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
	}

	request->length = sizeof (struct cerberus_protocol_get_cfm_id_version_response);

exit:
	cerberus_protocol_free_cfm (cfm_mgr, curr_cfm);
	return status;
}

/**
 * Process CFM component IDs packet
 *
 * @param cfm_mgr CFM manager instance to utilize
 * @param request CFM component IDs request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_cfm_component_ids (struct cfm_manager *cfm_mgr,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_get_cfm_component_ids *rq =
		(struct cerberus_protocol_get_cfm_component_ids*) request->data;
	struct cerberus_protocol_get_cfm_component_ids_response *rsp =
		(struct cerberus_protocol_get_cfm_component_ids_response*) request->data;
	struct cfm_component_ids component_ids;
	struct cfm *curr_cfm;
	uint16_t length;
	uint32_t id_length;
	uint32_t offset;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_get_cfm_component_ids)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = cerberus_protocol_get_curr_cfm (cfm_mgr, rq->region, &curr_cfm);
	if (status != 0) {
		return status;
	}

	offset = rq->offset;

	if (curr_cfm != NULL) {
		rsp->valid = 1;

		status = curr_cfm->base.get_id (&curr_cfm->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		status = curr_cfm->get_supported_component_ids (curr_cfm, &component_ids);
		if (status != 0) {
			goto exit;
		}

		id_length = component_ids.count * sizeof (uint32_t);

		if (offset >= id_length) {
			request->length = cerberus_protocol_get_cfm_component_ids_response_length (0);
			goto cleanup_component_ids;
		}

		length = min (CERBERUS_PROTOCOL_MAX_COMPONENT_IDS (request), id_length - offset);
		memcpy (cerberus_protocol_cfm_component_ids (rsp), &((uint8_t*) component_ids.ids)[offset],
			length);

		request->length = cerberus_protocol_get_cfm_component_ids_response_length (length);

	cleanup_component_ids:
		curr_cfm->free_component_ids (curr_cfm, &component_ids);
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
		request->length = cerberus_protocol_get_cfm_component_ids_response_length (0);
	}

exit:
	cerberus_protocol_free_cfm (cfm_mgr, curr_cfm);
	return status;
}

/**
 * Process a request to initialize a PCD update.
 *
 * @param pcd_interface Command interface for PCD processing
 * @param request Request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pcd_update_init (struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_manifest_update_init (pcd_interface, request);
}

/**
 * Process a request to write PCD update data.
 *
 * @param pcd_interface Command interface for PCD processing
 * @param request Request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pcd_update (struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_manifest_update (pcd_interface, request);
}

/**
 * Process a request to complete a PCD update.
 *
 * @param pcd_interface Command interface for PCD processing
 * @param request Request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pcd_update_complete (struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_manifest_update_complete (pcd_interface, request, false);
}

/**
 * Process PCD ID packet
 *
 * @param pcd_mgr PCD manager instance to utilize
 * @param request Get PCD ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pcd_id (struct pcd_manager *pcd_mgr,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_get_pcd_id *rq = (struct cerberus_protocol_get_pcd_id*) request->data;
	struct cerberus_protocol_get_pcd_id_version_response *rsp =
		(struct cerberus_protocol_get_pcd_id_version_response*) request->data;
	struct pcd *curr_pcd;
	int status = 0;

	if (request->length == (sizeof (struct cerberus_protocol_get_pcd_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_pcd_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (pcd_mgr == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	curr_pcd = pcd_mgr->get_active_pcd (pcd_mgr);
	if (curr_pcd != NULL) {
		status = curr_pcd->base.get_id (&curr_pcd->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		rsp->valid = 1;
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
	}

	request->length = sizeof (struct cerberus_protocol_get_pcd_id_version_response);

exit:
	cerberus_protocol_free_pcd (pcd_mgr, curr_pcd);
	return status;
}

/**
 * Process a FW update status packet
 *
 * @param control Firmware update control instance to query
 * @param rsp Status response message to update
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_fw_update_status (struct firmware_update_control *control,
	struct cerberus_protocol_update_status_response *rsp)
{
	if (control == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = control->get_status (control);
	return 0;
}

/**
 * Process PFM update status packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param request PFM update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_update_status (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_update_status *rq =
		(struct cerberus_protocol_update_status*) request->data;
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;
	struct manifest_cmd_interface *curr_pfm_interface;

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, rq->port_id);
	if (curr_pfm_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = curr_pfm_interface->get_status (curr_pfm_interface);
	return 0;
}

/**
 * Process manifest update status packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_manifest_update_status (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request)
{
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;

	if (manifest_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = manifest_interface->get_status (manifest_interface);
	return 0;
}

/**
 * Process CFM update status packet
 *
 * @param cfm_interface CFM command interface
 * @param request CFM update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_cfm_update_status (struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_get_manifest_update_status (cfm_interface, request);
}

/**
 * Process PCD update status packet
 *
 * @param pcd_interface PCD command interface
 * @param request PCD update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pcd_update_status (struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_request *request)
{
	return cerberus_protocol_get_manifest_update_status (pcd_interface, request);
}

/**
 * Process a request for host verification actions on reset.
 *
 * @param host_0 Host processor for port 0
 * @param host_1 Host processor for port 1
 * @param request Host verification actions request to process
 *
 * @return Response length if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_host_next_verification_status (struct host_processor *host_0,
	struct host_processor *host_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_update_status *rq =
		(struct cerberus_protocol_update_status*) request->data;
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;
	struct host_processor *host;
	int status;

	switch (rq->port_id) {
		case 0:
			host = host_0;
			break;

		case 1:
			host = host_1;
			break;

		default:
			return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (host == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = host->get_next_reset_verification_actions (host);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	rsp->update_status = (uint32_t) status;
	return 0;
}

/**
 * Process recovery image get update status packet
 *
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param request Recovery image update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_recovery_image_update_status (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_update_status *rq =
		(struct cerberus_protocol_update_status*) request->data;
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;
	struct recovery_image_cmd_interface *curr_recovery_interface;

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0,
		recovery_1, rq->port_id);
	if (curr_recovery_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = curr_recovery_interface->get_status (curr_recovery_interface);
	return 0;
}

/**
 * Process a rest configuration update status packet
 *
 * @param background Background command processing instance to query
 * @param rsp Status response message to update
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_reset_config_status (struct cmd_background *background,
	struct cerberus_protocol_update_status_response *rsp)
{
	if (background == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = background->get_config_reset_status (background);
	return 0;
}

/**
 * Process update status packet
 *
 * @param control Firmware update control instance to query
 * @param pfm_0 Port 0 PFM command interface
 * @param pfm_1 Port 1 PFM command interface
 * @param cfm CFM command interface
 * @param pcd PCD command interface
 * @param host_0 Port 0 host processor
 * @param host_1 Port 1 host processor
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param background Command background instance to query
 * @param request Update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_update_status (struct firmware_update_control *control,
	struct manifest_cmd_interface *pfm_0, struct manifest_cmd_interface *pfm_1,
	struct manifest_cmd_interface *cfm, struct manifest_cmd_interface *pcd,
	struct host_processor *host_0, struct host_processor *host_1,
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_background *background,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_update_status)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN]) {
		case CERBERUS_PROTOCOL_FW_UPDATE_STATUS:
			status = cerberus_protocol_get_fw_update_status (control, rsp);
			break;

		case CERBERUS_PROTOCOL_PFM_UPDATE_STATUS:
			status = cerberus_protocol_get_pfm_update_status (pfm_0, pfm_1, request);
			break;

		case CERBERUS_PROTOCOL_CFM_UPDATE_STATUS:
			status = cerberus_protocol_get_manifest_update_status (cfm, request);
			break;

		case CERBERUS_PROTOCOL_PCD_UPDATE_STATUS:
			status = cerberus_protocol_get_manifest_update_status (pcd, request);
			break;

		case CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET:
			status = cerberus_protocol_get_host_next_verification_status (host_0, host_1, request);
			break;

		case CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE_STATUS:
			status = cerberus_protocol_get_recovery_image_update_status (recovery_0, recovery_1,
				request);
			break;

		case CERBERUS_PROTOCOL_CONFIG_RESET_STATUS:
			status = cerberus_protocol_get_reset_config_status (background, rsp);
			break;

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (status == 0) {
		request->length = sizeof (struct cerberus_protocol_update_status_response);
	}
	return status;
}

/**
 * Process an extended FW update status packet
 *
 * @param control Firmware update control instance to query
 * @param rsp Status response message to update
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_extended_fw_update_status (struct firmware_update_control *control,
	struct cerberus_protocol_extended_update_status_response *rsp)
{
	rsp->update_status = control->get_status (control);
	rsp->remaining_len = control->get_remaining_len (control);

	return 0;
}

/**
 * Process recovery image extended get update status packet.
 *
 * @param manager_0 The recovery image manager instance for port 0.
 * @param manager_1 The recovery image manager instance for port 1.
 * @param cmd_0 The recovery image command interface instance for port 0.
 * @param cmd_1 The recovery image command interface instance for port 1.
 * @param port The port to query.
 * @param update_status Output buffer to store the update status.
 * @param rem_len Output buffer for the remaining update bytes.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_extended_recovery_image_update_status (
	struct recovery_image_manager *manager_0, struct recovery_image_manager *manager_1,
	struct recovery_image_cmd_interface *cmd_0, struct recovery_image_cmd_interface *cmd_1,
	uint8_t port, uint32_t *update_status, uint32_t *rem_len)
{
	struct recovery_image_cmd_interface *cmd_interface;
	struct recovery_image_manager *recovery_manager;
	struct flash_updater *updating;

	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	recovery_manager = cerberus_protocol_get_recovery_image_manager (manager_0, manager_1, port);
	if (recovery_manager == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	cmd_interface = cerberus_protocol_get_recovery_image_cmd_interface (cmd_0, cmd_1,
		port);

	if (cmd_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	*update_status = cmd_interface->get_status (cmd_interface);
	updating = recovery_manager->get_flash_update_manager (recovery_manager);
	*rem_len = 	flash_updater_get_remaining_bytes (updating);

	return 0;
}

/**
 * Process extended update status packet
 *
 * @param control Firmware update control instance to utilize
 * @param recovery_manager_0 The recovery image manager instance for port 0.
 * @param recovery_manager_1 The recovery image manager instance for port 1.
 * @param recovery_cmd_0 The recovery image command interface instance for port 0.
 * @param recovery_cmd_1 The recovery image command interface instance for port 1.
 * @param request Expected update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_extended_update_status (struct firmware_update_control *control,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1,
	struct recovery_image_cmd_interface *recovery_cmd_0,
	struct recovery_image_cmd_interface *recovery_cmd_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_extended_update_status *rq =
		(struct cerberus_protocol_extended_update_status*) request->data;
	struct cerberus_protocol_extended_update_status_response *rsp =
		(struct cerberus_protocol_extended_update_status_response*) request->data;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_extended_update_status)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (rq->update_type) {
		case CERBERUS_PROTOCOL_FW_UPDATE_STATUS:
			status = cerberus_protocol_get_extended_fw_update_status (control, rsp);
			break;

		case CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE_STATUS:
			status = cerberus_protocol_get_extended_recovery_image_update_status (
				recovery_manager_0,	recovery_manager_1, recovery_cmd_0, recovery_cmd_1, rq->port_id,
				&rsp->update_status, &rsp->remaining_len);
			break;

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (status == 0) {
		request->length = sizeof (struct cerberus_protocol_extended_update_status_response);
	}
	return status;
}

/**
 * Process certificate digest packet
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Certificate digest request to process
 *
 * @return 0 if request processed successfully or an error code.
 */
int cerberus_protocol_process_certificate_digest (struct attestation_master *attestation,
	struct cmd_interface_request *request)
{
	struct attestation_chain_digest digests;
	struct cerberus_protocol_cert_req_params cert_params;
	struct cerberus_protocol_challenge_req_params challenge_params;
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) request->data;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request->data;
	int status = 0;

	request->crypto_timeout = true;

	if (request->length !=
		(sizeof (struct cerberus_protocol_get_certificate_digest_response) +
			(rsp->num_digests * SHA256_HASH_LENGTH))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	digests.num_cert = rsp->num_digests;
	digests.digest = &request->data[sizeof (*rsp)];
	digests.digest_len = SHA256_HASH_LENGTH;

	/* TODO: This flow should be updated to handle the case where multiple certificates don't match.
	 * Otherwise, a new Get Digets command would need to be sent after getting ecah cert.
	 *
	 * Maybe instead of issuing the next command directly from here, the device mananger should be
	 * updated with some state indicating that certs need to be refreshed.  The top-level
	 * orchestrator for attestation would query the device manager and run the next appropriate
	 * steps. */
	status = attestation->compare_digests (attestation, request->source_eid, &digests);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	/* TODO: Use message max provided with the request. */
	if (status != 0) {
		cert_params.slot_num = ATTESTATION_RIOT_SLOT_NUM;
		cert_params.cert_num = status - 1;

		header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

		status = cerberus_protocol_issue_get_certificate (&cert_params,
			&request->data[sizeof (*header)], MCTP_PROTOCOL_MAX_MESSAGE_BODY - sizeof (*header));
	}
	else {
		challenge_params.slot_num = ATTESTATION_RIOT_SLOT_NUM;
		challenge_params.eid = request->source_eid;

		header->command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

		status = cerberus_protocol_issue_challenge (attestation, &challenge_params,
			&request->data[sizeof (*header)], MCTP_PROTOCOL_MAX_MESSAGE_BODY - sizeof (*header));
	}

	if ROT_IS_ERROR (status) {
		return status;
	}

	request->new_request = true;
	request->length = sizeof (struct cerberus_protocol_header) + status;
	return 0;
}

/**
 * Process certificate packet
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Certificate response to process
 *
 * @return 0 if request processed successfully or an error code.
 */
int cerberus_protocol_process_certificate (struct attestation_master *attestation,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_get_certificate_response *rsp =
		(struct cerberus_protocol_get_certificate_response*) request->data;
	struct cerberus_protocol_get_certificate_digest *rq =
		(struct cerberus_protocol_get_certificate_digest*) request->data;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_get_certificate_response)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = attestation->store_certificate (attestation, request->source_eid, rsp->slot_num,
		rsp->cert_num, &request->data[sizeof (*rsp)], request->length - sizeof (*rsp));
	if (status != 0) {
		return status;
	}

	rq->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	/* TODO: Use message max provided with the request. */
	status = cerberus_protocol_issue_get_certificate_digest (attestation,
		&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	request->new_request = true;
	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + status;
	return 0;
}

/**
 * Process challenge response packet
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Challenge response to process
 *
 * @return Completion status, 0 if success or an error code.
 */
int cerberus_protocol_process_challenge_response (struct attestation_master *attestation,
	struct cmd_interface_request *request)
{
	int status;

	request->crypto_timeout = true;

	status = attestation->process_challenge_response (attestation,
		&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		request->length - CERBERUS_PROTOCOL_MIN_MSG_LEN, request->source_eid);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	request->length = status;
	return 0;
}
