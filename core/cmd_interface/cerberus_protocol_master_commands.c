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
 * Populate the Cerberus protocol header segment of a Cerberus Protocol request
 *
 * @param header Buffer to fill with Cerberus Protocol header
 * @param command Command ID to utilize in header
 */
static void cerberus_protocol_populate_cerberus_protocol_header (
	struct cerberus_protocol_header *header, uint8_t command)
{
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = command;
}

/**
 * Construct get device capabilities request.
 *
 * @param device_mgr Device manager instance to utilize.
 * @param buf The buffer containing the generated request.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request if the request was successfully constructed or an
 * error code.
 */
int cerberus_protocol_generate_get_device_capabilities_request (struct device_manager *device_mgr,
	uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_device_capabilities *rq =
		(struct cerberus_protocol_device_capabilities*) buf;
	int status;

	if ((device_mgr == NULL) || (rq == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (buf_len < (sizeof (struct cerberus_protocol_device_capabilities))) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	cerberus_protocol_populate_cerberus_protocol_header (&rq->header,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES);

	status = device_manager_get_device_capabilities_request (device_mgr, &rq->capabilities);
	if (status != 0) {
		return status;
	}

	return sizeof (struct cerberus_protocol_device_capabilities);
}

/**
 * Construct get certificate digest request.
 *
 * @param slot_num Slot number to request.
 * @param key_alg Key exchange algorithm to request.
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_generate_get_certificate_digest_request (uint8_t slot_num, uint8_t key_alg,
	uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_get_certificate_digest *rq =
		(struct cerberus_protocol_get_certificate_digest*) buf;

	if (rq == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct cerberus_protocol_get_certificate_digest)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	if ((slot_num > ATTESTATION_MAX_SLOT_NUM) ||
		(key_alg >= NUM_ATTESTATION_KEY_EXCHANGE_ALGORITHMS)) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	cerberus_protocol_populate_cerberus_protocol_header (&rq->header, CERBERUS_PROTOCOL_GET_DIGEST);

	rq->slot_num = slot_num;
	rq->key_alg = key_alg;

	return (sizeof (struct cerberus_protocol_get_certificate_digest));
}

/**
 * Construct get certificate request.
 *
 * @param slot_num Slot number to request.
 * @param cert_num Certificate number to request.
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 * @param offset Offset from start of certificate in bytes to request
 * @param length Number of bytes to read back, 0 for max payload length
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_generate_get_certificate_request (uint8_t slot_num, uint8_t cert_num,
	uint8_t *buf, size_t buf_len, uint16_t offset, uint16_t length)
{
	struct cerberus_protocol_get_certificate *rq = (struct cerberus_protocol_get_certificate*) buf;

	if (rq == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct cerberus_protocol_get_certificate)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	if (slot_num > ATTESTATION_MAX_SLOT_NUM) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	cerberus_protocol_populate_cerberus_protocol_header (&rq->header,
		CERBERUS_PROTOCOL_GET_CERTIFICATE);

	rq->slot_num = slot_num;
	rq->cert_num = cert_num;
	rq->offset = offset;
	rq->length = length;

	return (sizeof (struct cerberus_protocol_get_certificate));
}

/**
 * Construct challenge request.
 *
 * @param attestation Attestation manager instance to utilize.
 * @param eid EID of target device in attestation challenge request.
 * @param slot_num Requested slot number for target device to utilize.
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_generate_challenge_request (struct attestation_master *attestation,
	uint8_t eid, uint8_t slot_num, uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_challenge *rq = (struct cerberus_protocol_challenge*) buf;
	int status;

	if ((attestation == NULL) || (rq == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct cerberus_protocol_challenge)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	if (slot_num > ATTESTATION_MAX_SLOT_NUM) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	cerberus_protocol_populate_cerberus_protocol_header (&rq->header,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE);

	status = attestation->generate_challenge_request (attestation, eid, slot_num, &rq->challenge);
	if (!ROT_IS_ERROR (status)) {
		return sizeof (struct cerberus_protocol_challenge);
	}
	else {
		return status;
	}
}

/**
 * Process manifest update init request
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_manifest_update_init (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_msg *request)
{
	/* Just use the CFM structures since they are the same for all manifests. */
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
 * Process manifest update request
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_manifest_update (struct manifest_cmd_interface *manifest_interface,
	struct cmd_interface_msg *request)
{
	/* Just use the CFM structures since they are the same for all manifests. */
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
 * Process manifest update complete request
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update complete request to process
 * @param delayed_activation_allowed Boolean indicating whether delayed activation is allowed
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_manifest_update_complete (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_msg *request,
	bool delayed_activation_allowed)
{
	/* Just use the CFM structures since they are the same for all manifests. */
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
	struct cmd_interface_msg *request)
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
	struct cmd_interface_msg *request)
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
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_manifest_update_complete (cfm_interface, request, true);
}

/**
 * Process manifest ID version
 *
 * @param manifest manifest to query
 * @param request manifest version ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_manifest_id_version (struct manifest *manifest,
	struct cmd_interface_msg *request)
{
	/* Just use the CFM structures since they are the same for all manifests. */
	struct cerberus_protocol_get_cfm_id_version_response *rsp =
		(struct cerberus_protocol_get_cfm_id_version_response*) request->data;
	int status = 0;

	if (manifest != NULL) {
		status = manifest->get_id (manifest, &rsp->version);
		if (status != 0) {
			return status;
		}

		rsp->valid = 1;
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
	}

	request->length = sizeof (struct cerberus_protocol_get_cfm_id_version_response);

	return status;
}

/**
 * Process manifest ID platform
 *
 * @param manifest manifest to query
 * @param request manifest platform ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_manifest_id_platform (struct manifest *manifest,
	struct cmd_interface_msg *request)
{
	/* Just use the CFM structures since the same same for all manifests. */
	struct cerberus_protocol_get_cfm_id_platform_response *rsp =
		(struct cerberus_protocol_get_cfm_id_platform_response*) request->data;
	char *platform_id = (char*) &rsp->platform;
	size_t platform_id_len;
	int status = 0;

	if (manifest != NULL) {
		status = manifest->get_platform_id (manifest, &platform_id,
			CERBERUS_PROTOCOL_MAX_CFM_ID_PLATFORM (request));
		if (status != 0) {
			return status;
		}

		rsp->valid = 1;
		platform_id_len = strlen (platform_id) + 1;
	}
	else {
		rsp->valid = 0;
		rsp->platform = '\0';
		platform_id_len = 1;
	}

	request->length = cerberus_protocol_get_cfm_id_platform_response_length (platform_id_len);

	return status;
}

/**
 * Process CFM ID version
 *
 * @param cfm CFM to query
 * @param request CFM platform ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_cfm_id_version (struct cfm *cfm,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_id_version (&cfm->base, request);
}

/**
 * Process CFM ID platform
 *
 * @param cfm CFM to query
 * @param request CFM version ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_cfm_id_platform (struct cfm *cfm,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_id_platform (&cfm->base, request);
}

/**
 * Process CFM ID request
 *
 * @param cfm_mgr CFM manager instance to utilize
 * @param request CFM ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_cfm_id (struct cfm_manager *cfm_mgr,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_cfm_id *rq = (struct cerberus_protocol_get_cfm_id*) request->data;
	struct cfm *curr_cfm = NULL;
	int status = 0;
	int id;

	if (request->length == (sizeof (struct cerberus_protocol_get_cfm_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_cfm_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	id = rq->id;
	if (id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	status = cerberus_protocol_get_curr_cfm (cfm_mgr, rq->region, &curr_cfm);
	/* When there's no valid CFM manager, return a success with response indicating no valid
	 * manifest. */
	if ((status != 0) && (status != CMD_HANDLER_UNSUPPORTED_COMMAND)) {
		return status;
	}

	if (id == 0) {
		status = cerberus_protocol_get_cfm_id_version (curr_cfm, request);
	}
	else {
		status = cerberus_protocol_get_cfm_id_platform (curr_cfm, request);
	}

	cerberus_protocol_free_cfm (cfm_mgr, curr_cfm);
	return status;
}

/**
 * Process CFM component IDs request
 *
 * @param cfm_mgr CFM manager instance to utilize
 * @param request CFM component IDs request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_cfm_component_ids (struct cfm_manager *cfm_mgr,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_cfm_component_ids *rq =
		(struct cerberus_protocol_get_cfm_component_ids*) request->data;
	struct cerberus_protocol_get_cfm_component_ids_response *rsp =
		(struct cerberus_protocol_get_cfm_component_ids_response*) request->data;
	struct cfm *curr_cfm = NULL;
	uint32_t offset;
	size_t length;
	int status = 0;

	if (request->length != sizeof (struct cerberus_protocol_get_cfm_component_ids)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (cfm_mgr == NULL) {
		rsp->valid = 0;
		rsp->version = 0;
		request->length = cerberus_protocol_get_cfm_component_ids_response_length (0);
		return status;
	}

	status = cerberus_protocol_get_curr_cfm (cfm_mgr, rq->region, &curr_cfm);
	if (status != 0) {
		return status;
	}

	if (curr_cfm != NULL) {
		offset = rq->offset;
		rsp->valid = 1;

		status = curr_cfm->base.get_id (&curr_cfm->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		length = CERBERUS_PROTOCOL_MAX_COMPONENT_IDS (request);

		status = curr_cfm->buffer_supported_components (curr_cfm, offset, length,
			cerberus_protocol_cfm_component_ids (rsp));
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		request->length = cerberus_protocol_get_cfm_component_ids_response_length (status);

		status = 0;
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
	struct cmd_interface_msg *request)
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
	struct cmd_interface_msg *request)
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
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_manifest_update_complete (pcd_interface, request, false);
}

/**
 * Process PCD platform ID request
 *
 * @param pcd PCD instance to utilize
 * @param request Get PCD platform ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_pcd_platform_id (struct pcd *pcd,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_id_platform (&pcd->base, request);
}

/**
 * Process PCD version ID request
 *
 * @param pcd PCD instance to utilize
 * @param request Get PCD version ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_pcd_version_id (struct pcd *pcd,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_id_version (&pcd->base, request);
}

/**
 * Process PCD ID request
 *
 * @param pcd_mgr PCD manager instance to utilize
 * @param request Get PCD ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pcd_id (struct pcd_manager *pcd_mgr,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_pcd_id *rq = (struct cerberus_protocol_get_pcd_id*) request->data;
	struct pcd *curr_pcd = NULL;
	int status;

	if (request->length == (sizeof (struct cerberus_protocol_get_pcd_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_pcd_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	/* When there's no valid PCD manager, return a success
	 * with response indicating no valid manifest */
	if (pcd_mgr != NULL) {
		curr_pcd = pcd_mgr->get_active_pcd (pcd_mgr);
	}

	if (rq->id == 0) {
		status = cerberus_protocol_get_pcd_version_id (curr_pcd, request);
	}
	else {
		status = cerberus_protocol_get_pcd_platform_id (curr_pcd, request);
	}

	cerberus_protocol_free_pcd (pcd_mgr, curr_pcd);
	return status;
}

/**
 * Process a FW update status request
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
 * Process PFM update status request
 *
 * @param pfm_cmd List of PFM command interfaces for all available ports.
 * @param num_ports Number of available ports.
 * @param request PFM update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_update_status (struct manifest_cmd_interface *pfm_cmd[],
	uint8_t num_ports, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_update_status *rq =
		(struct cerberus_protocol_update_status*) request->data;
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;

	if (rq->port_id >= num_ports) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (pfm_cmd[rq->port_id] == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = pfm_cmd[rq->port_id]->get_status (pfm_cmd[rq->port_id]);
	return 0;
}

/**
 * Process manifest update status request
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_manifest_update_status (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_msg *request)
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
 * Process CFM update status request
 *
 * @param cfm_interface CFM command interface
 * @param request CFM update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_cfm_update_status (struct manifest_cmd_interface *cfm_interface,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_update_status (cfm_interface, request);
}

/**
 * Process PCD update status request
 *
 * @param pcd_interface PCD command interface
 * @param request PCD update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pcd_update_status (struct manifest_cmd_interface *pcd_interface,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_update_status (pcd_interface, request);
}

/**
 * Process a request for host verification actions on reset.
 *
 * @param host List of host processors for all available ports
 * @param num_ports Number of available ports
 * @param request Host verification actions request to process
 *
 * @return Response length if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_host_next_verification_status (struct host_processor *host[],
	uint8_t num_ports, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_update_status *rq =
		(struct cerberus_protocol_update_status*) request->data;
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;
	int status;

	if (rq->port_id >= num_ports) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if ((host == NULL) || host[rq->port_id] == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = host[rq->port_id]->get_next_reset_verification_actions (host[rq->port_id]);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	rsp->update_status = (uint32_t) status;
	return 0;
}

/**
 * Process recovery image get update status request
 *
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param request Recovery image update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_recovery_image_update_status (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request)
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
 * Process a reset configuration update status request
 *
 * @param background Background command processing instance to query
 * @param rsp Status response message to update
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_reset_config_status (struct cmd_background *background,
	struct cerberus_protocol_update_status_response *rsp)
{
#ifdef CMD_ENABLE_RESET_CONFIG
	if (background == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = background->get_config_reset_status (background);
	return 0;
#else
	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}

/**
 * Process update status request
 *
 * @param control Firmware update control instance to query
 * @param num_ports Number of available ports
 * @param pfm_cmd List of PFM command interfaces for all available ports
 * @param cfm CFM command interface
 * @param pcd PCD command interface
 * @param host List of host processors for all available ports
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param background Command background instance to query
 * @param request Update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_update_status (struct firmware_update_control *control, uint8_t num_ports,
	struct manifest_cmd_interface *pfm_cmd[], struct manifest_cmd_interface *cfm,
	struct manifest_cmd_interface *pcd, struct host_processor *host[],
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_background *background,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_update_status *req =
		(struct cerberus_protocol_update_status*) request->data;
	struct cerberus_protocol_update_status_response *rsp =
		(struct cerberus_protocol_update_status_response*) request->data;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_update_status)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (req->update_type) {
		case CERBERUS_PROTOCOL_FW_UPDATE_STATUS:
			status = cerberus_protocol_get_fw_update_status (control, rsp);
			break;

		case CERBERUS_PROTOCOL_PFM_UPDATE_STATUS:
			status = cerberus_protocol_get_pfm_update_status (pfm_cmd, num_ports, request);
			break;

		case CERBERUS_PROTOCOL_CFM_UPDATE_STATUS:
			status = cerberus_protocol_get_manifest_update_status (cfm, request);
			break;

		case CERBERUS_PROTOCOL_PCD_UPDATE_STATUS:
			status = cerberus_protocol_get_manifest_update_status (pcd, request);
			break;

		case CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET:
			status = cerberus_protocol_get_host_next_verification_status (host, num_ports, request);
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
 * Process an extended FW update status request
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
 * Process recovery image extended get update status request.
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
 * Process extended update status request
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
	struct recovery_image_cmd_interface *recovery_cmd_1, struct cmd_interface_msg *request)
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
 * Process certificate digest response. This function only ensures the response is valid per
 * Cerberus protocol response definition, the certificate digest is not validated or stored.
 *
 * @param response Certificate digest response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int cerberus_protocol_process_certificate_digest_response (struct cmd_interface_msg *response)
{
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) response->data;
	size_t digests_len;

	if (response->length <= sizeof (struct cerberus_protocol_get_certificate_digest_response)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	digests_len = rsp->num_digests * SHA256_HASH_LENGTH;

	if (response->length !=
		cerberus_protocol_get_certificate_digest_response_length (digests_len)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	return 0;
}

/**
 * Process certificate response message. This function only ensures the response is valid per
 * Cerberus protocol response definition, the certificate is not validated or stored.
 *
 * @param response Certificate response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int cerberus_protocol_process_certificate_response (struct cmd_interface_msg *response)
{
	struct cerberus_protocol_get_certificate_response *rsp =
		(struct cerberus_protocol_get_certificate_response*) response->data;

	if (response->length <= sizeof (struct cerberus_protocol_get_certificate_response)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rsp->slot_num > ATTESTATION_MAX_SLOT_NUM) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	return 0;
}

/**
 * Process challenge response message. This function only ensures the response is valid per
 * Cerberus protocol response definition, the challenge is not validated.
 *
 * @param response Challenge response to process
 *
 * @return Completion status, 0 if success or an error code.
 */
int cerberus_protocol_process_challenge_response (struct cmd_interface_msg *response)
{
	struct cerberus_protocol_challenge_response *rsp =
		(struct cerberus_protocol_challenge_response*) response->data;

	if ((response->length <= sizeof (struct cerberus_protocol_challenge_response)) ||
		(response->length <= cerberus_protocol_challenge_response_length (rsp))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rsp->challenge.slot_num > ATTESTATION_MAX_SLOT_NUM) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (rsp->challenge.reserved != 0) {
		return CMD_HANDLER_RSVD_NOT_ZERO;
	}

	return 0;
}
