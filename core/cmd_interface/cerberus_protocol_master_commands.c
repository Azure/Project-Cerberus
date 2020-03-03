// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "common/certificate.h"
#include "common/common_math.h"
#include "i2c/i2c_slave_common.h"
#include "manifest/manifest_cmd_interface.h"
#include "manifest/cfm/cfm_manager.h"
#include "manifest/pcd/pcd_manager.h"
#include "attestation/attestation_master.h"
#include "attestation_cmd_interface.h"
#include "cerberus_protocol.h"
#include "cmd_background.h"
#include "cmd_interface.h"
#include "device_manager.h"
#include "cerberus_protocol_required_commands.h"
#include "cerberus_protocol_master_commands.h"


/**
 * Get CFM interface for a specified CFM location.
 *
 * @param manager The cfm managing responsible for cfm.
 * @param region The cfm region to query. 0 for active, 1 for pending.
 * @param cfm Output for the CFM
 *
 * @return 0 if the operation was successful or an error code.
 */
int cerberus_protocol_get_curr_cfm (struct cfm_manager *manager, uint8_t region,
	struct cfm **cfm)
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
 * @param buf The buffer containing the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_issue_get_certificate_digest (struct attestation_master *attestation,
	uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_get_certificate_digest_request_packet* rq =
		(struct cerberus_protocol_get_certificate_digest_request_packet*) buf;

	if (buf_len < sizeof (struct cerberus_protocol_get_certificate_digest_request_packet)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	rq->reserved = 0;
	rq->key_alg = attestation->encryption_algorithm;

	return (sizeof (struct cerberus_protocol_get_certificate_digest_request_packet));
}

/**
 * Construct get certificate request.
 *
 * @param params Parameters needed to construct request.
 * @param buf The buffer containing the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
int cerberus_protocol_issue_get_certificate (struct cerberus_protocol_cert_req_params *params,
	uint8_t *buf, size_t buf_len)
{
	struct cerberus_protocol_get_certificate_request_packet* rq =
		(struct cerberus_protocol_get_certificate_request_packet*) buf;

	if (params == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct cerberus_protocol_get_certificate_request_packet)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	rq->slot_num = params->slot_num;
	rq->cert_num = params->cert_num;
	rq->offset = 0;
	rq->length = 0;

	return (sizeof (struct cerberus_protocol_get_certificate_request_packet));
}

/**
 * Construct challenge request.
 *
 * @param attestation Attestation manager instance to utilize.
 * @param params Parameters needed to construct request.
 * @param buf The buffer containing the generated request data.
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
 * @param offset Offset in the request buffer to start processing
 * @param default_status Status if no manifest interface
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_manifest_update_init (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	int offset, int default_status)
{
	uint32_t manifest_size;

	if ((request->length - offset) != (CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (manifest_size))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	memcpy (&manifest_size, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + offset],
		sizeof (manifest_size));

	request->length = 0;
	if (manifest_interface != NULL) {
		return manifest_interface->prepare_manifest (manifest_interface, manifest_size);
	}
	else {
		return default_status;
	}
}

/**
 * Process manifest update packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update request to process
 * @param offset Offset in the request buffer to start processing
 * @param default_status Status if no manifest interface
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_manifest_update (struct manifest_cmd_interface *manifest_interface,
	struct cmd_interface_request *request, int offset, int default_status)
{
	int status = default_status;

	if ((request->length - offset) < (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (manifest_interface != NULL) {
		status = manifest_interface->store_manifest (manifest_interface,
			&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + offset], request->length - offset -
			CERBERUS_PROTOCOL_MIN_MSG_LEN);
	}

	request->length = 0;
	return status;
}

/**
 * Process manifest update complete packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update complete request to process
 * @param offset Offset in the request buffer to start processing
 * @param default_status Status if no manifest interface
 * @param delayed_activation_allowed Boolean indicating whether delayed activation is allowed
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_manifest_update_complete (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	int offset, int default_status, bool delayed_activation_allowed)
{
	if ((request->length - offset) !=
		(CERBERUS_PROTOCOL_MIN_MSG_LEN + delayed_activation_allowed)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;
	if (manifest_interface != NULL) {
		if (delayed_activation_allowed) {
			return manifest_interface->finish_manifest (manifest_interface,
				request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + offset]);
		}
		else {
			return manifest_interface->finish_manifest (manifest_interface, true);
		}
	}
	else {
		return default_status;
	}
}

/**
 * Process manifest update status packet
 *
 * @param manifest_interface Interface to handle manifest update commands
 * @param request Manifest update status request to process
 * @param default_status Status if no manifest interface
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_manifest_update_status (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	int default_status)
{
	uint32_t manifest_update_status;

	if (manifest_interface == NULL) {
		return default_status;
	}

	manifest_update_status = manifest_interface->get_status (manifest_interface);
	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &manifest_update_status,
		sizeof (manifest_update_status));

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (manifest_update_status);
	return 0;
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
	struct cfm *curr_cfm = NULL;
	uint32_t manifest_id;
	uint8_t region;
	int status = 0;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	region = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];

	status = cerberus_protocol_get_curr_cfm (cfm_mgr, region, &curr_cfm);
	if (status != 0) {
		return status;
	}

	if (curr_cfm == NULL) {
		request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0;
	}
	else {
		status = curr_cfm->base.get_id (&curr_cfm->base, &manifest_id);
		if (status != 0) {
			goto exit;
		}

		request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
		memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &manifest_id,
			sizeof (manifest_id));
	}

	request->length = sizeof (manifest_id) + CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;

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
	struct cfm_component_ids component_ids;
	struct cfm *curr_cfm = NULL;
	uint16_t length = 0;
	uint32_t id_length = 0;
	uint32_t manifest_id;
	uint32_t offset;
	uint8_t region;
	int status = 0;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 5)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	region = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	memcpy (&offset, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], sizeof (offset));

	status = cerberus_protocol_get_curr_cfm (cfm_mgr, region, &curr_cfm);
	if (status != 0) {
		return status;
	}

	if (curr_cfm != NULL) {
		status = curr_cfm->base.get_id (&curr_cfm->base, &manifest_id);
		if (status != 0) {
			goto exit;
		}

		status = curr_cfm->get_supported_component_ids (curr_cfm, &component_ids);
		if (status != 0) {
			goto exit;
		}

		id_length = component_ids.count * sizeof (uint32_t);

		if (offset >= id_length) {
			request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0;
			request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;

			goto cleanup_component_ids;
		}

		length = min (MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - sizeof (manifest_id), id_length - offset);

		request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;

		memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &manifest_id,
			sizeof (manifest_id));
		memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (manifest_id)],
			&((uint8_t*) component_ids.ids)[offset], length);

		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (manifest_id) + length;

	cleanup_component_ids:
		curr_cfm->free_component_ids (curr_cfm, &component_ids);
	}
	else {
		request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0;
		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	}

exit:
	cerberus_protocol_free_cfm (cfm_mgr, curr_cfm);
	return status;
}

#ifdef ENABLE_DEBUG_COMMANDS
/**
 * Process get device certificate packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Get device certificate request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_device_certificate (struct device_manager *device_mgr,
	struct cmd_interface_request *request)
{
	struct device_manager_cert_chain chain;
	uint8_t device_num;
	uint8_t cert_num;
	int status;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 3)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	device_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	cert_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2];

	status = device_manager_get_device_cert_chain (device_mgr, device_num, &chain);
	if (status != 0) {
		return status;
	}

	if (chain.num_cert <= cert_num) {
		return DEVICE_MGR_INVALID_CERT_NUM;
	}

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3], (uint8_t*) chain.cert[cert_num].cert,
		chain.cert[cert_num].length);

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + chain.cert[cert_num].length;
	return 0;
}

/**
 * Process get device certificate digest packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param hash Hash engine to utilize
 * @param request Get device certificate digest request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_device_cert_digest (struct device_manager *device_mgr,
	struct hash_engine *hash, struct cmd_interface_request *request)
{
	struct device_manager_cert_chain chain;
	uint8_t device_num;
	uint8_t cert_num;
	int status;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 3)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	device_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	cert_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2];

	status = device_manager_get_device_cert_chain (device_mgr, device_num, &chain);
	if (status != 0) {
		return status;
	}

	if (chain.num_cert <= cert_num) {
		return DEVICE_MGR_INVALID_CERT_NUM;
	}

	status = hash->calculate_sha256 (hash, chain.cert[cert_num].cert, chain.cert[cert_num].length,
		&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3], SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + SHA256_HASH_LENGTH;
	return 0;
}

/**
 * Process get device challenge packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param attestation Attestation manager instance to utilize
 * @param hash Hash engine to utilize
 * @param request Get device challenge request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_device_challenge (struct device_manager *device_mgr,
	struct attestation_master *attestation, struct hash_engine *hash,
	struct cmd_interface_request *request)
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

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1],
		attestation->challenge[device_num].nonce, ATTESTATION_NONCE_LEN);

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + ATTESTATION_NONCE_LEN;
	return 0;
}


/**
 * Process start attestation packet
 *
 * @param request Start attestation request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_start_attestation (struct cmd_interface_request *request)
{
	int status = 0;
	uint8_t device_num;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	device_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];

	status = (device_num << 16) | ((uint16_t) ATTESTATION_START_TEST_ESCAPE_SEQ);

	return status;
}

/**
 * Process get attestation state packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Attestation state request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_attestation_state (struct device_manager *device_mgr,
	struct cmd_interface_request *request)
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
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request->data;
	uint8_t command_id;
	uint8_t num_digests;
	int status = 0;

	request->crypto_timeout = true;

	num_digests = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1];

	if (request->length !=
		(CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + num_digests * SHA256_HASH_LENGTH)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	digests.num_cert = num_digests;
	digests.digest = &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2];
	digests.digest_len = SHA256_HASH_LENGTH;

	status = attestation->compare_digests (attestation, request->source_eid, &digests);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if (status != 0) {
		cert_params.slot_num = ATTESTATION_RIOT_SLOT_NUM;
		cert_params.cert_num = status - 1;

		command_id = CERBERUS_PROTOCOL_GET_CERTIFICATE;

		status = cerberus_protocol_issue_get_certificate (&cert_params,
			&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
			MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	}
	else {
		challenge_params.slot_num = ATTESTATION_RIOT_SLOT_NUM;
		challenge_params.eid = request->source_eid;

		command_id = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

		status = cerberus_protocol_issue_challenge (attestation, &challenge_params,
			&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
			MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	}

	if ROT_IS_ERROR (status) {
		return status;
	}

	request->new_request = true;
	header->command = command_id;
	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + status;
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
	uint8_t slot_num;
	uint8_t cert_num;
	int status;

	if (request->length <= (CERBERUS_PROTOCOL_MIN_MSG_LEN + 2)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	slot_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	cert_num = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1];

	status = attestation->store_certificate (attestation,
		request->source_eid, slot_num, cert_num, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2],
		request->length - (CERBERUS_PROTOCOL_MIN_MSG_LEN + 2));
	if (status != 0) {
		return status;
	}

	request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1] = CERBERUS_PROTOCOL_GET_DIGEST;

	status = cerberus_protocol_issue_get_certificate_digest (attestation,
		&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN);
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

/**
 * Process PCD ID packet
 *
 * @param pcd_mgr PCD manager instance to utilize
 * @param request Get PCD ID request to process
 *
 * @return Response length if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pcd_id (struct pcd_manager *pcd_mgr,
	struct cmd_interface_request *request)
{
	struct pcd *curr_pcd = NULL;
	uint32_t manifest_id;
	int status = 0;

	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (pcd_mgr == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}
	else {
		curr_pcd = pcd_mgr->get_active_pcd (pcd_mgr);

		if (curr_pcd == NULL) {
			request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0;
		}
		else {
			status = curr_pcd->base.get_id (&curr_pcd->base, &manifest_id);

			if (status != 0) {
				goto exit;
			}

			request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
			memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &manifest_id,
				sizeof (manifest_id));
		}
	}

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (manifest_id);

exit:
	cerberus_protocol_free_pcd (pcd_mgr, curr_pcd);

	return status;
}
