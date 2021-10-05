// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common/certificate.h"
#include "common/common_math.h"
#include "attestation/attestation_slave.h"
#include "mctp/mctp_logging.h"
#include "cerberus_protocol.h"
#include "cmd_interface.h"
#include "cmd_background.h"
#include "cmd_logging.h"
#include "device_manager.h"
#include "session_manager.h"
#include "cerberus_protocol_required_commands.h"


/**
 * Process FW version request
 *
 * @param fw_version The firmware version data
 * @param request FW version request to process
 *
 * @return 0 if request processed successfully or an error code.
 */
int cerberus_protocol_get_fw_version (struct cmd_interface_fw_version *fw_version,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_fw_version *rq =
		(struct cerberus_protocol_get_fw_version*) request->data;
	struct cerberus_protocol_get_fw_version_response *rsp =
		(struct cerberus_protocol_get_fw_version_response*) request->data;
	uint8_t area;

	if (request->length != sizeof (struct cerberus_protocol_get_fw_version)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->area >= fw_version->count) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	area = rq->area;
	memset (&rsp->version, 0, sizeof (rsp->version));

	if (fw_version->id[area] != NULL) {
		strncpy (rsp->version, fw_version->id[area], sizeof (rsp->version));
	}

	request->length = sizeof (struct cerberus_protocol_get_fw_version_response);
	return 0;
}

/**
 * Process get certificate digest request
 *
 * @param attestation Attestation manager instance to utilize
 * @param session Session manager instance to utilize
 * @param request Get certificate digest request to process
 *
 * @return 0 if input processed successfully or an error code.
 */
int cerberus_protocol_get_certificate_digest (struct attestation_slave *attestation,
	struct session_manager *session, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_certificate_digest *rq =
		(struct cerberus_protocol_get_certificate_digest*) request->data;
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) request->data;
	uint8_t num_cert = 0;
	int status = 0;

	request->crypto_timeout = true;

	if (request->length != sizeof (struct cerberus_protocol_get_certificate_digest)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->slot_num > ATTESTATION_MAX_SLOT_NUM) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (rq->key_alg >= NUM_ATTESTATION_KEY_EXCHANGE_ALGORITHMS) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (rq->key_alg != ATTESTATION_KEY_EXCHANGE_NONE) {
		if (session == NULL) {
			return CMD_HANDLER_UNSUPPORTED_OPERATION;
		}

		if (rq->header.crypt == 0) {
			session->reset_session (session, request->source_eid, NULL, 0);
		}
	}

	attestation->key_exchange_algorithm = rq->key_alg;

	status = attestation->get_digests (attestation, rq->slot_num,
		cerberus_protocol_certificate_digests (rsp), CERBERUS_PROTOCOL_MAX_CERT_DIGESTS (request),
		&num_cert);
	if (!ROT_IS_ERROR (status)) {
		rsp->capabilities = 1;
		rsp->num_digests = num_cert;
		request->length = cerberus_protocol_get_certificate_digest_response_length (status);
		status = 0;
	}
	else if ((status == ATTESTATION_INVALID_SLOT_NUM) ||
		(status == ATTESTATION_CERT_NOT_AVAILABLE)) {
		rsp->capabilities = 1;
		rsp->num_digests = 0;
		request->length = cerberus_protocol_get_certificate_digest_response_length (0);
		status = 0;
	}

	return status;
}

/**
 * Process get certificate request
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Get certificate request to process
 *
 * @return 0 if request processed successfully or an error code.
 */
int cerberus_protocol_get_certificate (struct attestation_slave *attestation,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_certificate *rq =
		(struct cerberus_protocol_get_certificate*) request->data;
	struct cerberus_protocol_get_certificate_response *rsp =
		(struct cerberus_protocol_get_certificate_response*) request->data;
	struct der_cert cert;
	uint8_t slot_num;
	uint8_t cert_num;
	uint16_t offset;
	uint16_t length;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_get_certificate)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	slot_num = rq->slot_num;
	cert_num = rq->cert_num;
	length = rq->length;
	offset = rq->offset;

	if (slot_num > ATTESTATION_MAX_SLOT_NUM) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	status = attestation->get_certificate (attestation, slot_num, cert_num, &cert);
	if ((status != 0) && (status != ATTESTATION_INVALID_SLOT_NUM) &&
		(status != ATTESTATION_INVALID_CERT_NUM) && (status != ATTESTATION_CERT_NOT_AVAILABLE)) {
		return status;
	}

	if (status == 0) {
		if (offset < cert.length) {
			if ((length == 0) || (length > CERBERUS_PROTOCOL_MAX_CERT_DATA (request))) {
				length = CERBERUS_PROTOCOL_MAX_CERT_DATA (request);
			}

			length = min (length, cert.length - offset);
			memcpy (cerberus_protocol_certificate (rsp), &cert.cert[offset], length);
		}
		else {
			length = 0;
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_NO_CERT, (slot_num << 8) | cert_num, status);

		length = 0;
	}

	rsp->slot_num = slot_num;
	rsp->cert_num = cert_num;

	request->length = cerberus_protocol_get_certificate_response_length (length);
	return 0;
}

/**
 * Process challenge request
 *
 * @param attestation Attestation manager instance to utilize
 * @param session Session manager instance to utilize if initialized
 * @param request Challenge request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_challenge_response (struct attestation_slave *attestation,
	struct session_manager *session, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_challenge *rq = (struct cerberus_protocol_challenge*) request->data;
	struct cerberus_protocol_challenge_response *rsp =
		(struct cerberus_protocol_challenge_response*) request->data;
	uint8_t device_nonce[ATTESTATION_NONCE_LEN];
	int status;

	request->crypto_timeout = true;

	if (request->length != sizeof (struct cerberus_protocol_challenge)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	memcpy (device_nonce, rq->challenge.nonce, sizeof (device_nonce));

	status = attestation->challenge_response (attestation, (uint8_t*) &rq->challenge,
		request->max_response - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	if (!ROT_IS_ERROR (status)) {
		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + status;
		status = 0;

		if ((session != NULL) &&
			(attestation->key_exchange_algorithm == ATTESTATION_ECDHE_KEY_EXCHANGE)) {
			session->add_session (session, request->source_eid, device_nonce, rsp->challenge.nonce);
		}
	}

	return status;
}

/**
 * Process a CSR request
 *
 * @param riot RIoT key manager to utilize
 * @param request Export CSR request to process
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_export_csr (struct riot_key_manager *riot,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_export_csr *rq = (struct cerberus_protocol_export_csr*) request->data;
	struct cerberus_protocol_export_csr_response *rsp =
		(struct cerberus_protocol_export_csr_response*) request->data;
	const struct riot_keys *keys;
	int status = 0;

	if (request->length != sizeof (struct cerberus_protocol_export_csr)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->index != 0) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	keys = riot_key_manager_get_riot_keys (riot);
	if (keys == NULL) {
		return CMD_HANDLER_PROCESS_FAILED;
	}

	if (keys->devid_csr_length > CERBERUS_PROTOCOL_LOCAL_MAX_CSR_DATA) {
		status = CMD_HANDLER_BUF_TOO_SMALL;
		goto exit;
	}
	else if (keys->devid_csr_length > CERBERUS_PROTOCOL_MAX_CSR_DATA (request)) {
		status = CMD_HANDLER_RESPONSE_TOO_SMALL;
		goto exit;
	}

	memcpy (&rsp->csr, keys->devid_csr, keys->devid_csr_length);
	request->length = cerberus_protocol_export_csr_response_length (keys->devid_csr_length);

exit:
	riot_key_manager_release_riot_keys (riot, keys);
	return status;
}

/**
 * Import a signed certificate
 *
 * @param riot RIoT key manager to utilize
 * @param background Background handler context for certificate authentication
 * @param request Import certificate request to process
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_import_ca_signed_cert (struct riot_key_manager *riot,
	struct cmd_background *background, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_import_certificate *rq =
		(struct cerberus_protocol_import_certificate*) request->data;
	int min_length =
		sizeof (struct cerberus_protocol_import_certificate) - sizeof (rq->certificate);
	int status;

	request->crypto_timeout = true;

	if (request->length < sizeof (struct cerberus_protocol_import_certificate)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((rq->cert_length == 0) || ((int) request->length != (min_length + rq->cert_length))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (rq->index) {
		case 0:
			status = riot_key_manager_store_signed_device_id (riot, &rq->certificate,
				rq->cert_length);
			break;

		case 1:
			status = riot_key_manager_store_root_ca (riot, &rq->certificate, rq->cert_length);
			break;

		case 2:
			status = riot_key_manager_store_intermediate_ca (riot, &rq->certificate,
				rq->cert_length);
			break;

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (status != 0) {
		return status;
	}

	status = background->authenticate_riot_certs (background);
	if (status != 0) {
		return status;
	}

	request->length = 0;
	return 0;
}

/**
 * Process a request to get the current state of signed RIoT certificates.
 *
 * @param background Background context that contains the necessary state information.
 * @param request State request to process.
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_get_signed_cert_state (struct cmd_background *background,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_certificate_state_response *rsp =
		(struct cerberus_protocol_get_certificate_state_response*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_get_certificate_state)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	rsp->cert_state = background->get_riot_cert_chain_state (background);

	request->length = sizeof (struct cerberus_protocol_get_certificate_state_response);
	return 0;
}

/**
 * Process get device capabilities request
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Capabilities request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_device_capabilities (struct device_manager *device_mgr,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_device_capabilities *rq =
		(struct cerberus_protocol_device_capabilities*) request->data;
	struct cerberus_protocol_device_capabilities_response *rsp =
		(struct cerberus_protocol_device_capabilities_response*) request->data;
	int device_num;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_device_capabilities)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	device_num = device_manager_get_device_num (device_mgr, request->source_eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	status = device_manager_update_device_capabilities_request (device_mgr, device_num,
		&rq->capabilities);
	if (status != 0) {
		return status;
	}

	status = device_manager_get_device_capabilities (device_mgr, DEVICE_MANAGER_SELF_DEVICE_NUM,
		&rsp->capabilities);
	if (status != 0) {
		return status;
	}

	request->length = sizeof (struct cerberus_protocol_device_capabilities_response);
	return 0;
}

/**
 * Process device info request
 *
 * @param device The device command handler to query the device information
 * @param request Device info request to process
 *
 * @return 0 if request processed successfully or an error code.
 */
int cerberus_protocol_get_device_info (struct cmd_device *device,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_device_info *rq =
		(struct cerberus_protocol_get_device_info*) request->data;
	struct cerberus_protocol_get_device_info_response *rsp =
		(struct cerberus_protocol_get_device_info_response*) request->data;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_get_device_info)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->info_index != 0) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = device->get_uuid (device, &rsp->info, CERBERUS_PROTOCOL_MAX_DEV_INFO_DATA (request));
	if (!ROT_IS_ERROR (status)) {
		request->length = cerberus_protocol_get_device_info_response_length (status);
		status = 0;
	}

	return status;
}

/**
 * Process device ID request
 *
 * @param id Device ID data
 * @param request Device ID request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_device_id (struct cmd_interface_device_id *id,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_device_id_response *rsp =
		(struct cerberus_protocol_get_device_id_response*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_get_device_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	rsp->vendor_id = id->vendor_id;
	rsp->device_id = id->device_id;
	rsp->subsystem_vid = id->subsystem_vid;
	rsp->subsystem_id = id->subsystem_id;

	request->length = sizeof (struct cerberus_protocol_get_device_id_response);
	return 0;
}

/**
 * Process reset counter request
 *
 * @param device The device command handler to query the counter data
 * @param request Reset counter request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_reset_counter (struct cmd_device *device,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_reset_counter *rq =
		(struct cerberus_protocol_reset_counter*) request->data;
	struct cerberus_protocol_reset_counter_response *rsp =
		(struct cerberus_protocol_reset_counter_response*) request->data;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_reset_counter)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = device->get_reset_counter (device, rq->type, rq->port, &rsp->counter);
	if (status != 0) {
		return status;
	}

	request->length = sizeof (struct cerberus_protocol_reset_counter_response);
	return 0;
}

/**
 * Process an error response
 *
 * @param response Error response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int cerberus_protocol_process_error_response (struct cmd_interface_msg *response)
{
	struct cerberus_protocol_error *error_msg = (struct cerberus_protocol_error*) response->data;

	if (response->length >= sizeof (struct cerberus_protocol_error)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_CHANNEL, response->channel_id, 0);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_ERROR_MESSAGE, (error_msg->error_code << 24 | response->source_eid << 16 |
			response->target_eid << 8),	error_msg->error_data);
	}
	else {
		return CMD_HANDLER_INVALID_ERROR_MSG;
	}

	return 0;
}
