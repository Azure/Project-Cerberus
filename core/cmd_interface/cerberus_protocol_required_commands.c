// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common/certificate.h"
#include "common/common_math.h"
#include "attestation/attestation_slave.h"
#include "cerberus_protocol.h"
#include "cmd_interface.h"
#include "cmd_background.h"
#include "device_manager.h"
#include "cerberus_protocol_required_commands.h"


/**
 * Process FW version packet
 *
 * @param fw_version The firmware version data
 * @param request FW version request to process
 *
 * @return 0 if packet processed successfully or an error code.
 */
int cerberus_protocol_get_fw_version (struct cmd_interface_fw_version *fw_version,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_fw_version_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (rsp,
		struct cerberus_protocol_get_fw_version_response_packet*, request);
	uint8_t area;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->area >= fw_version->count) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	area = rq->area;
	memset (&rsp->version, 0, CERBERUS_PROTOCOL_FW_VERSION_LEN);

	if (fw_version->id[area] != NULL) {
		strncpy (rsp->version, fw_version->id[area], CERBERUS_PROTOCOL_FW_VERSION_LEN);
	}

	request->length = CERBERUS_PROTOCOL_FW_VERSION_LEN + CERBERUS_PROTOCOL_MIN_MSG_LEN;
	return 0;
}

/**
 * Process get certificate digest packet
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Get certificate digest request to process
 *
 * @return 0 if input processed successfully or an error code.
 */
int cerberus_protocol_get_certificate_digest (struct attestation_slave *attestation,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_certificate_digest_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (rsp,
		struct cerberus_protocol_get_certificate_digest_response_header*, request);
	uint8_t num_cert = 0;
	int status = 0;

	request->crypto_timeout = true;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_digest_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->key_alg != ATTESTATION_ECDHE_KEY_EXCHANGE) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = attestation->get_digests (attestation, request->data + CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_digest_response_header),
		MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_digest_response_header), &num_cert);
	if (!ROT_IS_ERROR (status)) {
		rsp->capabilities = 1;
		rsp->num_digests = num_cert;
		request->length = CERBERUS_PROTOCOL_CMD_LEN (
			struct cerberus_protocol_get_certificate_digest_response_header) + status;
		status = 0;
	}

	return status;
}

/**
 * Process get certificate packet
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Get certificate request to process
 *
 * @return 0 if request processed successfully or an error code.
 */
int cerberus_protocol_get_certificate (struct attestation_slave *attestation,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_certificate_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (hdr, struct cerberus_protocol_get_certificate_response_header*, request);
	struct der_cert cert;
	uint8_t slot_num;
	uint8_t cert_num;
	const uint16_t max_length = MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header);
	uint16_t offset;
	uint16_t length;
	int status;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	slot_num = rq->slot_num;
	cert_num = rq->cert_num;
	length = rq->length;
	offset = rq->offset;

	if (slot_num >= NUM_ATTESTATION_SLOT_NUM) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = attestation->get_certificate (attestation, slot_num, cert_num, &cert);
	if (status != 0) {
		return status;
	}

	if (offset >= cert.length) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if ((length == 0) || (length > max_length)) {
		length = max_length;
	}

	length = min (length, cert.length - offset);

	hdr->slot_num = slot_num;
	hdr->cert_num = cert_num;

	memcpy (request->data + CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header), &cert.cert[offset], length);

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header) + length;
	return 0;
}

/**
 * Process challenge packet
 *
 * @param attestation Attestation manager instance to utilize
 * @param request Challenge request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_challenge_response (struct attestation_slave *attestation,
	struct cmd_interface_request *request)
{
	int status;

	request->crypto_timeout = true;

	if (request->length !=
		(CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (struct attestation_challenge))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = attestation->challenge_response (attestation, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	if (!ROT_IS_ERROR (status)) {
		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + status;
		status = 0;
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
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_export_csr_request_packet*, request);
	const struct riot_keys *keys;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_export_csr_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->index != 0) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	keys = riot_key_manager_get_riot_keys (riot);
	if (keys == NULL) {
		return CMD_HANDLER_PROCESS_FAILED;
	}

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], keys->devid_csr, keys->devid_csr_length);

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + keys->devid_csr_length;

	riot_key_manager_release_riot_keys (riot, keys);
	return 0;
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
	struct cmd_background *background, struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		request);
	int min_length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) - 1;
	int status;

	request->crypto_timeout = true;

	if (request->length < min_length) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((rq->cert_length == 0) || (request->length != (min_length + rq->cert_length))) {
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
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_certificate_state_response_packet*,
		request);

	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	rsp->cert_state = background->get_riot_cert_chain_state (background);

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_state_response_packet);
	return 0;
}

/**
 * Construct get device capabilities packet.
 *
 * @param device_mgr Device manager instance to utilize.
 * @param buf The buffer containing the generated packet.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated packet if the request was successfully constructed or an
 * error code.
 */
int cerberus_protocol_issue_get_device_capabilities (struct device_manager *device_mgr,
	uint8_t *buf, int buf_len)
{
	int status;

	if (buf_len < (sizeof (struct device_manager_capabilities))) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	status = device_manager_get_device_capabilities (device_mgr, 0,
		(struct device_manager_capabilities*) buf);

	if ROT_IS_ERROR (status) {
		return status;
	}

	return sizeof (struct device_manager_capabilities);
}

/**
 * Process get device capabilities packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Capabilities request to process
 * @param device_num Index of source device
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_device_capabilities (struct device_manager *device_mgr,
	struct cmd_interface_request *request, uint8_t device_num)
{
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_device_capabilities_response*,	request);
	int status;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_device_capabilities)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = device_manager_update_device_capabilities (device_mgr, device_num, &rsp->capabilities);
	if (status != 0) {
		return status;
	}

	status = device_manager_get_device_capabilities (device_mgr, 0, &rsp->capabilities);
	if (status != 0) {
		return status;
	}

	rsp->max_timeout = MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	rsp->max_sig = MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_device_capabilities_response);
	return 0;
}

/**
 * Process device info packet
 *
 * @param device The device command handler to query the device information
 * @param request Device info request to process
 *
 * @return 0 if packet processed successfully or an error code.
 */
int cerberus_protocol_get_device_info (struct cmd_device *device,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_device_info_request_packet*, request);
	int status;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_device_info_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->info != 0) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = device->get_uuid (device, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG);
	if (!ROT_IS_ERROR (status)) {
		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + status;
		status = 0;
	}

	return status;
}

/**
 * Process device ID packet
 *
 * @param id Device ID data
 * @param request Device ID request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_device_id (struct cmd_interface_device_id *id,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rsp,
		struct cerberus_protocol_get_device_id_response_packet*, request);

	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	rsp->vendor_id = id->vendor_id;
	rsp->device_id = id->device_id;
	rsp->subsystem_vid = id->subsystem_vid;
	rsp->subsystem_id = id->subsystem_id;

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_device_id_response_packet);
	return 0;
}

/**
 * Process reset counter packet
 * 
 * @param device The device command handler to query the counter data
 * @param request Reset counter request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_reset_counter (struct cmd_device *device,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_reset_counter_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_reset_counter_response_packet*, request);
	int status;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_reset_counter_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = device->get_reset_counter (device, rq->type, rq->port, &rsp->counter);
	if (status == 0) {
		request->length = CERBERUS_PROTOCOL_CMD_LEN (
			struct cerberus_protocol_reset_counter_response_packet);
	}

	return status;
}
