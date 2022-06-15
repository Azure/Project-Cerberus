// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "attestation/attestation_responder.h"
#include "cmd_interface/device_manager.h"
#include "common/common_math.h"
#include "crypto/hash.h"
#include "crypto/ecc.h"
#include "riot/riot_key_manager.h"
#include "cmd_interface_spdm.h"
#include "spdm_logging.h"
#include "spdm_commands.h"


/**
 * Generate the header segment of a SPDM protocol request
 *
 * @param header Buffer to fill with SPDM protocol header
 * @param command Command ID to utilize in header
 * @param spdm_minor_version SPDM minor version to utilize in header
 */
void spdm_populate_header (struct spdm_protocol_header *header, uint8_t command,
	uint8_t spdm_minor_version)
{
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	header->integrity_check = 0;
	header->spdm_minor_version = spdm_minor_version;
	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = command;
}

/**
 * Construct an SPDM error response.
 *
 * @param response Container to populate with SPDM error response
 * @param spdm_minor_version SPDM minor version to utilize in header
 * @param error_code Error code
 * @param error_data Error data
 * @param optional_data Buffer containing optional data, can be set to NULL if not needed
 * @param optional_data_len Optional data buffer length
 * @param req_code SPDM request code in failed request received
 * @param internal_error_code Internal error code to include in debug log entry
 */
void spdm_generate_error_response (struct cmd_interface_msg *response, uint8_t spdm_minor_version,
	uint8_t error_code, uint8_t error_data, uint8_t *optional_data, size_t optional_data_len,
	uint8_t req_code, int internal_error_code)
{
	struct spdm_error_response *rsp = (struct spdm_error_response*) response->data;
	size_t response_length = sizeof (struct spdm_error_response) + optional_data_len;

	memset (rsp, 0, sizeof (struct spdm_error_response));

	spdm_populate_header (&rsp->header, SPDM_RESPONSE_ERROR, spdm_minor_version);

	rsp->error_code = error_code;
	rsp->error_data = error_data;

	response->length = sizeof (struct spdm_error_response);

	if ((optional_data_len > 0) && (response_length <= response->max_response)) {
		memcpy (spdm_get_spdm_error_rsp_optional_data (rsp), optional_data, optional_data_len);
		response->length += optional_data_len;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SPDM,
		SPDM_LOGGING_ERR_MSG,
		(req_code << 24 | response->source_eid << 16 | error_code << 8 | error_data),
		internal_error_code);
}

/**
 * Process SPDM get version request
 *
 * @param request Get version request to process
 * @param hash Hashing engine to utilize. Must be same engine used in other SPDM commands for
 * 	transcript hashing, and must be independent of other hash instances.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_get_version (struct cmd_interface_msg *request, struct hash_engine *hash)
{
	struct spdm_get_version_request *rq;
	struct spdm_get_version_response *rsp;
	struct spdm_version_num_entry *version_num;
	uint8_t minor_version;
	int i_version;
	int status;

	if ((request == NULL) || (hash == NULL)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	rq = (struct spdm_get_version_request*) request->data;
	rsp = (struct spdm_get_version_response*) request->data;
	version_num = spdm_get_version_resp_version_table (rsp);

	if (request->length != sizeof (struct spdm_get_version_request)) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	status = hash->start_sha256 (hash);
	if (status != 0) {
		goto send_unspecified_error;
	}

	// TODO: Move hashing to cmd_interface_spdm_process_request
	status = hash->update (hash, (uint8_t*) rq, sizeof (struct spdm_get_version_request));
	if (status != 0) {
		goto hash_cancel;
	}

	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	rsp->reserved = 0;
	rsp->reserved2 = 0;
	rsp->reserved3 = 0;

	for (i_version = 0, minor_version = SPDM_MIN_MINOR_VERSION;
		minor_version <= SPDM_MAX_MINOR_VERSION; ++i_version, ++minor_version) {
		version_num[i_version].major_version = SPDM_MAJOR_VERSION;
		version_num[i_version].minor_version = minor_version;
		version_num[i_version].update_version = 0;
		version_num[i_version].alpha = 0;
	}

	rsp->version_num_entry_count = i_version;

	request->length = spdm_get_version_resp_length (rsp);

	// TODO: Move hashing to cmd_interface_spdm_process_request
	status = hash->update (hash, (uint8_t*) rsp, spdm_get_version_resp_length (rsp));
	if (status != 0) {
		goto hash_cancel;
	}

	return 0;

hash_cancel:
	hash->cancel (hash);

send_unspecified_error:
	spdm_generate_error_response (request, rq->header.spdm_minor_version, SPDM_ERROR_UNSPECIFIED,
		0x00, NULL, 0, SPDM_REQUEST_GET_VERSION, status);

	return 0;
}

/**
 * Construct SPDM get version request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_get_version_request (uint8_t *buf, size_t buf_len)
{
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;

	if (buf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct spdm_get_version_request)) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, sizeof (struct spdm_get_version_request));

	spdm_populate_header (&rq->header, SPDM_REQUEST_GET_VERSION, 0);

	return sizeof (struct spdm_get_version_request);
}

/**
 * Process a SPDM get version response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_get_version_response (struct cmd_interface_msg *response)
{
	struct spdm_get_version_response *resp;

	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	resp = (struct spdm_get_version_response*) response->data;

	if ((response->length < sizeof (struct spdm_get_version_response)) ||
		(response->length != spdm_get_version_resp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Process SPDM get capabilities request
 *
 * @param request Get capabilities request to process
 * @param device_mgr Device manager instance to utilize
 * @param hash Hashing engine to utilize. Must be same engine used in other SPDM commands for
 * 	transcript hashing, and must be independent of other hash instances.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_get_capabilities (struct cmd_interface_msg *request, struct device_manager *device_mgr,
	struct hash_engine *hash)
{
	struct spdm_get_capabilities *rq;
	struct device_manager_full_capabilities capabilities;
	int device_num;
	int status;

	if ((request == NULL) || (device_mgr == NULL) || (hash == NULL)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	rq = (struct spdm_get_capabilities*) request->data;

	if (request->length < sizeof (struct spdm_get_capabilities_1_1)) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	if (rq->base_capabilities.header.spdm_minor_version == 1) {
		if (request->length != sizeof (struct spdm_get_capabilities_1_1)) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}
	}
	else {
		if (request->length != sizeof (struct spdm_get_capabilities)) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}
	}

	device_num = device_manager_get_device_num (device_mgr, request->source_eid);
	if (ROT_IS_ERROR (device_num)) {
		status = device_num;
		goto send_unspecified_error;
	}

	status = device_manager_get_device_capabilities (device_mgr, device_num, &capabilities);
	if (status != 0) {
		goto send_unspecified_error;
	}

	// TODO: Move hashing to cmd_interface_spdm_process_request
	status = hash->update (hash, (uint8_t*) rq, request->length);
	if (status != 0) {
		goto send_unspecified_error;
	}

	// Limit maximum cryptographic timeout period of requester to prevent overflows
	if (rq->base_capabilities.ct_exponent > 24) {
		rq->base_capabilities.ct_exponent = 24;
	}

	capabilities.max_timeout = device_manager_set_timeout_ms (SPDM_MAX_RESPONSE_TIMEOUT_MS);
	capabilities.max_sig = device_manager_set_crypto_timeout_ms (
		spdm_capabilities_rsp_ct_to_ms (rq->base_capabilities.ct_exponent));

	if (rq->base_capabilities.header.spdm_minor_version > 1) {
		capabilities.request.max_message_size = rq->data_transfer_size;
	}

	status = device_manager_update_device_capabilities (device_mgr, device_num, &capabilities);
	if (status != 0) {
		goto send_unspecified_error;
	}

	rq->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	rq->base_capabilities.reserved = 0;
	rq->base_capabilities.reserved2 = 0;
	rq->base_capabilities.reserved3 = 0;
	rq->base_capabilities.ct_exponent = SPDM_CT_EXPONENT;
	rq->base_capabilities.reserved4 = 0;

	rq->base_capabilities.flags.cache_cap = SPDM_RESPONDER_CACHE_CAP;
	rq->base_capabilities.flags.cert_cap = SPDM_RESPONDER_CERT_CAP;
	rq->base_capabilities.flags.chal_cap = SPDM_RESPONDER_CHAL_CAP;
	rq->base_capabilities.flags.meas_cap = SPDM_RESPONDER_MEAS_CAP;
	rq->base_capabilities.flags.meas_fresh_cap = SPDM_RESPONDER_MEAS_FRESH_CAP;
	rq->base_capabilities.flags.encrypt_cap = SPDM_RESPONDER_ENCRYPT_CAP;
	rq->base_capabilities.flags.mac_cap = SPDM_RESPONDER_MAC_CAP;
	rq->base_capabilities.flags.mut_auth_cap = SPDM_RESPONDER_MUT_AUTH_CAP;
	rq->base_capabilities.flags.key_ex_cap = SPDM_RESPONDER_KEY_EX_CAP;
	rq->base_capabilities.flags.psk_cap = SPDM_RESPONDER_PSK_CAP;
	rq->base_capabilities.flags.encap_cap = SPDM_RESPONDER_ENCAP_CAP;
	rq->base_capabilities.flags.hbeat_cap = SPDM_RESPONDER_HBEAT_CAP;
	rq->base_capabilities.flags.key_upd_cap = SPDM_RESPONDER_KEY_UPD_CAP;
	rq->base_capabilities.flags.handshake_in_the_clear_cap =
		SPDM_RESPONDER_HANDSHAKE_IN_THE_CLEAR_CAP;
	rq->base_capabilities.flags.pub_key_id_cap = SPDM_RESPONDER_PUB_KEY_ID_CAP;
	rq->base_capabilities.flags.chunk_cap = SPDM_RESPONDER_CHUNK_CAP;
	rq->base_capabilities.flags.alias_cert_cap = SPDM_RESPONDER_ALIAS_CERT_CAP;

	if (rq->base_capabilities.header.spdm_minor_version < 2) {
		request->length = sizeof (struct spdm_get_capabilities_1_1);
	}
	else {
		rq->data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
		rq->max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

		request->length = sizeof (struct spdm_get_capabilities);
	}

	// TODO: Move hashing to cmd_interface_spdm_process_request
	status = hash->update (hash, (uint8_t*) rq, request->length);
	if (status != 0) {
		goto send_unspecified_error;
	}

	return 0;

send_unspecified_error:
	spdm_generate_error_response (request, rq->base_capabilities.header.spdm_minor_version,
		SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES, status);

	hash->cancel (hash);

	return 0;
}

/**
 * Construct SPDM get capabilities request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_get_capabilities_request (uint8_t *buf, size_t buf_len,
	uint8_t spdm_minor_version)
{
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;

	if (buf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (spdm_minor_version < 2) {
		if (buf_len < sizeof (struct spdm_get_capabilities_1_1)) {
			return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
		}
	}
	else {
		if (buf_len < sizeof (struct spdm_get_capabilities)) {
			return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
		}
	}

	memset (rq, 0, sizeof (struct spdm_get_capabilities));

	spdm_populate_header (&rq->base_capabilities.header, SPDM_REQUEST_GET_CAPABILITIES,
		spdm_minor_version);

	rq->base_capabilities.ct_exponent = SPDM_CT_EXPONENT;

	rq->base_capabilities.flags.cache_cap = SPDM_REQUESTER_CACHE_CAP;
	rq->base_capabilities.flags.cert_cap = SPDM_REQUESTER_CERT_CAP;
	rq->base_capabilities.flags.chal_cap = SPDM_REQUESTER_CHAL_CAP;
	rq->base_capabilities.flags.meas_cap = SPDM_REQUESTER_MEAS_CAP;
	rq->base_capabilities.flags.meas_fresh_cap = SPDM_REQUESTER_MEAS_FRESH_CAP;
	rq->base_capabilities.flags.encrypt_cap = SPDM_REQUESTER_ENCRYPT_CAP;
	rq->base_capabilities.flags.mac_cap = SPDM_REQUESTER_MAC_CAP;
	rq->base_capabilities.flags.mut_auth_cap = SPDM_REQUESTER_MUT_AUTH_CAP;
	rq->base_capabilities.flags.key_ex_cap = SPDM_REQUESTER_KEY_EX_CAP;
	rq->base_capabilities.flags.psk_cap = SPDM_REQUESTER_PSK_CAP;
	rq->base_capabilities.flags.encap_cap = SPDM_REQUESTER_ENCAP_CAP;
	rq->base_capabilities.flags.hbeat_cap = SPDM_REQUESTER_HBEAT_CAP;
	rq->base_capabilities.flags.key_upd_cap = SPDM_REQUESTER_KEY_UPD_CAP;
	rq->base_capabilities.flags.handshake_in_the_clear_cap =
		SPDM_REQUESTER_HANDSHAKE_IN_THE_CLEAR_CAP;
	rq->base_capabilities.flags.pub_key_id_cap = SPDM_REQUESTER_PUB_KEY_ID_CAP;
	rq->base_capabilities.flags.chunk_cap = SPDM_REQUESTER_CHUNK_CAP;
	rq->base_capabilities.flags.alias_cert_cap = SPDM_REQUESTER_ALIAS_CERT_CAP;

	if (spdm_minor_version < 2) {
		return sizeof (struct spdm_get_capabilities_1_1);
	}
	else {
		rq->data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
		rq->max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

		return sizeof (struct spdm_get_capabilities);
	}
}

/**
 * Process a SPDM get capabilities response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_get_capabilities_response (struct cmd_interface_msg *response)
{
	struct spdm_get_capabilities *resp;

	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	resp = (struct spdm_get_capabilities*) response->data;

	if (resp->base_capabilities.header.spdm_minor_version < 2) {
		if (response->length != sizeof (struct spdm_get_capabilities_1_1)) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}
	}
	else {
		if (response->length != sizeof (struct spdm_get_capabilities)) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}
	}

	return 0;
}

/**
 * Process SPDM negotiate algorithms request
 *
 * @param request Negotiate algorithms request to process
 * @param hash Hashing engine to utilize. Must be same engine used in other SPDM commands for
 * 	transcript hashing, and must be independent of other hash instances.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_negotiate_algorithms (struct cmd_interface_msg *request, struct hash_engine *hash)
{
	struct spdm_negotiate_algorithms_request *req;
	struct spdm_negotiate_algorithms_response *resp;
	struct spdm_algorithm_request *algstruct_table;
	size_t i_algstruct;
	size_t offset;
	int status;

	if ((request == NULL) || (hash == NULL)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	req = (struct spdm_negotiate_algorithms_request*) request->data;
	resp = (struct spdm_negotiate_algorithms_response*) request->data;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table (req);

	if ((request->length < sizeof (struct spdm_negotiate_algorithms_request)) ||
		(request->length != ((size_t) (req->length + 1))) ||
		(request->length < spdm_negotiate_algorithms_min_req_length (req))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	offset = spdm_negotiate_algorithms_min_req_length (req);

	for (i_algstruct = 0; i_algstruct < req->num_alg_structure_tables; ++ i_algstruct) {
		if (request->length <
			(offset + algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm))) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}

		algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
			algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm));
		offset += (algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm));
	}

	if ((req->measurement_specification & SPDM_MEASUREMENT_SPEC_DMTF) == 0) {
		spdm_generate_error_response (request, req->header.spdm_minor_version,
			SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS,
			CMD_HANDLER_SPDM_UNSUPPORTED_MEAS_SPEC);

		goto hash_cancel;
	}

	if ((req->base_asym_algo & SPDM_TPM_ALG_ECDSA_ECC_NIST_P256) == 0) {
		spdm_generate_error_response (request, req->header.spdm_minor_version,
			SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS,
			CMD_HANDLER_SPDM_UNSUPPORTED_ASYM_ALGO);

		goto hash_cancel;
	}

	if ((req->base_hash_algo & SPDM_TPM_ALG_SHA_256) == 0) {
		spdm_generate_error_response (request, req->header.spdm_minor_version,
			SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS,
			CMD_HANDLER_SPDM_UNSUPPORTED_HASH_ALGO);

		goto hash_cancel;
	}

	// TODO: Move hashing to cmd_interface_spdm_process_request
	status = hash->update (hash, (uint8_t*) req, request->length);
	if (status != 0) {
		spdm_generate_error_response (request, req->header.spdm_minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, status);

		goto hash_cancel;
	}

	resp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	resp->num_alg_structure_tables = 0;
	resp->reserved = 0;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1;
	resp->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	resp->reserved2 = 0;
	resp->measurement_hash_algo = SPDM_TPM_ALG_SHA_256;
	resp->base_asym_sel = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	resp->base_hash_sel = SPDM_TPM_ALG_SHA_256;

	memset (resp->reserved3, 0, sizeof (resp->reserved3));

	resp->ext_asym_sel_count = 0;
	resp->ext_hash_sel_count = 0;
	resp->reserved4 = 0;

	request->length = sizeof (struct spdm_negotiate_algorithms_response);

	// TODO: Move hashing to cmd_interface_spdm_process_request
	status = hash->update (hash, (uint8_t*) resp,
		sizeof (struct spdm_negotiate_algorithms_response));
	if (status != 0) {
		spdm_generate_error_response (request, req->header.spdm_minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, status);

		goto hash_cancel;
	}

	return 0;

hash_cancel:
	hash->cancel (hash);

	return 0;
}

/**
 * Construct SPDM negotiate algorithms request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 * @param base_asym_algo SPDM-enumerated supported asymmetric key signature algorithms.
 * @param base_hash_algo SPDM-enumerated supported cryptographic hashing algorithms.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_negotiate_algorithms_request (uint8_t *buf, size_t buf_len,
	uint32_t base_asym_algo, uint32_t base_hash_algo, uint8_t spdm_minor_version)
{
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;

	if (buf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct spdm_negotiate_algorithms_request)) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, sizeof (struct spdm_negotiate_algorithms_request));

	spdm_populate_header (&rq->header, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, spdm_minor_version);

	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->base_asym_algo = base_asym_algo;
	rq->base_hash_algo = base_hash_algo;

	return sizeof (struct spdm_negotiate_algorithms_request);
}

/**
 * Process a SPDM negotiate algorithms response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_negotiate_algorithms_response (struct cmd_interface_msg *response)
{
	struct spdm_negotiate_algorithms_response *resp;
	struct spdm_algorithm_request *algstruct_table;
	size_t i_algstruct;
	size_t offset;

	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	resp = (struct spdm_negotiate_algorithms_response*) response->data;
	algstruct_table = spdm_negotiate_algorithms_rsp_algstruct_table (resp);

	if ((response->length < sizeof (struct spdm_negotiate_algorithms_response)) ||
		(response->length != ((size_t)(resp->length + 1))) ||
		(response->length < spdm_negotiate_algorithms_min_rsp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	offset = spdm_negotiate_algorithms_min_rsp_length (resp);

	for (i_algstruct = 0; i_algstruct < resp->num_alg_structure_tables; ++ i_algstruct) {
		if (response->length <
			(offset + algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm))) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}

		algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
			(algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm)));
		offset += (algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm));
	}

	return 0;
}

/**
 * Construct SPDM get digests request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_get_digests_request (uint8_t *buf, size_t buf_len, uint8_t spdm_minor_version)
{
	struct spdm_get_digests_request *rq = (struct spdm_get_digests_request*) buf;

	if (buf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct spdm_get_digests_request)) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, sizeof (struct spdm_get_digests_request));

	spdm_populate_header (&rq->header, SPDM_REQUEST_GET_DIGESTS, spdm_minor_version);

	return sizeof (struct spdm_get_digests_request);
}

/**
 * Process a SPDM get digests response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_get_digests_response (struct cmd_interface_msg *response)
{
	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (response->length < sizeof (struct spdm_get_digests_response)) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct SPDM get certificate request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 * @param slot_num Slot number of certificate chain requested.
 * @param offset Offset in bytes from start of certificate chain requested.
 * @param length Length in bytes of certificate chain requested.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_get_certificate_request (uint8_t *buf, size_t buf_len, uint8_t slot_num,
	uint16_t offset, uint16_t length, uint8_t spdm_minor_version)
{
	struct spdm_get_certificate_request *rq = (struct spdm_get_certificate_request*) buf;

	if (buf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct spdm_get_certificate_request)) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, sizeof (struct spdm_get_certificate_request));

	spdm_populate_header (&rq->header, SPDM_REQUEST_GET_CERTIFICATE, spdm_minor_version);

	rq->slot_num = slot_num;
	rq->offset = offset;
	rq->length = length;

	return sizeof (struct spdm_get_certificate_request);
}

/**
 * Process a SPDM get certificate response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_get_certificate_response (struct cmd_interface_msg *response)
{
	struct spdm_get_certificate_response *resp;

	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	resp = (struct spdm_get_certificate_response*) response->data;

	if ((response->length < sizeof (struct spdm_get_certificate_response)) ||
		(response->length != spdm_get_certificate_resp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Format signature digest for SPDM v1.2+ according to section 15 in DSP0274 SPDM spec.
 *
 * @param hash Hashing engine to utilize.
 * @param hash_type Hash type to utilize.
 * @param spdm_minor_version SPDM minor version to utilize.
 * @param spdm_context Context string to utilize.
 * @param digest Buffer of size HASH_MAX_HASH_LEN with data to be signed incoming, formatted digest
 * 	outgoing.
 *
 * @return 0 if completed successfully, or an error code
 */
int spdm_format_signature_digest (struct hash_engine *hash, enum hash_type hash_type,
	uint8_t spdm_minor_version, char *spdm_context, uint8_t *digest)
{
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	size_t hash_len = hash_get_hash_len (hash_type);
	int status;

	spdm_prefix[13] = spdm_minor_version + '0';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	status = hash_start_new_hash (hash, hash_type);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, combined_spdm_prefix, sizeof (combined_spdm_prefix));
	if (status != 0) {
		goto fail;
	}

	status = hash->update (hash, digest, hash_len);
	if (status != 0) {
		goto fail;
	}

	status = hash->finish (hash, digest, HASH_MAX_HASH_LEN);
	if (status == 0) {
		return status;
	}

fail:
	hash->cancel (hash);

	return status;
}

/**
 * Construct SPDM challenge request.
 *
 * @param buf Output buffer for the generated request data.
 * @param slot_num Slot number requested for challenge.
 * @param req_measurement_summary_hash_type Requested measurement summary hash type.
 * @param nonce Random nonce to send in request.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_challenge_request (uint8_t *buf, size_t buf_len, uint8_t slot_num,
	uint8_t req_measurement_summary_hash_type, uint8_t* nonce, uint8_t spdm_minor_version)
{
	struct spdm_challenge_request *rq = (struct spdm_challenge_request*) buf;

	if ((buf == NULL) || (nonce == NULL)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct spdm_challenge_request)) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, sizeof (struct spdm_challenge_request));

	spdm_populate_header (&rq->header, SPDM_REQUEST_CHALLENGE, spdm_minor_version);

	rq->slot_num = slot_num;
	rq->req_measurement_summary_hash_type = req_measurement_summary_hash_type;

	memcpy (rq->nonce, nonce, sizeof (rq->nonce));

	return sizeof (struct spdm_challenge_request);
}

/**
 * Process a SPDM challenge response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_challenge_response (struct cmd_interface_msg *response)
{
	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (response->length <= sizeof (struct spdm_challenge_response)) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct SPDM get measurements request.
 *
 * @param buf Output buffer for the generated request data.
 * @param slot_num Slot number requested.
 * @param measurement_operation Requested measurement operation.
 * @param sig_required Flag indicating if signature is required in response.
 * @param raw_bitstream_requested For SPDM v1.2+, indicate whether to request raw or hashed
 * 	measurement block.
 * @param nonce Random nonce to send in request.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_get_measurements_request (uint8_t *buf, size_t buf_len, uint8_t slot_num,
	uint8_t measurement_operation, bool sig_required, bool raw_bitstream_requested, uint8_t *nonce,
	uint8_t spdm_minor_version)
{
	struct spdm_get_measurements_request *rq = (struct spdm_get_measurements_request*) buf;
	size_t rq_length = sizeof (struct spdm_get_measurements_request) + 1 +
		SPDM_NONCE_LEN * sig_required;
	uint8_t *slot_id;

	if ((buf == NULL) || ((nonce == NULL) && sig_required)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < rq_length) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, rq_length);

	spdm_populate_header (&rq->header, SPDM_REQUEST_GET_MEASUREMENTS, spdm_minor_version);

	rq->sig_required = sig_required;
	rq->measurement_operation = measurement_operation;

	if (spdm_minor_version >= 2) {
		rq->raw_bit_stream_requested = raw_bitstream_requested;
	}

	slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);
	*slot_id = slot_num;

	if (sig_required) {
		memcpy (spdm_get_measurements_rq_nonce (rq), nonce, SPDM_NONCE_LEN);
	}

	return rq_length;
}

/**
 * Process a SPDM get measurements response.
 *
 * @param response Response buffer to process.
 *
 * @return Response processing completion status, 0 if successful or error code otherwise.
 */
int spdm_process_get_measurements_response (struct cmd_interface_msg *response)
{
	struct spdm_get_measurements_response *resp;

	if (response == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	resp = (struct spdm_get_measurements_response*) response->data;

	if ((response->length < sizeof (struct spdm_get_measurements_response) ||
		(response->length < sizeof (struct spdm_get_measurements_response) +
			spdm_get_measurements_resp_measurement_record_len (resp) + SPDM_NONCE_LEN)) ||
		(response->length < spdm_get_measurements_resp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}
