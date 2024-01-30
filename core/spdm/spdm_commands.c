// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "attestation/attestation_responder.h"
#include "cmd_interface/device_manager.h"
#include "common/common_math.h"
#include "crypto/hash.h"
#include "crypto/ecc.h"
#include "mctp/mctp_base_protocol.h"
#include "riot/riot_key_manager.h"
#include "cmd_interface_spdm.h"
#include "spdm_logging.h"
#include "spdm_commands.h"
#include "cmd_interface_spdm_responder.h"


/**
 * Pre-process received SPDM protocol message and get the command Id.
 *
 * @param message The message being processed.
 * @param command_id Pointer to hold command ID of incoming message.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
int spdm_get_command_id (struct cmd_interface_msg *message, uint8_t *command_id)
{
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) message->payload;

	message->crypto_timeout = false;

	if (message->payload_length < SPDM_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT;
	}

	if (header->spdm_major_version != SPDM_MAJOR_VERSION) {
		return CMD_HANDLER_SPDM_NOT_INTEROPERABLE;
	}

	*command_id = header->req_rsp_code;

	return 0;
}

/**
 * Generate the header segment of a SPDM protocol request
 *
 * @param header Buffer to fill with SPDM protocol header
 * @param command Command ID to utilize in header
 * @param spdm_minor_version SPDM minor version to utilize in header
 */
static void spdm_populate_header (struct spdm_protocol_header *header, uint8_t command,
	uint8_t spdm_minor_version)
{
	header->spdm_minor_version = spdm_minor_version;
	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = command;
}

/**
 * Generate the MCTP header for an SPDM request.
 *
 * @param header Buffer to fill with the MCTP protocol header.
 */
void spdm_populate_mctp_header (struct spdm_protocol_mctp_header *header)
{
	if (header != NULL) {
		header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
		header->integrity_check = 0;
	}
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
	struct spdm_error_response *rsp = (struct spdm_error_response*) response->payload;
	size_t response_length = sizeof (struct spdm_error_response) + optional_data_len;

	memset (rsp, 0, sizeof (struct spdm_error_response));

	spdm_populate_header (&rsp->header, SPDM_RESPONSE_ERROR, spdm_minor_version);

	rsp->error_code = error_code;
	rsp->error_data = error_data;

	cmd_interface_msg_set_message_payload_length (response, sizeof (struct spdm_error_response));

	if ((optional_data_len > 0) &&
		(response_length <= cmd_interface_msg_get_max_response (response))) {
		cmd_interface_msg_add_payload_data (response, optional_data, optional_data_len);
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SPDM,
		SPDM_LOGGING_ERR_MSG,
		(req_code << 24 | response->source_eid << 16 | error_code << 8 | error_data),
		internal_error_code);
}

/**
 * Set the SPDM connection state.
 *
 * @param  state SPDM state.
 * @param  connection_state SPDM connection state.
 */
static void spdm_set_connection_state (struct spdm_state *state,
	enum spdm_connection_state connection_state)
{
	state->connection_info.connection_state = connection_state;
}

/**
 * Handle the erroneous response state and create a corresponding error message.
 *
 * @param state SPDM state.
 * @param request SPDM request.
 * @param req_code Request code.
 */
static void spdm_handle_response_state (struct spdm_state *state, struct cmd_interface_msg *request,
	uint8_t req_code)
{
	switch (state->response_state) {
		case SPDM_RESPONSE_STATE_BUSY:
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_BUSY, 0x00, NULL, 0, req_code, 0);
			break;

		case SPDM_RESPONSE_STATE_NEED_RESYNC:
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_REQUEST_RESYNCH, 0x00, NULL, 0, req_code, 0);

			/* Reset connection state. */
			spdm_set_connection_state (state, SPDM_CONNECTION_STATE_NOT_STARTED);
			break;

		case SPDM_RESPONSE_STATE_PROCESSING_ENCAP:
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_REQUEST_IN_FLIGHT, 0x00, NULL, 0, req_code, 0);
			break;

		case SPDM_RESPONSE_STATE_NOT_READY:
		/* [TODO] Implement this case in later messages. */
			break;

		default:
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, req_code, 0);
			break;
	}
}

/**
 * Process SPDM GET_VERSION request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request GET_VERSION request to process.
 *
 * @return 0 if request processed successfully (including SPDM error msg) or an error code.
 */
int spdm_get_version (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status;
	struct spdm_get_version_request *rq;
	struct spdm_get_version_response *rsp;
	struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	rq = (struct spdm_get_version_request*) request->payload;
	state = spdm_responder->state;
	transcript_manager = spdm_responder->transcript_manager;

	if (request->payload_length < sizeof (struct spdm_get_version_request)) {
		/* [TODO] Look into the possiblity of having a common place to encode the error msg. */
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_VERSION, 
			CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST);
		goto exit;
	}

	/*
	 * If the GET_VERSION request is improperly formed, then the version of the error message
	 * must be 1.0, regardless of what the negotiated version is. */
	if (SPDM_MAKE_VERSION (rq->header.spdm_major_version, rq->header.spdm_minor_version) !=
		SPDM_VERSION_1_0) {
		spdm_generate_error_response (request, 0,
			SPDM_ERROR_VERSION_MISMATCH, 0x00, NULL, 0, SPDM_REQUEST_GET_VERSION, 
			CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH);
		goto exit;
	}

	/* Receiving a GET_VERSION resets the need to resynchronize. */
	if ((state->response_state == SPDM_RESPONSE_STATE_NEED_RESYNC) ||
		(state->response_state == SPDM_RESPONSE_STATE_PROCESSING_ENCAP)) {
		state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	}

	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_GET_VERSION);
		goto exit;
	}

	/* Process the request. */

	/* Reset transcript manager state. */
	transcript_manager->reset (transcript_manager);

	/* Append request to VCA buffer. */
	status = transcript_manager->update (transcript_manager,
		TRANSCRIPT_CONTEXT_TYPE_VCA, (const uint8_t*) rq, sizeof (struct spdm_get_version_request),
		false, SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_GET_VERSION, status);
		goto exit;
	}

	/* Initialize the SPDM state. No error check as this function call cannot fail. */
	spdm_init_state (state);

	/* [TODO] Reset the SPDM Session Manager when it is available. */

	/* Contruct the response. */
	rsp = (struct spdm_get_version_response*) request->payload;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	rsp->reserved = 0;
	rsp->reserved2 = 0;
	rsp->reserved3 = 0;

	/* Copy the supported version(s) to the response buffer. */
	rsp->version_num_entry_count = spdm_responder->version_num_count;
	memcpy ((void *) spdm_get_version_resp_version_table (rsp),
		(void *) spdm_responder->version_num,
		spdm_responder->version_num_count * sizeof (struct spdm_version_num_entry));

	cmd_interface_msg_set_message_payload_length (request, spdm_get_version_resp_length (rsp));

	/* Append response to the VCA buffer. */
	status = transcript_manager->update (transcript_manager,
		TRANSCRIPT_CONTEXT_TYPE_VCA, (const uint8_t*) rsp, request->payload_length, false,
		SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_GET_VERSION, status);
		goto exit;
	}

	/* Update the connection state */
	spdm_set_connection_state (state, SPDM_CONNECTION_STATE_AFTER_VERSION);

exit:
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

	resp = (struct spdm_get_version_response*) response->payload;

	if ((response->payload_length < sizeof (struct spdm_get_version_response)) ||
		(response->payload_length != spdm_get_version_resp_length (resp))) {
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

	rq = (struct spdm_get_capabilities*) request->payload;

	if (request->payload_length < sizeof (struct spdm_get_capabilities_1_1)) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	if (rq->base_capabilities.header.spdm_minor_version == 1) {
		if (request->payload_length != sizeof (struct spdm_get_capabilities_1_1)) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}
	}
	else {
		if (request->payload_length != sizeof (struct spdm_get_capabilities)) {
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

	// TODO: Move hashing to a transcript hash manager.
	status = hash->update (hash, (uint8_t*) rq, request->payload_length);
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
		cmd_interface_msg_set_message_payload_length (request,
			sizeof (struct spdm_get_capabilities_1_1));
	}
	else {
		rq->data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
		rq->max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

		cmd_interface_msg_set_message_payload_length (request,
			sizeof (struct spdm_get_capabilities));
	}

	// TODO: Move hashing to a transcript hash manager.
	status = hash->update (hash, (uint8_t*) rq, request->payload_length);
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

	resp = (struct spdm_get_capabilities*) response->payload;

	if (resp->base_capabilities.header.spdm_minor_version < 2) {
		if (response->payload_length != sizeof (struct spdm_get_capabilities_1_1)) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}
	}
	else {
		if (response->payload_length != sizeof (struct spdm_get_capabilities)) {
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

	req = (struct spdm_negotiate_algorithms_request*) request->payload;
	resp = (struct spdm_negotiate_algorithms_response*) request->payload;

	if ((request->payload_length < sizeof (struct spdm_negotiate_algorithms_request)) ||
		(request->payload_length != req->length) ||
		(request->payload_length < spdm_negotiate_algorithms_min_req_length (req))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table (req);
	offset = spdm_negotiate_algorithms_min_req_length (req);

	for (i_algstruct = 0; i_algstruct < req->num_alg_structure_tables; ++i_algstruct) {
		/* TODO: Should probably define macros for these length and pointer calculations. */
		if (request->payload_length <
			(offset + (algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm)))) {
			return CMD_HANDLER_SPDM_BAD_LENGTH;
		}

		algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
			(algstruct_table->ext_alg_count * sizeof (struct spdm_extended_algorithm)));
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

	// TODO: Move hashing to a transcript hash manager
	status = hash->update (hash, (uint8_t*) req, request->payload_length);
	if (status != 0) {
		spdm_generate_error_response (request, req->header.spdm_minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, status);

		goto hash_cancel;
	}

	resp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	resp->num_alg_structure_tables = 0;
	resp->reserved = 0;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response);
	resp->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	resp->reserved2 = 0;
	resp->measurement_hash_algo = SPDM_TPM_ALG_SHA_256;
	resp->base_asym_sel = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	resp->base_hash_sel = SPDM_TPM_ALG_SHA_256;

	memset (resp->reserved3, 0, sizeof (resp->reserved3));

	resp->ext_asym_sel_count = 0;
	resp->ext_hash_sel_count = 0;
	resp->reserved4 = 0;

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct spdm_negotiate_algorithms_response));

	// TODO: Move hashing to a transcript hash manager.
	status = hash->update (hash, (uint8_t*) resp, resp->length);
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

	rq->length = sizeof (struct spdm_negotiate_algorithms_request);
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

	resp = (struct spdm_negotiate_algorithms_response*) response->payload;

	if ((response->payload_length < sizeof (struct spdm_negotiate_algorithms_response)) ||
		(response->payload_length != resp->length) ||
		(response->payload_length < spdm_negotiate_algorithms_min_rsp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	algstruct_table = spdm_negotiate_algorithms_rsp_algstruct_table (resp);
	offset = spdm_negotiate_algorithms_min_rsp_length (resp);

	for (i_algstruct = 0; i_algstruct < resp->num_alg_structure_tables; ++i_algstruct) {
		/* TODO: Maybe macro for length check. */
		if (response->payload_length <
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

	if (response->payload_length < sizeof (struct spdm_get_digests_response)) {
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

	resp = (struct spdm_get_certificate_response*) response->payload;

	if ((response->payload_length < sizeof (struct spdm_get_certificate_response)) ||
		(response->payload_length != spdm_get_certificate_resp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct SPDM challenge request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
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

	if (response->payload_length <= sizeof (struct spdm_challenge_response)) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct SPDM get measurements request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
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
	size_t rq_length = sizeof (struct spdm_get_measurements_request) +
		((1 + SPDM_NONCE_LEN) * sig_required);
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

	if (sig_required) {
		slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);
		*slot_id = slot_num;

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

	resp = (struct spdm_get_measurements_response*) response->payload;

	if ((response->payload_length < sizeof (struct spdm_get_measurements_response) ||
		(response->payload_length < (sizeof (struct spdm_get_measurements_response) +
			spdm_get_measurements_resp_measurement_record_len (resp) + SPDM_NONCE_LEN))) ||
		(response->payload_length < spdm_get_measurements_resp_length (resp))) {
		return CMD_HANDLER_SPDM_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct SPDM respond if ready request.
 *
 * @param buf Output buffer for the generated request data.
 * @param buf_len Maximum size of buffer.
 * @param original_request_code Original request code that triggered ResponseNotReady response.
 * @param token Token received in ResponseNotReady response.
 * @param spdm_minor_version SPDM minor version to utilize in request.
 *
 * @return Length of the generated request data if the request was successfully constructed or an
 * error code.
 */
int spdm_generate_respond_if_ready_request (uint8_t *buf, size_t buf_len,
	uint8_t original_request_code, uint8_t token, uint8_t spdm_minor_version)
{
	struct spdm_respond_if_ready_request *rq = (struct spdm_respond_if_ready_request*) buf;
	size_t rq_length = sizeof (struct spdm_respond_if_ready_request);

	if (buf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if (buf_len < rq_length) {
		return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
	}

	memset (rq, 0, rq_length);

	spdm_populate_header (&rq->header, SPDM_REQUEST_RESPOND_IF_READY, spdm_minor_version);

	rq->token = token;
	rq->original_request_code = original_request_code;

	return rq_length;
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
	size_t hash_len = hash_get_hash_length (hash_type);
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
 * Initialize the SPDM state.
 *
 * @param state SPDM state.
 * 
 * @return 0 if the state was successfully initialized or an error code.
 */
int spdm_init_state (struct spdm_state *state)
{
	int status = 0;

	if (state == NULL) {
		status = CMD_HANDLER_SPDM_INVALID_ARGUMENT;
		goto exit;
	}

	memset (state, 0, sizeof (struct spdm_state));

	/* Initialize the state. */
	state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;
	memset (&state->connection_info.version, 0, sizeof (struct spdm_version_number));
	state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	state->last_spdm_request_session_id = SPDM_INVALID_SESSION_ID;
	state->last_spdm_request_session_id_valid = false;

exit:
	return status;
}