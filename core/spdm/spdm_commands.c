// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "attestation/attestation_responder.h"
#include "cmd_interface/device_manager.h"
#include "common/array_size.h"
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
 * @param state SPDM state.
 * @param connection_state SPDM connection state.
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
 * Check the compatibility of the capabilities in the flags.
 * Some flags are mutually inclusive/exclusive.
 *
 * @param flags Capabilities to validate.
 * @param version SPDM message version.
 *
 * @return true if the received capabilities are valid, false otherwise.
 */
bool spdm_check_request_flag_compatibility (struct spdm_get_capabilities_flags_format flags,
	uint8_t version)
{
	/* Illegal to return reserved values. */
	if (flags.psk_cap >= SPDM_PSK_RESERVED) {
		return false;
	}

	/* Key exchange capabilities checks. */
	if ((flags.key_ex_cap == 1) || (flags.psk_cap == SPDM_PSK_SUPPORTED_NO_CONTEXT)) {
		/**
		 * While clearing MAC_CAP and setting ENCRYPT_CAP is legal according to DSP0274, the SPDM
		 * responder also implements DSP0277 secure messages, which requires at least MAC_CAP
		 * to be set. */
		if (flags.mac_cap == 0) {
			return false;
		}
	}
	else {
		/* mac_cap, encrypt_cap and key_upd_cap capabilities require either key exchange
		 * or pre-shared key capability.
		 *
		 * heartbeat messages are sent in a secure session, the setup of which also require
		 * either key exchange or pre-shared key capability.
		 *
		 * handshake_in_the_clear_cap requires key_ex_cap.
		 */
		if ((flags.mac_cap == 1) || (flags.encrypt_cap == 1) ||
			(flags.handshake_in_the_clear_cap == 1) || (flags.hbeat_cap == 1) ||
			(flags.key_upd_cap == 1)) {
			return false;
		}
	}
	/* This is per libSPDM, so keeping this check. */
	if ((flags.key_ex_cap == 0) && (flags.psk_cap == SPDM_PSK_SUPPORTED_NO_CONTEXT) &&
		(flags.handshake_in_the_clear_cap == 1)) {
		return false;
	}

	/* Certificate or public key capabilities checks. */
	if ((flags.cert_cap == 1) || (flags.pub_key_id_cap == 1)) {
		/* Certificate capabilities and public key capabilities cannot both be set. */
		if ((flags.cert_cap == 1) && (flags.pub_key_id_cap == 1)) {
			return false;
		}
		/**
		 * cert_cap and/or pub_key_id_cap are not needed if both chal_cap and key_ex_cap are 0.
		 * Theoretically, this might be ok, but libSPDM has this check, so keeping it.
		 */
		if ((flags.chal_cap == 0) && (flags.key_ex_cap == 0)) {
			return false;
		}
	}
	else {
		/**
		 * If certificates or public keys are not enabled, then these capabilities
		 * cannot be enabled. */
		if ((flags.chal_cap == 1) || (flags.mut_auth_cap == 1)) {
			return false;
		}
	}

	/* Checks specific to v1.1. */
	if (version == SPDM_VERSION_1_1) {
		/* Having mut_auth_cap requires encap_cap to be available. */
		if ((flags.mut_auth_cap == 1) && (flags.encap_cap == 0)) {
			return false;
		}
	}

	return true;
}

/**
 * Check if the received SPDM version is supported.
 *
 * @param peer_version SPDM message version in <major.minor> format.
 * @param version_num Version number table.
 * @param version_num_count Number of entries in the version number table.
 *
 * @return true if the received SPDM version is supported, false otherwise.
 */
static bool spdm_is_version_supported (uint8_t peer_version,
	const struct spdm_version_num_entry *version_num, const uint8_t version_num_count)
{
	uint8_t i;

	for (i = 0; i < version_num_count; i++) {
		if (SPDM_MAKE_VERSION (version_num[i].major_version, version_num[i].minor_version) ==
			peer_version) {
			return true;
		}
	}

	return false;
}

/**
 * Check the compatibility of the received SPDM version.
 * If the received version is valid, subsequent SPDM communication will use this version.
 *
 * @param state SPDM state.
 * @param peer_version SPDM message version in <major.minor> format.
 *
 * @return true if the received SPDM version is valid, else false.
 */
static bool spdm_check_request_version_compatibility (struct spdm_state *state,
	const struct spdm_version_num_entry *version_num, const uint8_t version_num_count,
	uint8_t peer_version)
{
	if (spdm_is_version_supported (peer_version, version_num, version_num_count)
		== true) {
		state->connection_info.version.major_version = SPDM_GET_MAJOR_VERSION (peer_version);
		state->connection_info.version.minor_version = SPDM_GET_MINOR_VERSION (peer_version);
		return true;
	}

	return false;
}

/**
 * Get the connection version negotiated by the GET_VERSION/VERSION messages.
 *
 * @param state SPDM state.
 *
 * @return Negotiated version.
 */
static uint8_t spdm_get_connection_version (const struct spdm_state *state)
{
	return SPDM_MAKE_VERSION (state->connection_info.version.major_version,
		state->connection_info.version.minor_version);
}

/**
 * Select the preferred supported algorithm according to the priority table. If no priority table is
 * provided, the first common lowest numbered algorithm is selected.
 *
 * @param priority_table The priority table.
 * @param priority_table_count The count of the priority table entries.
 * @param local_algo Local supported algorithm.
 * @param peer_algo Peer supported algorithm.

 * @return Preferred supported algorithm.
 */
static uint32_t spdm_prioritize_algorithm (const uint32_t *priority_table,
	size_t priority_table_count, uint32_t local_algo, uint32_t peer_algo)
{
	uint32_t common_algos;
	size_t index;
	uint32_t mask;

	common_algos = (local_algo & peer_algo);
	if (priority_table != NULL) {
		for (index = 0; index < priority_table_count; index++) {
			if ((common_algos & priority_table[index]) != 0) {
				return priority_table[index];
			}
		}
	}
	else {
		/* If a priority table was not provided, use the first common lowest numbered algorithm. */
		 mask = common_algos & -common_algos;
		 return (common_algos & mask);
	}

	return 0;
}

/**
 * Get the hash type for a single SPDM hash algorithm.
 *
 * @param hash_algo	A single SPDM Hash algorithm.
 *
 * @return Hash type if algorithm is supported, HASH_TYPE_INVALID otherwise.
 */
static enum hash_type spdm_get_hash_type (uint32_t hash_algo)
{
	enum hmac_hash hash_type = HASH_TYPE_INVALID;

	switch (hash_algo) {
		case SPDM_TPM_ALG_SHA_256:
			hash_type = HASH_TYPE_SHA256;
			break;

		case SPDM_TPM_ALG_SHA_384:
			hash_type = HASH_TYPE_SHA384;
			break;

		case SPDM_TPM_ALG_SHA_512:
			hash_type = HASH_TYPE_SHA512;
			break;
	}

	return hash_type;
}

/**
 * Reset transcript(s) in the Transcript Manager according to the request/response code.
 *
 * @param state SPDM state.
 * @param transcript_manager SPDM transcript manager.
 * @param req_rsp_code The SPDM request/response code.
 */
static void spdm_reset_transcript_via_request_code (struct spdm_state *state,
	struct spdm_transcript_manager *transcript_manager,	uint8_t req_rsp_code)
{
	/* Any requests other than SPDM_GET_MEASUREMENTS resets L1/L2 */
	if (req_rsp_code != SPDM_REQUEST_GET_MEASUREMENTS) {
		transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
			false, SPDM_MAX_SESSION_COUNT);
	}

	/**
	 * If the Requester issued GET_MEASUREMENTS or KEY_EXCHANGE or FINISH or PSK_EXCHANGE
	 * or PSK_FINISH or KEY_UPDATE or HEARTBEAT or GET_ENCAPSULATED_REQUEST or
	 * DELIVER_ENCAPSULATED_RESPONSE or END_SESSION request(s) and skipped CHALLENGE completion,
	 * M1 and M2 are reset to null. */
	switch (req_rsp_code) {
		case SPDM_REQUEST_KEY_EXCHANGE:
		case SPDM_REQUEST_GET_MEASUREMENTS:
		case SPDM_REQUEST_FINISH:
		case SPDM_REQUEST_PSK_EXCHANGE:
		case SPDM_REQUEST_PSK_FINISH:
		case SPDM_REQUEST_KEY_UPDATE:
		case SPDM_REQUEST_HEARTBEAT:
		case SPDM_REQUEST_GET_ENCAPSULATED_REQUEST:
		case SPDM_REQUEST_END_SESSION:
		case SPDM_REQUEST_DELIVER_ENCAPSULATED_RESPONSE:
			if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_AUTHENTICATED) {
				transcript_manager->reset_transcript (transcript_manager,
					TRANSCRIPT_CONTEXT_TYPE_M1M2, false, SPDM_MAX_SESSION_COUNT);
			}
			break;

		case SPDM_REQUEST_GET_DIGESTS:
			transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
				false, SPDM_MAX_SESSION_COUNT);
			break;

		default:
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
 * Process SPDM GET_CAPABILITIES request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request The GET_CAPABILITIES request to process.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_get_capabilities (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	struct spdm_protocol_header *header;
	struct spdm_get_capabilities *req_resp;
	int status;
	uint8_t spdm_version;
	size_t req_resp_size;
	struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	const struct spdm_device_capability *local_capabilities;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	local_capabilities = spdm_responder->local_capabilities;

	/* Verify the state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_GET_CAPABILITIES);
		goto exit;
	}
	if (state->connection_info.connection_state != SPDM_CONNECTION_STATE_AFTER_VERSION) {
		/* [TODO] Consolidate error reporting. */
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_UNEXPECTED_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
			CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST);
		goto exit;
	}

	/* Validate request version and save it in the connection info. */
	header = (struct spdm_protocol_header*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (header->spdm_major_version, header->spdm_minor_version);
	if (spdm_check_request_version_compatibility (state, spdm_responder->version_num,
			spdm_responder->version_num_count, spdm_version) == false) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_VERSION_MISMATCH, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
			CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH);
		goto exit;
	}

	/* Check request size. */
	if ((spdm_version >= SPDM_VERSION_1_2) &&
		(request->payload_length >= sizeof (struct spdm_get_capabilities))) {
		req_resp_size = sizeof (struct spdm_get_capabilities);
	}
	else if ((spdm_version == SPDM_VERSION_1_1) &&
			(request->payload_length >= sizeof (struct spdm_get_capabilities_1_1))) {
			req_resp_size = sizeof (struct spdm_get_capabilities_1_1);
	}
	else {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
			CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST);
		goto exit;
	}

	/* Process the request. */
	req_resp = (struct spdm_get_capabilities*) request->payload;

	/* Check for request flag compatibility. */
	if (spdm_check_request_flag_compatibility (req_resp->base_capabilities.flags, spdm_version)
		 == false) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
			CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST);
		goto exit;
	}

	/* Check the data transfer size. */
	if (spdm_version >= SPDM_VERSION_1_2) {
		if ((req_resp->data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2) ||
			(req_resp->data_transfer_size > req_resp->max_spdm_msg_size)) {
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
				CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST);
			goto exit;
		}
		if ((req_resp->base_capabilities.flags.chunk_cap == 0) &&
			(req_resp->data_transfer_size != req_resp->max_spdm_msg_size)) {
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
				CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST);
			goto exit;
		}
	}

	/* Check the CT Exponent. */
	if (spdm_version >= SPDM_VERSION_1_1) {
		if (req_resp->base_capabilities.ct_exponent > SPDM_MAX_CT_EXPONENT) {
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_INVALID_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES,
				CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST);
			goto exit;
		}
	}

	/* Reset the transcript manager state as per the request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager,
		SPDM_REQUEST_GET_CAPABILITIES);

	/* Append the request to the VCA buffer. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) req_resp, req_resp_size, false, SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES, status);
		goto exit;
	}

	/* Save the requester capabilities in the connection info. */
	state->connection_info.peer_capabilities.flags = req_resp->base_capabilities.flags;
	state->connection_info.peer_capabilities.ct_exponent = req_resp->base_capabilities.ct_exponent;

	if (spdm_version >= SPDM_VERSION_1_2) {
		state->connection_info.peer_capabilities.data_transfer_size = req_resp->data_transfer_size;
		state->connection_info.peer_capabilities.max_spdm_msg_size = req_resp->max_spdm_msg_size;
	}
	else {
		state->connection_info.peer_capabilities.data_transfer_size = 0;
		state->connection_info.peer_capabilities.max_spdm_msg_size = 0;
	}

	/* Response phase. */

	/* Contruct the response. */
	memset (req_resp, 0, req_resp_size);
	spdm_populate_header (&req_resp->base_capabilities.header, SPDM_RESPONSE_GET_CAPABILITIES,
		SPDM_GET_MINOR_VERSION (spdm_version));

	req_resp->base_capabilities.reserved = 0;
	req_resp->base_capabilities.reserved2 = 0;
	req_resp->base_capabilities.reserved3 = 0;
	req_resp->base_capabilities.reserved4 = 0;

	req_resp->base_capabilities.ct_exponent = local_capabilities->ct_exponent;
	req_resp->base_capabilities.flags = local_capabilities->flags;

	if (spdm_version >= SPDM_VERSION_1_2) {
		req_resp->data_transfer_size = local_capabilities->data_transfer_size;
		req_resp->max_spdm_msg_size = local_capabilities->max_spdm_msg_size;
	}

	/* Append the reponse to the VCA buffer. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) req_resp, req_resp_size, false, SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_GET_CAPABILITIES, status);
		goto exit;
	}

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, req_resp_size);

	/* Update connection state */
	spdm_set_connection_state (state, SPDM_CONNECTION_STATE_AFTER_CAPABILITIES);

exit:
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

	rq->base_capabilities.ct_exponent = SPDM_MAX_CT_EXPONENT;

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
 * Constructs a NEGOTIATE_ALGORITHMS response.
 *
 * @param state SPDM state.
 * @param local_capabilities Local SPDM device capabilities.
 * @param local_device_algorithms Local SPDM device algorithms and their priority order.
 * @param rq NEGOTIATE_ALGORITHMS request to process.
 * @param resp_no_ext_alg NEGOTIATE_ALGORITHMS response to be filled.
 * @param spdm_error SPDM error code.
 *
 * @return 0 if response was populated successfully or an error code.
 */
static int spdm_negotiate_algorithms_construct_response (struct spdm_state *state,
	const struct spdm_device_capability *local_capabilities,
	const struct spdm_local_device_algorithms *local_device_algorithms,
	struct spdm_negotiate_algorithms_request *rq,
	struct spdm_negotiate_algorithms_response_no_ext_alg *resp_no_ext_alg, int *spdm_error)
{
	int status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
	size_t response_size;
	uint8_t spdm_version;
	struct spdm_algorithm_request *algstruct_table;
	size_t i_algstruct;
	struct spdm_negotiate_algorithms_response *resp =
		(struct spdm_negotiate_algorithms_response*) resp_no_ext_alg;
	const struct spdm_device_algorithms *local_algorithms;
	const struct spdm_local_device_algorithms_priority_table *local_algo_priority_table;
	uint32_t measurement_hash_algo;

	*spdm_error = SPDM_ERROR_INVALID_REQUEST;
	local_algorithms = &local_device_algorithms->device_algorithms;
	local_algo_priority_table = &local_device_algorithms->algorithms_priority_table;

	/* Construct the response. */
	memset (resp, 0, sizeof (struct spdm_negotiate_algorithms_response_no_ext_alg));
	resp->header.spdm_major_version = rq->header.spdm_major_version;
	resp->header.spdm_minor_version = rq->header.spdm_minor_version;
	resp->num_alg_structure_tables = rq->num_alg_structure_tables;

	/* Respond with the same number of Algorithms Structure Tables as requested. */
	response_size = spdm_negotiate_algorithms_rsp_size (rq);

	resp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;
	resp->reserved = 0;
	resp->length = (uint16_t) response_size;

	/* Save requester algorithms in connection info. */
	state->connection_info.peer_algorithms.measurement_spec = rq->measurement_specification;
	if (rq->measurement_specification != 0) {
		/* Measurement hash algorithm is a responder selected value. It is not negotiated. */
		measurement_hash_algo = local_algorithms->measurement_hash_algo;
	}
	else {
		measurement_hash_algo = 0;
	}
	state->connection_info.peer_algorithms.base_asym_algo = rq->base_asym_algo;
	state->connection_info.peer_algorithms.base_hash_algo = rq->base_hash_algo;

	/* Process the request algorithm structures. */
	spdm_version = SPDM_MAKE_VERSION (rq->header.spdm_major_version, rq->header.spdm_minor_version);
	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table (rq);

	for (i_algstruct = 0; i_algstruct < rq->num_alg_structure_tables; ++i_algstruct) {
		switch (algstruct_table->alg_type) {
			case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
				if (algstruct_table->alg_supported == 0) {
					goto exit;
				}

				resp_no_ext_alg->algstruct_table[i_algstruct].alg_type = algstruct_table->alg_type;
				resp_no_ext_alg->algstruct_table[i_algstruct].fixed_alg_count = 2;
				resp_no_ext_alg->algstruct_table[i_algstruct].ext_alg_count = 0;
				resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported =
					(uint16_t) spdm_prioritize_algorithm (
						local_algo_priority_table->dhe_priority_table,
						local_algo_priority_table->dhe_priority_table_count,
						local_algorithms->dhe_named_group,
						algstruct_table->alg_supported);

				state->connection_info.peer_algorithms.dhe_named_group =
					resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported;
				break;

			case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
				if (algstruct_table->alg_supported == 0) {
					goto exit;
				}

				resp_no_ext_alg->algstruct_table[i_algstruct].alg_type = algstruct_table->alg_type;
				resp_no_ext_alg->algstruct_table[i_algstruct].fixed_alg_count = 2;
				resp_no_ext_alg->algstruct_table[i_algstruct].ext_alg_count = 0;
				resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported =
					(uint16_t) spdm_prioritize_algorithm (
						local_algo_priority_table->aead_priority_table,
						local_algo_priority_table->aead_priority_table_count,
						local_algorithms->aead_cipher_suite,
						algstruct_table->alg_supported);

				state->connection_info.peer_algorithms.aead_cipher_suite =
					resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported;
				break;

			case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
				if (algstruct_table->alg_supported == 0) {
					goto exit;
				}

				resp_no_ext_alg->algstruct_table[i_algstruct].alg_type = algstruct_table->alg_type;
				resp_no_ext_alg->algstruct_table[i_algstruct].fixed_alg_count = 2;
				resp_no_ext_alg->algstruct_table[i_algstruct].ext_alg_count = 0;
				resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported =
					(uint16_t) spdm_prioritize_algorithm (
						local_algo_priority_table->req_asym_priority_table,
						local_algo_priority_table->req_asym_priority_table_count,
						local_algorithms->req_base_asym_alg,
						algstruct_table->alg_supported);

				state->connection_info.peer_algorithms.req_base_asym_alg =
					resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported;
				break;

			case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
				if (algstruct_table->alg_supported == 0) {
					goto exit;
				}

				resp_no_ext_alg->algstruct_table[i_algstruct].alg_type = algstruct_table->alg_type;;
				resp_no_ext_alg->algstruct_table[i_algstruct].fixed_alg_count = 2;
				resp_no_ext_alg->algstruct_table[i_algstruct].ext_alg_count = 0;
				resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported =
					(uint16_t) spdm_prioritize_algorithm (
						local_algo_priority_table->key_schedule_priority_table,
						local_algo_priority_table->key_schedule_priority_table_count,
						local_algorithms->key_schedule,
						algstruct_table->alg_supported);

				state->connection_info.peer_algorithms.key_schedule =
					resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported;
				break;
			}

		/* Go to the next algstruct_table entry. */
		algstruct_table =
			spdm_negotiate_algorithms_get_next_alg_struct_table_entry (algstruct_table);
	}

	if (local_capabilities->flags.meas_cap == 1) {
		resp->measurement_specification = (uint8_t) spdm_prioritize_algorithm (
			local_algo_priority_table->measurement_spec_priority_table,
			local_algo_priority_table->measurement_spec_priority_table_count,
			local_algorithms->measurement_spec,
			state->connection_info.peer_algorithms.measurement_spec);

		/* Measurement hash algorithm is not negotiated but rather selected by the responder.
		 * Thus, there is no priority table for measurement hash algorithm. */
		resp->measurement_hash_algo = spdm_prioritize_algorithm (NULL, 0,
			local_algorithms->measurement_hash_algo, measurement_hash_algo);
	}
	else {
		resp->measurement_specification = 0;
		resp->measurement_hash_algo = 0;
	}

	state->connection_info.peer_algorithms.measurement_spec = resp->measurement_specification;
	state->connection_info.peer_algorithms.measurement_hash_algo = resp->measurement_hash_algo;

	resp->base_asym_sel = spdm_prioritize_algorithm (
		local_algo_priority_table->asym_priority_table,
		local_algo_priority_table->asym_priority_table_count,
		local_algorithms->base_asym_algo,
		state->connection_info.peer_algorithms.base_asym_algo);
	state->connection_info.peer_algorithms.base_asym_algo = resp->base_asym_sel;

	resp->base_hash_sel = spdm_prioritize_algorithm (
		local_algo_priority_table->hash_priority_table,
		local_algo_priority_table->hash_priority_table_count,
		local_algorithms->base_hash_algo,
		state->connection_info.peer_algorithms.base_hash_algo);
	state->connection_info.peer_algorithms.base_hash_algo = resp->base_hash_sel;

	if (spdm_version >= SPDM_VERSION_1_2) {
		resp->other_params_selection.opaque_data_format = (uint8_t) spdm_prioritize_algorithm (
			local_algo_priority_table->other_params_support_priority_table,
			local_algo_priority_table->other_params_support_priority_table_count,
			local_algorithms->other_params_support.opaque_data_format,
			rq->other_params_support.opaque_data_format);

			state->connection_info.peer_algorithms.other_params_support.opaque_data_format =
				resp->other_params_selection.opaque_data_format;
	}

	status = 0;
	*spdm_error = SPDM_ERROR_RESERVED;

exit:
	return status;
}

/**
 * Process the SPDM NEGOTIATE_ALGORITHMS request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request NEGOTIATE_ALGORITHMS request to process.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_negotiate_algorithms (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	struct spdm_protocol_header *header;
	struct spdm_negotiate_algorithms_request *rq;
	struct spdm_negotiate_algorithms_response_no_ext_alg resp_no_ext_alg;
	struct spdm_algorithm_request *algstruct_table;
	size_t i_algstruct;
	uint8_t spdm_version;
	uint8_t alg_type_pre;
	uint16_t ext_alg_total_count = 0;
	size_t request_size;
	struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	const struct spdm_device_capability *local_capabilities;
	const struct spdm_local_device_algorithms *local_algorithms;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	local_capabilities = spdm_responder->local_capabilities;
	local_algorithms = spdm_responder->local_algorithms;

	/* Validate the request. */
	header = (struct spdm_protocol_header*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (header->spdm_major_version, header->spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify the state */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_NEGOTIATE_ALGORITHMS);
		goto exit;
	}
	if (state->connection_info.connection_state != SPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Check request size. */
	rq = (struct spdm_negotiate_algorithms_request*) request->payload;
	if ((request->payload_length < sizeof (struct spdm_negotiate_algorithms_request)) ||
		(request->payload_length < spdm_negotiate_algorithms_min_req_length (rq))) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	if (rq->length > SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_LENGTH) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Validate the algorithm structs. */
	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table (rq);
	for (i_algstruct = 0; i_algstruct < rq->num_alg_structure_tables; i_algstruct++) {

		/* Check if alg_type is valid. */
		 if ((algstruct_table->alg_type < SPDM_ALG_REQ_STRUCT_ALG_TYPE_DHE) ||
			 (algstruct_table->alg_type > SPDM_ALG_REQ_STRUCT_ALG_TYPE_KEY_SCHEDULE)) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}

		/* Check if alg_type is monotonically increasing for subsequent entries. */
		if ((i_algstruct != 0) && (algstruct_table->alg_type <= alg_type_pre)) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}
		alg_type_pre = algstruct_table->alg_type;
		ext_alg_total_count += algstruct_table->ext_alg_count;
		if (algstruct_table->fixed_alg_count != 2) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}

		/* Check if payload contains the extended algorithm(s) in the algstruct_table entry. */
		if (spdm_negotiate_algorithms_actual_extended_algo_size (rq, algstruct_table) <
			spdm_negotiate_algorithms_expected_extended_algo_size (algstruct_table)) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}

		/* Go to the next algstruct_table entry. */
		algstruct_table = spdm_negotiate_algorithms_get_next_alg_struct_table_entry (
			algstruct_table);
	}
	ext_alg_total_count += (rq->ext_asym_count + rq->ext_hash_count);

	/* Check the algorithm count and message size. */
	if (ext_alg_total_count > SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_EXT_ALG_COUNT_VERSION) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Check Opaque Data Format. */
	if (spdm_version >= SPDM_VERSION_1_2) {
		switch (rq->other_params_support.opaque_data_format) {
			case SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE:
			case SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0:
			case SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1:
				break;

			default:
				status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
				spdm_error = SPDM_ERROR_INVALID_REQUEST;
				goto exit;
		}
	}

	request_size = (size_t) algstruct_table - (size_t) rq;
	if (request_size != rq->length) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Construct the response. */
	status = spdm_negotiate_algorithms_construct_response (state, local_capabilities,
		local_algorithms, rq, &resp_no_ext_alg, &spdm_error);
	if (status != 0) {
		goto exit;
	}

	/* Reset transcript manager state as per request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager,
		SPDM_REQUEST_NEGOTIATE_ALGORITHMS);

	/* Append the request to the VCA buffer. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) rq, request_size, false, SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Append the response to the VCA buffer. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) &resp_no_ext_alg, resp_no_ext_alg.base.length, false,
		SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Set the negotiated hash algorithm on the Transcript Manager. */
	if (state->connection_info.peer_algorithms.base_hash_algo != 0) {
		status = transcript_manager->set_hash_algo (transcript_manager,
			spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo));
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Copy response in the payload buffer. */
	memcpy (request->payload, &resp_no_ext_alg, resp_no_ext_alg.base.length);
	cmd_interface_msg_set_message_payload_length (request, resp_no_ext_alg.base.length);

	/* Update the connection state */
	spdm_set_connection_state (state, SPDM_CONNECTION_STATE_NEGOTIATED);

exit:
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, status);
	}
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
	state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	state->last_spdm_request_session_id = SPDM_INVALID_SESSION_ID;
	state->last_spdm_request_session_id_valid = false;

exit:
	return status;
}