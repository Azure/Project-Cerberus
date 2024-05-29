// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "cmd_interface_spdm.h"
#include "cmd_interface_spdm.h"
#include "cmd_interface_spdm_responder.h"
#include "cmd_interface_spdm_responder.h"
#include "spdm_commands.h"
#include "spdm_commands.h"
#include "spdm_logging.h"
#include "spdm_logging.h"
#include "spdm_secure_session_manager.h"
#include "attestation/attestation_responder.h"
#include "cmd_interface/device_manager.h"
#include "common/array_size.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/unused.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"
#include "crypto/kdf.h"
#include "mctp/mctp_base_protocol.h"
#include "riot/riot_key_manager.h"


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

	/* [TODO] Remove this check from here for compliance with the SPDM device validator. */
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
		/* While clearing MAC_CAP and setting ENCRYPT_CAP is legal according to DSP0274, the SPDM
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
		 * handshake_in_the_clear_cap requires key_ex_cap. */
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

		/* cert_cap and/or pub_key_id_cap are not needed if both chal_cap and key_ex_cap are 0.
		 * Theoretically, this might be ok, but libSPDM has this check, so keeping it.
		 *
		 * TODO:  This needs to be re-evaluated.  There is no requirement per the SPDM spec for this
		 * check as there is no specified coupling between certificate and challenge/key exchange
		 * support.  It's reasonable to envision an implementation that doesn't support challenge
		 * but supports measurement signing. */
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
	if (spdm_is_version_supported (peer_version, version_num, version_num_count) ==
		true) {
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
enum hash_type spdm_get_hash_type (uint32_t hash_algo)
{
	enum hash_type hash_type = HASH_TYPE_INVALID;

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
 * Get the signature size for the signature algorithm.
 *
 * @param asym_algo Signature algorithm.
 *
 * @return Signature size if the algorithm is supported, 0 otherwise.
 */
static uint32_t spdm_get_asym_signature_size (uint32_t asym_algo)
{
	/* [TODO] Add support for other algorithms. */
	switch (asym_algo) {
		case SPDM_TPM_ALG_ECDSA_ECC_NIST_P384:
			return (ECC_KEY_LENGTH_384 << 1);

		default:
			return 0;
	}
}

/**
 * Get the DHE algorithm public key size.
 *
 * @param dhe_named_group DHE named group.
 *
 * @return DHE algorithm public key size if the algorithm is supported, 0 otherwise.
 */
uint32_t spdm_get_dhe_pub_key_size (uint16_t dhe_named_group)
{
	/* [TODO] Add support for other algorithms. */
	switch (dhe_named_group) {
		case SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1:
			return (ECC_KEY_LENGTH_384 << 1);

		default:
			return 0;
	}
}

/**
 * Get the AEAD algorithm key size.
 *
 * @param aead_cipher_suite AEAD cipher suite
 *
 * @return AEAD algorithm key size if the algorithm is supported, 0 otherwise.
 */
uint32_t spdm_get_aead_key_size (uint16_t aead_cipher_suite)
{
	/* [TODO] Add support for other algorithms. */
	switch (aead_cipher_suite) {
		case SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM:
			return 32;

		default:
			return 0;
	}
}

/**
 * Get the AEAD algorithm IV size.
 *
 * @param aead_cipher_suite aead cipher suite
 *
 * @return AEAD algorithm IV size if the algorithm is supported, 0 otherwise.
 */
uint32_t spdm_get_aead_iv_size (uint16_t aead_cipher_suite)
{
	/* [TODO] Add support for other algorithms. */
	switch (aead_cipher_suite) {
		case SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM:
			return 12;

		default:
			return 0;
	}
}

/**
 * Get the AEAD algorithm tag size.
 *
 * @param aead_cipher_suite AEAD cipher suite
 *
 * @return AEAD algorithm tag size if the algorithm is supported, 0 otherwise.
 */
uint32_t spdm_get_aead_tag_size (uint16_t aead_cipher_suite)
{
	/* [TODO] Add support for other algorithms. */
	switch (aead_cipher_suite) {
		case SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM:
			return 16;

		default:
			return 0;
	}
}

/**
 *  Validate the opaque data in KEY_EXCHANGE request.
 *
 * @param  spdm_version SPDM version.
 * @param  opaque_data_format Opaque data format.
 * @param  data_in Opaque data pointer.
 * @param  data_in_size Size of opaque data.
 *
 * @retval 0 if the general opaque data is valid, error code otherwise.
 */
static int spdm_validate_general_opaque_data (uint8_t spdm_version, uint8_t opaque_data_format,
	const void *data_in, size_t data_in_size)
{
	int status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
	const struct spdm_general_opaque_data_table_header *general_opaque_data_table_header;
	const struct spdm_opaque_element_table_header *opaque_element_table_header;
	uint8_t element_num;
	uint8_t element_index;
	uint16_t opaque_element_data_len;
	size_t data_element_size;
	size_t current_element_len;
	size_t total_element_len;
	uint8_t zero_padding[4] = {0};

	total_element_len = 0;

	if ((spdm_version >= SPDM_VERSION_1_2) &&
		(opaque_data_format == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1)) {
		/* Check byte alignment. */
		if ((data_in_size & 3) != 0) {
			goto exit;
		}

		general_opaque_data_table_header = data_in;
		/* Buffer will be atleast of size struct spdm_general_opaque_data_table_header (4 Bytes)
		 * due to the alignment check above, so no additional check needed. */

		if (general_opaque_data_table_header->total_elements == 0) {
			goto exit;
		}
		opaque_element_table_header = (const void*) (general_opaque_data_table_header + 1);
		element_num = general_opaque_data_table_header->total_elements;
		data_element_size = data_in_size - sizeof (struct spdm_general_opaque_data_table_header);

		for (element_index = 0; element_index < element_num; element_index++) {
			/* Ensure the opaque_element_table_header is valid. */
			if ((total_element_len + sizeof (struct spdm_opaque_element_table_header) +
				sizeof (opaque_element_data_len)) > data_element_size) {
				goto exit;
			}

			/* Validate the element header id. */
			if (opaque_element_table_header->id > SPDM_REGISTRY_ID_MAX) {
				goto exit;
			}

			opaque_element_data_len = *(uint16_t*) ((size_t) (opaque_element_table_header + 1)) +
				opaque_element_table_header->vendor_len;

			current_element_len = sizeof (struct spdm_opaque_element_table_header) +
				opaque_element_table_header->vendor_len + sizeof (opaque_element_data_len) +
				opaque_element_data_len;

			if ((current_element_len & 3) != 0) {
				if (memcmp (zero_padding,
					(uint8_t*) (size_t) (opaque_element_table_header) + current_element_len,
					4 - (current_element_len & 3)) != 0) {
					goto exit;
				}
			}

			/* Add Padding. */
			current_element_len = (current_element_len + 3) & ~3;

			total_element_len += current_element_len;

			if (total_element_len > data_element_size) {
				goto exit;
			}

			/* Move to next the element. */
			opaque_element_table_header = (const struct spdm_opaque_element_table_header*)
				((const uint8_t*) opaque_element_table_header + current_element_len);
		}
	}

	status = 0;

exit:

	return status;
}

/**
 * Get the size of the opaque data supported version.
 *
 * @param  negotiated_version Negotiated connection version.
 * @param  version_count Version count.
 *
 * @return Size of the opaque data supported version.
 **/
static size_t spdm_get_untrusted_opaque_data_supported_version_data_size (
	uint8_t negotiated_version, uint8_t version_count)
{
	size_t size;

	if (negotiated_version >= SPDM_VERSION_1_2) {
		size = sizeof (struct spdm_general_opaque_data_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_supported_version) +
			sizeof (struct spdm_version_number) * version_count;
	}
	else {
		size = sizeof (struct spdm_secured_message_general_opaque_data_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_supported_version) +
			sizeof (struct spdm_version_number) * version_count;
	}

	/* Add Padding. */
	return (size + 3) & ~3;
}

/**
 * Get the size of opaque data version selection.
 *
 * @param negotiated_version Negotiated connection version.
 * @param secure_message_version_count Number of secure message versions supported.
 *
 * @return Size in bytes of opaque data version selection.
 */
static size_t spdm_get_opaque_data_version_selection_data_size (uint8_t negotiated_version,
	uint8_t secure_message_version_count)
{
	size_t size;

	/* If no secure message version(s) supported, no opaque data is added. */
	if (secure_message_version_count == 0) {
		return 0;
	}

	if (negotiated_version >= SPDM_VERSION_1_2) {
		size = sizeof (struct spdm_general_opaque_data_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_version_selection);
	}
	else {
		size = sizeof (struct spdm_secured_message_general_opaque_data_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_table_header) +
			sizeof (struct spdm_secured_message_opaque_element_version_selection);
	}

	/* Add Padding*/
	return (size + 3) & ~3;
}

/**
 * Get element from multi-element opaque data by element id.
 *
 * @param state SPDM state.
 * @param data_in_size Size of multi-element opaque data.
 * @param data_in Multi-element opaque data buffer.
 * @param element_id Element id.
 * @param sm_data_id Id to identify the secured message data type.
 * @param get_element_ptr Pointer to the element found.
 * @param get_element_len Length of the element found.
 *
 * @retval 0 if the element was rerieved successfully, error code otherwise.
 */
static int spdm_get_element_from_opaque_data (struct spdm_state *state, size_t data_in_size,
	const void *data_in, uint8_t element_id, uint8_t sm_data_id, const void **get_element_ptr,
	size_t *get_element_len)
{
	int status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
	const struct spdm_secured_message_general_opaque_data_table_header
	*general_opaque_data_table_header;
	const struct spdm_general_opaque_data_table_header *spdm_general_opaque_data_table_header;
	const struct spdm_secured_message_opaque_element_table_header *opaque_element_table_header;
	const struct spdm_secured_message_opaque_element_header *secured_message_element_header;
	uint8_t element_num;
	uint8_t element_index;
	size_t data_element_size;
	size_t current_element_len;
	size_t total_element_len;

	total_element_len = 0;

	if ((element_id > SPDM_REGISTRY_ID_MAX) || (data_in_size == 0) || (data_in == NULL)) {
		goto exit;
	}

	if (spdm_get_connection_version (state) >= SPDM_VERSION_1_2) {
		spdm_general_opaque_data_table_header = data_in;
		if (data_in_size < sizeof (struct spdm_general_opaque_data_table_header)) {
			goto exit;
		}
		if (spdm_general_opaque_data_table_header->total_elements < 1) {
			goto exit;
		}
		opaque_element_table_header = (const void*) (spdm_general_opaque_data_table_header + 1);

		element_num = spdm_general_opaque_data_table_header->total_elements;

		data_element_size = data_in_size - sizeof (struct spdm_general_opaque_data_table_header);
	}
	else {
		general_opaque_data_table_header = data_in;
		if (data_in_size < sizeof (struct spdm_secured_message_general_opaque_data_table_header)) {
			goto exit;
		}
		if ((general_opaque_data_table_header->spec_id !=
			SPDM_SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
			(general_opaque_data_table_header->opaque_version !=
			SPDM_SECURED_MESSAGE_OPAQUE_VERSION) ||
			(general_opaque_data_table_header->total_elements < 1)) {
			goto exit;
		}
		opaque_element_table_header = (const void*) (general_opaque_data_table_header + 1);

		element_num = general_opaque_data_table_header->total_elements;

		data_element_size = data_in_size -
			sizeof (struct spdm_secured_message_general_opaque_data_table_header);
	}

	for (element_index = 0; element_index < element_num; element_index++) {
		/* Ensure the opaque_element_table_header is valid. */
		if ((total_element_len + sizeof (struct spdm_secured_message_opaque_element_table_header)) >
			data_element_size) {
			goto exit;
		}

		/* Check element header Id. */
		if ((opaque_element_table_header->id > SPDM_REGISTRY_ID_MAX) ||
			(opaque_element_table_header->vendor_len != 0)) {
			goto exit;
		}

		current_element_len = sizeof (struct spdm_secured_message_opaque_element_table_header) +
			opaque_element_table_header->opaque_element_data_len;
		/* Add Padding. */
		current_element_len = (current_element_len + 3) & ~3;

		total_element_len += current_element_len;

		if (data_element_size < total_element_len) {
			goto exit;
		}

		if (opaque_element_table_header->id == element_id) {
			secured_message_element_header = (const void*) (opaque_element_table_header + 1);
			if (((const uint8_t*) secured_message_element_header +
				sizeof (struct spdm_secured_message_opaque_element_header)) >
				((const uint8_t*) data_in + data_in_size)) {
				goto exit;
			}

			if ((secured_message_element_header->sm_data_id == sm_data_id) &&
				(secured_message_element_header->sm_data_version ==
				SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION)) {
				/* Get the element by element id. */
				*get_element_ptr = opaque_element_table_header;
				*get_element_len = current_element_len;
			}
		}

		/* Move to the next element. */
		opaque_element_table_header =
			(const struct spdm_secured_message_opaque_element_table_header*)
			((const uint8_t*) opaque_element_table_header + current_element_len);
	}

	/* Ensure the data size is correct. */
	if (data_element_size != total_element_len) {
		goto exit;
	}

	status = 0;

exit:

	return status;
}

/**
 * Process the opaque data supported version data and find a common secure message version.
 *
 * @param state SPDM state.
 * @param secure_message_version_num Local secure message version number(s).
 * @param secure_message_version_num_count Secure message version number count.
 * @param data_in Opaque data buffer.
 * @param data_in_size Opaque data buffer size.
 *
 * @return 0 if the opaque data supported version data is valid, error code otherwise.
 */
static int spdm_process_opaque_data_supported_version_data (struct spdm_state *state,
	const struct spdm_version_num_entry *secure_message_version_num,
	uint8_t secure_message_version_num_count, const void *data_in, size_t data_in_size)
{
	int status;
	const struct spdm_secured_message_opaque_element_table_header *opaque_element_table_header;
	const struct spdm_secured_message_opaque_element_supported_version
	*opaque_element_support_version;
	const struct spdm_version_number *versions_list;
	struct spdm_version_number common_version = {0};
	struct spdm_version_number temp_version;
	uint8_t version_count;
	const void *get_element_ptr;
	size_t get_element_len;
	uint8_t local_ver_idx, peer_ver_idx;
	uint8_t local_ver, peer_ver;

	get_element_ptr = NULL;

	if (secure_message_version_num_count == 0) {
		return 0;
	}

	if (data_in_size <
		spdm_get_untrusted_opaque_data_supported_version_data_size (spdm_get_connection_version (
			state), 1)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		goto exit;
	}

	status = spdm_get_element_from_opaque_data (state, data_in_size, data_in, SPDM_REGISTRY_ID_DMTF,
		SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION, &get_element_ptr,
		&get_element_len);
	if (status != 0) {
		goto exit;
	}

	if (get_element_ptr == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
		goto exit;
	}

	opaque_element_table_header = (const struct spdm_secured_message_opaque_element_table_header*)
		get_element_ptr;

	/* Check for supported version data. */
	opaque_element_support_version = (const void*) (opaque_element_table_header + 1);

	if ((const uint8_t*) opaque_element_support_version +
		sizeof (struct spdm_secured_message_opaque_element_supported_version) >
		(const uint8_t*) opaque_element_table_header + get_element_len) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
		goto exit;
	}

	if (opaque_element_support_version->version_count == 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
		goto exit;
	}

	version_count = opaque_element_support_version->version_count;

	if ((opaque_element_table_header->vendor_len != 0) ||
		(opaque_element_table_header->opaque_element_data_len !=
		sizeof (struct spdm_secured_message_opaque_element_supported_version) +
		sizeof (struct spdm_version_number) * version_count)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
		goto exit;
	}

	versions_list = (const void*) (opaque_element_support_version + 1);

	if (((const uint8_t*) versions_list + (sizeof (struct spdm_version_number) * version_count)) >
		((const uint8_t*) opaque_element_table_header + get_element_len)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_OPAQUE_DATA_FORMAT;
		goto exit;
	}

	/* Find a common secure message version. */
	for (local_ver_idx = 0; local_ver_idx < secure_message_version_num_count; local_ver_idx++) {
		local_ver = SPDM_MAKE_VERSION (secure_message_version_num[local_ver_idx].major_version,
			secure_message_version_num[local_ver_idx].minor_version);

		for (peer_ver_idx = 0; peer_ver_idx < version_count; peer_ver_idx++) {
			memcpy (&temp_version, &versions_list[peer_ver_idx], sizeof (temp_version));
			peer_ver = SPDM_MAKE_VERSION (temp_version.major_version, temp_version.minor_version);

			if (local_ver == peer_ver) {
				memcpy (&common_version, &versions_list[peer_ver_idx], sizeof (common_version));
				break;
			}
		}
	}

	if (SPDM_MAKE_VERSION (common_version.major_version, common_version.minor_version) == 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		goto exit;
	}
	state->connection_info.secure_message_version = common_version;

exit:

	return status;
}

/**
 * Build the opaque data version selection data.
 *
 * @param spdm_responder SPDM responder instance.
 * @param data_out A pointer to the buffer to store the opaque data version selection.
 **/
static void spdm_build_opaque_data_version_selection_data (
	const struct cmd_interface_spdm_responder *spdm_responder, void *data_out)
{
	size_t final_data_size;
	struct spdm_secured_message_general_opaque_data_table_header*
		secured_general_opaque_data_table_header;
	struct spdm_general_opaque_data_table_header *general_opaque_data_table_header;
	struct spdm_secured_message_opaque_element_table_header *opaque_element_table_header;
	struct spdm_secured_message_opaque_element_version_selection *opaque_element_version_section;
	void *end;
	struct spdm_state *state = spdm_responder->state;

	if (spdm_responder->secure_message_version_num_count == 0) {
		return;
	}

	final_data_size =
		spdm_get_opaque_data_version_selection_data_size (spdm_get_connection_version (state),
		spdm_responder->secure_message_version_num_count);

	if (spdm_get_connection_version (state) >= SPDM_VERSION_1_2) {
		general_opaque_data_table_header = data_out;
		general_opaque_data_table_header->total_elements = 1;
		buffer_unaligned_write24 (general_opaque_data_table_header->reserved, 0);

		opaque_element_table_header = (void*) (general_opaque_data_table_header + 1);
	}
	else {
		secured_general_opaque_data_table_header = data_out;
		secured_general_opaque_data_table_header->spec_id =
			SPDM_SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
		secured_general_opaque_data_table_header->opaque_version =
			SPDM_SECURED_MESSAGE_OPAQUE_VERSION;
		secured_general_opaque_data_table_header->total_elements = 1;
		secured_general_opaque_data_table_header->reserved = 0;

		opaque_element_table_header = (void*) (secured_general_opaque_data_table_header + 1);
	}
	opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
	opaque_element_table_header->vendor_len = 0;
	opaque_element_table_header->opaque_element_data_len =
		sizeof (struct spdm_secured_message_opaque_element_version_selection);

	opaque_element_version_section = (void*) (opaque_element_table_header + 1);
	opaque_element_version_section->sm_data_version =
		SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
	opaque_element_version_section->sm_data_id =
		SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
	opaque_element_version_section->selected_version =
		state->connection_info.secure_message_version;

	/* Zero Padding */
	end = opaque_element_version_section + 1;
	memset (end, 0, (size_t) data_out + final_data_size - (size_t) end);
}

/**
 * Reset transcript(s) in the Transcript Manager according to the request/response code.
 *
 * @param state SPDM state.
 * @param transcript_manager SPDM transcript manager.
 * @param req_rsp_code The SPDM request/response code.
 */
static void spdm_reset_transcript_via_request_code (struct spdm_state *state,
	const struct spdm_transcript_manager *transcript_manager, uint8_t req_rsp_code)
{
	/* Any requests other than SPDM_GET_MEASUREMENTS resets L1/L2 */
	if (req_rsp_code != SPDM_REQUEST_GET_MEASUREMENTS) {
		transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
			false, SPDM_MAX_SESSION_COUNT);
	}

	/* If the Requester issued GET_MEASUREMENTS or KEY_EXCHANGE or FINISH or PSK_EXCHANGE
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
 * Get the list of the cerficates in slot 0.
 *
 * @param key_manager RIoT device key manager.
 * @param cert_count_out Number of certificates in the chain.
 * @param cert Certificate chain list in DER format.
 * @param keys_out On success, ptr. to the RIoT keys. This must be released by the caller by calling
 * riot_key_manager_release_riot_keys.
 *
 * @return 0 if certificate list was retrieved successfully or an error code.
 */
static int spdm_get_certificate_list (struct riot_key_manager *key_manager,	uint8_t *cert_count_out,
	struct der_cert *cert, const struct riot_keys **keys_out)
{
	int status = 0;
	const struct der_cert *int_ca;
	const struct der_cert *root_ca;
	const struct riot_keys *keys = NULL;
	uint8_t cert_count = 0;

	root_ca = riot_key_manager_get_root_ca (key_manager);
	if (root_ca != NULL) {
		cert[cert_count] = *root_ca;
		cert_count += 1;
	}
	int_ca = riot_key_manager_get_intermediate_ca (key_manager);
	if (int_ca != NULL) {
		cert[cert_count] = *int_ca;
		cert_count += 1;
	}

	keys = riot_key_manager_get_riot_keys (key_manager);
	if ((keys->devid_cert == NULL) || (keys->devid_cert_length == 0)) {
		status = CMD_HANDLER_SPDM_RESPONDER_DEVICE_CERT_NOT_AVAILABLE;
		goto exit;
	}
	cert[cert_count].cert = keys->devid_cert;
	cert[cert_count].length = keys->devid_cert_length;
	cert_count += 1;

	if ((keys->alias_cert == NULL) || (keys->alias_cert_length == 0)) {
		status = CMD_HANDLER_SPDM_RESPONDER_ALIAS_CERT_NOT_AVAILABLE;
		goto exit;
	}
	cert[cert_count].cert = keys->alias_cert;
	cert[cert_count].length = keys->alias_cert_length;
	cert_count += 1;

	*cert_count_out = cert_count;
	*keys_out = keys;
	keys = NULL;

exit:
	if (keys != NULL) {
		riot_key_manager_release_riot_keys (key_manager, keys);
	}

	return status;
}

/**
 * Get the digest of the spdm certificate chain.
 *
 * @param key_manager RIoT device key manager.
 * @param hash_engine Hash engine for hashing operations.
 * @param hash_type Hash type.
 * @param digest Buffer to hold the digest.
 *
 * @return 0 if the digest was calculated successfully or an error code.
 */
static int spdm_get_certificate_chain_digest (struct riot_key_manager *key_manager,
	struct hash_engine *hash_engine, enum hash_type hash_type, uint8_t *digest)
{
	int status;
	uint8_t i_cert;
	struct der_cert cert[SPDM_MAX_CERT_COUNT_IN_CHAIN];
	uint8_t cert_count;
	struct spdm_cert_chain cert_chain;
	uint32_t cert_chain_length;
	const struct riot_keys *keys = NULL;
	int hash_size;
	bool cancel_hash = false;

	/* Retrieve the certificate chain. */
	status = spdm_get_certificate_list (key_manager, &cert_count, cert, &keys);
	if (status != 0) {
		goto exit;
	}

	hash_size = hash_get_hash_length (hash_type);
	if (hash_size == HASH_ENGINE_UNKNOWN_HASH) {
		status = HASH_ENGINE_UNKNOWN_HASH;
		goto exit;
	}

	/* Hash the root cert. */
	status = hash_calculate (hash_engine, hash_type, cert[0].cert, cert[0].length,
		cert_chain.root_hash, hash_size);
	if (ROT_IS_ERROR (status)) {
		goto exit;
	}
	status = 0;

	/* Calculate the cert chain length. */
	cert_chain_length = 0;
	for (i_cert = 0; i_cert < cert_count; ++i_cert) {
		cert_chain_length += cert[i_cert].length;
	}

	cert_chain.header.length = spdm_get_digests_cert_chain_length (hash_size, cert_chain_length);
	cert_chain.header.reserved = 0;

	/* Start the cert chain hash. */
	status = hash_start_new_hash (hash_engine, hash_type);
	if (status != 0) {
		goto exit;
	}
	cancel_hash = true;

	/* Hash the header of the cert chain and the root cert digest. */
	status = hash_engine->update (hash_engine, (uint8_t*) &cert_chain,
		offsetof (struct spdm_cert_chain, root_hash) + hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Hash the individual certs in the cert chain. */
	for (i_cert = 0; i_cert < cert_count; i_cert++) {
		status = hash_engine->update (hash_engine, cert[i_cert].cert, cert[i_cert].length);
		if (status != 0) {
			goto exit;
		}
	}

	status = hash_engine->finish (hash_engine, digest, hash_size);
	if (status != 0) {
		goto exit;
	}
	cancel_hash = false;

exit:
	if (keys != NULL) {
		riot_key_manager_release_riot_keys (key_manager, keys);
	}

	if (cancel_hash == true) {
		hash_engine->cancel (hash_engine);
	}

	return status;
}

/**
 * SPDM signature context as described in Section 15 of the SPDM specification.
 */
static const struct spdm_signing_context_str spdm_signing_context_str_table[] = {
	{
		.is_requester = false,
		.op_code = SPDM_RESPONSE_CHALLENGE,
		.context = SPDM_CHALLENGE_AUTH_SIGN_CONTEXT,
		.context_size = SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE,
		.zero_pad_size = 36 - SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE
	},
	{
		.is_requester = true,
		.op_code = SPDM_RESPONSE_CHALLENGE,
		.context = SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT,
		.context_size = SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE,
		.zero_pad_size = 36 - SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE
	},
	{
		.is_requester = false,
		.op_code = SPDM_RESPONSE_GET_MEASUREMENTS,
		.context = SPDM_MEASUREMENTS_SIGN_CONTEXT,
		.context_size = SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE,
		.zero_pad_size = 36 - SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE
	},
	{
		.is_requester = false,
		.op_code = SPDM_RESPONSE_KEY_EXCHANGE,
		.context = SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT,
		.context_size = SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE,
		.zero_pad_size = 36 - SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE
	},
	{
		.is_requester = true,
		.op_code = SPDM_REQUEST_FINISH,
		.context = SPDM_FINISH_SIGN_CONTEXT,
		.context_size = SPDM_FINISH_SIGN_CONTEXT_SIZE,
		.zero_pad_size = 36 - SPDM_FINISH_SIGN_CONTEXT_SIZE
	},
};


/**
 * Create a SPDM signing context, which is required since SPDM 1.2.
 *
 * @param state SPDM state.
 * @param op_code SPDM request/response opcode.
 * @param is_requester True if the message is from the requester, false if from the responder.
 * @param spdm_signing_context SPDM signing context.
 */
static void spdm_create_signing_context (struct spdm_state *state, uint8_t op_code,
	bool is_requester, char *spdm_signing_context)
{
	uint8_t index;
	struct spdm_version_number version = state->connection_info.version;

	for (index = 0; index < 4; index++) {
		memcpy (spdm_signing_context, SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT,
			SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE);

		/* Patch the version. */
		spdm_signing_context[SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_MAJOR_VERSION_OFFSET] =
			(char) ('0' + (version.major_version));
		spdm_signing_context[SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_MINOR_VERSION_OFFSET] =
			(char) ('0' + (version.minor_version));
		spdm_signing_context[SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_ASTERIX_OFFSET] = (char) ('*');
		spdm_signing_context += SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE;
	}

	for (index = 0; index < ARRAY_SIZE (spdm_signing_context_str_table); index++) {
		if ((spdm_signing_context_str_table[index].is_requester == is_requester) &&
			(spdm_signing_context_str_table[index].op_code == op_code)) {
			memset (spdm_signing_context, 0, spdm_signing_context_str_table[index].zero_pad_size);
			memcpy (spdm_signing_context + spdm_signing_context_str_table[index].zero_pad_size,
				spdm_signing_context_str_table[index].context,
				spdm_signing_context_str_table[index].context_size);

			return;
		}
	}
}

/**
 * Generate a SPDM response signature.
 *
 * @param state SPDM state.
 * @param key_manager RIoT device key manager.
 * @param ecc_engine ECC engine.
 * @param hash_engine Hash engine.
 * @param op_code SPDM request opcode.
 * @param message_hash The message hash to be signed.
 * @param hash_size The size in bytes of the message hash.
 * @param signature Buffer to store the signature.
 * @param sig_size The size of the signature buffer.
 *
 * @return 0 if signature is generated successfully, error code otherwise.
 */
static int spdm_responder_data_sign (struct spdm_state *state, struct riot_key_manager *key_manager,
	struct ecc_engine *ecc_engine, struct hash_engine *hash_engine, uint8_t op_code,
	const uint8_t *message_hash, size_t hash_size, uint8_t *signature, size_t sig_size)
{
	int status;
	uint8_t *message;
	size_t message_size;
	uint8_t full_message_hash[HASH_MAX_HASH_LEN];
	uint8_t spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE +
		HASH_MAX_HASH_LEN];
	struct ecc_private_key alias_priv_key;
	bool release_alias_key = false;
	uint8_t spdm_version;
	int sig_size_der;
	uint8_t sig_der[ECC_DER_ECDSA_MAX_LENGTH];
	uint32_t sig_r_component_size = sig_size >> 1;
	enum hash_type hash_type;
	const struct riot_keys *keys = NULL;

	spdm_version = SPDM_MAKE_VERSION (state->connection_info.version.major_version,
		state->connection_info.version.minor_version);
	hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);
	keys = riot_key_manager_get_riot_keys (key_manager);

	/* Get the private key reference for the alias certificate. */
	status = ecc_engine->init_key_pair (ecc_engine, keys->alias_key, keys->alias_key_length,
		&alias_priv_key, NULL);
	if (status != 0) {
		goto exit;
	}
	release_alias_key = true;

	sig_size_der = ecc_engine->get_signature_max_length (ecc_engine, &alias_priv_key);
	if (ROT_IS_ERROR (sig_size_der)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		goto exit;
	}

	/* v1.2 (and greater) requires a signing context prepended to the hash. */
	if (spdm_version > SPDM_VERSION_1_1) {
		/* Create the signing context. */
		spdm_create_signing_context (state, op_code, false,
			(char*) spdm12_signing_context_with_hash);

		/* Copy the hash to the signing context buffer. */
		memcpy (&spdm12_signing_context_with_hash[SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE],
			message_hash, hash_size);

		/* Assign message and message_size for signing. */
		message = spdm12_signing_context_with_hash;
		message_size = SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + hash_size;

		/* Calculate the message hash as required by ECDSA. It may not be needed for other algos. */
		status = hash_calculate (hash_engine, hash_type, message, message_size, full_message_hash,
			hash_size);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}
		status = 0;

		/* Sign the full message hash. */
		sig_size_der = ecc_engine->sign (ecc_engine, &alias_priv_key, full_message_hash, hash_size,
			sig_der, sig_size_der);
	}
	else {
		sig_size_der = ecc_engine->sign (ecc_engine, &alias_priv_key, message_hash, hash_size,
			sig_der, sig_size_der);
	}
	if (ROT_IS_ERROR (sig_size_der)) {
		status = sig_size_der;
		goto exit;
	}

	/* Convert signature from DER encoding to <r,s> format. */
	status = ecc_der_decode_ecdsa_signature (sig_der, sig_size_der, signature,
		&signature[sig_r_component_size], sig_r_component_size);
	if (status != 0) {
		goto exit;
	}

exit:
	if (release_alias_key == true) {
		ecc_engine->release_key_pair (ecc_engine, &alias_priv_key, NULL);
	}

	if (keys != NULL) {
		riot_key_manager_release_riot_keys (key_manager, keys);
	}

	return status;
}

/**
 * Generate the SPDM measurement signature.
 *
 * @param transcript_manager SPDM transcript manager.
 * @param state SPDM state.
 * @param key_manager RIoT device key manager.
 * @param ecc_engine ECC engine.
 * @param hash_engine Hash engine.
 * @param session_info Session information.
 * @param signature Buffer to store the signature.
 * @param sig_size The size of the signature.
 *
 * @return 0 if signature is generated successfully, error code otherwise.
 */
static int spdm_generate_measurement_signature (
	const struct spdm_transcript_manager *transcript_manager, struct spdm_state *state,
	struct riot_key_manager *key_manager, struct ecc_engine *ecc_engine,
	struct hash_engine *hash_engine, void *session_info, uint8_t *signature, size_t sig_size)
{
	int status;
	uint8_t l1l2_hash[HASH_MAX_HASH_LEN];
	int l1l2_hash_size;
	uint8_t session_idx = SPDM_MAX_SESSION_COUNT;

	l1l2_hash_size =
		hash_get_hash_length (spdm_get_hash_type (
		state->connection_info.peer_algorithms.base_hash_algo));

	/* Get the L1L2 hash. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		true /* finish hash */, (session_info != NULL), session_idx, l1l2_hash, l1l2_hash_size);

	/* Reset the L1L2 hash context. */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(session_info != NULL), session_idx);

	if (status != 0) {
		goto exit;
	}

	/* Sign the L1L2 hash. */
	status = spdm_responder_data_sign (state, key_manager, ecc_engine, hash_engine,
		SPDM_RESPONSE_GET_MEASUREMENTS, l1l2_hash, l1l2_hash_size, signature, sig_size);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Generate the KEY_EXCHANGE response signature.
 *
 * @param transcript_manager SPDM transcript manager.
 * @param state SPDM state.
 * @param key_manager RIoT device key manager.
 * @param ecc_engine ECC engine.
 * @param hash_engine Hash engine.
 * @param session SPDM secure session.
 * @param signature Buffer to store the signature.
 * @param sig_size The size of the signature buffer.
 *
 * @return 0 if the signature is generated successfully, error code otherwise.
 */
static int spdm_generate_key_exchange_rsp_signature (
	const struct spdm_transcript_manager *transcript_manager, struct spdm_state *state,
	struct riot_key_manager *key_manager, struct ecc_engine *ecc_engine,
	struct hash_engine *hash_engine, struct spdm_secure_session *session, uint8_t *signature,
	uint32_t sig_size)
{
	int status;
	uint8_t th_hash[HASH_MAX_HASH_LEN];
	int th_hash_size;

	th_hash_size =
		hash_get_hash_length (spdm_get_hash_type (
		state->connection_info.peer_algorithms.base_hash_algo));

	/* Get the TH hash; do not complete the hash context as it is needed later. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		true, session->session_index, th_hash, th_hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Sign the TH hash. */
	status = spdm_responder_data_sign (state, key_manager, ecc_engine, hash_engine,
		SPDM_RESPONSE_KEY_EXCHANGE, th_hash, th_hash_size, signature, sig_size);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/*
 * Calculate the TH HMAC with the response finished_key.
 *
 * @param transcript_manager SPDM transcript manager.
 * @param state SPDM state.
 * @param ecc_engine ECC engine.
 * @param hash_engine Hash engine.
 * @param session SPDM session.
 * @param th_hmac_buffer Buffer to store the TH HMAC
 *
 * @return 0 if the current TH HMAC is calculated successfully, error code otherwise.
 */
static int spdm_calculate_th_hmac_for_key_exchange_rsp (
	const struct spdm_transcript_manager *transcript_manager, struct spdm_state *state,
	struct ecc_engine *ecc_engine, struct hash_engine *hash_engine,
	struct spdm_secure_session *session, uint8_t *th_hmac_buffer)
{
	int status;
	uint8_t th_hash[HASH_MAX_HASH_LEN];
	int hash_size;
	enum hash_type hash_type;

	UNUSED (ecc_engine);

	hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);
	hash_size = hash_get_hash_length (hash_type);

	/* Get the TH hash; do not complete the hash as it is needed later. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		true, session->session_index, th_hash, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Calculate the TH HMAC. */
	status = hash_generate_hmac (hash_engine, session->handshake_secret.response_finished_key,
		hash_size, th_hash, hash_size, (enum hmac_hash) hash_type, th_hmac_buffer, hash_size);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Verify the reqester HMAC.
 *
 * @param transcript_manager SPDM transcript manager.
 * @param hash_engine Hash engine.
 * @param session SPDM session state.
 * @param hmac Requester HMAC.
 * @param hmac_size Requester HMAC size.
 *
 * @return 0 if the HMAC is verified successfully, error code otherwise.
 */
static int spdm_verify_finish_req_hmac (const struct spdm_transcript_manager *transcript_manager,
	struct hash_engine *hash_engine, struct spdm_secure_session *session, const uint8_t *hmac,
	size_t hmac_size)
{
	int status;
	uint8_t th_hash[HASH_MAX_HASH_LEN];
	uint8_t hmac_computed[HASH_MAX_HASH_LEN];

	/* Get the TH hash; do not complete the hash as it is needed later. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		true, session->session_index, th_hash, session->hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the HMAC with the Requester Finished key. */
	status = hash_generate_hmac (hash_engine, session->handshake_secret.request_finished_key,
		session->hash_size, th_hash, session->hash_size,
		(enum hmac_hash) spdm_get_hash_type (session->base_hash_algo), hmac_computed, hmac_size);
	if (status != 0) {
		goto exit;
	}

	/* Compare the HMAC values. */
	if (memcmp (hmac, hmac_computed, hmac_size) != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		goto exit;
	}

exit:

	return status;
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
	const struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	struct spdm_secure_session_manager *session_manager;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	rq = (struct spdm_get_version_request*) request->payload;
	state = spdm_responder->state;
	transcript_manager = spdm_responder->transcript_manager;
	session_manager = spdm_responder->session_manager;

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
		spdm_generate_error_response (request, 0, SPDM_ERROR_VERSION_MISMATCH, 0x00, NULL, 0,
			SPDM_REQUEST_GET_VERSION, CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH);
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
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) rq, sizeof (struct spdm_get_version_request), false,
		SPDM_MAX_SESSION_COUNT);
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			SPDM_ERROR_UNSPECIFIED, 0x00, NULL, 0, SPDM_REQUEST_GET_VERSION, status);
		goto exit;
	}

	/* Initialize the SPDM state. No error check as this function call cannot fail. */
	spdm_init_state (state);

	/* Reset any in-progress session(s). */
	if (session_manager) {
		session_manager->reset (session_manager);
	}

	/* Contruct the response. */
	rsp = (struct spdm_get_version_response*) request->payload;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	rsp->reserved = 0;
	rsp->reserved2 = 0;
	rsp->reserved3 = 0;

	/* Copy the supported version(s) to the response buffer. */
	rsp->version_num_entry_count = spdm_responder->version_num_count;
	memcpy ((void*) spdm_get_version_resp_version_table (rsp), (void*) spdm_responder->version_num,
		spdm_responder->version_num_count * sizeof (struct spdm_version_num_entry));

	cmd_interface_msg_set_message_payload_length (request, spdm_get_version_resp_length (rsp));

	/* Append response to the VCA buffer. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) rsp, request->payload_length, false, SPDM_MAX_SESSION_COUNT);
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
	const struct spdm_transcript_manager *transcript_manager;
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
		spdm_generate_error_response (request, 0, SPDM_ERROR_VERSION_MISMATCH, 0x00, NULL, 0,
			SPDM_REQUEST_GET_CAPABILITIES, CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH);
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
	if (spdm_check_request_flag_compatibility (req_resp->base_capabilities.flags, spdm_version) ==
		false) {
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

	/* Update SPDM version in transcript manager to make sure proper behavior */
	transcript_manager->set_spdm_version (spdm_responder->transcript_manager, spdm_version);

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

	if (spdm_minor_version < 1) {
		if (buf_len < sizeof (struct spdm_get_capabilities_1_0)) {
			return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
		}
		memset (rq, 0, sizeof (struct spdm_get_capabilities_1_0));
	}
	else if (spdm_minor_version < 2) {
		if (buf_len < sizeof (struct spdm_get_capabilities_1_1)) {
			return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
		}
		memset (rq, 0, sizeof (struct spdm_get_capabilities_1_1));
	}
	else {
		if (buf_len < sizeof (struct spdm_get_capabilities)) {
			return CMD_HANDLER_SPDM_BUF_TOO_SMALL;
		}
		memset (rq, 0, sizeof (struct spdm_get_capabilities));
	}

	spdm_populate_header (&rq->base_capabilities.header, SPDM_REQUEST_GET_CAPABILITIES,
		spdm_minor_version);

	if (spdm_minor_version > 0) {
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
	}

	if (spdm_minor_version < 1) {
		return sizeof (struct spdm_get_capabilities_1_0);
	}
	else if (spdm_minor_version < 2) {
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
					local_algorithms->dhe_named_group, algstruct_table->alg_supported);

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
					local_algorithms->aead_cipher_suite, algstruct_table->alg_supported);

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
					local_algorithms->req_base_asym_alg, algstruct_table->alg_supported);

				state->connection_info.peer_algorithms.req_base_asym_alg =
					resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported;
				break;

			case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
				if (algstruct_table->alg_supported == 0) {
					goto exit;
				}

				resp_no_ext_alg->algstruct_table[i_algstruct].alg_type = algstruct_table->alg_type;
				resp_no_ext_alg->algstruct_table[i_algstruct].fixed_alg_count = 2;
				resp_no_ext_alg->algstruct_table[i_algstruct].ext_alg_count = 0;
				resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported =
					(uint16_t) spdm_prioritize_algorithm (
					local_algo_priority_table->key_schedule_priority_table,
					local_algo_priority_table->key_schedule_priority_table_count,
					local_algorithms->key_schedule,	algstruct_table->alg_supported);

				state->connection_info.peer_algorithms.key_schedule =
					resp_no_ext_alg->algstruct_table[i_algstruct].alg_supported;
				break;
		}

		/* Go to the next algstruct_table entry. */
		algstruct_table =
			spdm_negotiate_algorithms_get_next_alg_struct_table_entry (algstruct_table);
	}

	if ((local_capabilities->flags.meas_cap == SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITHOUT_SIG) ||
		(local_capabilities->flags.meas_cap == SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITH_SIG)) {
		resp->measurement_specification =
			(uint8_t) spdm_prioritize_algorithm (
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

	resp->base_asym_sel = spdm_prioritize_algorithm (local_algo_priority_table->asym_priority_table,
		local_algo_priority_table->asym_priority_table_count, local_algorithms->base_asym_algo,
		state->connection_info.peer_algorithms.base_asym_algo);
	state->connection_info.peer_algorithms.base_asym_algo = resp->base_asym_sel;

	resp->base_hash_sel = spdm_prioritize_algorithm (local_algo_priority_table->hash_priority_table,
		local_algo_priority_table->hash_priority_table_count, local_algorithms->base_hash_algo,
		state->connection_info.peer_algorithms.base_hash_algo);
	state->connection_info.peer_algorithms.base_hash_algo = resp->base_hash_sel;

	if (spdm_version >= SPDM_VERSION_1_2) {
		resp->other_params_selection.opaque_data_format =
			(uint8_t) spdm_prioritize_algorithm (
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
	const struct spdm_transcript_manager *transcript_manager;
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
		algstruct_table =
			spdm_negotiate_algorithms_get_next_alg_struct_table_entry (algstruct_table);
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
	if (resp->header.spdm_minor_version < 1) {
		if (resp->num_alg_structure_tables != 0) {
			return CMD_HANDLER_SPDM_BAD_RESPONSE;
		}
	}

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
 * Process the SPDM GET_DIGESTS request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request GET_DIGESTS request to process.
 *
 * @return 0 if the request was processed successfully or an error code.
 */
int spdm_get_digests (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	struct spdm_get_digests_request *spdm_request;
	struct spdm_get_digests_response *spdm_response;
	uint8_t spdm_version;
	uint32_t response_size;
	int hash_size;
	const struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	const struct spdm_device_capability *local_capabilities;
	struct riot_key_manager *key_manager;
	struct hash_engine *hash_engine;
	enum hash_type hash_type;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_secure_session *session = NULL;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	local_capabilities = spdm_responder->local_capabilities;
	key_manager = spdm_responder->key_manager;
	hash_engine = spdm_responder->hash_engine[0];
	hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);
	session_manager = spdm_responder->session_manager;

	/* Validate the request. */
	if (request->payload_length < sizeof (struct spdm_get_digests_request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}
	spdm_request = (struct spdm_get_digests_request*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
		spdm_request->header.spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify SPDM state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_GET_DIGESTS);
		goto exit;
	}
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Check if the certificate capability is supported. */
	if (local_capabilities->flags.cert_cap == 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		spdm_error = SPDM_ERROR_UNSUPPORTED_REQUEST;
		goto exit;
	}

	/* Check if a session is ongoing. */
	if ((session_manager != NULL) &&
		(session_manager->is_last_session_id_valid (session_manager) == true)) {
		session = session_manager->get_session (session_manager,
			session_manager->get_last_session_id (session_manager));
		if (session == NULL) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
			spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
			goto exit;
		}

		/* Check session state. */
		if (session->session_state != SPDM_SESSION_STATE_ESTABLISHED) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
			spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
			goto exit;
		}
	}

	/* Reset transcript manager state as per request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager, SPDM_REQUEST_GET_DIGESTS);

	/* Add request to M1M2 hash context. */
	if (session == NULL) {
		status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
			request->payload, sizeof (struct spdm_get_digests_request), false,
			SPDM_MAX_SESSION_COUNT);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Construct the response. */
	hash_size = hash_get_hash_length (hash_type);
	if (hash_size == HASH_ENGINE_UNKNOWN_HASH) {
		status = HASH_ENGINE_UNKNOWN_HASH;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	response_size = sizeof (struct spdm_get_digests_response) + hash_size;
	if (response_size > cmd_interface_msg_get_max_response (request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_RESPONSE_TOO_LARGE;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	spdm_response = (struct spdm_get_digests_response*) request->payload;
	memset (spdm_response, 0, response_size);

	spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_GET_DIGESTS,
		SPDM_GET_MINOR_VERSION (spdm_version));
	spdm_response->slot_mask = 1;

	/* Get the digest of the certificate chain. */
	status = spdm_get_certificate_chain_digest (key_manager, hash_engine, hash_type,
		(uint8_t*) (spdm_response + 1));
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Add response to M1M2 hash context. */
	if (session == NULL) {
		status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
			(uint8_t*) spdm_response, response_size, false, SPDM_MAX_SESSION_COUNT);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, response_size);

	/* Update connection state */
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_AFTER_DIGESTS) {
		spdm_set_connection_state (state, SPDM_CONNECTION_STATE_AFTER_DIGESTS);
	}

exit:
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_GET_DIGESTS, status);
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
 * Process SPDM GET_CERTIFICATE request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request GET_CERTIFICATE request to process.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_get_certificate (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	uint8_t spdm_version;
	uint8_t slot_id;
	struct spdm_get_certificate_request *spdm_request;
	struct spdm_get_certificate_response *spdm_response;
	uint16_t requested_offset;
	uint16_t requested_length;
	size_t remainder_length = 0;
	size_t response_size;
	struct der_cert cert[SPDM_MAX_CERT_COUNT_IN_CHAIN];
	uint8_t cert_count = ARRAY_SIZE (cert);
	uint32_t hash_size;
	uint8_t *cert_chain = NULL;
	uint32_t cert_chain_length;
	uint32_t cert_chain_offset;
	uint8_t i_cert;
	uint32_t max_cert_block_len;
	struct spdm_cert_chain_header *cert_chain_header;
	const struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	const struct spdm_device_capability *local_capabilities;
	struct riot_key_manager *key_manager;
	struct hash_engine *hash_engine;
	enum hash_type hash_type;
	const struct riot_keys *keys = NULL;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_secure_session *session = NULL;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	local_capabilities = spdm_responder->local_capabilities;
	key_manager = spdm_responder->key_manager;
	hash_engine = spdm_responder->hash_engine[0];
	hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);
	session_manager = spdm_responder->session_manager;

	/* Validate the request. */
	if (request->payload_length < sizeof (struct spdm_get_certificate_request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}
	spdm_request = (struct spdm_get_certificate_request*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
		spdm_request->header.spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify SPDM state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_GET_CERTIFICATE);
		goto exit;
	}
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Check if the certificate capability is supported. */
	if (local_capabilities->flags.cert_cap == 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		spdm_error = SPDM_ERROR_UNSUPPORTED_REQUEST;
		goto exit;
	}

	/* Check if a session is ongoing. */
	if ((session_manager != NULL) &&
		(session_manager->is_last_session_id_valid (session_manager) == true)) {
		session = session_manager->get_session (session_manager,
			session_manager->get_last_session_id (session_manager));
		if (session == NULL) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
			spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
			goto exit;
		}

		/* Check session state. */
		if (session->session_state != SPDM_SESSION_STATE_ESTABLISHED) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
			spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
			goto exit;
		}
	}

	slot_id = spdm_request->slot_num & SPDM_GET_CERTIFICATE_SLOT_ID_MASK;
	if (slot_id != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Retrieve the list of certificates in the certificate chain. */
	status = spdm_get_certificate_list (key_manager, &cert_count, cert, &keys);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	hash_size = hash_get_hash_length (hash_type);
	if (hash_size == HASH_ENGINE_UNKNOWN_HASH) {
		status = HASH_ENGINE_UNKNOWN_HASH;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Calculate the cert chain data struct. length. */
	cert_chain_length = sizeof (struct spdm_cert_chain_header) + hash_size;
	for (i_cert = 0; i_cert < cert_count; ++i_cert) {
		cert_chain_length += cert[i_cert].length;
	}

	/* Allocate a temp. buffer to hold the certificate chain. */
	cert_chain = platform_malloc (cert_chain_length);
	if (cert_chain == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_NO_MEMORY;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}
	cert_chain_header = (struct spdm_cert_chain_header*) cert_chain;
	cert_chain_header->length = (uint16_t) cert_chain_length;
	cert_chain_header->reserved = 0;

	/* Copy cert(s) to the temp. buffer. */
	cert_chain_offset = sizeof (struct spdm_cert_chain_header) + hash_size;
	for (i_cert = 0; i_cert < cert_count; i_cert++) {
		memcpy (&cert_chain[cert_chain_offset], cert[i_cert].cert, cert[i_cert].length);
		cert_chain_offset += cert[i_cert].length;
	}

	requested_offset = spdm_request->offset;
	requested_length = spdm_request->length;

	/* Check if the requested cert. chain offset is valid. */
	if (requested_offset >= cert_chain_length) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Compute the maximum cert block that can be sent. */
	max_cert_block_len = cmd_interface_msg_get_max_response (request) -
		sizeof (struct spdm_get_certificate_response);

	/* If chunking capability is not supported, adjust the requested cert chain length. */
	if (!(state->connection_info.peer_capabilities.flags.chunk_cap &&
		local_capabilities->flags.chunk_cap)) {
		if (requested_length > max_cert_block_len) {
			requested_length = max_cert_block_len;
		}
	}

	/* Adjust the requested length. */
	if ((size_t) (requested_offset + requested_length) > cert_chain_length) {
		requested_length = (uint16_t) (cert_chain_length - requested_offset);
	}
	remainder_length = cert_chain_length - (requested_length + requested_offset);
	response_size = sizeof (struct spdm_get_certificate_response) + requested_length;

	/* Reset transcript manager state as per request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager,
		SPDM_REQUEST_GET_CERTIFICATE);

	/* Add request to M1M2 hash context. */
	if (session == NULL) {
		status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
			(uint8_t*) spdm_request, sizeof (struct spdm_get_certificate_request), false,
			SPDM_MAX_SESSION_COUNT);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Construct the response. */
	spdm_response = (struct spdm_get_certificate_response*) request->payload;
	memset (spdm_response, 0, response_size);

	spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_GET_CERTIFICATE,
		SPDM_GET_MINOR_VERSION (spdm_version));
	spdm_response->slot_num = slot_id;
	spdm_response->portion_len = requested_length;
	spdm_response->remainder_len = (uint16_t) remainder_length;

	/* Hash the root certificate if not already provided to the requester. */
	if (requested_offset < (sizeof (struct spdm_cert_chain_header) + hash_size)) {
		status = hash_calculate (hash_engine, hash_type, cert[0].cert, cert[0].length,
			cert_chain + sizeof (struct spdm_cert_chain_header), hash_size);
		if (ROT_IS_ERROR (status)) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
		status = 0;
	}

	/* Copy cert_chain portion to response. */
	memcpy (spdm_get_certificate_resp_cert_chain (spdm_response), cert_chain + requested_offset,
		requested_length);

	/* Add response to M1M2 hash context. */
	if (session == NULL) {
		status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
			(uint8_t*) spdm_response, response_size, false, SPDM_MAX_SESSION_COUNT);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, response_size);

	/* Update connection state */
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_AFTER_CERTIFICATE) {
		spdm_set_connection_state (state, SPDM_CONNECTION_STATE_AFTER_CERTIFICATE);
	}

exit:
	if (keys != NULL) {
		riot_key_manager_release_riot_keys (key_manager, keys);
	}

	platform_free (cert_chain);

	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_GET_CERTIFICATE, status);
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
	uint8_t req_measurement_summary_hash_type, uint8_t *nonce, uint8_t spdm_minor_version)
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
 * Process the SPDM GET_MEASUREMENTS request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request GET_MEASUREMENTS request to process.
 *
 * @return 0 if the request was processed successfully or an error code.
 */
int spdm_get_measurements (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	const struct spdm_get_measurements_request *spdm_request;
	struct spdm_get_measurements_response *spdm_response;
	uint8_t spdm_version;
	const struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	const struct spdm_device_capability *local_capabilities;
	struct hash_engine *hash_engine;
	enum hash_type hash_type;
	size_t signature_size;
	size_t request_size;
	size_t response_size;
	const struct spdm_measurements *measurements;
	struct rng_engine *rng_engine;
	uint8_t measurement_operation;
	int measurement_count;
	int measurement_length;
	bool raw_bit_stream_requested;
	bool signature_requested;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_secure_session *session = NULL;
	uint8_t session_idx = SPDM_MAX_SESSION_COUNT;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	local_capabilities = spdm_responder->local_capabilities;
	hash_engine = spdm_responder->hash_engine[0];
	hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);
	measurements = spdm_responder->measurements;
	rng_engine = spdm_responder->rng_engine;
	session_manager = spdm_responder->session_manager;

	/* Check if a session is ongoing. */
	if ((session_manager != NULL) &&
		(session_manager->is_last_session_id_valid (session_manager) == true)) {
		session = session_manager->get_session (session_manager,
			session_manager->get_last_session_id (session_manager));
		if (session == NULL) {
			/* Don't reset the L1L2 hash context in this failure case as the correct session context
			 * is not known. This behavior is per libSPDM. */
			spdm_generate_error_response (request, state->connection_info.version.minor_version,
				SPDM_ERROR_UNEXPECTED_REQUEST, 0x00, NULL, 0, SPDM_REQUEST_GET_MEASUREMENTS,
				status);

			return 0;
		}

		session_idx = session->session_index;

		/* Check session state. */
		if (session->session_state != SPDM_SESSION_STATE_ESTABLISHED) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_SESSION_STATE;
			spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
			goto exit;
		}
	}

	/* Validate the request. */
	if (request->payload_length < sizeof (struct spdm_get_measurements_request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}
	request_size = sizeof (struct spdm_get_measurements_request);
	spdm_request = (struct spdm_get_measurements_request*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
		spdm_request->header.spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify SPDM state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		/* [TODO] Handle RESPOND_IF_READY condition when supported. */

		/* [TODO] Remove error response building from this function. */
		spdm_handle_response_state (state, request, SPDM_REQUEST_GET_MEASUREMENTS);

		/* Reset L1L2 hash context. */
		transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
			(session != NULL), session_idx);
		goto exit;
	}
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Check if the measurement capability is supported. */
	if (local_capabilities->flags.meas_cap == 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		spdm_error = SPDM_ERROR_UNSUPPORTED_REQUEST;
		goto exit;
	}

	/* Check if the negotiated parameters for measurement are valid. */
	if ((state->connection_info.peer_algorithms.measurement_spec == 0) ||
		(state->connection_info.peer_algorithms.measurement_hash_algo == 0)) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* If signature generation is requested, check if responder has the support for it. */
	signature_requested = spdm_request->sig_required;
	if (signature_requested == true) {
		if (local_capabilities->flags.meas_cap != SPDM_MEAS_CAP_WITH_SIG) {
			status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
			spdm_error = SPDM_ERROR_UNSUPPORTED_REQUEST;
			goto exit;
		}
		request_size += (SPDM_NONCE_LEN + sizeof (uint8_t));
		if (request->payload_length < request_size) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}

		/* Check if slot id is valid. */
		if (*(spdm_get_measurements_rq_slot_id_ptr (spdm_request)) != 0) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}

		signature_size =
			spdm_get_asym_signature_size (state->connection_info.peer_algorithms.base_asym_algo);
	}
	else {
		signature_size = 0;
	}

	/* Check if sufficient buffer is available for the response including the optional signature. */
	response_size = SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH + signature_size;
	if (cmd_interface_msg_get_max_response (request) < response_size) {
		status = CMD_HANDLER_SPDM_RESPONDER_RESPONSE_TOO_LARGE;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	raw_bit_stream_requested = spdm_request->raw_bit_stream_requested;
	measurement_operation = spdm_request->measurement_operation;

	/* Reset transcript manager state as per request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager,
		SPDM_REQUEST_GET_MEASUREMENTS);

	/* Add request to L1L2 hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		request->payload, request_size, (session != NULL), session_idx);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Construct the response. */
	spdm_response = (struct spdm_get_measurements_response*) request->payload;
	memset (spdm_response, 0, sizeof (struct spdm_get_measurements_response));

	spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_GET_MEASUREMENTS,
		SPDM_GET_MINOR_VERSION (spdm_version));

	/* Get the total number of measurement(s) available on the device. */
	measurement_count = measurements->get_measurement_count (measurements);
	if (ROT_IS_ERROR (measurement_count)) {
		status = measurement_count;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	switch (measurement_operation) {
		case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
			spdm_response->num_measurement_indices = measurement_count;
			break;

		case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
			/* Get the measurement record. */
			measurement_length = measurements->get_all_measurement_blocks (measurements,
				raw_bit_stream_requested, hash_engine, hash_type,
				spdm_get_measurements_resp_measurement_record (spdm_response),
				(cmd_interface_msg_get_max_response (request) - response_size));

			if (ROT_IS_ERROR (measurement_length)) {
				status = measurement_length;
				spdm_error = SPDM_ERROR_UNSPECIFIED;
				goto exit;
			}
			response_size += measurement_length;

			spdm_response->number_of_blocks = (uint8_t) measurement_count;
			buffer_unaligned_write24 (spdm_response->measurement_record_len,
				(uint32_t) measurement_length);
			break;

		default:
			/* Get a single measurement. */
			measurement_length = measurements->get_measurement_block (measurements,
				measurement_operation, raw_bit_stream_requested, hash_engine, hash_type,
				spdm_get_measurements_resp_measurement_record (spdm_response),
				(cmd_interface_msg_get_max_response (request) - response_size));

			if (ROT_IS_ERROR (measurement_length)) {
				status = measurement_length;
				spdm_error = SPDM_ERROR_UNSPECIFIED;
				goto exit;
			}
			response_size += measurement_length;

			spdm_response->number_of_blocks = 1;

			buffer_unaligned_write24 (spdm_response->measurement_record_len,
				(uint32_t) measurement_length);
			break;
	}

	/* Add the random nonce. */
	status = rng_engine->generate_random_buffer (rng_engine, SPDM_NONCE_LEN,
		spdm_get_measurements_resp_nonce (spdm_response));
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Add response to L1L2 hash context. Signature is not included in the hash. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(const uint8_t*) spdm_response, response_size - signature_size, (session != NULL),
		session_idx);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Generate the signature, if requested. */
	if (signature_requested == true) {
		status = spdm_generate_measurement_signature (transcript_manager, state,
			spdm_responder->key_manager, spdm_responder->ecc_engine, hash_engine, session,
			spdm_get_measurements_resp_signature (spdm_response), signature_size);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, response_size);

exit:
	if (status != 0) {
		/* Reset L1L2 hash context on error. */
		transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
			(session != NULL), session_idx);

		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_GET_MEASUREMENTS, status);
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
		((SPDM_NONCE_LEN) *sig_required);
	uint8_t *slot_id;

	if ((buf == NULL) || ((nonce == NULL) && sig_required)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	if ((spdm_minor_version == 0) && (slot_num != 0)) {
		return CMD_HANDLER_SPDM_UNSUPPORTED_SLOT_ID;
	}

	if (spdm_minor_version > 0) {
		rq_length += sig_required;
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
		if (spdm_minor_version > 0) {
			slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);
			*slot_id = slot_num;
		}

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

	if (((response->payload_length < sizeof (struct spdm_get_measurements_response)) ||
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
 * Process the SPDM KEY_EXCHANGE request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request KEY_EXCHANGE request to process.
 *
 * @return 0 if request was processed successfully, or an error code.
 */
int spdm_key_exchange (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	uint8_t spdm_version;
	struct spdm_key_exchange_request *spdm_request;
	struct spdm_key_exchange_response *spdm_response;
	uint8_t slot_id;
	size_t dhe_key_size;
	size_t hash_size;
	uint32_t meas_summary_hash_size;
	uint32_t sig_size;
	size_t request_size;
	size_t response_size;
	uint16_t req_session_id;
	uint16_t rsp_session_id;
	uint32_t session_id = SPDM_INVALID_SESSION_ID;
	struct spdm_secure_session *session = NULL;
	uint8_t *ptr;
	uint16_t opaque_data_length;
	size_t opaque_key_exchange_rsp_size;
	size_t pub_key_component_size;
	uint8_t session_policy = 0;
	const struct spdm_transcript_manager *transcript_manager;
	struct spdm_state *state;
	const struct spdm_device_capability *local_capabilities;
	struct riot_key_manager *key_manager;
	struct hash_engine *hash_engine;
	struct rng_engine *rng_engine;
	bool release_session = false;
	uint8_t cert_chain_hash[HASH_MAX_HASH_LEN];
	struct spdm_secure_session_manager *session_manager;
	struct ecc_point_public_key peer_pub_key_point;
	enum hash_type hash_type;
	const struct spdm_measurements *measurements;
	uint8_t meas_summary_hash_type;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	local_capabilities = spdm_responder->local_capabilities;
	key_manager = spdm_responder->key_manager;
	hash_engine = spdm_responder->hash_engine[0];
	rng_engine = spdm_responder->rng_engine;
	session_manager = spdm_responder->session_manager;
	measurements = spdm_responder->measurements;
	hash_type = spdm_get_hash_type (state->connection_info.peer_algorithms.base_hash_algo);

	/* Check if secure session support is available. This is excessive check, as session_manager
	 * can't be NULL if secure_message_version_num_count !=0 based on initialization checks, but
	 * it is still safer to check both */
	if ((spdm_responder->secure_message_version_num_count == 0) || (session_manager == NULL)) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Validate the request. */
	if (request->payload_length < sizeof (struct spdm_key_exchange_request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}
	spdm_request = (struct spdm_key_exchange_request*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
		spdm_request->header.spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify SPDM state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_KEY_EXCHANGE);
		goto exit;
	}
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Check for key exchange capability support. */
	if ((local_capabilities->flags.key_ex_cap == 0) ||
		(state->connection_info.peer_capabilities.flags.key_ex_cap == 0)) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		spdm_error = SPDM_ERROR_UNSUPPORTED_REQUEST;
		goto exit;
	}

	/* Check if a previous session is active. */
	if (session_manager->is_last_session_id_valid (session_manager) == true) {
		status = CMD_HANDLER_SPDM_RESPONDER_PREV_SESSION_VALID;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Check the type of measurement summary hash. */
	meas_summary_hash_type = spdm_request->measurement_summary_hash_type;

	if ((meas_summary_hash_type != SPDM_MEASUREMENT_SUMMARY_HASH_NONE) &&
		(meas_summary_hash_type != SPDM_MEASUREMENT_SUMMARY_HASH_TCB) &&
		(meas_summary_hash_type != SPDM_MEASUREMENT_SUMMARY_HASH_ALL)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	if ((meas_summary_hash_type > SPDM_MEASUREMENT_SUMMARY_HASH_NONE) &&
		((local_capabilities->flags.meas_cap == 0) ||
		(state->connection_info.peer_algorithms.measurement_spec == 0) ||
		(state->connection_info.peer_algorithms.measurement_hash_algo == 0))) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Check the slot Id. */
	slot_id = spdm_request->slot_id;
	if (slot_id != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Get the crypto parameter sizes. */
	hash_size = hash_get_hash_length (hash_type);
	sig_size = spdm_get_asym_signature_size (state->connection_info.peer_algorithms.base_asym_algo);
	dhe_key_size =
		spdm_get_dhe_pub_key_size (state->connection_info.peer_algorithms.dhe_named_group);
	meas_summary_hash_size =
		(spdm_request->measurement_summary_hash_type == SPDM_MEASUREMENT_SUMMARY_HASH_NONE) ?
			0 : hash_size;

	/* Check if the request contains the DHE public key and the opaque data length. */
	if (request->payload_length < (sizeof (struct spdm_key_exchange_request) + dhe_key_size +
		sizeof (uint16_t))) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Copy the public key from the request. Public key is in point format (x, y). */
	ptr = spdm_key_exchange_rq_exchange_data (spdm_request);
	pub_key_component_size = dhe_key_size >> 1;
	memcpy (peer_pub_key_point.x, ptr, pub_key_component_size);
	memcpy (peer_pub_key_point.y, ptr + pub_key_component_size, pub_key_component_size);
	peer_pub_key_point.key_length = pub_key_component_size;

	/* Read the opaque data length. */
	ptr += dhe_key_size;
	opaque_data_length = buffer_unaligned_read16 ((const uint16_t*) ptr);

	/* Check if the request contains the DHE public key, the opaque data length and the opaque data. */
	if (request->payload_length < (sizeof (struct spdm_key_exchange_request) + dhe_key_size +
		sizeof (uint16_t) + opaque_data_length)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}
	request_size = sizeof (struct spdm_key_exchange_request) + dhe_key_size + sizeof (uint16_t) +
		opaque_data_length;

	ptr += sizeof (uint16_t);
	if (opaque_data_length != 0) {
		/* Validate the opaque data. */
		status = spdm_validate_general_opaque_data (spdm_version,
			state->connection_info.peer_algorithms.other_params_support.opaque_data_format, ptr,
			opaque_data_length);
		if (status != 0) {
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}

		/* Process the opaque data and negotiate the secure message version. */
		status = spdm_process_opaque_data_supported_version_data (state,
			spdm_responder->secure_message_version_num,
			spdm_responder->secure_message_version_num_count, ptr, opaque_data_length);
		if (status != 0) {
			spdm_error = SPDM_ERROR_INVALID_REQUEST;
			goto exit;
		}
	}

	/* Get the size of the opaque data for the response. */
	opaque_key_exchange_rsp_size = spdm_get_opaque_data_version_selection_data_size (spdm_version,
		spdm_responder->secure_message_version_num_count);

	/* Reset the transcript manager state as per the request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager, SPDM_REQUEST_KEY_EXCHANGE);

	/* Construct the session Id from the requester and responder session Ids. */
	req_session_id = spdm_request->req_session_id;
	rsp_session_id = (state->current_local_session_id + 1);
	session_id = MAKE_SESSION_ID (req_session_id, rsp_session_id);

	/* Create a session and assign the constructed session Id to it. */
	session = session_manager->create_session (session_manager, session_id, false,
		&state->connection_info);
	if (session == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_SESSION_LIMIT_EXCEEDED;
		spdm_error = SPDM_ERROR_SESSION_LIMIT_EXCEEDED;
		goto exit;
	}
	release_session = true;

	/* Obtain the cert chain hash. */
	status = spdm_get_certificate_chain_digest (key_manager, hash_engine, hash_type,
		cert_chain_hash);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Add the cert chain hash to the TH session hash context. This is needed for signature and hmac. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		cert_chain_hash, hash_size, true, session->session_index);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Add the request to the TH session hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) spdm_request, request_size, true, session->session_index);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Save the session policy from the request. */
	if (spdm_version >= SPDM_VERSION_1_2) {
		session_policy = spdm_request->session_policy;
	}

	/* Construct the response. */
	response_size = sizeof (struct spdm_key_exchange_response) + dhe_key_size +
		meas_summary_hash_size + sizeof (uint16_t) + opaque_key_exchange_rsp_size + sig_size +
		hash_size /* HMAC */;
	if (response_size > cmd_interface_msg_get_max_response (request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_RESPONSE_TOO_LARGE;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	spdm_response = (struct spdm_key_exchange_response*) request->payload;
	memset (spdm_response, 0, response_size);

	spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_KEY_EXCHANGE,
		SPDM_GET_MINOR_VERSION (spdm_version));
	spdm_response->heartbeat_period = 0;
	spdm_response->rsp_session_id = rsp_session_id;
	spdm_response->mut_auth_requested = 0;
	spdm_response->req_slot_id_param = 0;

	/* Generate random data for the response. */
	status = rng_engine->generate_random_buffer (rng_engine, sizeof (spdm_response->random_data),
		spdm_response->random_data);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Generate the shared secret. Also, copy the generated local public key to the response buffer. */
	ptr = spdm_key_exchange_resp_exchange_data (spdm_response);
	status = session_manager->generate_shared_secret (session_manager, session,	&peer_pub_key_point,
		ptr);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}
	ptr += dhe_key_size;

	/* Add the measurement summary hash if requested. */
	if (meas_summary_hash_type > SPDM_MEASUREMENT_SUMMARY_HASH_NONE) {
		status = measurements->get_measurement_summary_hash (measurements,
			spdm_responder->hash_engine[0], hash_type, spdm_responder->hash_engine[1], hash_type,
			(meas_summary_hash_type == SPDM_MEASUREMENT_SUMMARY_HASH_TCB), ptr,
			meas_summary_hash_size);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
		ptr += meas_summary_hash_size;
	}

	/* Write the opaque data length. */
	buffer_unaligned_write16 ((uint16_t*) ptr, opaque_key_exchange_rsp_size);
	ptr += sizeof (uint16_t);

	/* Build the selected secure session version as opaque data. */
	spdm_build_opaque_data_version_selection_data (spdm_responder, ptr);
	ptr += opaque_key_exchange_rsp_size;

	/* Add the response to the TH session hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) spdm_response, ((size_t) ptr - (size_t) spdm_response), true,
		session->session_index);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Generate the response signature. */
	status = spdm_generate_key_exchange_rsp_signature (transcript_manager, state,
		spdm_responder->key_manager, spdm_responder->ecc_engine, hash_engine, session, ptr,
		sig_size);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Add the signature to the TH session hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, ptr,
		sig_size, true, session->session_index);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}
	ptr += sig_size;

	/* Generate the session handshake keys. */
	status = session_manager->generate_session_handshake_keys (session_manager, session);
	if (status != 0) {
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Generate the responder verification data. */
	if ((state->connection_info.peer_capabilities.flags.handshake_in_the_clear_cap == 0) &&
		(local_capabilities->flags.handshake_in_the_clear_cap == 0)) {
		status = spdm_calculate_th_hmac_for_key_exchange_rsp (transcript_manager, state,
			spdm_responder->ecc_engine, hash_engine, session, ptr);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}

		/* Add the HMAC to the TH Session transcript. */
		status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, ptr,
			hash_size, true, session->session_index);
		if (status != 0) {
			spdm_error = SPDM_ERROR_UNSPECIFIED;
			goto exit;
		}
	}

	/* Set the request session policy on the session. */
	if (spdm_version >= SPDM_VERSION_1_2) {
		session->session_policy = session_policy;
	}

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, response_size);

	/* Set the session state. */
	session_manager->set_session_state (session_manager, session_id,
		SPDM_SESSION_STATE_HANDSHAKING);

	/* Update the Responder state. */
	state->current_local_session_id += 1;

	release_session = false;

exit:
	if (release_session == true) {
		session_manager->release_session (session_manager, session_id);
	}

	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_KEY_EXCHANGE, status);
	}

	return 0;
}

/**
 * Process SPDM FINISH request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request FINISH request to process.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_finish (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	uint8_t spdm_version;
	struct spdm_finish_request *spdm_request;
	struct spdm_finish_response *spdm_response;
	size_t response_size;
	uint32_t session_id;
	struct spdm_secure_session *session;
	uint32_t hmac_size;
	uint32_t sig_size = 0;
	struct spdm_state *state;
	const struct spdm_transcript_manager *transcript_manager;
	const struct spdm_device_capability *local_capabilities;
	struct spdm_secure_session_manager *session_manager;
	const uint8_t *hmac_ptr;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	state = spdm_responder->state;
	transcript_manager = spdm_responder->transcript_manager;
	local_capabilities = spdm_responder->local_capabilities;
	session_manager = spdm_responder->session_manager;

	if (session_manager == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Validate the request. */
	if (request->payload_length < sizeof (struct spdm_finish_request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}
	spdm_request = (struct spdm_finish_request*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
		spdm_request->header.spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify SPDM state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_FINISH);
		goto exit;
	}
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Confirm that we are in a session.*/
	if ((local_capabilities->flags.handshake_in_the_clear_cap == 0) &&
		(state->connection_info.peer_capabilities.flags.handshake_in_the_clear_cap == 0)) {
		if (session_manager->is_last_session_id_valid (session_manager) == false) {
			status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
			spdm_error = SPDM_ERROR_SESSION_REQUIRED;
			goto exit;
		}
	}
	else {
		/* [TODO] Check if handshake in clear needs to be supported.*/
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
		spdm_error = SPDM_ERROR_SESSION_REQUIRED;
		goto exit;
	}

	/* Session id is retrieved from the secure session message header. */
	session_id = session_manager->get_last_session_id (session_manager);
	session = session_manager->get_session (session_manager, session_id);
	if (session == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
		spdm_error = SPDM_ERROR_SESSION_REQUIRED;
		goto exit;
	}

	/* Check session state. */
	if (session->session_state != SPDM_SESSION_STATE_HANDSHAKING) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Since mutual auth is not supported, requester should not have included a signature. */
	if ((spdm_request->signature_included &
		SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	hmac_size = session->hash_size;
	sig_size = 0;

	if (request->payload_length <
		(sizeof (struct spdm_finish_request) + sig_size + hmac_size)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Reset the transcript manager state as per the request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager, SPDM_REQUEST_FINISH);

	/* Add the FINISH request (no HMAC) to the TH hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(const uint8_t*) spdm_request, sizeof (struct spdm_finish_request), true,
		session->session_index);
	if (status != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Verify the request HMAC. */
	hmac_ptr = spdm_finish_rq_hmac (spdm_request, sig_size);
	status = spdm_verify_finish_req_hmac (transcript_manager, spdm_responder->hash_engine[0],
		session, hmac_ptr, hmac_size);
	if (status != 0) {
		if ((state->handle_error_return_policy &
			SPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR) == 0) {
			spdm_error = SPDM_ERROR_DECRYPT_ERROR;
			goto exit;
		}
		else {
			/* Ignore this message. Don't send a response back. */
			return status;
		}
	}

	/* Add the HMAC from the FINISH request to the TH hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, hmac_ptr,
		hmac_size, true, session->session_index);
	if (status != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Construct the response. Payload buffer is guranteed to be greater than response size. */
	response_size = sizeof (struct spdm_finish_response);
	spdm_response = (struct spdm_finish_response*) request->payload;
	memset (spdm_response, 0, response_size);

	spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_FINISH,
		SPDM_GET_MINOR_VERSION (spdm_version));
	spdm_response->reserved1 = 0;
	spdm_response->reserved2 = 0;

	/* Add the FINISH response to the TH hash context. */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(const uint8_t*) spdm_response, response_size, true, session->session_index);
	if (status != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Generate the session data keys. */
	status = session_manager->generate_session_data_keys (session_manager, session);
	if (status != 0) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		spdm_error = SPDM_ERROR_UNSPECIFIED;
		goto exit;
	}

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, response_size);

exit:
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_FINISH, status);
	}

	return 0;
}

/**
 * Process SPDM end session request.
 *
 * @param spdm_responder SPDM responder instance.
 * @param request END_SESSION request to process.
 *
 * @return 0 if request processed successfully or an error code.
 */
int spdm_end_session (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request)
{
	int status = 0;
	int spdm_error;
	uint8_t spdm_version;
	struct spdm_end_session_request *spdm_request;
	struct spdm_end_session_response *spdm_response;
	size_t response_size;
	uint32_t session_id;
	struct spdm_secure_session *session;
	struct spdm_state *state;
	const struct spdm_transcript_manager *transcript_manager;
	struct spdm_secure_session_manager *session_manager;

	if ((spdm_responder == NULL) || (request == NULL)) {
		return CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
	}

	transcript_manager = spdm_responder->transcript_manager;
	state = spdm_responder->state;
	session_manager = spdm_responder->session_manager;

	if (session_manager == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	/* Validate request. This message can only be in a secured session, so checking exact size. */
	if (request->payload_length != sizeof (struct spdm_end_session_request)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		spdm_error = SPDM_ERROR_INVALID_REQUEST;
		goto exit;
	}

	spdm_request = (struct spdm_end_session_request*) request->payload;
	spdm_version = SPDM_MAKE_VERSION (spdm_request->header.spdm_major_version,
		spdm_request->header.spdm_minor_version);
	if (spdm_version != spdm_get_connection_version (state)) {
		status = CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH;
		spdm_error = SPDM_ERROR_VERSION_MISMATCH;
		goto exit;
	}

	/* Verify SPDM state. */
	if (state->response_state != SPDM_RESPONSE_STATE_NORMAL) {
		spdm_handle_response_state (state, request, SPDM_REQUEST_END_SESSION);
		goto exit;
	}
	if (state->connection_info.connection_state < SPDM_CONNECTION_STATE_NEGOTIATED) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Confirm that we are in a session. */
	if (session_manager->is_last_session_id_valid (session_manager) == false) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
		spdm_error = SPDM_ERROR_SESSION_REQUIRED;
		goto exit;
	}

	/* Session id is retrieved from the secure session message header. */
	session_id = session_manager->get_last_session_id (session_manager);
	session = session_manager->get_session (session_manager, session_id);
	if (session == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_CONNECTION_STATE;
		spdm_error = SPDM_ERROR_SESSION_REQUIRED;
		goto exit;
	}

	/* Check if the session is in the correct state. */
	if (session->session_state != SPDM_SESSION_STATE_ESTABLISHED) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNEXPECTED_REQUEST;
		spdm_error = SPDM_ERROR_UNEXPECTED_REQUEST;
		goto exit;
	}

	/* Reset the transcript manager state as per the request code. */
	spdm_reset_transcript_via_request_code (state, transcript_manager, SPDM_REQUEST_END_SESSION);

	session->end_session_attributes = spdm_request->end_session_attributes;
	if ((spdm_request->end_session_attributes.negotiated_state_preservation_indicator ==
		SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR)) {
		state->connection_info.end_session_attributes.negotiated_state_preservation_indicator =
			SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;
	}

	/* Construct the response. */
	response_size = sizeof (struct spdm_end_session_response);
	spdm_response = (struct spdm_end_session_response*) request->payload;
	memset (spdm_response, 0, response_size);

	spdm_populate_header (&spdm_response->header, SPDM_RESPONSE_END_SESSION,
		SPDM_GET_MINOR_VERSION (spdm_version));
	spdm_response->reserved1 = 0;
	spdm_response->reserved2 = 0;

	/* Set the payload length. */
	cmd_interface_msg_set_message_payload_length (request, response_size);

exit:
	if (status != 0) {
		spdm_generate_error_response (request, state->connection_info.version.minor_version,
			spdm_error, 0x00, NULL, 0, SPDM_REQUEST_END_SESSION, status);
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

exit:

	return status;
}
