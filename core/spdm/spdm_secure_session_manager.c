// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "spdm_secure_session_manager.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "crypto/ecdh.h"
#include "crypto/kdf.h"
#include "fips/fips_logging.h"
#include "firmware/impactful_check.h"

/**
 * Initialize a secure session's state.
 *
 * @param session_manager Session Manager.
 * @param session_index Session index.
 * @param session_id SPDM Session Id.
 * @param is_requester true if the local host is the SPDM requester.
 * @param connection_info Peer Connection info.
 */
static void spdm_secure_session_manager_init_session_state (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_index,
	uint32_t session_id, bool is_requester, const struct spdm_connection_info *connection_info)
{
	enum spdm_secure_session_type session_type;
	struct spdm_get_capabilities_flags_format req_capability;
	struct spdm_get_capabilities_flags_format resp_capability;
	struct spdm_secure_session *session;
	const struct spdm_transcript_manager *transcript_manager;

	session = &session_manager->state->sessions[session_index];
	transcript_manager = session_manager->transcript_manager;

	/* Determine the session type. */
	req_capability = connection_info->peer_capabilities.flags;
	resp_capability = session_manager->local_capabilities->flags;

	if ((req_capability.encrypt_cap == 1) && (req_capability.mac_cap == 1) &&
		(resp_capability.encrypt_cap == 1) && (resp_capability.mac_cap == 1)) {
		session_type = SPDM_SESSION_TYPE_ENC_MAC;
	}
	else if ((req_capability.mac_cap == 1) && (resp_capability.mac_cap == 1)) {
		session_type = SPDM_SESSION_TYPE_MAC_ONLY;
	}
	else {
		session_type = SPDM_SESSION_TYPE_NONE;
	}

	memset (session, 0, sizeof (struct spdm_secure_session));

	/* Reset the session transcipt for TH hash. */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		session_index);

	session->session_id = session_id;
	session->session_index = session_index;
	session->is_requester = is_requester;
	session->session_type = session_type;
	session->version = connection_info->version;
	session->secure_message_version = connection_info->secure_message_version;
	session->base_hash_algo = connection_info->peer_algorithms.base_hash_algo;
	session->dhe_named_group = connection_info->peer_algorithms.dhe_named_group;
	session->aead_cipher_suite = connection_info->peer_algorithms.aead_cipher_suite;
	session->key_schedule = connection_info->peer_algorithms.key_schedule;
	session->hash_size = hash_get_hash_length (spdm_get_hash_type (session->base_hash_algo));
	session->dhe_key_size = spdm_get_dhe_pub_key_size (session->dhe_named_group);
	session->aead_key_size = spdm_get_aead_key_size (session->aead_cipher_suite);
	session->aead_iv_size = spdm_get_aead_iv_size (session->aead_cipher_suite);
	session->aead_tag_size = spdm_get_aead_tag_size (session->aead_cipher_suite);
	session->peer_capabilities = connection_info->peer_capabilities;
}

struct spdm_secure_session* spdm_secure_session_manager_create_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
	bool is_requester, const struct spdm_connection_info *connection_info)
{
	struct spdm_secure_session *sessions;
	uint8_t index;

	if ((session_manager == NULL) || (session_id == SPDM_INVALID_SESSION_ID) ||
		(connection_info == NULL) ||
		(session_manager->state->current_session_count >= SPDM_MAX_SESSION_COUNT)) {
		return NULL;
	}

	sessions = session_manager->state->sessions;

	/* Check if the session exists. */
	for (index = 0; index < SPDM_MAX_SESSION_COUNT; index++) {
		if (sessions[index].session_id == session_id) {
			return NULL;
		}
	}

	/* Initialize a session. */
	for (index = 0; index < SPDM_MAX_SESSION_COUNT; index++) {
		if (sessions[index].session_id == SPDM_INVALID_SESSION_ID) {
			spdm_secure_session_manager_init_session_state (session_manager, index, session_id,
				is_requester, connection_info);

			session_manager->state->current_session_count++;

			return &sessions[index];
		}
	}

	return NULL;
}

void spdm_secure_session_manager_release_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id)
{
	struct spdm_secure_session *sessions;
	const struct spdm_transcript_manager *transcript_manager;
	size_t session_index;

	if ((session_manager == NULL) || (session_id == SPDM_INVALID_SESSION_ID)) {
		return;
	}

	sessions = session_manager->state->sessions;
	transcript_manager = session_manager->transcript_manager;

	for (session_index = 0; session_index < SPDM_MAX_SESSION_COUNT; session_index++) {
		if (sessions[session_index].session_id == session_id) {
			memset (&sessions[session_index], 0, sizeof (struct spdm_secure_session));
			transcript_manager->reset_session_transcript (transcript_manager, session_index);
			session_manager->state->current_session_count--;

			return;
		}
	}
}

/**
 * Clear the handshake secrets.
 *
 * @param session SPDM secure session.
 */
static void spdm_secure_session_clear_handshake_secret (struct spdm_secure_session *session)
{
	memset (&session->handshake_secret, 0, sizeof (struct spdm_secure_session_handshake_secrets));

	session->requester_backup_valid = false;
	session->responder_backup_valid = false;
}

void spdm_secure_session_manager_set_session_state (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
	enum spdm_secure_session_state session_state)
{
	struct spdm_secure_session *session;

	if ((session_manager == NULL) || (session_id == SPDM_INVALID_SESSION_ID) ||
		(session_state == SPDM_SESSION_STATE_MAX)) {
		return;
	}

	session = session_manager->get_session (session_manager, session_id);
	if (session == NULL) {
		return;
	}

	if (session->session_state != session_state) {
		session->session_state = session_state;

		/* Session handshake keys should be zeroized after the handshake phase. */
		if (session_state == SPDM_SESSION_STATE_ESTABLISHED) {
			spdm_secure_session_clear_handshake_secret (session);
		}
	}
}

void spdm_secure_session_manager_reset (const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session *sessions;
	size_t session_index;
	uint32_t session_id;

	if (session_manager == NULL) {
		return;
	}

	sessions = session_manager->state->sessions;

	/* Release all sessions. */
	for (session_index = 0; session_index < SPDM_MAX_SESSION_COUNT; session_index++) {
		session_id = sessions[session_index].session_id;

		if (session_id != SPDM_INVALID_SESSION_ID) {
			spdm_secure_session_manager_release_session (session_manager, session_id);

			observable_notify_observers_with_ptr (&session_manager->state->observable,
				offsetof (struct spdm_protocol_session_observer, on_close_session), &session_id);
		}
	}

	/* Reset the state, maintaining the observer manager. */
	memset (session_manager->state, 0,
		offsetof (struct spdm_secure_session_manager_state, observable));
}

struct spdm_secure_session* spdm_secure_session_manager_get_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id)
{
	struct spdm_secure_session *sessions;
	size_t index;

	if ((session_manager == NULL) || (session_id == SPDM_INVALID_SESSION_ID)) {
		return NULL;
	}

	sessions = (struct spdm_secure_session*) session_manager->state->sessions;
	for (index = 0; index < SPDM_MAX_SESSION_COUNT; index++) {
		if (sessions[index].session_id == session_id) {
			return &sessions[index];
		}
	}

	return NULL;
}

int spdm_secure_session_manager_generate_shared_secret (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session,
	const struct ecc_point_public_key *peer_pub_key_point, uint8_t *local_pub_key_point)
{
	int status;
	uint8_t peer_pub_key_der[ECC_DER_MAX_PUBLIC_LENGTH] = {0};
	int der_len;
	const struct ecc_engine *ecc_engine;
	struct ecc_public_key peer_pub_key;
	struct ecc_private_key local_priv_key;
	struct ecc_public_key local_pub_key;
	uint8_t *local_pub_key_der = NULL;
	size_t local_pub_key_der_len;
	bool release_local_key_pair = false;
	bool release_peer_pub_key = false;
	int shared_secret_len;
	struct debug_log_entry_info pct_error = {};
	size_t key_point_length;

	if ((session_manager == NULL) || (session == NULL) || (peer_pub_key_point == NULL) ||
		(local_pub_key_point == NULL)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	ecc_engine = session_manager->ecc_engine;
	key_point_length = peer_pub_key_point->key_length;

	/* Step 1: Convert the peer public key to DER format. */
	der_len = ecc_der_encode_public_key (peer_pub_key_point->x, peer_pub_key_point->y,
		key_point_length, peer_pub_key_der, sizeof (peer_pub_key_der));
	if (ROT_IS_ERROR (der_len)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		goto exit;
	}

	/* Step 2: Convert the peer public key (converted to DER format above) to internal format. */
	status = ecc_engine->init_public_key (ecc_engine, peer_pub_key_der, der_len, &peer_pub_key);
	if (status != 0) {
		goto exit;
	}
	release_peer_pub_key = true;

	/* Generate an ephemeral key pair. */
	status = ecdh_generate_random_key (ecc_engine, key_point_length, &local_priv_key,
		&local_pub_key);
	if (status != 0) {
		if (session_manager->error != NULL) {
			/* TODO: Consider creating global fatal_error() function which would pass control to
			 * error handling task for eventual reset. */
			pct_error.severity = DEBUG_LOG_SEVERITY_ERROR;
			pct_error.component = DEBUG_LOG_COMPONENT_FIPS;
			pct_error.msg_index = FIPS_LOGGING_ECDH_PCT_FAILED;
			pct_error.arg1 = session_manager->algo_info.ecdh_instance_id;
			pct_error.arg2 = status;
			pct_error.format = 1;

			session_manager->error->enter_error_state (session_manager->error, &pct_error);
		}
		goto exit;
	}
	release_local_key_pair = true;

	/* Convert the local public key to DER format. */
	status = ecc_engine->get_public_key_der (ecc_engine, &local_pub_key, &local_pub_key_der,
		&local_pub_key_der_len);
	if (status != 0) {
		goto exit;
	}

	/* Convert the local public key from DER to point format and copy it to the output buffer. */
	status = ecc_der_decode_public_key (local_pub_key_der, local_pub_key_der_len,
		local_pub_key_point, &local_pub_key_point[key_point_length], key_point_length);
	if (ROT_IS_ERROR (status)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		goto exit;
	}
	status = 0;

	/* Get the shared secret length. */
	shared_secret_len = ecc_engine->get_shared_secret_max_length (ecc_engine, &local_priv_key);
	if (ROT_IS_ERROR (shared_secret_len)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		goto exit;
	}
	if (shared_secret_len > SPDM_MAX_DHE_SHARED_SECRET_SIZE) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_DHE_KEY_SIZE;
		goto exit;
	}

	/* Generate the shared secret. */
	shared_secret_len = ecc_engine->compute_shared_secret (ecc_engine, &local_priv_key,
		&peer_pub_key, session->master_secret.dhe_secret, shared_secret_len);
	if (ROT_IS_ERROR (shared_secret_len)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR;
		goto exit;
	}
	session->dhe_key_size = shared_secret_len;

exit:
	if (release_local_key_pair == true) {
		ecc_engine->release_key_pair (ecc_engine, &local_priv_key, &local_pub_key);
	}

	if (release_peer_pub_key == true) {
		ecc_engine->release_key_pair (ecc_engine, NULL, &peer_pub_key);
	}

	buffer_zeroize (local_pub_key_der, local_pub_key_der_len);
	platform_free (local_pub_key_der);

	buffer_zeroize (peer_pub_key_der, sizeof (peer_pub_key_der));

	return status;
}

/**
 * Concatenate binary data to be used as info in HKDF.
 *
 * @param version The SPDM message version.
 * @param label An ascii string label for the concat operation.
 * @param label_size The size in bytes of the ASCII string label, not including NULL terminator.
 * @param context A pre-defined hash value as the context for the concat operation.
 * @param length 16 bits length for the concat operation.
 * @param hash_size The size in bytes of the context hash.
 * @param out_bin The buffer to store the output binary.
 * @param out_bin_size The size in bytes for the out_bin.
 */
static void spdm_secure_session_manager_bin_concat (struct spdm_version_number version,
	const char *label, size_t label_size, const uint8_t *context, uint16_t length, size_t hash_size,
	uint8_t *out_bin, size_t *out_bin_size)
{
	size_t final_size;

	final_size = sizeof (uint16_t) + sizeof (SPDM_BIN_CONCAT_LABEL) - 1 + label_size;
	if (context != NULL) {
		final_size += hash_size;
	}

	*out_bin_size = final_size;

	memcpy (out_bin, &length, sizeof (uint16_t));
	memcpy ((out_bin + sizeof (uint16_t)), SPDM_BIN_CONCAT_LABEL,
		sizeof (SPDM_BIN_CONCAT_LABEL) - 1);

	/* Patch the version. */
	out_bin[6] = (char) ('0' + version.major_version);
	out_bin[8] = (char) ('0' + version.minor_version);

	memcpy ((out_bin + sizeof (uint16_t) + sizeof (SPDM_BIN_CONCAT_LABEL) - 1), label, label_size);

	if (context != NULL) {
		memcpy ((out_bin + sizeof (uint16_t) + sizeof (SPDM_BIN_CONCAT_LABEL) - 1 + label_size),
			context, hash_size);
	}
}

/**
 * Generate the SPDM finished key for a session.
 *
 * @param hkdf HKDF interface to be used.
 * @param session SPDM session.
 * @param finished_key Buffer to store the finished key.
 *
 * @return 0 if the SPDM finished key for a session is generated, error code otherwise.
 */
static int spdm_secure_session_manager_generate_finished_key (const struct hkdf_interface *hkdf,
	struct spdm_secure_session *session, uint8_t *finished_key)
{
	int status;
	size_t hash_size;
	uint8_t bin_str7[128];
	size_t bin_str7_size;

	hash_size = session->hash_size;

	bin_str7_size = sizeof (bin_str7);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_7_LABEL,
		sizeof (SPDM_BIN_STR_7_LABEL) - 1, NULL, (uint16_t) hash_size, hash_size, bin_str7,
		&bin_str7_size);

	status = hkdf->expand (hkdf, bin_str7, bin_str7_size, finished_key, hash_size);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Generate the SPDM AEAD key and IV for a session.
 *
 * @param hkdf HKDF interface
 * @param session SPDM secured session.
 * @param hmac_hash_type HMAC hash type.
 * @param key Buffer to store the AEAD key.
 * @param iv Buffer to store the AEAD IV.
 *
 * @return 0 if the SPDM AEAD key and IV are generated, error code otherwise.
 */
static int spdm_secure_session_manager_generate_aead_key_and_iv (
	const struct hkdf_interface *hkdf, struct spdm_secure_session *session,	uint8_t *key,
	uint8_t *iv)
{
	int status;
	size_t hash_size;
	size_t key_length;
	size_t iv_length;
	uint8_t bin_str5[128];
	size_t bin_str5_size;
	uint8_t bin_str6[128];
	size_t bin_str6_size;

	hash_size = session->hash_size;
	key_length = session->aead_key_size;
	iv_length = session->aead_iv_size;

	/* Generate the AEAD key. */
	bin_str5_size = sizeof (bin_str5);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_5_LABEL,
		sizeof (SPDM_BIN_STR_5_LABEL) - 1, NULL, (uint16_t) key_length, hash_size, bin_str5,
		&bin_str5_size);

	status = hkdf->expand (hkdf, bin_str5, bin_str5_size, key, key_length);
	if (status != 0) {
		goto exit;
	}

	/* Generate the AEAD IV. */
	bin_str6_size = sizeof (bin_str6);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_6_LABEL,
		sizeof (SPDM_BIN_STR_6_LABEL) - 1, NULL, (uint16_t) iv_length, hash_size, bin_str6,
		&bin_str6_size);

	status = hkdf->expand (hkdf, bin_str6, bin_str6_size, iv, iv_length);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

int spdm_secure_session_manager_generate_session_handshake_keys (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session)
{
	int status;
	const struct spdm_transcript_manager *transcript_manager;
	uint8_t th1_hash[HASH_MAX_HASH_LEN] = {0};
	size_t hash_size;
	uint8_t bin_str0[128];
	size_t bin_str0_size;
	uint8_t bin_str1[128];
	size_t bin_str1_size;
	uint8_t bin_str2[128];
	size_t bin_str2_size;
	enum hash_type hash_type;

	if ((session_manager == NULL) || (session == NULL)) {
		return SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
	}

	transcript_manager = session_manager->transcript_manager;
	hash_size = session->hash_size;

	/* Step 1: Get the TH hash; do not complete the hash context as it is needed later. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		true, session->session_index, th1_hash, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Step 2: Use the TH hash to generate the session handshake key. */
	hash_type = spdm_get_hash_type (session->base_hash_algo);

	/* Generate HKDF PRK of salt0 with DHE shared secret. */
	status = session_manager->hkdf->extract (session_manager->hkdf, hash_type,
		session->master_secret.dhe_secret, hash_size, NULL, 0);

	if (status != 0) {
		goto exit;
	}

	/* Generate Salt1 for future master secret generation */
	bin_str0_size = sizeof (bin_str0);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_0_LABEL,
		sizeof (SPDM_BIN_STR_0_LABEL) - 1, NULL, (uint16_t) hash_size, hash_size, bin_str0,
		&bin_str0_size);

	status = session_manager->hkdf->expand (session_manager->hkdf, bin_str0, bin_str0_size,
		session->master_secret.master_secret_salt1, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Derive the request handshake secret. */
	bin_str1_size = sizeof (bin_str1);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_1_LABEL,
		sizeof (SPDM_BIN_STR_1_LABEL) - 1, th1_hash, (uint16_t) hash_size, hash_size, bin_str1,
		&bin_str1_size);

	/* Generate request handshake secret and set it as PRK */
	status = session_manager->hkdf->update_prk (session_manager->hkdf, bin_str1, bin_str1_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the requester finished key. */
	status = spdm_secure_session_manager_generate_finished_key (session_manager->hkdf, session,
		session->handshake_secret.request_finished_key);
	if (status != 0) {
		goto exit;
	}

	/* Generate the requester AEAD key and IV. */
	status = spdm_secure_session_manager_generate_aead_key_and_iv (session_manager->hkdf, session,
		session->handshake_secret.request_handshake_encryption_key,
		session->handshake_secret.request_handshake_salt);
	if (status != 0) {
		goto exit;
	}
	session->handshake_secret.request_handshake_sequence_number = 0;

	/* Generate HKDF PRK of salt0 with DHE shared secret. */
	status = session_manager->hkdf->extract (session_manager->hkdf, hash_type,
		session->master_secret.dhe_secret, hash_size, NULL, 0);
	if (status != 0) {
		goto exit;
	}

	/* Derive the response handshake secret. */
	bin_str2_size = sizeof (bin_str2);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_2_LABEL,
		sizeof (SPDM_BIN_STR_2_LABEL) - 1, th1_hash, (uint16_t) hash_size, hash_size, bin_str2,
		&bin_str2_size);

	status = session_manager->hkdf->update_prk (session_manager->hkdf, bin_str2, bin_str2_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the responder finished key. */
	status = spdm_secure_session_manager_generate_finished_key (session_manager->hkdf, session,
		session->handshake_secret.response_finished_key);
	if (status != 0) {
		goto exit;
	}

	/* Generate the responder AEAD key and IV. */
	status = spdm_secure_session_manager_generate_aead_key_and_iv (session_manager->hkdf, session,
		session->handshake_secret.response_handshake_encryption_key,
		session->handshake_secret.response_handshake_salt);
	if (status != 0) {
		goto exit;
	}
	session->handshake_secret.response_handshake_sequence_number = 0;

	/* Clear the DHE shared secret. */
	buffer_zeroize (session->master_secret.dhe_secret, SPDM_MAX_DHE_SHARED_SECRET_SIZE);

exit:
	buffer_zeroize (th1_hash, sizeof (th1_hash));
	session_manager->hkdf->clear_prk (session_manager->hkdf);

	return status;
}

bool spdm_secure_session_manager_is_last_session_id_valid (
	const struct spdm_secure_session_manager *session_manager)
{
	return session_manager->state->last_spdm_request_secure_session_id_valid;
}

uint32_t spdm_secure_session_manager_get_last_session_id (
	const struct spdm_secure_session_manager *session_manager)
{
	return session_manager->state->last_spdm_request_secure_session_id;
}

void spdm_secure_session_manager_reset_last_session_id_validity (
	const struct spdm_secure_session_manager *session_manager)
{
	session_manager->state->last_spdm_request_secure_session_id_valid = false;
}

int spdm_secure_session_manager_generate_session_data_keys (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session)
{
	int status;
	size_t hash_size;
	uint8_t bin_str3[128];
	size_t bin_str3_size;
	uint8_t bin_str4[128];
	size_t bin_str4_size;
	enum hash_type hash_type;
	const struct spdm_transcript_manager *transcript_manager;
	uint8_t th2_hash[HASH_MAX_HASH_LEN] = {0};
	uint8_t zero_filled_buffer[HASH_MAX_HASH_LEN];

	if ((session_manager == NULL) || (session == NULL)) {
		return SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
	}

	hash_size = session->hash_size;
	hash_type = spdm_get_hash_type (session->base_hash_algo);
	transcript_manager = session_manager->transcript_manager;

	memset (zero_filled_buffer, 0, sizeof (zero_filled_buffer));

	/* Generate the master secret. */
	status = session_manager->hkdf->extract (session_manager->hkdf, hash_type, zero_filled_buffer,
		hash_size, session->master_secret.master_secret_salt1, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Get the TH hash; do not complete the hash context as it is needed later. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		true, session->session_index, th2_hash, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the request data secret. */
	bin_str3_size = sizeof (bin_str3);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_3_LABEL,
		sizeof (SPDM_BIN_STR_3_LABEL) - 1, th2_hash, (uint16_t) hash_size, hash_size, bin_str3,
		&bin_str3_size);

	status = session_manager->hkdf->update_prk (session_manager->hkdf, bin_str3, bin_str3_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the requester data encryption key and IV. */
	status = spdm_secure_session_manager_generate_aead_key_and_iv (session_manager->hkdf, session,
		session->data_secret.request_data_encryption_key, session->data_secret.request_data_salt);
	if (status != 0) {
		goto exit;
	}
	session->data_secret.request_data_sequence_number = 0;

	/* Generate the master secret for respond key generation. */
	status = session_manager->hkdf->extract (session_manager->hkdf, hash_type, zero_filled_buffer,
		hash_size, session->master_secret.master_secret_salt1, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the response_data_secret. */
	bin_str4_size = sizeof (bin_str4);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_4_LABEL,
		sizeof (SPDM_BIN_STR_4_LABEL) - 1, th2_hash, (uint16_t) hash_size, hash_size, bin_str4,
		&bin_str4_size);

	status = session_manager->hkdf->update_prk (session_manager->hkdf, bin_str4, bin_str4_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the responder data encryption key and IV. */
	status = spdm_secure_session_manager_generate_aead_key_and_iv (session_manager->hkdf, session,
		session->data_secret.response_data_encryption_key, session->data_secret.response_data_salt);
	if (status != 0) {
		goto exit;
	}
	session->data_secret.response_data_sequence_number = 0;

	/* Don't generate export master secret. We are keeping Salt1 for generating mster secret,
	 * so we could use it later to regenearate export secret */

exit:
	buffer_zeroize (th2_hash, sizeof (th2_hash));
	session_manager->hkdf->clear_prk (session_manager->hkdf);

	return status;
}

/**
 * Generate the AEAD IV for a session.
 *
 * @param sequence_number The sequence number.
 * @param iv The buffer to store the AEAD IV.
 * @param salt The salt to use in the AEAD IV generation.
 * @param aead_iv_size The size of the AEAD IV.
 */
static void spdm_secure_session_manager_generate_iv (uint64_t sequence_number, uint8_t *iv,
	const uint8_t *salt, size_t aead_iv_size)
{
	uint8_t iv_temp[SPDM_MAX_AEAD_IV_SIZE] = {0};
	size_t index;

	/* Construct the AEAD IV from the salt and the sequence number. */
	memcpy (iv, salt, aead_iv_size);

	/*
	 * Per 'Secured Messages using SPDM' specification, Section 4.2.3,
	 * sequence number is little-endian, so it is zero-extended to the higher indices.
	 * The sequence number begins at the lowest index (0). */
	memcpy (iv_temp, &sequence_number, sizeof (sequence_number));
	for (index = 0; index < sizeof (sequence_number); index++) {
		iv[index] = iv[index] ^ iv_temp[index];
	}

	buffer_zeroize (iv_temp, sizeof (iv_temp));
}

/**
 * Decrypt a message using the session's AEAD key and IV.
 *
 * @param session_manager The SPDM session manager.
 * @param session The SPDM session.
 * @param request The request message to decrypt.
 * @param sequence_number The sequence number.
 * @param sequence_num_in_header_size The size of the sequence number in the message header.
 * @param key The AEAD key.
 * @param salt The AEAD salt.
 * @param iv The AEAD IV.
 *
 * @return 0 if the message is decrypted, error code otherwise.
 */
int spdm_secure_session_manager_decrypt_message (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session,
	struct cmd_interface_msg *request, uint64_t sequence_number,
	uint8_t sequence_num_in_header_size, const uint8_t *key, const uint8_t *salt, const uint8_t *iv)
{
	int status;
	size_t aead_tag_size;
	size_t aead_key_size;
	size_t aead_iv_size;
	size_t record_header_size;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;
	struct spdm_secured_message_cipher_header *enc_msg_header;
	const uint8_t *add_data;
	uint8_t *ciphertext;
	size_t plaintext_size;
	size_t ciphertext_size;
	const uint8_t *tag;
	const struct aes_gcm_engine *aes_engine;

	UNUSED (sequence_number);
	UNUSED (salt);

	aead_tag_size = session->aead_tag_size;
	aead_key_size = session->aead_key_size;
	aead_iv_size = session->aead_iv_size;
	aes_engine = session_manager->aes_engine;

	record_header_size = sizeof (struct spdm_secured_message_data_header_1) +
		sequence_num_in_header_size + sizeof (struct spdm_secured_message_data_header_2);

	if (request->payload_length < (record_header_size + aead_tag_size)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE;
		goto exit;
	}

	record_header_1 = (void*) request->payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1) + sequence_num_in_header_size);

	if (record_header_2->length > (request->payload_length - record_header_size)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE;
		goto exit;
	}
	if (record_header_2->length < aead_tag_size) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE;
		goto exit;
	}
	ciphertext_size = (record_header_2->length - aead_tag_size);
	if (ciphertext_size > (request->payload_length - (record_header_size + aead_tag_size))) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE;
		goto exit;
	}

	ciphertext = (void*) (record_header_2 + 1);
	tag = (const uint8_t*) record_header_1 + record_header_size + ciphertext_size;
	add_data = (const uint8_t*) record_header_1;	/* Header is also included in MAC calculation. */

	status = aes_engine->set_key (aes_engine, key, aead_key_size);
	if (status != 0) {
		goto exit;
	}

	status = aes_engine->decrypt_with_add_data (aes_engine, ciphertext, ciphertext_size, tag, iv,
		aead_iv_size, add_data, record_header_size, ciphertext, ciphertext_size);
	if (status != 0) {
		/* Backup keys are valid, fail and alert rollback and retry if possible. */
		if (session->requester_backup_valid == true) {
			status = SPDM_SECURE_SESSION_MANAGER_SESSION_TRY_DISCARD_KEY_UPDATE;
			goto exit;
		}
		/* [TODO] Set last spdm error. */
		goto exit;
	}

	enc_msg_header = (void*) (record_header_2 + 1);
	plaintext_size = enc_msg_header->application_data_length;
	if (plaintext_size > ciphertext_size) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE;
		goto exit;
	}

	cmd_interface_msg_remove_protocol_header (request, record_header_size +
		sizeof (struct spdm_secured_message_cipher_header));
	request->payload_length = plaintext_size;

exit:

	return status;
}

int spdm_secure_session_manager_decode_secure_message (
	const struct spdm_secure_session_manager *session_manager, struct cmd_interface_msg *request)
{
	int status;
	struct spdm_secure_session *session;
	enum spdm_secure_session_state session_state;
	enum spdm_secure_session_type session_type;
	size_t aead_iv_size;
	const uint8_t *key;
	uint8_t *salt;
	uint64_t sequence_number;
	uint8_t sequence_num_in_header_size;
	uint8_t iv[SPDM_MAX_AEAD_IV_SIZE] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1;
	struct spdm_secure_session_manager_state *session_manager_state;

	if ((session_manager == NULL) || (request == NULL)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	session_manager_state = session_manager->state;

	/* Reset the last secure session id processed. */
	session_manager_state->last_spdm_request_secure_session_id = SPDM_INVALID_SESSION_ID;
	session_manager_state->last_spdm_request_secure_session_id_valid = false;

	/* Get the session Id from the secure message. */
	if (request->payload_length < sizeof (struct spdm_secured_message_data_header_1)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		goto exit;
	}

	secured_message_data_header_1 = (struct spdm_secured_message_data_header_1*) request->payload;

	/* Retrieve the session object. */
	session = session_manager->get_session (session_manager,
		secured_message_data_header_1->session_id);
	if (session == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST;
		goto exit;
	}

	session_state = session->session_state;
	session_type = session->session_type;
	aead_iv_size = session->aead_iv_size;

	switch (session_state) {
		case SPDM_SESSION_STATE_HANDSHAKING:
			key = (const uint8_t*) session->handshake_secret.request_handshake_encryption_key;
			salt = (uint8_t*) session->handshake_secret.request_handshake_salt;
			sequence_number = session->handshake_secret.request_handshake_sequence_number;
			break;

		case SPDM_SESSION_STATE_ESTABLISHED:
			key = (const uint8_t*) session->data_secret.request_data_encryption_key;
			salt = (uint8_t*) session->data_secret.request_data_salt;
			sequence_number = session->data_secret.request_data_sequence_number;
			break;

		default:
			status = SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR;
			goto exit;
	}

	if (sequence_number >= session_manager->max_spdm_session_sequence_number) {
		status = SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW;
		goto exit;
	}

	spdm_secure_session_manager_generate_iv (sequence_number, iv, salt, aead_iv_size);

	/* Per CMA-SPDM specification section 6.31.4, sequence number in header should be not present. */
	sequence_num_in_header_size = 0;

	if (session_state == SPDM_SESSION_STATE_HANDSHAKING) {
		session->handshake_secret.request_handshake_sequence_number++;
	}
	else {
		session->data_secret.request_data_sequence_number++;
	}

	switch (session_type) {
		case SPDM_SESSION_TYPE_ENC_MAC:
			status = spdm_secure_session_manager_decrypt_message (session_manager, session, request,
				sequence_number, sequence_num_in_header_size, key, salt, iv);
			break;

		case SPDM_SESSION_TYPE_MAC_ONLY:
		default:
			status = SPDM_SECURE_SESSION_MANAGER_UNSUPPORTED_CAPABILITY;
			goto exit;
	}

	session_manager_state->last_spdm_request_secure_session_id = session->session_id;
	session_manager_state->last_spdm_request_secure_session_id_valid = true;

exit:
	buffer_zeroize (iv, sizeof (iv));

	return status;
}

/**
 * Encrypt a message using the session's AEAD key and IV.
 *
 * @param session_manager The SPDM session manager.
 * @param session The SPDM session.
 * @param request The message to encrypt.
 * @param sequence_num_in_header_size The size of the sequence number in the message header.
 * @param key The AEAD key.
 * @param iv The AEAD IV.
 *
 * @return 0 if the message is encrypted, error code otherwise.
 */
static int spdm_secure_session_manager_encrypt_message (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session,
	struct cmd_interface_msg *request, uint8_t sequence_num_in_header_size, const uint8_t *key,
	const uint8_t *iv)
{
	int status;
	size_t record_header_size;
	uint32_t random_data_size;
	size_t total_secured_message_size;
	size_t plaintext_size;
	size_t application_data_length;
	size_t ciphertext_size;
	size_t aead_tag_size;
	size_t aead_key_size;
	size_t aead_iv_size;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;
	struct spdm_secured_message_cipher_header *enc_msg_header;
	const struct aes_gcm_engine *aes_engine;
	uint8_t *tag;
	uint8_t *add_data;

	aead_tag_size = session->aead_tag_size;
	aead_key_size = session->aead_key_size;
	aead_iv_size = session->aead_iv_size;
	aes_engine = session_manager->aes_engine;

	record_header_size = sizeof (struct spdm_secured_message_data_header_1) +
		sequence_num_in_header_size +
		sizeof (struct spdm_secured_message_data_header_2);

	/* Per CMA-SPDM specification section 6.31.4, random data must be not present. */
	random_data_size = 0;

	application_data_length = request->payload_length;
	plaintext_size = sizeof (struct spdm_secured_message_cipher_header) + request->payload_length +
		random_data_size;
	ciphertext_size = plaintext_size;
	total_secured_message_size = record_header_size + ciphertext_size + aead_tag_size;

	if (request->max_response < total_secured_message_size) {
		status = SPDM_SECURE_SESSION_MANAGER_BUFFER_TOO_SMALL;
		goto exit;
	}

	/* Move the payload to accomodate the record headers and sequence number. */
	cmd_interface_msg_add_protocol_header (request,
		record_header_size + sizeof (struct spdm_secured_message_cipher_header));

	record_header_1 = (void*) request->payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1) +
		sequence_num_in_header_size);
	record_header_1->session_id = session->session_id;
	record_header_2->length = (uint16_t) (ciphertext_size + aead_tag_size);

	enc_msg_header = (void*) (record_header_2 + 1);
	enc_msg_header->application_data_length = (uint16_t) application_data_length;
	tag = (uint8_t*) record_header_1 + record_header_size + plaintext_size;
	add_data = (uint8_t*) record_header_1;

	/* Set the encryption key. */
	status = aes_engine->set_key (aes_engine, key, aead_key_size);
	if (status != 0) {
		goto exit;
	}

	status = aes_engine->encrypt_with_add_data (aes_engine, (const uint8_t*) enc_msg_header,
		plaintext_size, iv, aead_iv_size, add_data, record_header_size, (uint8_t*) enc_msg_header,
		ciphertext_size, tag, aead_tag_size);
	if (status != 0) {
		goto exit;
	}

	/* Set the payload size. */
	cmd_interface_msg_set_message_payload_length (request, total_secured_message_size);

exit:

	return status;
}

int spdm_secure_session_manager_encode_secure_message (
	const struct spdm_secure_session_manager *session_manager, struct cmd_interface_msg *request)
{
	int status;
	enum spdm_secure_session_state session_state;
	enum spdm_secure_session_type session_type;
	const uint8_t *key;
	uint8_t *salt;
	size_t aead_iv_size;
	uint8_t iv[SPDM_MAX_AEAD_IV_SIZE] = {0};
	uint64_t sequence_number;
	uint8_t sequence_num_in_header_size;
	struct spdm_secure_session *session;
	uint8_t req_rsp_code;
	uint32_t session_id;

	if ((session_manager == NULL) || (request == NULL)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	if (session_manager->state->last_spdm_request_secure_session_id_valid == false) {
		status = SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR;
		goto exit;
	}

	session = session_manager->get_session (session_manager,
		session_manager->state->last_spdm_request_secure_session_id);
	if (session == NULL) {
		status = SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR;
		goto exit;
	}

	session_state = session->session_state;
	aead_iv_size = session->aead_iv_size;
	session_type = session->session_type;

	switch (session_state) {
		case SPDM_SESSION_STATE_HANDSHAKING:
			key = (const uint8_t*) session->handshake_secret.response_handshake_encryption_key;
			salt = (uint8_t*) session->handshake_secret.response_handshake_salt;
			sequence_number = session->handshake_secret.response_handshake_sequence_number;
			break;

		case SPDM_SESSION_STATE_ESTABLISHED:
			key = (const uint8_t*) session->data_secret.response_data_encryption_key;
			salt = (uint8_t*) session->data_secret.response_data_salt;
			sequence_number = session->data_secret.response_data_sequence_number;
			break;

		default:
			status = SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR;
			goto exit;
	}

	if (sequence_number >= session_manager->max_spdm_session_sequence_number) {
		status = SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW;
		goto exit;
	}

	spdm_secure_session_manager_generate_iv (sequence_number, iv, salt, aead_iv_size);

	/* Per CMA-SPDM specification section 6.31.4, sequence number in header should be not present. */
	sequence_num_in_header_size = 0;

	if (session_state == SPDM_SESSION_STATE_HANDSHAKING) {
		session->handshake_secret.response_handshake_sequence_number++;
	}
	else {
		session->data_secret.response_data_sequence_number++;
	}

	/* Get the req_rsp_code before encrypting the SPDM message. */
	req_rsp_code = ((struct spdm_protocol_header*) request->payload)->req_rsp_code;

	switch (session_type) {
		case SPDM_SESSION_TYPE_ENC_MAC:
			status = spdm_secure_session_manager_encrypt_message (session_manager, session, request,
				sequence_num_in_header_size, key, iv);
			break;

		case SPDM_SESSION_TYPE_MAC_ONLY:
		default:
			status = SPDM_SECURE_SESSION_MANAGER_UNSUPPORTED_CAPABILITY;
			goto exit;
	}

	if (status == 0) {
		session_id = session->session_id;

		switch (req_rsp_code) {
			case SPDM_RESPONSE_FINISH:
				/* Change session state regardless of handshake type (in clear vs not)*/
				spdm_secure_session_manager_set_session_state (session_manager, session_id,
					SPDM_SESSION_STATE_ESTABLISHED);

				observable_notify_observers_with_ptr (&session_manager->state->observable,
					offsetof (struct spdm_protocol_session_observer, on_new_session), &session_id);
				break;

			case SPDM_RESPONSE_END_SESSION:
				session_manager->release_session (session_manager, session_id);

				observable_notify_observers_with_ptr (&session_manager->state->observable,
					offsetof (struct spdm_protocol_session_observer, on_close_session),
					&session_id);
				break;
		}
	}

exit:
	buffer_zeroize (iv, sizeof (iv));

	return status;
}

int spdm_secure_session_manager_is_termination_policy_set (
	const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session *session;
	uint8_t index;

	if (session_manager == NULL) {
		return SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
	}

	for (index = 0; index < SPDM_MAX_SESSION_COUNT; index++) {
		session = &session_manager->state->sessions[index];

		/* The termination policy value is only valid for established sessions. */
		if ((session->session_id == SPDM_INVALID_SESSION_ID) ||
			(session->session_state != SPDM_SESSION_STATE_ESTABLISHED)) {
			continue;
		}

		if (session->session_policy == 0) {
			return SPDM_SECURE_SESSION_MANAGER_TERMINATION_POLICY_NOT_SET;
		}
	}

	return 0;
}

/**
 * Initialize the Session Manager.
 *
 * @param session_manager SPDM Session Manager to initialize.
 * @param state SPDM Session Manager state.
 * @param local_capabilities Local capabilities.
 * @param local_algorithms Local algorithms.
 * @param aes AES engine.
 * @param hash Hashing engine.
 * @param rng RNG engine.
 * @param ecc ECC engine.
 * @param transcript_manager Transcript Manager.
 * @param hkdf HKDF implementation
 * @param error Error state management interface.
 * @param algo_info Metadata for provided algorithms
 *
 * @return 0 if the session manager is initialized successfully, error code otherwise.
 */
int spdm_secure_session_manager_init (struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session_manager_state *state,
	const struct spdm_device_capability *local_capabilities,
	const struct spdm_device_algorithms *local_algorithms, const struct aes_gcm_engine *aes_engine,
	const struct hash_engine *hash_engine, const struct rng_engine *rng_engine,
	const struct ecc_engine *ecc_engine, const struct spdm_transcript_manager *transcript_manager,
	const struct hkdf_interface *hkdf, const struct error_state_entry_interface *error,
	struct spdm_secure_session_manager_algo_info algo_info)
{
	int status;

	if (session_manager == NULL) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (session_manager, 0, sizeof (struct spdm_secure_session_manager));

	session_manager->state = state;
	session_manager->local_capabilities = local_capabilities;
	session_manager->local_algorithms = local_algorithms;
	session_manager->aes_engine = aes_engine;
	session_manager->hash_engine = hash_engine;
	session_manager->rng_engine = rng_engine;
	session_manager->ecc_engine = ecc_engine;
	session_manager->transcript_manager = transcript_manager;
	session_manager->max_spdm_session_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER;
	session_manager->hkdf = hkdf;
	session_manager->error = error;
	session_manager->algo_info = algo_info;

	session_manager->create_session = spdm_secure_session_manager_create_session;
	session_manager->release_session = spdm_secure_session_manager_release_session;
	session_manager->set_session_state = spdm_secure_session_manager_set_session_state;
	session_manager->reset = spdm_secure_session_manager_reset;
	session_manager->get_session = spdm_secure_session_manager_get_session;
	session_manager->generate_shared_secret = spdm_secure_session_manager_generate_shared_secret;
	session_manager->generate_session_handshake_keys =
		spdm_secure_session_manager_generate_session_handshake_keys;
	session_manager->generate_session_data_keys =
		spdm_secure_session_manager_generate_session_data_keys;
	session_manager->is_last_session_id_valid =
		spdm_secure_session_manager_is_last_session_id_valid;
	session_manager->get_last_session_id = spdm_secure_session_manager_get_last_session_id;
	session_manager->reset_last_session_id_validity =
		spdm_secure_session_manager_reset_last_session_id_validity;
	session_manager->decode_secure_message = spdm_secure_session_manager_decode_secure_message;
	session_manager->encode_secure_message = spdm_secure_session_manager_encode_secure_message;
	session_manager->is_termination_policy_set =
		spdm_secure_session_manager_is_termination_policy_set;

	status = spdm_secure_session_manager_init_state (session_manager);

exit:

	return status;
}

/**
 * Release the Session Manager.
 *
 * @param session_manager SPDM Session Manager to release.
 */
void spdm_secure_session_manager_release (const struct spdm_secure_session_manager *session_manager)
{
	if ((session_manager != NULL) && (session_manager->state != NULL)) {
		observable_release (&session_manager->state->observable);
	}
}

/**
 * Initialize the Session Manager state.
 *
 * @param session_manager Session manager whose state is to be initialized.
 *
 * @return 0 if a session manager state was initialize successfully or an error code.
 */
int spdm_secure_session_manager_init_state (
	const struct spdm_secure_session_manager *session_manager)
{
	int status = 0;
	struct spdm_secure_session_manager_state *state;

	if ((session_manager == NULL) || (session_manager->state == NULL) ||
		(session_manager->local_capabilities == NULL) ||
		(session_manager->local_algorithms == NULL) ||
		(session_manager->aes_engine == NULL) || (session_manager->hash_engine == NULL) ||
		(session_manager->rng_engine == NULL) || (session_manager->ecc_engine == NULL) ||
		(session_manager->transcript_manager == NULL) ||
		(session_manager->max_spdm_session_sequence_number == 0) ||
		(session_manager->hkdf == NULL)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	state = session_manager->state;
	memset (state, 0, sizeof (struct spdm_secure_session_manager_state));

	/* Initialize the state. */
	state->last_spdm_request_secure_session_id = SPDM_INVALID_SESSION_ID;
	state->last_spdm_request_secure_session_id_valid = false;

	status = observable_init (&state->observable);

exit:

	return status;
}

/**
 * Add an observer for session management notifications.
 *
 * @param session_manager The session manager to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int spdm_secure_session_manager_add_spdm_protocol_session_observer (
	const struct spdm_secure_session_manager *session_manager,
	const struct spdm_protocol_session_observer *observer)
{
	if ((session_manager == NULL) || (session_manager->state == NULL)) {
		return SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&session_manager->state->observable, (void*) observer);
}

/**
 * Remove an observer from session management notifications.
 *
 * @param session_manager The session manager to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int spdm_secure_session_manager_remove_spdm_protocol_session_observer (
	const struct spdm_secure_session_manager *session_manager,
	const struct spdm_protocol_session_observer *observer)
{
	if ((session_manager == NULL) || (session_manager->state == NULL)) {
		return SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&session_manager->state->observable, (void*) observer);
}
