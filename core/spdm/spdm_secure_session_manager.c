// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "common/unused.h"
#include "crypto/kdf.h"
#include "spdm_secure_session_manager.h"

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
	const struct spdm_secure_session_manager *session_manager,
	uint32_t session_index, uint32_t session_id, bool is_requester,
	const struct spdm_connection_info *connection_info)
{
	enum spdm_secure_session_type session_type;
	struct spdm_get_capabilities_flags_format req_capability;
	struct spdm_get_capabilities_flags_format resp_capability;
	struct spdm_secure_session *session;
	struct spdm_transcript_manager *transcript_manager;

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
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		true, session_index);

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
	struct spdm_transcript_manager *transcript_manager;
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
	memset (session->master_secret.handshake_secret, 0,
		sizeof (session->master_secret.handshake_secret));
	memset (&session->handshake_secret, 0,
		sizeof (struct spdm_secure_session_handshake_secrets));

	session->requester_backup_valid = false;
	session->responder_backup_valid = false;
}

/**
 * Clear the master secrets.
 *
 * @param session SPDM secure session.
 */
static void spdm_secure_session_clear_master_secret (struct spdm_secure_session *session)
{
	memset (session->master_secret.master_secret, 0, sizeof (session->master_secret.master_secret));
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
			spdm_secure_session_clear_master_secret (session);
		}
	}
}

void spdm_secure_session_manager_reset (const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session *sessions;
	size_t session_index;

	if (session_manager == NULL) {
		return;
	}

	sessions = session_manager->state->sessions;

	/* Release all sessions. */
	for (session_index = 0; session_index < SPDM_MAX_SESSION_COUNT; session_index++) {
		if (sessions[session_index].session_id != SPDM_INVALID_SESSION_ID) {
			spdm_secure_session_manager_release_session (session_manager,
				sessions[session_index].session_id);
		}
	}

	/* Reset the state. */
	memset (session_manager->state, 0, sizeof (struct spdm_secure_session_manager_state));
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
	const struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session* session, const struct ecc_point_public_key *peer_pub_key_point,
	uint8_t *local_pub_key_point)
{
	int status;
	uint8_t peer_pub_key_der[ECC_DER_MAX_PUBLIC_LENGTH];
	int der_len;
	struct ecc_engine *ecc_engine;
	struct ecc_public_key peer_pub_key;
	struct ecc_private_key local_priv_key;
	struct ecc_public_key local_pub_key;
	uint8_t *local_pub_key_der = NULL;
	size_t local_pub_key_der_len;
	bool release_local_key_pair = false;
	bool release_peer_pub_key = false;
	int shared_secret_len;
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
	status = ecc_engine->generate_key_pair (ecc_engine, key_point_length, &local_priv_key,
		&local_pub_key);
	if (status != 0) {
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

	platform_free (local_pub_key_der);

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

	final_size = sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1 + label_size;
	if (context != NULL) {
		final_size += hash_size;
	}

	*out_bin_size = final_size;

	memcpy (out_bin, &length, sizeof (uint16_t));
	memcpy ((out_bin + sizeof (uint16_t)), SPDM_BIN_CONCAT_LABEL,
		sizeof (SPDM_BIN_CONCAT_LABEL) - 1);

	/* Patch the version. */
	out_bin[6] = (char)('0' + version.major_version);
	out_bin[8] = (char)('0' + version.minor_version);

	memcpy ((out_bin + sizeof (uint16_t) + sizeof (SPDM_BIN_CONCAT_LABEL) - 1), label, label_size);

	if (context != NULL) {
		memcpy ((out_bin + sizeof (uint16_t) + sizeof (SPDM_BIN_CONCAT_LABEL) - 1 + label_size),
			context, hash_size);
	}
}

/**
 * Generate the SPDM finished key for a session.
 *
 * @param hash_engine Hash engine instance to use.
 * @param session SPDM session.
 * @param hmac_hash_type HMAC hash type.
 * @param handshake_secret Handshake secret.
 * @param finished_key Buffer to store the finished key.
 *
 * @return 0 if the SPDM finished key for a session is generated, error code otherwise.
 */
static int spdm_secure_session_manager_generate_finished_key (struct hash_engine *hash_engine,
	struct spdm_secure_session* session, enum hmac_hash hmac_hash_type,
	const uint8_t *handshake_secret, uint8_t *finished_key)
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

	status = kdf_hkdf_expand (hash_engine, hmac_hash_type, handshake_secret, hash_size,
		bin_str7, bin_str7_size, finished_key, hash_size);
	if (status != 0) {
		goto exit;
	}

exit:
	return status;
}

/**
 * Generate the SPDM AEAD key and IV for a session.
 *
 * @param hash_engine Hash engine instance to use.
 * @param spdm_secured_message_context SPDM secured message context.
 * @param hmac_hash_type HMAC hash type.
 * @param major_secret Major secret.
 * @param key Buffer to store the AEAD key.
 * @param iv Buffer to store the AEAD IV.
 *
 * @return 0 if the SPDM AEAD key and IV are generated, error code otherwise.
 */
static int spdm_session_manager_generate_aead_key_and_iv (struct hash_engine *hash_engine,
	struct spdm_secure_session* session, enum hmac_hash hmac_hash_type,
	const uint8_t *major_secret, uint8_t *key, uint8_t *iv)
{
	bool status;
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

	status = kdf_hkdf_expand (hash_engine, hmac_hash_type, major_secret, hash_size, bin_str5,
		bin_str5_size, key, key_length);
	if (status != 0) {
		goto exit;
	}

	/* Generate the AEAD IV. */
	bin_str6_size = sizeof (bin_str6);
	spdm_secure_session_manager_bin_concat (session->version, SPDM_BIN_STR_6_LABEL,
		sizeof (SPDM_BIN_STR_6_LABEL) - 1, NULL, (uint16_t) iv_length, hash_size, bin_str6,
		&bin_str6_size);

	status = kdf_hkdf_expand (hash_engine, hmac_hash_type, major_secret, hash_size, bin_str6,
		bin_str6_size, iv, iv_length);
	if (status != 0) {
		goto exit;
	}

exit:
	return status;
}

int spdm_secure_session_manager_generate_session_handshake_keys (
	const struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session *session)
{
	int status;
	struct spdm_transcript_manager *transcript_manager;
	struct hash_engine *hash_engine;
	uint8_t th1_hash[HASH_MAX_HASH_LEN];
	size_t hash_size;
	uint8_t bin_str1[128];
	size_t bin_str1_size;
	uint8_t bin_str2[128];
	size_t bin_str2_size;
	uint8_t salt0[HASH_MAX_HASH_LEN];
	enum hmac_hash hmac_hash_type;

	if ((session_manager == NULL) || (session == NULL)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}
	transcript_manager = session_manager->transcript_manager;
	hash_engine = session_manager->hash_engine;
	hash_size = session->hash_size;

	/* Step 1: Get the TH hash; do not complete the hash context as it is needed later. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		true, session->session_index, th1_hash, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Step 2: Use the TH hash to generate the session handshake key. */
	hmac_hash_type = (enum hmac_hash) spdm_get_hash_type (session->base_hash_algo);

	memset (salt0, 0, sizeof (salt0));

	/* Generate HMAC of salt0 with DHE shared secret. */
	status = hash_generate_hmac (hash_engine, salt0, session->dhe_key_size,
		session->master_secret.dhe_secret, hash_size, hmac_hash_type,
		session->master_secret.handshake_secret, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Derive the request handshake secret. */
	bin_str1_size = sizeof (bin_str1);
	spdm_secure_session_manager_bin_concat (session->version,
		SPDM_BIN_STR_1_LABEL, sizeof (SPDM_BIN_STR_1_LABEL) - 1, th1_hash,
		(uint16_t) hash_size, hash_size, bin_str1, &bin_str1_size);

	status = kdf_hkdf_expand (hash_engine, hmac_hash_type,
		session->master_secret.handshake_secret, hash_size, bin_str1, bin_str1_size,
		session->handshake_secret.request_handshake_secret, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Derive the response handshake secret. */
	bin_str2_size = sizeof(bin_str2);
	spdm_secure_session_manager_bin_concat(session->version, SPDM_BIN_STR_2_LABEL,
		sizeof (SPDM_BIN_STR_2_LABEL) - 1, th1_hash, (uint16_t) hash_size, hash_size, bin_str2,
		&bin_str2_size);

	status = kdf_hkdf_expand (hash_engine, hmac_hash_type,
		session->master_secret.handshake_secret, hash_size, bin_str2, bin_str2_size,
		session->handshake_secret.response_handshake_secret, hash_size);
	if (status != 0) {
		goto exit;
	}

	/* Generate the requester finished key. */
	status = spdm_secure_session_manager_generate_finished_key (hash_engine, session,
		hmac_hash_type, session->handshake_secret.request_handshake_secret,
		session->handshake_secret.request_finished_key);
	if (status != 0) {
		goto exit;
	}

	/* Generate the responder finished key. */
	status = spdm_secure_session_manager_generate_finished_key (hash_engine, session,
		hmac_hash_type, session->handshake_secret.response_handshake_secret,
		session->handshake_secret.response_finished_key);
	if (status != 0) {
		goto exit;
	}

	/* Generate the requester AEAD key and IV. */
	status = spdm_session_manager_generate_aead_key_and_iv (hash_engine, session,
		hmac_hash_type, session->handshake_secret.request_handshake_secret,
		session->handshake_secret.request_handshake_encryption_key,
		session->handshake_secret.request_handshake_salt);
	if (status != 0) {
		goto exit;
	}
	session->handshake_secret.request_handshake_sequence_number = 0;

	/* Generate the responder AEAD key and IV. */
	status = spdm_session_manager_generate_aead_key_and_iv (hash_engine, session,
		hmac_hash_type, session->handshake_secret.response_handshake_secret,
		session->handshake_secret.response_handshake_encryption_key,
		session->handshake_secret.response_handshake_salt);
	if (status != 0) {
		goto exit;
	}
	session->handshake_secret.response_handshake_sequence_number = 0;

	/* Clear the DHE shared secret. */
	memset (session->master_secret.dhe_secret, 0, SPDM_MAX_DHE_SHARED_SECRET_SIZE);

exit:
	return status;
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
 *
 * @return 0 if the session manager is initialized successfully, error code otherwise.
 */
int spdm_secure_session_manager_init (struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session_manager_state *state,
	const struct spdm_device_capability *local_capabilities,
	const struct spdm_device_algorithms *local_algorithms, struct aes_engine *aes_engine,
	struct hash_engine *hash_engine, struct rng_engine *rng_engine, struct ecc_engine *ecc_engine,
	struct spdm_transcript_manager *transcript_manager)
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

	session_manager->create_session = spdm_secure_session_manager_create_session;
	session_manager->release_session = spdm_secure_session_manager_release_session;
	session_manager->set_session_state = spdm_secure_session_manager_set_session_state;
	session_manager->reset = spdm_secure_session_manager_reset;
	session_manager->get_session = spdm_secure_session_manager_get_session;
	session_manager->generate_shared_secret = spdm_secure_session_manager_generate_shared_secret;
	session_manager->generate_session_handshake_keys = 
		spdm_secure_session_manager_generate_session_handshake_keys;

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
	UNUSED (session_manager);
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

	if ((session_manager == NULL) || (session_manager->state == NULL) || 
		(session_manager->local_capabilities == NULL) ||
		(session_manager->local_algorithms == NULL) ||
		(session_manager->aes_engine == NULL) || (session_manager->hash_engine == NULL) ||
		(session_manager->rng_engine == NULL) || (session_manager->ecc_engine == NULL) ||
		(session_manager->transcript_manager == NULL)) {
		status = SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (session_manager->state, 0, sizeof (struct spdm_secure_session_manager_state));

exit:
	return status;
}


