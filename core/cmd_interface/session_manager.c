// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "crypto/aes.h"
#include "crypto/hash.h"
#include "crypto/kdf.h"
#include "riot/riot_core.h"
#include "riot/riot_key_manager.h"
#include "session_manager.h"


/**
 * Search session manager's active sessions table and find entry for requested EID if it exists.
 *
 * @param session Session manager instance to utilize.
 * @param eid Requested EID for device in session.
 *
 * @return Requested session container if exists, NULL otherwise.
 */
struct session_manager_entry* session_manager_get_session (struct session_manager *session,
	uint8_t eid)
{
	size_t i_session;

	for (i_session = 0; i_session < session->num_sessions; ++i_session) {
		if ((session->sessions_table[i_session].eid == eid) &&
			(session->sessions_table[i_session].session_state != SESSION_STATE_UNUSED)) {
			return &session->sessions_table[i_session];
		}
	}

	return NULL;
}

/**
 * Search session manager's sessions table and find first unused entry.
 *
 * @param session Session manager instance to utilize.
 *
 * @return Free session container if exists, NULL otherwise.
 */
struct session_manager_entry* session_manager_get_free_session (struct session_manager *session)
{
	size_t i_session;

	for (i_session = 0; i_session < session->num_sessions; ++i_session) {
		if (session->sessions_table[i_session].session_state == SESSION_STATE_UNUSED) {
			return &session->sessions_table[i_session];
		}
	}

	return NULL;
}

/**
 * Search session manager's pairing devices EID list and find keystore index for requested EID if it
 * exists.
 *
 * @param session Session manager instance to utilize.
 * @param eid Requested EID for device in session.
 *
 * @return Requested keystore index if exists, or an error code.
 */
static int session_manager_get_paired_key_index (struct session_manager *session, uint8_t eid)
{
	size_t i_key;

	for (i_key = 0; i_key < session->num_pairing_eids; ++i_key) {
		if (session->pairing_eids[i_key] == eid) {
			return i_key;
		}
	}

	return SESSION_MANAGER_PAIRING_NOT_SUPPORTED_WITH_DEVICE;
}

/**
 * Find AES session key for requested EID then set it in the AES engine
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int session_manager_set_key (struct session_manager *session, uint8_t eid)
{
	struct session_manager_entry *curr_session;
	int status;

	curr_session = session_manager_get_session (session, eid);
	if (curr_session == NULL) {
		return SESSION_MANAGER_UNEXPECTED_EID;
	}
	else if (curr_session->session_state < SESSION_STATE_ESTABLISHED) {
		return SESSION_MANAGER_SESSION_NOT_ESTABLISHED;
	}

	status = session->aes->set_key (session->aes, curr_session->session_key,
		sizeof (curr_session->session_key));

	return status;
}

/**
 * Check if device EID is on an established session.
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 *
 * @return 1 if established, 0 if not or an error code.
 */
int session_manager_is_session_established (struct session_manager *session, uint8_t eid)
{
	struct session_manager_entry *req_session;

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	req_session = session_manager_get_session (session, eid);
	if (req_session == NULL) {
		return false;
	}

	return (req_session->session_state >= SESSION_STATE_ESTABLISHED);
}

/**
 * Check pairing state of session with device.
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 *
 * @return Pairing state or an error code.
 */
int session_manager_get_pairing_state (struct session_manager *session, uint8_t eid)
{
	struct session_manager_entry *req_session;
	uint8_t *pairing_key_buf;
	size_t pairing_key_len;
	int key_id;
	int status;

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	key_id = session_manager_get_paired_key_index (session, eid);
	if (ROT_IS_ERROR (key_id) || (session->store == NULL)) {
		return SESSION_PAIRING_STATE_NOT_SUPPORTED;
	}

	status = session->store->load_key (session->store, key_id, &pairing_key_buf,
		&pairing_key_len);
	if (status == KEYSTORE_NO_KEY) {
		return SESSION_PAIRING_STATE_NOT_INITIALIZED;
	}
	else if (status != 0) {
		return status;
	}

	riot_core_clear (pairing_key_buf, pairing_key_len);
	platform_free (pairing_key_buf);

	req_session = session_manager_get_session (session, eid);
	if ((req_session == NULL) || (req_session->session_state != SESSION_STATE_PAIRED)) {
		return SESSION_PAIRING_STATE_NOT_PAIRED;
	}

	return SESSION_PAIRING_STATE_PAIRED;
}

/**
 * Decrypt message using AES session key generated for session with device with requested EID.
 *
 * @param session Session manager instance to utilize.
 * @param request Request to decrypt.
 *
 * @return Completion status, 0 if success or an error code.
 */
int session_manager_decrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request)
{
	uint8_t *payload;
	size_t payload_len;
	size_t buffer_len;
	int status;

	if ((session == NULL) || (request == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	if (request->length <= (SESSION_MANAGER_TRAILER_LEN +
		sizeof (struct cerberus_protocol_header))) {
		return SESSION_MANAGER_MALFORMED_MSG;
	}

	if ((request->max_response < (request->length - SESSION_MANAGER_TRAILER_LEN)) ||
		(request->max_response <=
			(sizeof (struct cerberus_protocol_header) + SESSION_MANAGER_TRAILER_LEN))) {
		return SESSION_MANAGER_BUF_TOO_SMALL;
	}

	payload = request->data + sizeof (struct cerberus_protocol_header);
	payload_len = request->length - sizeof (struct cerberus_protocol_header) -
		SESSION_MANAGER_TRAILER_LEN;
	buffer_len = request->max_response - sizeof (struct cerberus_protocol_header);

	status = session_manager_set_key (session, request->source_eid);
	if (status != 0) {
		return status;
	}

	request->length -= SESSION_MANAGER_TRAILER_LEN;

	return session->aes->decrypt_data (session->aes, payload, payload_len, &payload[payload_len],
		&payload[payload_len + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN], CERBERUS_PROTOCOL_AES_IV_LEN,
		payload, buffer_len);
}

/**
 * Encrypt message using AES session key generated for session with device with requested EID.
 *
 * @param session Session manager instance to utilize.
 * @param request Request to encrypt.
 *
 * @return Completion status, 0 if success or an error code.
 */
int session_manager_encrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_header *header;
	uint8_t *aes_iv;
	uint8_t *payload;
	size_t payload_len;
	size_t buffer_len;
	int status;

	if ((session == NULL) || (request == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	if (request->length <= sizeof (struct cerberus_protocol_header)) {
		return 0;
	}

	if ((request->length + SESSION_MANAGER_TRAILER_LEN) > request->max_response) {
		return SESSION_MANAGER_BUF_TOO_SMALL;
	}

	payload = request->data + sizeof (struct cerberus_protocol_header);
	payload_len = request->length - sizeof (struct cerberus_protocol_header);
	buffer_len = request->max_response - sizeof (struct cerberus_protocol_header);
	aes_iv = &payload[payload_len + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN];

	status = session_manager_set_key (session, request->source_eid);
	if (status != 0) {
		return status;
	}

	status = session->rng->generate_random_buffer (session->rng, CERBERUS_PROTOCOL_AES_IV_LEN,
		aes_iv);
	if (status != 0) {
		return status;
	}

	status = session->aes->encrypt_data (session->aes, payload, payload_len, aes_iv,
		CERBERUS_PROTOCOL_AES_IV_LEN, payload, buffer_len - SESSION_MANAGER_TRAILER_LEN,
		&payload[payload_len],
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN);
	if (status != 0) {
		return status;
	}

	request->length += SESSION_MANAGER_TRAILER_LEN;

	header = (struct cerberus_protocol_header*) request->data;
	header->crypt = 1;

	return status;
}

/**
 * Use provided nonces to either create or restart session with device specified using EID.
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 * @param device_nonce 32 byte random nonce generated by device used for AES key generation.
 * @param cerberus_nonce 32 byte random nonce generated by Cerberus used for AES key generation.
 *
 * @return Completion status, 0 if success or an error code.
 */
int session_manager_add_session (struct session_manager *session, uint8_t eid,
	const uint8_t *device_nonce, const uint8_t *cerberus_nonce)
{
	struct session_manager_entry *curr_session;

	if ((session == NULL) || (device_nonce == NULL) || (cerberus_nonce == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	curr_session = session_manager_get_session (session, eid);
	if (curr_session == NULL) {
		curr_session = session_manager_get_free_session (session);
		if (curr_session == NULL) {
			return SESSION_MANAGER_FULL;
		}
	}

	memcpy (curr_session->device_nonce, device_nonce, SESSION_MANAGER_NONCE_LEN);
	memcpy (curr_session->cerberus_nonce, cerberus_nonce, SESSION_MANAGER_NONCE_LEN);
	curr_session->session_state = SESSION_STATE_SETUP;
	curr_session->eid = eid;

	return 0;
}

/**
 * Generate HMAC of data and compare to received HMAC.
 *
 * @param session Session manager instance to utilize.
 * @param hmac_hash_type HMAC hash type to utilize.
 * @param hmac_key HMAC key to utilize.
 * @param hmac_key_len HMAC key length.
 * @param data Data buffer to compute HMAC of.
 * @param data_len Length of data.
 * @param hmac HMAC provided by device.
 * @param hmac_len HMAC length.
 *
 * @return Completion status, 0 if success or an error code.
 */
static int session_manager_generate_and_compare_hmac (struct session_manager *session,
	enum hmac_hash hmac_hash_type, uint8_t *hmac_key, size_t hmac_key_len, uint8_t *data,
	size_t data_len, uint8_t *hmac, size_t hmac_len)
{
	uint8_t computed_hmac[SHA256_HASH_LENGTH];
	int status;

	if (hmac_len != sizeof (computed_hmac)) {
		return SESSION_MANAGER_OPERATION_UNSUPPORTED;
	}

	status = hash_generate_hmac (session->hash, hmac_key, hmac_key_len, data, data_len,
		hmac_hash_type, computed_hmac, sizeof (computed_hmac));
	if (status != 0) {
		return status;
	}

	if (memcmp (computed_hmac, hmac, sizeof (computed_hmac)) != 0) {
		return SESSION_MANAGER_OPERATION_NOT_PERMITTED;
	}

	return 0;
}

/**
 * Terminate and reset session.
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 * @param hmac Optional HMAC provided by device. Set to NULL if not used.
 * @param hmac_len HMAC length.
 *
 * @return Completion status, 0 if success or an error code.
 */
int session_manager_reset_session (struct session_manager *session, uint8_t eid, uint8_t *hmac,
	size_t hmac_len)
{
	struct session_manager_entry *req_session;
	int status;

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	req_session = session_manager_get_session (session, eid);
	if (req_session == NULL) {
		return SESSION_MANAGER_UNEXPECTED_EID;
	}

	if ((hmac != NULL) && (req_session->session_state >= SESSION_STATE_ESTABLISHED)) {
		status = session_manager_generate_and_compare_hmac (session, req_session->hmac_hash_type,
			req_session->hmac_key, sizeof (req_session->hmac_key), req_session->session_key,
			sizeof (req_session->session_key), hmac, hmac_len);
		if (status != 0) {
			return status;
		}
	}

	memset (req_session, 0, sizeof (struct session_manager_entry));

	req_session->session_state = SESSION_STATE_UNUSED;

	return 0;
}

/**
 * Generate digest of the device and Cerberus session keys
 *
 * @param session Session manager instance to utilize.
 * @param device_key Device session public key.
 * @param device_key_len Device session public key length.
 * @param session_pub_key Cerberus session public key.
 * @param session_pub_key_len Cerberus session public key length.
 * @param digest Buffer to store generated digest.
 * @param digest_len Digest buffer length.
 *
 * @return Completion status, 0 if success or an error code.
 */
int session_manager_generate_keys_digest (struct session_manager *session,
	const uint8_t *device_key, size_t device_key_len, const uint8_t *session_pub_key,
	size_t session_pub_key_len, uint8_t *digest, size_t digest_len)
{
	int status;

	if ((session == NULL) || (device_key == NULL) || (session_pub_key == NULL) ||
		(digest == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	status = session->hash->start_sha256 (session->hash);
	if (status != 0) {
		return status;
	}

	status = session->hash->update (session->hash, device_key, device_key_len);
	if (status != 0) {
		session->hash->cancel (session->hash);
		return status;
	}

	status = session->hash->update (session->hash, session_pub_key, session_pub_key_len);
	if (status != 0) {
		session->hash->cancel (session->hash);
		return status;
	}

	status = session->hash->finish (session->hash, digest, digest_len);
	if (status != 0) {
		session->hash->cancel (session->hash);
		return status;
	}

	return status;
}

/**
 * Setup device binding in an established encrypted session.
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 * @param pairing_key_len Length of the pairing key.
 * @param pairing_key_hmac Buffer containing HMAC generated by device for pairing key.
 * @param pairing_key_hmac_len Length of the pairing key HMAC.
 *
 * @return Completion status, 0 if success or an error code.
 */
int session_manager_setup_paired_session (struct session_manager *session, uint8_t eid,
	size_t pairing_key_len, uint8_t *pairing_key_hmac, size_t pairing_key_hmac_len)
{
	struct session_manager_entry *req_session;
	uint8_t pairing_key[SHA256_HASH_LENGTH];
	uint8_t label[AES256_KEY_LENGTH];
	uint8_t *pairing_key_buf;
	bool pairing_key_generated = false;
	char *label_str = "pairing";
	int keystore_index;
	int status;

	if ((session == NULL) || (pairing_key_hmac == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	if (session->store == NULL) {
		return SESSION_MANAGER_OPERATION_UNSUPPORTED;
	}

	req_session = session_manager_get_session (session, eid);
	if (req_session == NULL) {
		return SESSION_MANAGER_UNEXPECTED_EID;
	}

	if (req_session->session_state < SESSION_STATE_ESTABLISHED) {
		return SESSION_MANAGER_INVALID_ORDER;
	}

	keystore_index = session_manager_get_paired_key_index (session, eid);
	if (ROT_IS_ERROR (keystore_index)) {
		return keystore_index;
	}

	status = session->store->load_key (session->store, keystore_index, &pairing_key_buf,
		&pairing_key_len);
	if (status == KEYSTORE_NO_KEY) {
		status = kdf_nist800_108_counter_mode (session->hash, req_session->hmac_hash_type,
			req_session->session_key, sizeof (req_session->session_key), (const uint8_t*) label_str,
			strlen (label_str), NULL, 0, pairing_key, sizeof (pairing_key));
		if (status != 0) {
			return status;
		}

		pairing_key_generated = true;
	}
	else if (status != 0) {
		return status;
	}
	else {
		memcpy (pairing_key, pairing_key_buf, pairing_key_len);
		riot_core_clear (pairing_key_buf, pairing_key_len);
		platform_free (pairing_key_buf);
	}

	status = session_manager_generate_and_compare_hmac (session, req_session->hmac_hash_type,
		req_session->hmac_key, sizeof (req_session->hmac_key), pairing_key, sizeof (pairing_key),
		pairing_key_hmac, pairing_key_hmac_len);
	if (status != 0) {
		goto exit;
	}

	memcpy (label, req_session->session_key, sizeof (label));

	status = kdf_nist800_108_counter_mode (session->hash, HMAC_SHA256, pairing_key,
		sizeof (pairing_key), label, sizeof (label), NULL, 0, req_session->session_key,
		sizeof (req_session->session_key));
	if (status != 0) {
		goto exit;
	}

	if (pairing_key_generated) {
		status = session->store->save_key (session->store, keystore_index, pairing_key,
			sizeof (pairing_key));
		if (status != 0) {
			goto exit;
		}
	}

	req_session->session_state = SESSION_STATE_PAIRED;

exit:
	riot_core_clear (pairing_key, sizeof (pairing_key));
	return status;
}

/**
 * Get session sync hmac.
 *
 * @param session Session manager instance to utilize.
 * @param eid Device EID.
 * @param rn_req Random number provided by device.
 * @param hmac Buffer to hold generated HMAC.
 * @param hmac_len Size of provided HMAC buffer.
 *
 * @return Size of generated HMAC or an error code.
 */
int session_manager_session_sync (struct session_manager *session, uint8_t eid, uint32_t rn_req,
	uint8_t *hmac, size_t hmac_len)
{
	struct session_manager_entry *req_session;
	int status;

	if ((session == NULL) || (hmac == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	req_session = session_manager_get_session (session, eid);
	if (req_session == NULL) {
		return SESSION_MANAGER_UNEXPECTED_EID;
	}

	if (req_session->session_state < SESSION_STATE_ESTABLISHED) {
		return SESSION_MANAGER_SESSION_NOT_ESTABLISHED;
	}

	status = hash_generate_hmac (session->hash, req_session->hmac_key,
		sizeof (req_session->hmac_key), (const uint8_t*) &rn_req, sizeof (rn_req),
		req_session->hmac_hash_type, hmac, hmac_len);
	if (status != 0) {
		return status;
	}

	return SHA256_HASH_LENGTH;
}

/**
 * Initialize session manager instance
 *
 * @param session Session manager instance to initialize.
 * @param aes AES engine to utilize for packet encryption/decryption.
 * @param hash Hash engine to utilize for AES key generation.
 * @param rng RNG engine used to generate IV buffers.
 * @param riot RIoT key manager to utilize to get alias key for AES key generation.
 * @param sessions_table Preallocated table to use to store session manager entries. Set to NULL to
 * 	dynamically allocate from heap.
 * @param num_sessions Number of sessions to support.
 * @param pairing_eids List of supported devices for pairing mode. Each element corresponds to a
 * 	device EID, with the element index corresponding to the keystore key ID. The keystore needs to
 * 	be initialized to support storing a key for each device in this array.
 * @param num_pairing_eids Total number of supported devices for pairing mode.
 * @param store Keystore used to persist pairing keys. Set to NULL if pairing feature not supported.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int session_manager_init (struct session_manager *session, struct aes_engine *aes,
	struct hash_engine *hash, struct rng_engine *rng, struct riot_key_manager *riot,
	struct session_manager_entry *sessions_table, size_t num_sessions, const uint8_t *pairing_eids,
	size_t num_pairing_eids, struct keystore *store)
{
	if ((session == NULL) || (aes == NULL) || (hash == NULL) || (rng == NULL) || (riot == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	memset (session, 0, sizeof (struct session_manager));

	session->aes = aes;
	session->hash = hash;
	session->rng = rng;
	session->riot = riot;
	session->num_sessions = num_sessions;
	session->sessions_table = sessions_table;
	session->num_pairing_eids = num_pairing_eids;
	session->pairing_eids = pairing_eids;
	session->store = store;

	if (session->sessions_table == NULL) {
		session->sessions_table = (struct session_manager_entry*) platform_calloc (num_sessions,
			sizeof (struct session_manager_entry));
		if (session->sessions_table == NULL) {
			return SESSION_MANAGER_NO_MEMORY;
		}

		session->sessions_table_preallocated = false;
	}
	else {
		memset (session->sessions_table, 0, sizeof (struct session_manager_entry) * num_sessions);
		session->sessions_table_preallocated = true;
	}

	return 0;
}

/**
 * Release session manager
 *
 * @param session Session manager instance to release
 */
void session_manager_release (struct session_manager *session)
{
	if ((session != NULL) && !session->sessions_table_preallocated) {
		platform_free (session->sessions_table);
	}
}
