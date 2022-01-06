// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "crypto/aes.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"
#include "crypto/kdf.h"
#include "riot/riot_key_manager.h"
#include "cerberus_protocol_optional_commands.h"
#include "session_manager.h"
#include "session_manager_ecc.h"


static int session_manager_ecc_establish_session (struct session_manager *session,
	struct cmd_interface_msg *request)
{
	struct session_manager_ecc *session_mgr = (struct session_manager_ecc*) session;
	struct cerberus_protocol_key_exchange_type_0 *rq;
	struct cerberus_protocol_key_exchange_response_type_0 *rsp;
	struct session_manager_entry *curr_session;
	struct ecc_private_key session_priv_key;
	struct ecc_public_key session_pub_key;
	struct ecc_private_key alias_priv_key;
	struct ecc_public_key device_pub_key;
	const struct riot_keys *keys;
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t *session_pub_key_der;
	uint8_t *shared_secret;
	uint16_t hash_len;
	size_t session_pub_key_der_len;
	int shared_secret_len;
	int sig_len;
	int status;

	if ((session_mgr == NULL) || (request == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	if (request->length <= cerberus_protocol_key_exchange_type_0_length (0)) {
		return SESSION_MANAGER_INVALID_REQUEST;
	}

	if (request->max_response <= sizeof (struct cerberus_protocol_key_exchange_response)) {
		return SESSION_MANAGER_BUF_TOO_SMALL;
	}

	curr_session = (struct session_manager_entry*) session_manager_get_session (&session_mgr->base,
		request->source_eid);
	if (curr_session != NULL) {
		if (curr_session->session_state != SESSION_STATE_SETUP) {
			return SESSION_MANAGER_INVALID_ORDER;
		}
	}
	else {
		return SESSION_MANAGER_UNEXPECTED_EID;
	}

	rq = (struct cerberus_protocol_key_exchange_type_0*) request->data;
	rsp = (struct cerberus_protocol_key_exchange_response_type_0*) request->data;

	if (rq->hmac_type == CERBERUS_PROTOCOL_HMAC_SHA256) {
		curr_session->hmac_hash_type = HMAC_SHA256;
		hash_len = SHA256_HASH_LENGTH;
	}
	else {
		return SESSION_MANAGER_OPERATION_UNSUPPORTED;
	}

	status = session_mgr->ecc->init_public_key (session_mgr->ecc,
		cerberus_protocol_key_exchange_type_0_key_data (rq),
		cerberus_protocol_key_exchange_type_0_key_len (request), &device_pub_key);
	if (status != 0) {
		return status;
	}

	status = session_mgr->ecc->generate_key_pair (session_mgr->ecc, ECC_KEY_LENGTH_256,
		&session_priv_key, &session_pub_key);
	if (status != 0) {
		goto free_device_key;
	}

	status = session_mgr->ecc->get_public_key_der (session_mgr->ecc, &session_pub_key,
		&session_pub_key_der, &session_pub_key_der_len);
	if (status != 0) {
		goto free_session_keys;
	}

	status = session_manager_generate_keys_digest (&session_mgr->base,
		cerberus_protocol_key_exchange_type_0_key_data (rq),
		cerberus_protocol_key_exchange_type_0_key_len (request), session_pub_key_der,
		session_pub_key_der_len, hash, sizeof (hash));
	if (status != 0) {
		goto free_session_pub_der;
	}

	rsp->reserved = 0;

	if (CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_KEY_DATA (request) <=
		session_pub_key_der_len) {
		status = SESSION_MANAGER_BUF_TOO_SMALL;
		goto free_session_pub_der;
	}

	memcpy (cerberus_protocol_key_exchange_type_0_response_key_data (rsp),
		session_pub_key_der, session_pub_key_der_len);

	rsp->key_len = (uint16_t) session_pub_key_der_len;

	keys = riot_key_manager_get_riot_keys (session_mgr->base.riot);
	if (keys == NULL) {
		status = SESSION_MANAGER_INVALID_ARGUMENT;
		goto free_session_pub_der;
	}

	status = session_mgr->ecc->init_key_pair (session_mgr->ecc, keys->alias_key,
		keys->alias_key_length, &alias_priv_key, NULL);
	if (status != 0) {
		goto release_riot_keys;
	}

	status = session_mgr->ecc->get_signature_max_length (session_mgr->ecc, &alias_priv_key);
	if (ROT_IS_ERROR (status)) {
		goto free_alias_key;
	}

	sig_len = session_mgr->ecc->sign (session_mgr->ecc, &alias_priv_key, hash, sizeof (hash),
		cerberus_protocol_key_exchange_type_0_response_sig_data (rsp),
		CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_SIG_DATA (request));
	if (ROT_IS_ERROR (sig_len)) {
		status = sig_len;
		goto free_alias_key;
	}

	cerberus_protocol_key_exchange_type_0_response_sig_len (rsp) = (uint16_t) sig_len;

	status = session_mgr->ecc->get_shared_secret_max_length (session_mgr->ecc, &session_priv_key);
	if (ROT_IS_ERROR (status)) {
		goto free_alias_key;
	}

	shared_secret = platform_malloc (status);
	if (shared_secret == NULL) {
		status = SESSION_MANAGER_NO_MEMORY;
		goto free_alias_key;
	}

	shared_secret_len = session_mgr->ecc->compute_shared_secret (session_mgr->ecc,
		&session_priv_key, &device_pub_key, shared_secret, status);
	if (ROT_IS_ERROR (shared_secret_len)) {
		status = shared_secret_len;
		goto free_shared_secret;
	}

	status = kdf_nist800_108_counter_mode (session_mgr->base.hash, HMAC_SHA256, shared_secret,
		shared_secret_len, curr_session->device_nonce, sizeof (curr_session->device_nonce),
		curr_session->cerberus_nonce, sizeof (curr_session->cerberus_nonce),
		curr_session->session_key, sizeof (curr_session->session_key));
	if (status != 0) {
		goto free_shared_secret;
	}

	status = kdf_nist800_108_counter_mode (session_mgr->base.hash, HMAC_SHA256, shared_secret,
		shared_secret_len, curr_session->cerberus_nonce, sizeof (curr_session->cerberus_nonce),
		curr_session->device_nonce, sizeof (curr_session->device_nonce), curr_session->hmac_key,
		sizeof (curr_session->hmac_key));
	if (status != 0) {
		goto free_shared_secret;
	}

	status = hash_generate_hmac (session_mgr->base.hash, curr_session->hmac_key,
		sizeof (curr_session->hmac_key), keys->alias_cert, keys->alias_cert_length,
		curr_session->hmac_hash_type,
		cerberus_protocol_key_exchange_type_0_response_hmac_data (rsp),
		CERBERUS_PROTOCOL_KEY_EXCHANGE_TYPE_0_RESPONSE_MAX_HMAC_DATA (request));
	if (status != 0) {
		goto free_shared_secret;
	}

	cerberus_protocol_key_exchange_type_0_response_hmac_len (rsp) = hash_len;

	curr_session->session_state = SESSION_STATE_ESTABLISHED;

	request->length =
		cerberus_protocol_key_exchange_type_0_response_length (session_pub_key_der_len, sig_len,
			hash_len);
	request->crypto_timeout = true;

free_shared_secret:
	platform_free (shared_secret);

free_alias_key:
	session_mgr->ecc->release_key_pair (session_mgr->ecc, &alias_priv_key, NULL);

release_riot_keys:
	riot_key_manager_release_riot_keys (session_mgr->base.riot, keys);

free_session_pub_der:
	platform_free (session_pub_key_der);

free_session_keys:
	session_mgr->ecc->release_key_pair (session_mgr->ecc, &session_priv_key, &session_pub_key);

free_device_key:
	session_mgr->ecc->release_key_pair (session_mgr->ecc, NULL, &device_pub_key);

	return status;
}

/**
 * Initialize session manager instance
 *
 * @param session Session manager instance to initialize.
 * @param aes AES engine to utilize for packet encryption/decryption.
 * @param ecc ECC engine to utilize for AES key generation.
 * @param hash Hash engine to utilize for AES key generation.
 * @param rng RNG engine used to generate IV buffers.
 * @param riot RIoT key manager to utilize to get alias key for AES key generation.
 * @param sessions_table Preallocated table to use to store session manager entries. Set to NULL to
 * 	dynamically allocate from heap.
 * @param num_sessions Number of sessions to support.
 * @param pairing_eids List of supported devices for pairing mode.
 * @param num_pairing_eids Total number of supported devices for pairing mode.
 * @param store Keystore used to persist pairing keys.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int session_manager_ecc_init (struct session_manager_ecc *session, struct aes_engine *aes,
	struct ecc_engine *ecc, struct hash_engine *hash, struct rng_engine *rng,
	struct riot_key_manager *riot, struct session_manager_entry *sessions_table,
	size_t num_sessions, const uint8_t *pairing_eids, size_t num_pairing_eids,
	struct keystore *store)
{
	int status;

	if ((session == NULL) || (ecc == NULL)) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	status = session_manager_init (&session->base, aes, hash, rng, riot, sessions_table,
		num_sessions, pairing_eids, num_pairing_eids, store);
	if (status == 0) {
		session->base.add_session = session_manager_add_session;
		session->base.establish_session = session_manager_ecc_establish_session;
		session->base.is_session_established = session_manager_is_session_established;
		session->base.get_pairing_state = session_manager_get_pairing_state;
		session->base.decrypt_message = session_manager_decrypt_message;
		session->base.encrypt_message = session_manager_encrypt_message;
		session->base.reset_session = session_manager_reset_session;
		session->base.setup_paired_session = session_manager_setup_paired_session;
		session->base.session_sync = session_manager_session_sync;
		session->ecc = ecc;
	}

	return status;
}

/**
 * Release session manager
 *
 * @param session Session manager instance to release
 */
void session_manager_ecc_release (struct session_manager_ecc *session)
{
	session_manager_release (&session->base);
}
