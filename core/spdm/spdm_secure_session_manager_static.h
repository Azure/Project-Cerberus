// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_SECURE_SESSION_MANAGER_STATIC_H_
#define SPDM_SECURE_SESSION_MANAGER_STATIC_H_


#include "spdm_secure_session_manager.h"


/* Internal function declarations to allow for static initialization. */
struct spdm_secure_session* spdm_secure_session_manager_create_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
	bool is_requester, const struct spdm_connection_info *connection_info);


void spdm_secure_session_manager_release_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id);

void spdm_secure_session_manager_set_session_state (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
	enum spdm_secure_session_state session_state);

void spdm_secure_session_manager_reset (const struct spdm_secure_session_manager *session_manager);

struct spdm_secure_session* spdm_secure_session_manager_get_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id);


int spdm_secure_session_manager_generate_shared_secret (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session,
	const struct ecc_point_public_key *peer_pub_key_point, uint8_t *local_pub_key_point);

int spdm_secure_session_manager_generate_session_handshake_keys (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session);

int spdm_secure_session_manager_generate_session_data_keys (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session);

bool spdm_secure_session_manager_is_last_session_id_valid (
	const struct spdm_secure_session_manager *session_manager);

uint32_t spdm_secure_session_manager_get_last_session_id (
	const struct spdm_secure_session_manager *session_manager);

void spdm_secure_session_manager_reset_last_session_id_validity (
	const struct spdm_secure_session_manager *session_manager);

int spdm_secure_session_manager_decode_secure_message (
	const struct spdm_secure_session_manager *session_manager, struct cmd_interface_msg *request);

int spdm_secure_session_manager_encode_secure_message (
	const struct spdm_secure_session_manager *session_manager, struct cmd_interface_msg *request);

int spdm_secure_session_manager_is_termination_policy_set (
	const struct spdm_secure_session_manager *session_manager);

void spdm_secure_session_manager_unlock_session (
	const struct spdm_secure_session_manager *session_manager, struct spdm_secure_session *session);


/**
 * Constant initializer for the Secure Session Manager API.
 */
#define	SECURE_SESSION_MANAGER_API_INIT \
	.create_session = spdm_secure_session_manager_create_session, \
	.release_session = spdm_secure_session_manager_release_session, \
	.get_session = spdm_secure_session_manager_get_session, \
	.unlock_session = spdm_secure_session_manager_unlock_session, \
	.set_session_state = spdm_secure_session_manager_set_session_state, \
	.reset = spdm_secure_session_manager_reset, \
	.generate_shared_secret = spdm_secure_session_manager_generate_shared_secret, \
	.generate_session_handshake_keys = spdm_secure_session_manager_generate_session_handshake_keys, \
	.generate_session_data_keys = spdm_secure_session_manager_generate_session_data_keys, \
	.is_last_session_id_valid = spdm_secure_session_manager_is_last_session_id_valid, \
	.get_last_session_id = spdm_secure_session_manager_get_last_session_id, \
	.reset_last_session_id_validity = spdm_secure_session_manager_reset_last_session_id_validity, \
	.decode_secure_message = spdm_secure_session_manager_decode_secure_message, \
	.encode_secure_message = spdm_secure_session_manager_encode_secure_message, \
	.is_termination_policy_set = spdm_secure_session_manager_is_termination_policy_set \

/**
 * SPDM Secure Session Manager Static Initialization.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Pointer to the state.
 * @param local_cap_ptr Pointer to the local capabilities.
 * @param local_algo_ptr Pointer to the local algorithms.
 * @param aes_engine_ptr Pointer to the AES engine.
 * @param hash_engine_ptr Pointer to the hash engine.
 * @param rng_engine_ptr Pointer to the RNG engine.
 * @param ecc_engine_ptr Pointer to the ECC engine.
 * @param transcript_manager_ptr Pointer to the transcript manager.
 * @param hkdf_ptr Pointer to HKDF implementation
 * @param error_ptr Error state management interface
 * @param algo_info Metadata of provided algorithms
 * @param spdm_context_ptr Pointer to the persistent context for managing persistent SPDM state.
 */
#define	spdm_secure_session_manager_static_init(state_ptr, local_cap_ptr, local_algo_ptr, aes_engine_ptr, \
	hash_engine_ptr, rng_engine_ptr, ecc_engine_ptr, transcript_manager_ptr, hkdf_ptr, \
	error_ptr, algo_info_arg, spdm_context_ptr)	{ \
		SECURE_SESSION_MANAGER_API_INIT, \
		.state = state_ptr, \
		.local_capabilities = local_cap_ptr, \
		.local_algorithms = local_algo_ptr, \
		.aes_engine = aes_engine_ptr, \
		.hash_engine = hash_engine_ptr, \
		.rng_engine = rng_engine_ptr, \
		.ecc_engine = ecc_engine_ptr, \
		.transcript_manager = transcript_manager_ptr, \
		.max_spdm_session_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER, \
		.hkdf = hkdf_ptr, \
		.error = error_ptr, \
		.algo_info = algo_info_arg, \
		.spdm_context = spdm_context_ptr, \
	}


#endif	/* SPDM_SECURE_SESSION_MANAGER_STATIC_H_ */
