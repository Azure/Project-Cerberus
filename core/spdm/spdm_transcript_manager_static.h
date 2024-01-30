// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_TRANSCRIPT_MANAGER_STATIC_H_
#define SPDM_TRANSCRIPT_MANAGER_STATIC_H_

#include "spdm_transcript_manager.h"


/* Internal function declarations to allow for static initialization. */
int spdm_transcript_manager_set_hash_algo (
	const struct spdm_transcript_manager *transcript_manager, enum hash_type hash_algo);

void spdm_transcript_manager_set_spdm_version (
	const struct spdm_transcript_manager *transcript_manager, uint8_t spdm_version);

int spdm_transcript_manager_update (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, const uint8_t *message,
	size_t message_size, bool use_session_context, uint8_t session_idx);

int spdm_transcript_manager_get_hash (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, bool use_session_context,
	uint8_t session_idx, uint8_t *hash, size_t hash_size);

void spdm_transcript_manager_reset_context (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, bool use_session_context,
	uint8_t session_idx);

void spdm_transcript_manager_reset (
	const struct spdm_transcript_manager *transcript_manager);

void spdm_transcript_manager_reset_session_transcript (
	const struct spdm_transcript_manager *transcript_manager, uint8_t session_idx);

/**
 * Constant initializer for the Transcript Manager API.
 */
#define	TRANSCRIPT_MANAGER_API_INIT \
	.set_hash_algo = spdm_transcript_manager_set_hash_algo, \
	.set_spdm_version = spdm_transcript_manager_set_spdm_version, \
	.update = spdm_transcript_manager_update, \
	.get_hash = spdm_transcript_manager_get_hash, \
	.reset_transcript = spdm_transcript_manager_reset_context, \
	.reset = spdm_transcript_manager_reset, \
	.reset_session_transcript = spdm_transcript_manager_reset_session_transcript

/**
 * SPDM Transcript Manager Static Initialization.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr				Transcript Manager state pointer.
 * @param hash_engine_ptr		Array of hash engine instances.
 * @param hash_engine_count_arg	Number of hash engine instances provided.
 */
#define	spdm_transcript_manager_static_init(state_ptr, hash_engine_ptr, hash_engine_count_arg)	{ \
		TRANSCRIPT_MANAGER_API_INIT, \
		.state = state_ptr, \
		.hash_engine = hash_engine_ptr, \
		.hash_engine_count = hash_engine_count_arg \
	}


#endif /* SPDM_TRANSCRIPT_MANAGER_STATIC_H_ */