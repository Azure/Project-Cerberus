// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "spdm_commands.h"
#include "spdm_protocol.h"
#include "spdm_transcript_manager.h"
#include "common/array_size.h"
#include "common/common_math.h"
#include "common/unused.h"


/**
 * Add a message to the hash context. A new hash will be started with the message data using
 * the negotiated hash algorithm if there is no active hash for the context.
 *
 * There is no validation on the parameters since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param hash_context			Hash context to add the message to.
 * @param message				Message to add to the hash context.
 * @param message_size			Size of message.
 * @param add_vca				Flag indicating if the VCA buffer should be added to the hash.
 *
 * @return 0 if the message was added to the hash successfully or an error code.
 */
static int spdm_transcript_manager_add_msg (
	const struct spdm_transcript_manager *transcript_manager,
	struct spdm_transcript_manager_hash_context *hash_context, const void *message,
	size_t message_size, bool add_vca)
{
	int status;
	struct hash_engine *hash_engine;

	hash_engine = transcript_manager->hash_engine[hash_context->hash_engine_idx];

	/* Start the hash if it has not been started. */
	if (hash_context->hash_started == false) {
		status = hash_start_new_hash (hash_engine, transcript_manager->state->hash_algo);
		if (status != 0) {
			goto exit;
		}
		hash_context->hash_started = true;

		/* Add the VCA buffer to the hash context if requested by the caller
		 * and only if the hash was just started.
		 */
		if (add_vca == true) {
			status = hash_engine->update (hash_engine,
				transcript_manager->state->message_vca.buffer,
				transcript_manager->state->message_vca.buffer_size);
			if (status != 0) {
				goto exit;
			}
		}
	}

	/* Update the hash context with the message. */
	status = hash_engine->update (hash_engine, message, message_size);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Update VCA cache.
 *
 * There is no validation on the parameters since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param message_size			Size of message to append to message VCA cache.
 * @param message				Message to append to message A cache.
 *
 * @return 0 if the message was appended to the cache successfully or an error code.
 */
static int spdm_transcript_manager_update_vca (
	const struct spdm_transcript_manager *transcript_manager, const uint8_t *message,
	size_t message_size)
{
	int status = 0;
	struct spdm_transcript_manager_vca_managed_buffer *message_vca;

	message_vca = &transcript_manager->state->message_vca;
	if (message_size > (ARRAY_SIZE (message_vca->buffer) - message_vca->buffer_size)) {
		status = SPDM_TRANSCRIPT_MANAGER_BUFFER_FULL;
		goto exit;
	}

	memcpy (message_vca->buffer + message_vca->buffer_size, message, message_size);
	message_vca->buffer_size += message_size;

exit:

	return status;
}

/**
 * Update the M1M2 Hash.
 *
 * There is no validation on the parameter since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param message				Message to add to the hash.
 * @param message_size			Size of message.
 *
 * @return 0 if the message was added to the hash successfully or an error code.
 */
static int spdm_transcript_manager_update_m1m2 (
	const struct spdm_transcript_manager *transcript_manager, const uint8_t *message,
	size_t message_size)
{
	int status = 0;
	struct spdm_transcript_manager_state *state = transcript_manager->state;
	struct spdm_transcript_manager_hash_context *hash_context = &state->m1m2;

	/* Add the message to the hash context. */
	status = spdm_transcript_manager_add_msg (transcript_manager, hash_context, message,
		message_size, true);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Update the L1L2 Hash.
 *
 * There is no validation on the parameter since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param message				Message to add to the hash.
 * @param message_size			Size of message.
 *
 * @return 0 if the message was added to the hash successfully or an error code.
 */
static int spdm_transcript_manager_update_l1l2 (
	const struct spdm_transcript_manager *transcript_manager, const uint8_t *message,
	size_t message_size, bool use_session_context, uint32_t session_idx)
{
	int status = 0;
	struct spdm_transcript_manager_state *state = transcript_manager->state;
	struct spdm_transcript_manager_hash_context *hash_context;

	if (use_session_context == true) {
		hash_context = &state->session_transcript[session_idx].l1l2;
	}
	else {
		hash_context = &state->l1l2;
	}

	/* Add the message to the hash context. */
	status = spdm_transcript_manager_add_msg (transcript_manager, hash_context, message,
		message_size, (state->spdm_version > SPDM_VERSION_1_1));
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Update the TH Hash.
 *
 * There is no validation on the parameters since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param message				Message to add to the hash.
 * @param message_size			Size of message.
 * @param session_idx			Index of the session transcript context to update the hash for.
 *
 * @return 0 if the message was added to the hash successfully or an error code.
 */
static int spdm_transcript_manager_update_th (
	const struct spdm_transcript_manager *transcript_manager, const uint8_t *message,
	size_t message_size, uint32_t session_idx)
{
	int status = 0;
	struct spdm_transcript_manager_state *state = transcript_manager->state;
	struct spdm_transcript_manager_hash_context *hash_context;

	hash_context = &state->session_transcript[session_idx].th;

	/* Add the message to the hash context. */
	status = spdm_transcript_manager_add_msg (transcript_manager, hash_context, message,
		message_size, true);
	if (status != 0) {
		goto exit;
	}

exit:

	return status;
}

/**
 * Clear the VCA message buffer.
 *
 * There is no validation on the parameter since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 */
static void spdm_transcript_manager_reset_vca (
	const struct spdm_transcript_manager *transcript_manager)
{
	struct spdm_transcript_manager_vca_managed_buffer *managed_buffer =
		&transcript_manager->state->message_vca;

	if (managed_buffer->buffer_size != 0) {
		memset (managed_buffer->buffer, 0, managed_buffer->buffer_size);
		managed_buffer->buffer_size = 0;
	}
}

/**
 * Reset the M1M2 hash engine context.
 *
 * There is no validation on the parameter since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 */
static void spdm_transcript_manager_reset_m1m2 (
	const struct spdm_transcript_manager *transcript_manager)
{
	struct hash_engine *m1m2;
	struct spdm_transcript_manager_state *state = transcript_manager->state;

	if (state->m1m2.hash_started == true) {
		m1m2 = transcript_manager->hash_engine[state->m1m2.hash_engine_idx];
		m1m2->cancel (m1m2);
		state->m1m2.hash_started = false;
	}
}

/**
 * Reset the L1L2 global or session hash engine context.
 *
 * There is no validation on the parameter since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param use_session_context	Flag indicating if the session context should be used.
 * @param session_idx			Index of the session transcript context to reset the hash for.
 */
static void spdm_transcript_manager_reset_l1l2 (
	const struct spdm_transcript_manager *transcript_manager, bool use_session_context,
	uint8_t session_idx)
{
	struct hash_engine *l1l2;
	struct spdm_transcript_manager_hash_context *hash_context;
	struct spdm_transcript_manager_state *state = transcript_manager->state;

	hash_context = (use_session_context == true) ?
			&state->session_transcript[session_idx].l1l2 : &state->l1l2;

	if (hash_context->hash_started == true) {
		l1l2 = transcript_manager->hash_engine[hash_context->hash_engine_idx];
		l1l2->cancel (l1l2);
		hash_context->hash_started = false;
	}
}

/**
 * Reset the TH hash engine context.
 *
 * There is no validation on the parameters since this is an internal function.
 *
 * @param transcript_manager	Transcript manager instance.
 * @param session_idx			Index of the session transcript context to reset the hash for.
 */
static void spdm_transcript_manager_reset_th (
	const struct spdm_transcript_manager *transcript_manager, uint8_t session_idx)
{
	struct hash_engine *th;
	struct spdm_transcript_manager_hash_context *hash_context;
	struct spdm_transcript_manager_state *state = transcript_manager->state;

	hash_context = &state->session_transcript[session_idx].th;
	if (hash_context->hash_started == true) {
		th = transcript_manager->hash_engine[hash_context->hash_engine_idx];
		th->cancel (th);
		hash_context->hash_started = false;
	}
}

void spdm_transcript_manager_reset_session_transcript (
	const struct spdm_transcript_manager *transcript_manager, uint8_t session_idx)
{
	struct spdm_transcript_manager_state *state;

	if (transcript_manager == NULL) {
		return;
	}
	state = transcript_manager->state;

	if (session_idx >= state->session_transcript_count) {
		return;
	}

	spdm_transcript_manager_reset_l1l2 (transcript_manager, true, session_idx);

	spdm_transcript_manager_reset_th (transcript_manager, session_idx);
}

void spdm_transcript_manager_reset_context (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, bool use_session_context,
	uint8_t session_idx)
{
	struct spdm_transcript_manager_state *state;

	if (transcript_manager != NULL) {
		state = transcript_manager->state;

		/* M1/M2 hash is only valid for the global SPDM requester/responder. */
		/* TH hash is only valid for an SPDM session. */
		if (((use_session_context == true) && (context_type == TRANSCRIPT_CONTEXT_TYPE_M1M2)) ||
			((use_session_context == false) && (context_type == TRANSCRIPT_CONTEXT_TYPE_TH))) {
			return;
		}

		if ((use_session_context == true) && (session_idx >= state->session_transcript_count)) {
			return;
		}

		switch (context_type) {
			case TRANSCRIPT_CONTEXT_TYPE_VCA:
				spdm_transcript_manager_reset_vca (transcript_manager);
				break;

			case TRANSCRIPT_CONTEXT_TYPE_M1M2:
				spdm_transcript_manager_reset_m1m2 (transcript_manager);
				break;

			case TRANSCRIPT_CONTEXT_TYPE_L1L2:
			case TRANSCRIPT_CONTEXT_TYPE_TH:
				if (context_type == TRANSCRIPT_CONTEXT_TYPE_L1L2) {
					spdm_transcript_manager_reset_l1l2 (transcript_manager,	use_session_context,
						session_idx);
				}
				else {
					spdm_transcript_manager_reset_th (transcript_manager, session_idx);
				}

				break;

			default:
				break;
		}
	}

	return;
}

void spdm_transcript_manager_reset (const struct spdm_transcript_manager *transcript_manager)
{
	uint8_t session_idx;
	struct spdm_transcript_manager_state *state;

	if (transcript_manager != NULL) {
		state = transcript_manager->state;

		state->hash_algo = HASH_TYPE_INVALID;

		/* Reset global transcripts. */
		spdm_transcript_manager_reset_vca (transcript_manager);
		spdm_transcript_manager_reset_m1m2 (transcript_manager);
		spdm_transcript_manager_reset_l1l2 (transcript_manager, false, SPDM_MAX_SESSION_COUNT);

		/* Reset session transcript(s). */
		for (session_idx = 0; session_idx < state->session_transcript_count; session_idx++) {
			spdm_transcript_manager_reset_session_transcript (transcript_manager, session_idx);
		}
	}
}

int spdm_transcript_manager_set_hash_algo (
	const struct spdm_transcript_manager *transcript_manager, enum hash_type hash_algo)
{
	int status = 0;

	if ((transcript_manager == NULL) || (hash_algo >= HASH_TYPE_INVALID)) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	if (transcript_manager->state->hash_algo != HASH_TYPE_INVALID) {
		status = SPDM_TRANSCRIPT_MANAGER_HASH_ALGO_ALREADY_SET;
		goto exit;
	}

	transcript_manager->state->hash_algo = hash_algo;

exit:

	return status;
}

void spdm_transcript_manager_set_spdm_version (
	const struct spdm_transcript_manager *transcript_manager, uint8_t spdm_version)
{
	if (transcript_manager != NULL) {
		transcript_manager->state->spdm_version = spdm_version;
	}
}

int spdm_transcript_manager_update (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, const uint8_t *message,
	size_t message_size, bool use_session_context, uint8_t session_idx)
{
	int status;

	if ((transcript_manager == NULL) || (message == NULL) || (message_size == 0)) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	switch (context_type) {
		case TRANSCRIPT_CONTEXT_TYPE_VCA:
			status = spdm_transcript_manager_update_vca (transcript_manager, message, message_size);
			break;

		case TRANSCRIPT_CONTEXT_TYPE_M1M2:
			status = spdm_transcript_manager_update_m1m2 (transcript_manager, message,
				message_size);
			break;

		case TRANSCRIPT_CONTEXT_TYPE_L1L2:
		case TRANSCRIPT_CONTEXT_TYPE_TH:
			if ((use_session_context == true) &&
				(session_idx >= SPDM_MAX_SESSION_COUNT)) {
				status = SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX;
				goto exit;
			}

			if (context_type == TRANSCRIPT_CONTEXT_TYPE_L1L2) {
				status = spdm_transcript_manager_update_l1l2 (transcript_manager, message,
					message_size, use_session_context, session_idx);
			}
			else {
				status = spdm_transcript_manager_update_th (transcript_manager, message,
					message_size, session_idx);
			}

			break;

		default:
			status = SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE;
			break;
	}

exit:

	return status;
}

int spdm_transcript_manager_get_hash (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, bool finish_hash,
	bool use_session_context, uint8_t session_idx, uint8_t *hash, size_t hash_size)
{
	int status;
	struct spdm_transcript_manager_state *state;
	struct spdm_transcript_manager_hash_context *hash_context;
	struct hash_engine *hash_engine;

	if ((transcript_manager == NULL) || (hash == NULL) || (hash_size == 0)) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	/* M1/M2 hash is only valid for the global SPDM requester/responder. */
	/* TH hash is only valid for an SPDM session. */
	if (((use_session_context == true) && (context_type == TRANSCRIPT_CONTEXT_TYPE_M1M2)) ||
		((use_session_context == false) && (context_type == TRANSCRIPT_CONTEXT_TYPE_TH))) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}
	state = transcript_manager->state;

	if ((use_session_context == true) && (session_idx >= state->session_transcript_count)) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX;
		goto exit;
	}

	switch (context_type) {
		case TRANSCRIPT_CONTEXT_TYPE_M1M2:
			hash_context = &state->m1m2;
			break;

		case TRANSCRIPT_CONTEXT_TYPE_L1L2:
		case TRANSCRIPT_CONTEXT_TYPE_TH:

			if (context_type == TRANSCRIPT_CONTEXT_TYPE_L1L2) {
				hash_context = (use_session_context == true) ?
						&state->session_transcript[session_idx].l1l2 : &state->l1l2;
			}
			else {
				hash_context = &state->session_transcript[session_idx].th;
			}

			break;

		default:
			status = SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE;
			goto exit;
	}

	if (hash_context->hash_started == false) {
		status = SPDM_TRANSCRIPT_MANAGER_HASH_NOT_STARTED;
		goto exit;
	}

	hash_engine = transcript_manager->hash_engine[hash_context->hash_engine_idx];
	status = finish_hash ?
			hash_engine->finish (hash_engine, hash, hash_size) :
			hash_engine->get_hash (hash_engine, hash, hash_size);
	if (status != 0) {
		goto exit;
	}
	hash_context->hash_started = !finish_hash;

exit:

	return status;
}

/**
 * Initialize a Transcript manager for transcript hashing.
 *
 * @param transcript_manager	Transcript manager to initialize.
 * @param hash_engine			Array of hash engine instances.
 * @param hash_engine_count		Number of hash engine instances provided.
 *
 * @return 0 if a transcipt manager was instantiated successfully or an error code.
 */
int spdm_transcript_manager_init (struct spdm_transcript_manager *transcript_manager,
	struct spdm_transcript_manager_state *state, struct hash_engine **hash_engine,
	uint8_t hash_engine_count)
{
	int status = 0;

	if ((transcript_manager == NULL) || (state == NULL)) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (transcript_manager, 0, sizeof (struct spdm_transcript_manager));

	/* Save the reference to the hash engine array. Validation of the hash engine array is done in
	 * the spdm_transcript_manager_init_state function.
	 */
	transcript_manager->hash_engine = hash_engine;
	transcript_manager->hash_engine_count = hash_engine_count;

	/* Save the state. */
	transcript_manager->state = state;

	/* Set the functions pointers. */
	transcript_manager->set_hash_algo = spdm_transcript_manager_set_hash_algo;
	transcript_manager->set_spdm_version = spdm_transcript_manager_set_spdm_version;
	transcript_manager->update = spdm_transcript_manager_update;
	transcript_manager->get_hash = spdm_transcript_manager_get_hash;
	transcript_manager->reset_transcript = spdm_transcript_manager_reset_context;
	transcript_manager->reset = spdm_transcript_manager_reset;
	transcript_manager->reset_session_transcript = spdm_transcript_manager_reset_session_transcript;

	/* Initialize the state. */
	status = spdm_transcript_manager_init_state (transcript_manager);

exit:

	return status;
}

/**
 * Initialize the Transcript manager state.
 *
 * @param transcript_manager	Transcript manager whose state is to be initialized.
 *
 * @return 0 if a transcipt manager state was initialize successfully or an error code.
 */
int spdm_transcript_manager_init_state (const struct spdm_transcript_manager *transcript_manager)
{
	int status = 0;
	int max_session_count;
	struct spdm_transcript_manager_session_context *session_transcript;
	uint8_t hash_engine_idx;
	uint8_t session_idx;
	struct spdm_transcript_manager_state *state;

	if ((transcript_manager == NULL) || (transcript_manager->state == NULL) ||
		(transcript_manager->hash_engine_count <
		SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT)	||
		(transcript_manager->hash_engine == NULL)) {
		status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
		goto exit;
	}

	/* Check if the hash engine instances are valid. */
	for (hash_engine_idx = 0; hash_engine_idx < transcript_manager->hash_engine_count;
		hash_engine_idx++) {
		if (transcript_manager->hash_engine[hash_engine_idx] == NULL) {
			status = SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT;
			goto exit;
		}
	}

	state = transcript_manager->state;
	memset (state, 0, sizeof (struct spdm_transcript_manager_state));

	state->hash_algo = HASH_TYPE_INVALID;

	/* Process hash engines for global SPDM. */
	state->m1m2.hash_engine_idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;
	state->l1l2.hash_engine_idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	/* Process hash engines for SPDM session(s). */
	session_transcript = state->session_transcript;
	max_session_count = (transcript_manager->hash_engine_count -
		SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT) /
		SPDM_TRANSCRIPT_MANAGER_SESSION_HASH_ENGINE_REQUIRED_COUNT;
	state->session_transcript_count =
		min (max_session_count, SPDM_MAX_SESSION_COUNT);

	/* Assig indices from the hash_engine array to session transcript hashes. */
	for (session_idx = 0, hash_engine_idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT;
		session_idx < state->session_transcript_count; session_idx++) {
		session_transcript[session_idx].l1l2.hash_engine_idx = hash_engine_idx++;
		session_transcript[session_idx].th.hash_engine_idx = hash_engine_idx++;
	}

exit:

	return status;
}

/**
 * Deinitialize the transcript manager.
 *
 * @param transcript_manager	Transcript manager to deinitialize.
 */
void spdm_transcript_manager_release (const struct spdm_transcript_manager *transcript_manager)
{
	if (transcript_manager != NULL) {
		spdm_transcript_manager_reset (transcript_manager);
	}
}
