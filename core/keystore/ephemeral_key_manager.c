// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_io.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "keystore/ephemeral_key_manager.h"
#include "keystore/keystore_logging.h"


/**
 * It will schedule/set the thread execution timeout for the next execution cycle
 *
 * @param key_manager The pointer of ephemeral_key_manager.
 */
static void ephemeral_key_manager_schedule_next_execute (
	const struct ephemeral_key_manager *key_manager)
{
	if (platform_init_timeout (key_manager->period_ms, &key_manager->state->next) == 0) {
		key_manager->state->next_valid = true;
	}
	else {
		key_manager->state->next_valid = false;
	}
}

void ephemeral_key_manager_prepare (const struct periodic_task_handler *handler)
{
	const struct ephemeral_key_manager *key_manager = TO_DERIVED_TYPE (handler,
		const struct ephemeral_key_manager, base);

	if (key_manager->key_cache->is_full (key_manager->key_cache) == false) {
		key_manager->state->next_valid = false;
	}
	else {
		ephemeral_key_manager_schedule_next_execute (key_manager);
	}
}

const platform_clock* ephemeral_key_manager_get_next_execution (
	const struct periodic_task_handler *handler)
{
	const struct ephemeral_key_manager *key_manager = TO_DERIVED_TYPE (handler,
		const struct ephemeral_key_manager, base);

	if (key_manager->state->next_valid) {
		return &key_manager->state->next;
	}
	else {
		/* Do not wait to call execute again. */
		return NULL;
	}
}

void ephemeral_key_manager_execute (const struct periodic_task_handler *handler)
{
	const struct ephemeral_key_manager *key_manager = TO_DERIVED_TYPE (handler,
		const struct ephemeral_key_manager, base);
	size_t key_length = 0;
	int status;

	if (key_manager->key_cache->is_full (key_manager->key_cache) == false) {
		/* The cache is not full, so generate a new key pair and add it to the cache. */
		status = key_manager->key_gen->generate_key (key_manager->key_gen, key_manager->key_size,
			key_manager->key, key_manager->key_buf_size, &key_length);
		if (status == 0) {
			status = key_manager->key_cache->add (key_manager->key_cache, key_manager->key,
				key_length);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
					KEYSTORE_LOGGING_ADD_KEY_FAIL, key_length, status);
			}
		}
		else {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
				KEYSTORE_LOGGING_KEY_GENERATION_FAIL, key_manager->key_size, status);
		}

		/* Schedule the next execution immediately since another key may need to be generated and
		 * stored. */
		key_manager->state->next_valid = false;
	}
	else {
		/* The cache is full.  Wait some time before executing again. */
		ephemeral_key_manager_schedule_next_execute (key_manager);
	}
}

/**
 * Initialize an instance of the ephemeral key manager object
 *
 * @param key_manager Key manager instance to initialize.
 * @param state Variable context for the key manager.  This must be uninitialized.
 * @param key_cache The key cache to use for storing and retrieving generated key pairs.
 * @param key_gen A generator for ephemeral key pairs.
 * @param period_ms The time between task execution cycles while the cache is full.  The task will
 * run without delay while the cache is not full.
 * @param key_size Length of the private key, in bits, that should be generated.
 * @param key A pointer to a buffer to use as temporary storage for the generated key pair.
 * @param key_buf_size Size of the key buffer.
 *
 * @return 0 if completed successfully or an error code.
 */
int ephemeral_key_manager_init (struct ephemeral_key_manager *key_manager,
	struct ephemeral_key_manager_state *state, const struct key_cache *key_cache,
	const struct ephemeral_key_generation *key_gen, uint32_t period_ms, size_t key_size,
	uint8_t *key, size_t key_buf_size)
{
	if ((key_manager == NULL) || (key_cache == NULL) || (key_gen == NULL) || (state == NULL) ||
		(key == NULL)) {
		return EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT;
	}

	memset (key_manager, 0, sizeof (*key_manager));

	key_manager->base.prepare = ephemeral_key_manager_prepare;
	key_manager->base.get_next_execution = ephemeral_key_manager_get_next_execution;
	key_manager->base.execute = ephemeral_key_manager_execute;

	key_manager->state = state;
	key_manager->key_cache = key_cache;
	key_manager->key_gen = key_gen;

	key_manager->period_ms = period_ms;
	key_manager->key_size = key_size;

	key_manager->key = key;
	key_manager->key_buf_size = key_buf_size;

	return ephemeral_key_manager_init_state (key_manager);
}

/**
 * Initialize the state information for the ephemeral key manager.
 *
 * @param key_manager The key manager containing the state to initialize.
 *
 * @return 0 if the ephemeral key manager was successfully initialized or an error code.
 */
int ephemeral_key_manager_init_state (const struct ephemeral_key_manager *key_manager)
{
	if ((key_manager == NULL) || (key_manager->state == NULL) || (key_manager->key_cache == NULL) ||
		(key_manager->key_gen == NULL)) {
		return EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT;
	}

	memset (key_manager->state, 0, sizeof (struct ephemeral_key_manager_state));

	return 0;
}

/**
 * Release a key manager instance.
 *
 * @param key_manager The key manager to release.
 */
void ephemeral_key_manager_release (const struct ephemeral_key_manager *key_manager)
{
	UNUSED (key_manager);
}

/**
 * Retrieve a pre-generated ephemeral key from the cache for the specified requestor ID.
 *
 * @param key_manager The ephemeral key manager to query.
 * @param requestor_id The ID of the requestor for the key.
 * @param key Output for the key data.
 * @param key_buf_size Length of the output key buffer.
 * @param length Output for the length of the key data.
 *
 * @return 0 if the key was successfully retrieved or an error code.
 */
int ephemeral_key_manager_get_key (const struct ephemeral_key_manager *key_manager,
	uint32_t requestor_id, uint8_t *key, size_t key_buf_size, size_t *length)
{
	int status;

	if ((key_manager == NULL) || (key == NULL) || (length == NULL)) {
		return EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT;
	}

	status = key_manager->key_cache->remove (key_manager->key_cache, requestor_id, key,
		key_buf_size, length);

	return status;
}
