// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EPHEMERAL_KEY_MANAGER_STATIC_H_
#define EPHEMERAL_KEY_MANAGER_STATIC_H_

#include <stdbool.h>
#include <stdint.h>
#include "keystore/ephemeral_key_manager.h"


/* Internal functions declared to allow for static initialization. */
void ephemeral_key_manager_prepare (const struct periodic_task_handler *handler);
const platform_clock* ephemeral_key_manager_get_next_execution (
	const struct periodic_task_handler *handler);
void ephemeral_key_manager_execute (const struct periodic_task_handler *handler);

/**
 * Constant initializer for the ephemeral Key manager handler API.
 */
#define	EPHEMERAL_KEY_MANAGER_HANDLER_API_INIT { \
		.prepare = ephemeral_key_manager_prepare, \
		.get_next_execution = ephemeral_key_manager_get_next_execution, \
		.execute = ephemeral_key_manager_execute \
	}

/**
 * Initialize a static instance of a manager for generating a cache of ephemeral keys.
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the key manager.  This must be uninitialized.
 * @param key_cache_ptr The key cache to use for storing and retrieving generated key pairs.
 * @param key_gen_ptr A generator for ephemeral key pairs.
 * @param period_ms_val The time between task execution cycles while the cache is full.  The task
 * will run without delay while the cache is not full.
 * @param key_size_val Length of the private key, in bits, that should be generated.
 * @param key_ptr A pointer to a buffer to use as temporary storage for the generated key pair.
 * @param key_buf_size_val Size of the key buffer.
 */
#define	ephemeral_key_manager_static_init(state_ptr, key_cache_ptr, key_gen_ptr, period_ms_val, \
	key_size_val, key_ptr, key_buf_size_val) { \
		.base = EPHEMERAL_KEY_MANAGER_HANDLER_API_INIT, \
		.state = state_ptr, \
		.key_gen = key_gen_ptr, \
		.key_cache = key_cache_ptr, \
		.period_ms = period_ms_val, \
		.key_size = key_size_val, \
		.key = key_ptr, \
		.key_buf_size = key_buf_size_val \
	}


#endif	/* EPHEMERAL_KEY_MANAGER_STATIC_H_ */
