// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_THREAD_SAFE_H_
#define HASH_THREAD_SAFE_H_

#include "platform_api.h"
#include "crypto/hash.h"


/**
 * Variable context for a thread-safe hash wrapper.
 */
struct hash_engine_thread_safe_state {
	platform_mutex lock;	/**< Synchronization lock. */
};

/**
 * Thread-safe wrapper for a hash instance.
 */
struct hash_engine_thread_safe {
	struct hash_engine base;						/**< Base API implementation. */
	struct hash_engine_thread_safe_state *state;	/**< Variable context for the hash engine. */
	const struct hash_engine *engine;				/**< Hash instance to use for execution. */
};


int hash_thread_safe_init (struct hash_engine_thread_safe *engine,
	struct hash_engine_thread_safe_state *state, const struct hash_engine *target);
int hash_thread_safe_init_state (const struct hash_engine_thread_safe *engine);
void hash_thread_safe_release (const struct hash_engine_thread_safe *engine);


#endif	/* HASH_THREAD_SAFE_H_ */
