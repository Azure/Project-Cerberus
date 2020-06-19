// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_THREAD_SAFE_H_
#define HASH_THREAD_SAFE_H_

#include "platform.h"
#include "crypto/hash.h"


/**
 * Thread-safe wrapper for a hash instance.
 */
struct hash_engine_thread_safe {
	struct hash_engine base;			/**< Base API implementation. */
	struct hash_engine *engine;			/**< Hash instance to use for execution. */
	platform_mutex lock;				/**< Synchronization lock. */
};


int hash_thread_safe_init (struct hash_engine_thread_safe *engine, struct hash_engine *target);
void hash_thread_safe_release (struct hash_engine_thread_safe *engine);


#endif /* HASH_THREAD_SAFE_H_ */
