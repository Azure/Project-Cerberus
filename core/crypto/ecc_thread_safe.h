// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_THREAD_SAFE_H_
#define ECC_THREAD_SAFE_H_

#include "platform_api.h"
#include "crypto/ecc.h"


/**
 * Variable context for the thread-safe ECC instance.
 */
struct ecc_engine_thread_safe_state {
	platform_mutex lock;	/**< Synchronization lock. */
};

/**
 * Thread-safe wrapper for an ECC instance.
 */
struct ecc_engine_thread_safe {
	struct ecc_engine base;						/**< Base API implementation. */
	struct ecc_engine_thread_safe_state *state;	/**< Variable context for the instance. */
	const struct ecc_engine *engine;			/**< ECC instance to use for execution. */
};


int ecc_thread_safe_init (struct ecc_engine_thread_safe *engine,
	struct ecc_engine_thread_safe_state *state, const struct ecc_engine *target);
int ecc_thread_safe_init_state (const struct ecc_engine_thread_safe *engine);
void ecc_thread_safe_release (const struct ecc_engine_thread_safe *engine);


#endif	/* ECC_THREAD_SAFE_H_ */
