// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_THREAD_SAFE_H_
#define RSA_THREAD_SAFE_H_

#include "platform_api.h"
#include "crypto/rsa.h"


/**
 * Variable context for the thread-safe RSA wrapper.
 */
struct rsa_engine_thread_safe_state {
	platform_mutex lock;	/**< Synchronization lock. */
};

/**
 * Thread-safe wrapper for an RSA instance.
 */
struct rsa_engine_thread_safe {
	struct rsa_engine base;						/**< Base API implementation. */
	struct rsa_engine_thread_safe_state *state;	/**< Variable context for the RSA wrapper */
	const struct rsa_engine *engine;			/**< RSA instance to use for execution. */
};


int rsa_thread_safe_init (struct rsa_engine_thread_safe *engine,
	struct rsa_engine_thread_safe_state *state, const struct rsa_engine *target);
int rsa_thread_safe_init_state (const struct rsa_engine_thread_safe *engine);
void rsa_thread_safe_release (const struct rsa_engine_thread_safe *engine);


#endif	/* RSA_THREAD_SAFE_H_ */
