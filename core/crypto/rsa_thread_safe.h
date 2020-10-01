// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_THREAD_SAFE_H_
#define RSA_THREAD_SAFE_H_

#include "platform.h"
#include "crypto/rsa.h"


/**
 * Thread-safe wrapper for an RSA instance.
 */
struct rsa_engine_thread_safe {
	struct rsa_engine base;				/**< Base API implementation. */
	struct rsa_engine *engine;			/**< RSA instance to use for execution. */
	platform_mutex lock;				/**< Synchronization lock. */
};


int rsa_thread_safe_init (struct rsa_engine_thread_safe *engine, struct rsa_engine *target);
void rsa_thread_safe_release (struct rsa_engine_thread_safe *engine);


#endif /* RSA_THREAD_SAFE_H_ */
