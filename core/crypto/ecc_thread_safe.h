// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_THREAD_SAFE_H_
#define ECC_THREAD_SAFE_H_

#include "platform.h"
#include "crypto/ecc.h"


/**
 * Thread-safe wrapper for an ECC instance.
 */
struct ecc_engine_thread_safe {
	struct ecc_engine base;				/**< Base API implementation. */
	struct ecc_engine *engine;			/**< ECC instance to use for execution. */
	platform_mutex lock;				/**< Synchronization lock. */
};


int ecc_thread_safe_init (struct ecc_engine_thread_safe *engine, struct ecc_engine *target);
void ecc_thread_safe_release (struct ecc_engine_thread_safe *engine);


#endif /* ECC_THREAD_SAFE_H_ */
