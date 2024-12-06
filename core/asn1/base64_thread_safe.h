// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_THREAD_SAFE_H_
#define BASE64_THREAD_SAFE_H_

#include "platform_api.h"
#include "asn1/base64.h"


/**
 * Variable context for the Base64 wrapper.
 */
struct base64_engine_thread_safe_state {
	platform_mutex lock;	/**< Synchronization lock. */
};

/**
 * Thread-safe wrapper for a Base64 instance.
 */
struct base64_engine_thread_safe {
	struct base64_engine base;						/**< Base API implementation. */
	struct base64_engine_thread_safe_state *state;	/**< Variable context for the engine. */
	const struct base64_engine *engine;				/**< Base64 instance to use for execution. */
};


int base64_thread_safe_init (struct base64_engine_thread_safe *engine,
	struct base64_engine_thread_safe_state *state, const struct base64_engine *target);
int base64_thread_safe_init_state (const struct base64_engine_thread_safe *engine);
void base64_thread_safe_release (const struct base64_engine_thread_safe *engine);


#endif	/* BASE64_THREAD_SAFE_H_ */
