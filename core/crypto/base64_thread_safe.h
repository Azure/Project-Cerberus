// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_THREAD_SAFE_H_
#define BASE64_THREAD_SAFE_H_

#include "platform.h"
#include "crypto/base64.h"


/**
 * Thread-safe wrapper for a Base64 instance.
 */
struct base64_engine_thread_safe {
	struct base64_engine base;			/**< Base API implementation. */
	struct base64_engine *engine;		/**< Base64 instance to use for execution. */
	platform_mutex lock;				/**< Synchronization lock. */
};


int base64_thread_safe_init (struct base64_engine_thread_safe *engine,
	struct base64_engine *target);
void base64_thread_safe_release (struct base64_engine_thread_safe *engine);


#endif /* BASE64_THREAD_SAFE_H_ */
