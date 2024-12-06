// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_THREAD_SAFE_H_
#define X509_THREAD_SAFE_H_

#include "platform_api.h"
#include "asn1/x509.h"


/**
 * Variable context for the thread-safe X.509 wrapper.
 */
struct x509_engine_thread_safe_state {
	platform_mutex lock;	/**< Synchronization lock. */
};

/**
 * Thread-safe wrapper for an X.509 instance.
 */
struct x509_engine_thread_safe {
	struct x509_engine base;						/**< Base API implementation. */
	struct x509_engine_thread_safe_state *state;	/**< Variable context for the X.509 engine. */
	const struct x509_engine *engine;				/**< X.509 instance to use for execution. */
};


int x509_thread_safe_init (struct x509_engine_thread_safe *engine,
	struct x509_engine_thread_safe_state *state, const struct x509_engine *target);
int x509_thread_safe_init_state (const struct x509_engine_thread_safe *engine);
void x509_thread_safe_release (const struct x509_engine_thread_safe *engine);


#endif	/* X509_THREAD_SAFE_H_ */
