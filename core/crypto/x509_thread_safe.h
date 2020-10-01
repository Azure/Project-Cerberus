// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_THREAD_SAFE_H_
#define X509_THREAD_SAFE_H_

#include "platform.h"
#include "crypto/x509.h"


/**
 * Thread-safe wrapper for an X.509 instance.
 */
struct x509_engine_thread_safe {
	struct x509_engine base;			/**< Base API implementation. */
	struct x509_engine *engine;			/**< X.509 instance to use for execution. */
	platform_mutex lock;				/**< Synchronization lock. */
};


int x509_thread_safe_init (struct x509_engine_thread_safe *engine, struct x509_engine *target);
void x509_thread_safe_release (struct x509_engine_thread_safe *engine);


#endif /* X509_THREAD_SAFE_H_ */
