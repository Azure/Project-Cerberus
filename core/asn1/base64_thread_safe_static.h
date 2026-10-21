// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_THREAD_SAFE_STATIC_H_
#define BASE64_THREAD_SAFE_STATIC_H_

#include "asn1/base64_thread_safe.h"


/* Internal functions declared to allow for static initialization. */
int base64_thread_safe_encode (const struct base64_engine *engine, const uint8_t *data,
	size_t length, uint8_t *encoded, size_t enc_length);


/**
 * Constant initializer for the Base64 API.
 */
#define	BASE64_THREAD_SAFE_API_INIT  { \
		.encode = base64_thread_safe_encode \
	}


/**
 * Initialize a static thread-safe wrapper for Base64 encoding.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the thread-safe engine.
 * @param target_ptr The target engine that will be used to execute operations.
 */
#define	base64_thread_safe_static_init(state_ptr, target_ptr)	{ \
		.base = BASE64_THREAD_SAFE_API_INIT, \
		.state = state_ptr, \
		.engine = target_ptr, \
	}


#endif	/* BASE64_THREAD_SAFE_STATIC_H_ */
