// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_MBEDTLS_H_
#define BASE64_MBEDTLS_H_

#include "base64.h"


/**
 * mbedTLS implementation for base64 encoding.
 */
struct base64_engine_mbedtls {
	struct base64_engine base;		/**< The base base64 engine. */
};


int base64_mbedtls_init (struct base64_engine_mbedtls *engine);
void base64_mbedtls_release (struct base64_engine_mbedtls *engine);


#endif /* BASE64_MBEDTLS_H_ */
