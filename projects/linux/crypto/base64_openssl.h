// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_OPENSSL_H_
#define BASE64_OPENSSL_H_

#include "crypto/base64.h"


/**
 * OpenSSL implementation for base64 encoding.
 */
struct base64_engine_openssl {
	struct base64_engine base;		/**< The base base64 engine. */
};


int base64_openssl_init (struct base64_engine_openssl *engine);
void base64_openssl_release (struct base64_engine_openssl *engine);


#endif /* BASE64_OPENSSL_H_ */
