// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_OPENSSL_STATIC_H_
#define BASE64_OPENSSL_STATIC_H_

#include "asn1/base64_openssl.h"


/* Internal functions declared to allow for static initialization. */
int base64_openssl_encode (const struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length);


/**
 * Constant initializer for the Base64 API.
 */
#define	BASE64_OPENSSL_API_INIT  { \
		.encode = base64_openssl_encode \
	}


/**
 * Initialize a static instance for base64 encoding using OpenSSL.
 */
#define	base64_openssl_static_init	{ \
		.base = BASE64_OPENSSL_API_INIT, \
	}


#endif	/* BASE64_OPENSSL_STATIC_H_ */
