// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_CORE_STATIC_H_
#define BASE64_CORE_STATIC_H_

#include "asn1/base64_core.h"


/* Internal functions declared to allow for static initialization. */
int base64_core_encode (const struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length);


/**
 * Constant initializer for the Base64 API.
 */
#define	BASE64_CORE_API_INIT  { \
		.encode = base64_core_encode \
	}


/**
 * Initialize a static instance for base64 encoding that doesn't require any external dependencies.
 */
#define	base64_core_static_init	{ \
		.base = BASE64_CORE_API_INIT, \
	}


#endif	/* BASE64_CORE_STATIC_H_ */
