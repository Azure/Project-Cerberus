// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_RIOT_STATIC_H_
#define BASE64_RIOT_STATIC_H_

#include "riot/base64_riot.h"


/* Internal functions declared to allow for static initialization. */
int base64_riot_encode (struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length);


/**
 * Constant initializer for the Base64 API.
 */
#define	BASE64_RIOT_API_INIT  { \
		.encode = base64_riot_encode \
	}


/**
 * Initialize a static instance for base64 encoding using reference RIoT crypto.
 */
#define	base64_riot_static_init	{ \
		.base = BASE64_RIOT_API_INIT, \
	}


#endif /* BASE64_RIOT_STATIC_H_ */
