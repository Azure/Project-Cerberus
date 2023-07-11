// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include "base64_openssl.h"


static int base64_openssl_encode (struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length)
{
	if ((engine == NULL) || (data == NULL) || (encoded == NULL)) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	if (enc_length < BASE64_LENGTH (length)) {
		return BASE64_ENGINE_ENC_BUFFER_TOO_SMALL;
	}

	EVP_EncodeBlock (encoded, data, length);

	return 0;
}

/**
 * Initialize an instance for base64 encoding using OpenSSL.
 *
 * @param engine The base64 engine to initialize.
 *
 * @return 0 if the engine was initialize successfully or an error code.
 */
int base64_openssl_init (struct base64_engine_openssl *engine)
{
	if (engine == NULL) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct base64_engine_openssl));

	engine->base.encode = base64_openssl_encode;

	return 0;
}

/**
 * Release the resources used by an OpenSSL base64 engine.
 *
 * @param engine The base64 engine to release.
 */
void base64_openssl_release (struct base64_engine_openssl *engine)
{

}
