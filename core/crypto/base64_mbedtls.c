// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "base64_mbedtls.h"
#include "mbedtls/base64.h"


static int base64_mbedtls_encode (struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length)
{
	int status;

	if ((engine == NULL) || (data == NULL) || (encoded == NULL)) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	status = mbedtls_base64_encode (encoded, enc_length, &enc_length, data, length);
	if (status == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
		return BASE64_ENGINE_ENC_BUFFER_TOO_SMALL;
	}

	return status;
}

/**
 * Initialize an instance for base64 encoding using mbedTLS.
 *
 * @param engine The base64 engine to initialize.
 *
 * @return 0 if the engine was initialized successfully for an error code.
 */
int base64_mbedtls_init (struct base64_engine_mbedtls *engine)
{
	if (engine == NULL) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct base64_engine_mbedtls));

	engine->base.encode = base64_mbedtls_encode;

	return 0;
}

/**
 * Release the resources used by an mbedTLS base64 engine.
 *
 * @param engine The base64 engine to release.
 */
void base64_mbedtls_release (struct base64_engine_mbedtls *engine)
{

}
