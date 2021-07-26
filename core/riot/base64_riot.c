// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "base64_riot.h"
#include "reference/include/RiotBase64.h"


/**
 * Generate a base64 encoding using reference RIoT core.
 *
 * @param engine The base64 engine to run.
 * @param data Input data to encode.
 * @param length The length of the input data block.
 * @param encoded Output buffer to store base64 encoding string.
 * @param enc_length The length of the resulting base64 encoding string.
 *
 * @return 0 if the base64 engine successfully encoded the input data block.
*/
static int base64_riot_encode (struct base64_engine *engine, const uint8_t *data,
	size_t length, uint8_t *encoded, size_t enc_length)
{
	int status;

	if ((engine == NULL) || (data == NULL) || (encoded == NULL)) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	status = Base64Encode (data, length, (char*) encoded, &enc_length);
	if (status == -1) {
		return BASE64_ENGINE_ENC_BUFFER_TOO_SMALL;
	}

	return status;
}

/**
 * Initialize an instance for base64 encoding using reference RIoT core.
 *
 * @param engine The base64 engine to initialize.
 *
 * @return 0 if the engine was initialized successfully for an error code.
 */
int base64_riot_init (struct base64_engine_riot *engine)
{
	if (engine == NULL) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct base64_engine_riot));

	engine->base.encode = base64_riot_encode;

	return 0;
}

/**
 * Release the resources used by a reference RIoT core base64 engine.
 *
 * @param engine The base64 engine to release.
 */
void base64_riot_release (struct base64_engine_riot *engine)
{

}
