// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "base64_riot.h"
#include "common/unused.h"


/**
 * Map of character values fo encoding in base64.
 */
static const uint8_t base64_riot_encoding[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

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
int base64_riot_encode (struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length)
{
	size_t in_pos = 0;
	size_t out_pos = 0;

	if ((engine == NULL) || (data == NULL) || (encoded == NULL)) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	if (enc_length < BASE64_LENGTH (length)) {
		return BASE64_ENGINE_ENC_BUFFER_TOO_SMALL;
	}

	/* Encode each complete group of 3 bytes into 4 characters.
	 *
	 * https://en.wikipedia.org/wiki/Base64 */
	while ((length - in_pos) >= 3) {
		uint8_t byte1 = data[in_pos++];
		uint8_t byte2 = data[in_pos++];
		uint8_t byte3 = data[in_pos++];

		encoded[out_pos++] = base64_riot_encoding [byte1 >> 2];
		encoded[out_pos++] = base64_riot_encoding [((byte1 & 0x03) << 4) | (byte2 >> 4)];
		encoded[out_pos++] = base64_riot_encoding [((byte2 & 0x0f) << 2) | ((byte3 >> 6) & 0x03)];
		encoded[out_pos++] = base64_riot_encoding [byte3 & 0x3f];
	}

	/* Deal with any remaining bytes that are not in a group of three. */
	if (in_pos != length) {
		uint8_t val = data[in_pos++];

		encoded[out_pos++] = base64_riot_encoding [val >> 2];
		val = (val & 0x03) << 4;

		if (in_pos != length) {
			encoded[out_pos++] = base64_riot_encoding[val | (data[in_pos] >> 4)];
			encoded[out_pos++] = base64_riot_encoding[(data[in_pos] & 0x0f) << 2];
		}
		else {
			encoded[out_pos++] = base64_riot_encoding[val];
			encoded[out_pos++] = '=';
		}

		encoded[out_pos++] = '=';
	}

    encoded[out_pos] = '\0';

	return 0;
}

/**
 * Initialize an instance for base64 encoding using reference RIoT crypto.
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
 * Release the resources used by a reference RIoT crypto base64 engine.
 *
 * @param engine The base64 engine to release.
 */
void base64_riot_release (struct base64_engine_riot *engine)
{
	UNUSED (engine);
}
