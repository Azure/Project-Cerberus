// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include "platform_api.h"
#include "common/common_math.h"
#include "kdf.h"


/**
 * Generate key using NIST SP800-108 counter mode
 *
 * @param hash Hash engine to utilize.
 * @param hash_type HMAC hash type to utilize.
 * @param key_derivation_key Key used to derive keying material.
 * @param key_derivation_key_len Key derivation key length.
 * @param label Buffer containing label used as input to the KDF.
 * @param label_len Label length.
 * @param context Buffer containing context used as input to the KDF. Set to NULL if not used.
 * @param context_len Context length.
 * @param key Buffer to store generated key.
 * @param key_len Output key length.
 *
 * @return Completion status, 0 if success or an error code.
 */
int kdf_nist800_108_counter_mode (struct hash_engine *hash, enum hmac_hash hash_type,
	const uint8_t *key_derivation_key, size_t key_derivation_key_len, const uint8_t *label,
	size_t label_len, const uint8_t *context, size_t context_len, uint8_t *key, uint32_t key_len)
{
	struct hmac_engine hmac;
	uint32_t i_key = 0;
	uint32_t hash_len;
	uint32_t copy_len;
	uint32_t L = key_len * 8;
	uint32_t i;
	uint32_t rounds;
	uint32_t temp;
	uint8_t hash_buf[SHA512_HASH_LENGTH];
	uint8_t separator = 0x00;
	int status;

	if ((hash == NULL) || (key_derivation_key == NULL) || (label == NULL) || (key == NULL)) {
		return KDF_INVALID_ARGUMENT;
	}

	hash_len = hash_hmac_get_hmac_length (hash_type);
	if (hash_len == HASH_ENGINE_UNKNOWN_HASH) {
		return KDF_OPERATION_UNSUPPORTED;
	}

	rounds = key_len / hash_len;
	if ((key_len % hash_len) != 0) {
		rounds++;
	}

	memset (key, 0, key_len);

	for (i = 1; i <= rounds; ++i) {
		status = hash_hmac_init (&hmac, hash, hash_type, key_derivation_key,
			key_derivation_key_len);
		if (status != 0) {
			return status;
		}

		temp = platform_htonl (i);

		status = hash_hmac_update (&hmac, (const uint8_t*) &temp, sizeof (temp));
		if (status != 0) {
			goto fail;
		}

		status = hash_hmac_update (&hmac, label, label_len);
		if (status != 0) {
			goto fail;
		}

		status = hash_hmac_update (&hmac, &separator, sizeof (separator));
		if (status != 0) {
			goto fail;
		}

		if (context != NULL) {
			status = hash_hmac_update (&hmac, context, context_len);
			if (status != 0) {
				goto fail;
			}
		}

		temp = platform_htonl (L);

		status = hash_hmac_update (&hmac, (const uint8_t*) &temp, sizeof (temp));
		if (status != 0) {
			goto fail;
		}

		status = hash_hmac_finish (&hmac, hash_buf, sizeof (hash_buf));
		if (status != 0) {
			return status;
		}

		copy_len = min (hash_len, key_len - i_key);

		memcpy (&key[i_key], hash_buf, copy_len);

		i_key += copy_len;
	}

	return status;

fail:
	hash_hmac_cancel (&hmac);

	return status;
}
