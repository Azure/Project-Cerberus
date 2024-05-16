// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kdf.h"
#include "platform_api.h"
#include "common/common_math.h"


/**
 * Generate key using NIST SP800-108 counter mode with HMAC.
 *
 * @param hash Hash engine to use for HMAC calculations.
 * @param hash_type HMAC hash type to use in the KDF.
 * @param key_derivation_key Input key used to derive the output keying material.
 * @param key_derivation_key_len Input key length.
 * @param label Buffer containing label used as input to the KDF.
 * @param label_len Label length.
 * @param context Buffer containing context used as input to the KDF. Set to NULL if not used.
 * @param context_len Context length.
 * @param key Output for the generated key keying material.
 * @param key_len Length of the output key to generate.
 *
 * @return 0 if the output key was successfully generated or an error code.
 */
int kdf_nist800_108_counter_mode (struct hash_engine *hash, enum hmac_hash hash_type,
	const uint8_t *key_derivation_key, size_t key_derivation_key_len, const uint8_t *label,
	size_t label_len, const uint8_t *context, size_t context_len, uint8_t *key, size_t key_len)
{
	struct hmac_engine hmac;
	size_t key_out_pos = 0;
	size_t hash_len;
	size_t copy_len;
	uint32_t L = key_len * 8;
	uint32_t i;
	uint32_t rounds;
	uint32_t int_be;
	uint8_t round_hmac[HASH_MAX_HASH_LEN];
	const uint8_t separator = 0x00;
	int status;

	if ((hash == NULL) || (key_derivation_key == NULL) || (label == NULL) || (key == NULL)) {
		return KDF_INVALID_ARGUMENT;
	}

	hash_len = hash_hmac_get_hmac_length (hash_type);
	if (hash_len == HASH_ENGINE_UNKNOWN_HASH) {
		return HASH_ENGINE_UNKNOWN_HASH;
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

		int_be = platform_htonl (i);

		status = hash_hmac_update (&hmac, (const uint8_t*) &int_be, sizeof (int_be));
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

		int_be = platform_htonl (L);

		status = hash_hmac_update (&hmac, (const uint8_t*) &int_be, sizeof (int_be));
		if (status != 0) {
			goto fail;
		}

		status = hash_hmac_finish (&hmac, round_hmac, sizeof (round_hmac));
		if (status != 0) {
			return status;
		}

		copy_len = min (hash_len, key_len - key_out_pos);

		memcpy (&key[key_out_pos], round_hmac, copy_len);

		key_out_pos += copy_len;
	}

	return status;

fail:
	hash_hmac_cancel (&hmac);

	return status;
}

/**
 * Expands keying material from a pseudorandom key and optional additional information using the
 * HKDF-Expand algorithm as described in RFC#5869.
 *
 * @param hash The hash engine to use for HMAC operations.
 * @param hash_type The hash type to use for HMAC operations.
 * @param pseudorandom_key The pseudorandom key to use for key extraction.
 * @param pseudorandom_key_len The length of the pseudorandom key.
 * @param info Additional information to use for key extraction.  Can be NULL if not used.
 * @param info_len The length of the additional information.
 * @param output_keying_material The buffer to store the extracted keying material.
 * @param output_keying_material_len The length of the buffer for the extracted keying material.
 *
 * @return 0 if the keying material was successfully expanded or an error code.
 */
int kdf_hkdf_expand (struct hash_engine *hash, enum hmac_hash hash_type,
	const uint8_t *pseudorandom_key, size_t pseudorandom_key_len, const uint8_t *info,
	size_t info_len, uint8_t *output_keying_material, size_t output_keying_material_len)
{
	struct hmac_engine hmac;
	uint32_t hash_len;
	uint32_t i;
	int status = 0;
	size_t n;
	uint8_t t[HASH_MAX_HASH_LEN];
	size_t t_len = 0;
	size_t where = 0;
	uint8_t c;
	size_t num_to_copy;

	if ((hash == NULL) || (pseudorandom_key == NULL) || (output_keying_material == NULL)) {
		return KDF_INVALID_ARGUMENT;
	}

	hash_len = hash_hmac_get_hmac_length (hash_type);
	if (hash_len == HASH_ENGINE_UNKNOWN_HASH) {
		return HASH_ENGINE_UNKNOWN_HASH;
	}

	/* Per RFC 5869 Section 2.3, the PSK must be at least as large as the hash length. */
	if (pseudorandom_key_len < hash_len) {
		return KDF_INPUT_KEY_TOO_SHORT;
	}

	n = output_keying_material_len / hash_len;
	if ((output_keying_material_len % hash_len) != 0) {
		n++;
	}

	/* Per RFC 5869 Section 2.3, output_keying_material_len must not exceed 255 times the hash
	 * length. */
	if (n > 255) {
		return KDF_OUTPUT_KEY_TOO_LONG;
	}

	memset (t, 0, hash_len);

	/* Compute T = T(1) | T(2) | T(3) | ... | T(N)
	 * Where T(N) is defined in RFC 5869 Section 2.3. */
	for (i = 1; i <= n; i++) {
		c = i & 0xff;

		status = hash_hmac_init (&hmac, hash, hash_type, pseudorandom_key, pseudorandom_key_len);
		if (status != 0) {
			return status;
		}

		if (t_len != 0) {
			status = hash_hmac_update (&hmac, t, t_len);
			if (status != 0) {
				goto fail;
			}
		}

		if (info != NULL) {
			status = hash_hmac_update (&hmac, info, info_len);
			if (status != 0) {
				goto fail;
			}
		}

		/* The constant concatenated to the end of each T(n) is a single octet. */
		status = hash_hmac_update (&hmac, &c, 1);
		if (status != 0) {
			goto fail;
		}

		status = hash_hmac_finish (&hmac, t, sizeof (t));
		if (status != 0) {
			return status;
		}

		num_to_copy = (i != n) ? hash_len : (output_keying_material_len - where);
		memcpy (output_keying_material + where, t, num_to_copy);
		where += hash_len;
		t_len = hash_len;
	}

	return status;

fail:
	hash_hmac_cancel (&hmac);

	return status;
}
