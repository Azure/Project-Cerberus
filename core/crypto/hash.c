// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "hash.h"


/**
 * Configure a hash engine to start a new hashing calculation.
 *
 * @param engine The hash engine to configure.
 * @param type The type of hash to start.
 *
 * @return 0 if the hash engine was successfully configured or an error code.
 */
int hash_start_new_hash (struct hash_engine *engine, enum hash_type type)
{
	int status;

	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (type) {
		case HASH_TYPE_SHA1:
#ifdef HASH_ENABLE_SHA1
			status = engine->start_sha1 (engine);
#else
			status = HASH_ENGINE_UNSUPPORTED_HASH;
#endif
			break;

		case HASH_TYPE_SHA256:
			status = engine->start_sha256 (engine);
			break;

		case HASH_TYPE_SHA384:
#ifdef HASH_ENABLE_SHA384
			status = engine->start_sha384 (engine);
#else
			status = HASH_ENGINE_UNSUPPORTED_HASH;
#endif
			break;

		case HASH_TYPE_SHA512:
#ifdef HASH_ENABLE_SHA512
			status = engine->start_sha512 (engine);
#else
			status = HASH_ENGINE_UNSUPPORTED_HASH;
#endif
			break;

		default:
			status = HASH_ENGINE_UNKNOWN_HASH;
			break;
	}

	return status;
}

/**
 * Calculate the hash on a complete set of data.
 *
 * @param engine The hash engine to use to calculate the hash.
 * @param type The type of hash to calculate.
 * @param data The data to hash.
 * @param length The length of the data.
 * @param hash The buffer that will contain the generated hash.
 * @param hash_length The size of the hash buffer.
 *
 * @return The length of the calculated hash or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int hash_calculate (struct hash_engine *engine, enum hash_type type, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	int status = 0;

	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (type) {
		case HASH_TYPE_SHA1:
#ifdef HASH_ENABLE_SHA1
			status = engine->calculate_sha1 (engine, data, length, hash, hash_length);
			if (status == 0) {
				status = SHA1_HASH_LENGTH;
			}
#else
			status = HASH_ENGINE_UNSUPPORTED_HASH;
#endif
			break;

		case HASH_TYPE_SHA256:
			status = engine->calculate_sha256 (engine, data, length, hash, hash_length);
			if (status == 0) {
				status = SHA256_HASH_LENGTH;
			}
			break;

		case HASH_TYPE_SHA384:
#ifdef HASH_ENABLE_SHA384
			status = engine->calculate_sha384 (engine, data, length, hash, hash_length);
			if (status == 0) {
				status = SHA384_HASH_LENGTH;
			}
#else
			status = HASH_ENGINE_UNSUPPORTED_HASH;
#endif
			break;

		case HASH_TYPE_SHA512:
#ifdef HASH_ENABLE_SHA512
			status = engine->calculate_sha512 (engine, data, length, hash, hash_length);
			if (status == 0) {
				status = SHA512_HASH_LENGTH;
			}
#else
			status = HASH_ENGINE_UNSUPPORTED_HASH;
#endif
			break;

		default:
			status = HASH_ENGINE_UNKNOWN_HASH;
	}

	return status;
}

/**
 * Get hash length for indicated hash type.
 *
 * @param hash_type The type of hashing algorithm to use.
 *
 * @return Hash length if hash type is supported or an error code.
 */
int hash_get_hash_len (enum hash_type hash_type)
{
	switch (hash_type) {
		case HASH_TYPE_SHA1:
			return SHA1_HASH_LENGTH;

		case HASH_TYPE_SHA256:
			return SHA256_HASH_LENGTH;

		case HASH_TYPE_SHA384:
			return SHA384_HASH_LENGTH;

		case HASH_TYPE_SHA512:
			return SHA512_HASH_LENGTH;

		default:
			return HASH_ENGINE_UNKNOWN_HASH;
	}
}

/**
 * Generate an HMAC for a block of data.
 *
 * @param engine The hashing engine to use for generating the HMAC.
 * @param key The secret key for the HMAC.
 * @param key_length The length of the key.
 * @param data The data to generate the HMAC for.
 * @param length The length of the data.
 * @param hash The hashing algorithm to use.
 * @param hmac The output buffer that will hold the HMAC.  It must be the right size for the hashing
 * algorithm being used.
 * @param hmac_length The size of the HMAC buffer.
 *
 * @return 0 if the HMAC was successfully generated or an error code.
 */
int hash_generate_hmac (struct hash_engine *engine, const uint8_t *key, size_t key_length,
	const uint8_t *data, size_t length, enum hmac_hash hash, uint8_t *hmac, size_t hmac_length)
{
	struct hmac_engine hmac_engine;
	int status;

	status = hash_hmac_init (&hmac_engine, engine, hash, key, key_length);
	if (status != 0) {
		return status;
	}

	if (hmac_length < hmac_engine.hash_length) {
		status = HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
		goto fail;
	}

	status = hash_hmac_update (&hmac_engine, data, length);
	if (status != 0) {
		goto fail;
	}

	return hash_hmac_finish (&hmac_engine, hmac, hmac_length);

fail:
	hash_hmac_cancel (&hmac_engine);
	return status;
}

/**
 * Initialize an engine for generating an HMAC.
 *
 * An initialized HMAC engine must be released by either finishing or canceling the operation.
 *
 * @param engine The HMAC engine to initialize.
 * @param hash The hash engine to use to generate the HMAC.
 * @param hash_type The type of hashing algorithm to use.
 * @param key The key to use with the HMAC.
 * @param key_length The length of the key.
 *
 * @return 0 if the HMAC engine was successfully initialized or an error code.
 */
int hash_hmac_init (struct hmac_engine *engine, struct hash_engine *hash, enum hmac_hash hash_type,
	const uint8_t *key, size_t key_length)
{
	int status;
	size_t i;

	if ((engine == NULL) || (hash == NULL) || (key == NULL) || (key_length == 0)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (hash_type) {
		case HMAC_SHA1:
#ifdef HASH_ENABLE_SHA1
			if (key_length > SHA1_BLOCK_SIZE) {
				status = hash->calculate_sha1 (hash, key, key_length, engine->key,
					sizeof (engine->key));
				if (status != 0) {
					return status;
				}

				key_length = SHA1_HASH_LENGTH;
			}
			else {
				memcpy (engine->key, key, key_length);
			}

			engine->block_size = SHA1_BLOCK_SIZE;
			engine->hash_length = SHA1_HASH_LENGTH;
			break;
#else
			return HASH_ENGINE_UNSUPPORTED_HASH;
#endif

		case HMAC_SHA256:
			if (key_length > SHA256_BLOCK_SIZE) {
				status = hash->calculate_sha256 (hash, key, key_length, engine->key,
					sizeof (engine->key));
				if (status != 0) {
					return status;
				}

				key_length = SHA256_HASH_LENGTH;
			}
			else {
				memcpy (engine->key, key, key_length);
			}

			engine->block_size = SHA256_BLOCK_SIZE;
			engine->hash_length = SHA256_HASH_LENGTH;
			break;

		case HMAC_SHA384:
#ifdef HASH_ENABLE_SHA384
			if (key_length > SHA384_BLOCK_SIZE) {
				status = hash->calculate_sha384 (hash, key, key_length, engine->key,
					sizeof (engine->key));
				if (status != 0) {
					return status;
				}

				key_length = SHA384_HASH_LENGTH;
			}
			else {
				memcpy (engine->key, key, key_length);
			}

			engine->block_size = SHA384_BLOCK_SIZE;
			engine->hash_length = SHA384_HASH_LENGTH;
			break;
#else
			return HASH_ENGINE_UNSUPPORTED_HASH;
#endif

		case HMAC_SHA512:
#ifdef HASH_ENABLE_SHA512
			if (key_length > SHA512_BLOCK_SIZE) {
				status = hash->calculate_sha512 (hash, key, key_length, engine->key,
					sizeof (engine->key));
				if (status != 0) {
					return status;
				}

				key_length = SHA512_HASH_LENGTH;
			}
			else {
				memcpy (engine->key, key, key_length);
			}

			engine->block_size = SHA512_BLOCK_SIZE;
			engine->hash_length = SHA512_HASH_LENGTH;
			break;
#else
			return HASH_ENGINE_UNSUPPORTED_HASH;
#endif

		default:
			return HASH_ENGINE_UNKNOWN_HASH;
	}

	status = hash_start_new_hash (hash, (enum hash_type) hash_type);
	if (status != 0) {
		return status;
	}

	engine->hash = hash;
	engine->type = hash_type;

	/* Transform the key for the inner hash. */
	for (i = 0; i < engine->block_size; i++) {
		if (i < key_length) {
			engine->key[i] ^= 0x36;
		}
		else {
			engine->key[i] = 0x36;
		}
	}

	status = hash->update (hash, engine->key, engine->block_size);
	if (status != 0) {
		hash->cancel (hash);
		return status;
	}

	/* We've already hashed the inner key, so transform it for use in the outer hash. */
	for (i = 0; i < engine->block_size; i++) {
		engine->key[i] ^= (0x5c ^ 0x36);
	}

	return 0;
}

/**
 * Add message data to the HMAC calculation.
 *
 * @param engine The HMAC engine to update with new message data.
 * @param data The message data to add.
 * @param length The length of the message data.
 *
 * @return 0 if the HMAC was successfully updated or an error code.
 */
int hash_hmac_update (struct hmac_engine *engine, const uint8_t *data, size_t length)
{
	if ((engine == NULL) || (data == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	return engine->hash->update (engine->hash, data, length);
}

/**
 * Get the HMAC for the message and release the HMAC operation.  The HMAC operation is released
 * whether or not the HMAC was successfully generated, except in the case where the HMAC buffer is
 * not large enough or an input argument is not valid.
 *
 * @param engine The engine to get the HMAC from.
 * @param hmac The buffer to hold the HMAC value.
 * @param hmac_length The length of the HMAC buffer.
 *
 * @return 0 if the HMAC was successfully generated or an error code.
 * HASH_ENGINE_HASH_BUFFER_TOO_SMALL is returned if the HMAC buffer is not large enough for the
 * result.
 */
int hash_hmac_finish (struct hmac_engine *engine, uint8_t *hmac, size_t hmac_length)
{
	uint8_t inner_hash[SHA512_HASH_LENGTH];
	int status;

	if ((engine == NULL) || (hmac == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hmac_length < engine->hash_length) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	status = engine->hash->finish (engine->hash, inner_hash, sizeof (inner_hash));
	if (status != 0) {
		goto fail;
	}

	status = hash_start_new_hash (engine->hash, (enum hash_type) engine->type);
	if (status != 0) {
		goto fail;
	}

	status = engine->hash->update (engine->hash, engine->key, engine->block_size);
	if (status != 0) {
		goto fail;
	}

	status = engine->hash->update (engine->hash, inner_hash, engine->hash_length);
	if (status != 0) {
		goto fail;
	}

	status = engine->hash->finish (engine->hash, hmac, hmac_length);
	if (status != 0) {
		goto fail;
	}

	return 0;

fail:
	engine->hash->cancel (engine->hash);
	return status;
}

/**
 * Cancel and release the current HMAC operation without generating the HMAC.
 *
 * @param engine The engine to release.
 */
void hash_hmac_cancel (struct hmac_engine *engine)
{
	if (engine != NULL) {
		engine->hash->cancel (engine->hash);
	}
}
