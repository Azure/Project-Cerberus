// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "common/buffer_util.h"


/**
 * Configure a hash engine to start a new hashing calculation.
 *
 * @param engine The hash engine to configure.
 * @param type The type of hash to start.
 *
 * @return 0 if the hash engine was successfully configured or an error code.
 */
int hash_start_new_hash (const struct hash_engine *engine, enum hash_type type)
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
int hash_calculate (const struct hash_engine *engine, enum hash_type type, const uint8_t *data,
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
 * Get the hash algorithm used to generate a hash based on the output length.
 *
 * @param hash_length The length of the hash output.
 *
 * @return Hash algorithm used if the length is known or HASH_TYPE_INVALID.
 */
enum hash_type hash_get_type_from_length (size_t hash_length)
{
	switch (hash_length) {
		case SHA1_HASH_LENGTH:
			return HASH_TYPE_SHA1;

		case SHA256_HASH_LENGTH:
			return HASH_TYPE_SHA256;

		case SHA384_HASH_LENGTH:
			return HASH_TYPE_SHA384;

		case SHA512_HASH_LENGTH:
			return HASH_TYPE_SHA512;

		default:
			return HASH_TYPE_INVALID;
	}
}

/**
 * Get the hash algorithm type for the active hash identifier.
 *
 * This is not something that is expected to be called generally.  It's primarily a helper function
 * for hash engine implementations that use the active hash enumeration.
 *
 * @param active The HASH_ACTIVE_* identifier for the hash algorithm.
 *
 * @return The HASH_TYPE_* enumeration for the identifier.
 */
enum hash_type hash_get_type_from_active (uint8_t active)
{
	return (active == HASH_ACTIVE_NONE) ? HASH_TYPE_INVALID : (enum hash_type) active;
}

/**
 * Get the length of the output digest for the indicated hash algorithm.
 *
 * @param hash_type The hashing algorithm to check.
 *
 * @return Digest length if the hash type is known or HASH_ENGINE_UNKNOWN_HASH.
 */
int hash_get_hash_length (enum hash_type hash_type)
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
 * Get the length of the output digest for the active hash calculation on a specified hash engine.
 *
 * @param hash The hash engine to query.
 *
 * @return Length of the output digest or 0 if no hash calculation is ongoing.
 */
size_t hash_get_active_hash_length (const struct hash_engine *hash)
{
	size_t length = 0;

	if (hash != NULL) {
		length = hash_get_hash_length (hash->get_active_algorithm (hash));
		if (length == HASH_ENGINE_UNKNOWN_HASH) {
			length = 0;
		}
	}

	return length;
}

/**
 * Get the block size used for the indicated hash algorithm.
 *
 * @param hash_type The hashing algorithm to check.
 *
 * @return Hash block size if the hash type is known or HASH_ENGINE_UNKNOWN_HASH.
 */
int hash_get_block_size (enum hash_type hash_type)
{
	switch (hash_type) {
		case HASH_TYPE_SHA1:
			return SHA1_BLOCK_SIZE;

		case HASH_TYPE_SHA256:
			return SHA256_BLOCK_SIZE;

		case HASH_TYPE_SHA384:
			return SHA384_BLOCK_SIZE;

		case HASH_TYPE_SHA512:
			return SHA512_BLOCK_SIZE;

		default:
			return HASH_ENGINE_UNKNOWN_HASH;
	}
}

/**
 * Determine if a specific hashing algorithm is supported by the device.
 *
 * @param hash_type The hashing algorithm to check.
 *
 * @return True if algorithm is supported, False otherwise.
 */
bool hash_is_alg_supported (enum hash_type type)
{
	switch (type) {
#ifdef HASH_ENABLE_SHA1
		case HASH_TYPE_SHA1:
			return true;
#endif

		case HASH_TYPE_SHA256:
			return true;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			return true;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			return true;
#endif

		default:
			return false;
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
int hash_generate_hmac (const struct hash_engine *engine, const uint8_t *key, size_t key_length,
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
int hash_hmac_init (struct hmac_engine *engine, const struct hash_engine *hash,
	enum hmac_hash hash_type, const uint8_t *key, size_t key_length)
{
	int status;
	size_t i;

	if ((engine == NULL) || (hash == NULL) || ((key == NULL) && (key_length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	engine->block_size = hash_get_block_size ((enum hash_type) hash_type);
	if (engine->block_size == HASH_ENGINE_UNKNOWN_HASH) {
		return HASH_ENGINE_UNKNOWN_HASH;
	}

	engine->hash = hash;
	engine->type = hash_type;
	engine->hash_length = hash_hmac_get_hmac_length (hash_type);

	if (key_length > engine->block_size) {
		/* If the HMAC key is longer than the algorithm block size, it needs to be hashed so that it
		 * can fit within the algorithm block size. */
		status = hash_calculate (hash, (enum hash_type) hash_type, key, key_length, engine->key,
			sizeof (engine->key));
		if (ROT_IS_ERROR (status)) {
			goto error;
		}

		key_length = status;
	}
	else if (key_length != 0) {
		memcpy (engine->key, key, key_length);
	}

	/* Start the inner hash. */
	status = hash_start_new_hash (hash, (enum hash_type) hash_type);
	if (status != 0) {
		goto error;
	}

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
		goto error;
	}

	/* We've already hashed the inner key, so transform it for use in the outer hash. */
	for (i = 0; i < engine->block_size; i++) {
		engine->key[i] ^= (0x5c ^ 0x36);
	}

	return 0;

error:
	buffer_zeroize (engine->key, sizeof (engine->key));

	return status;
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

	/* Finish the inner hash. */
	status = engine->hash->finish (engine->hash, inner_hash, sizeof (inner_hash));
	if (status != 0) {
		goto fail;
	}

	/* Run the outer hash.  The key data for this has already been set in the context buffer. */
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

	/* Clear the HMAC key after the HMAC has been calculated. */
	buffer_zeroize (engine->key, sizeof (engine->key));

	return 0;

fail:
	hash_hmac_cancel (engine);

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

		buffer_zeroize (engine->key, sizeof (engine->key));
	}
}
