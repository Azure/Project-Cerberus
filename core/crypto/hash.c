// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "common/buffer_util.h"
#include "crypto/kat/hash_kat_vectors.h"
#include "crypto/kat/hmac_kat_vectors.h"


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
 * Run SHA known answer tests (KAT) against the hash engine instance for a single hash algorithm.
 *
 * @param hash The hash engine to self test.
 * @param hash_algo The hash algorithm to self test.
 * @param calculate_expected The expected output for direct digest calculation.
 * @param update_expected The expected output for start/update/finish digest calculation.
 * @param kat_error Error code to report if the KAT fails.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
static int hash_run_self_test (struct hash_engine *hash, enum hash_type hash_algo,
	const uint8_t *calculate_expected, const uint8_t *update_expected, int kat_error)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	size_t digest_length;
	int status;

	/* Test the calculate API. */
	status = hash_calculate (hash, hash_algo, SHA_KAT_VECTORS_CALCULATE_DATA,
		SHA_KAT_VECTORS_CALCULATE_DATA_LEN, digest, sizeof (digest));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	digest_length = status;

	status = buffer_compare (digest, calculate_expected, digest_length);
	if (status != 0) {
		return kat_error;
	}

	/* Test the start/update/finish APIs. */
	status = hash_start_new_hash (hash, hash_algo);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN);
	if (status != 0) {
		goto exit;
	}

	status = hash->update (hash, SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN);
	if (status != 0) {
		goto exit;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (digest, update_expected, digest_length);
	if (status != 0) {
		return kat_error;
	}

exit:
	if (status != 0) {
		hash->cancel (hash);
	}

	return status;
}

/**
 * Run SHA-1 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_run_self_test_sha1 (struct hash_engine *hash)
{
	return hash_run_self_test (hash, HASH_TYPE_SHA1, SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST, HASH_ENGINE_SHA1_SELF_TEST_FAILED);
}

/**
 * Run SHA-256 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_run_self_test_sha256 (struct hash_engine *hash)
{
	return hash_run_self_test (hash, HASH_TYPE_SHA256, SHA_KAT_VECTORS_CALCULATE_SHA256_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA256_DIGEST, HASH_ENGINE_SHA256_SELF_TEST_FAILED);
}

/**
 * Run SHA-384 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_run_self_test_sha384 (struct hash_engine *hash)
{
	return hash_run_self_test (hash, HASH_TYPE_SHA384, SHA_KAT_VECTORS_CALCULATE_SHA384_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA384_DIGEST, HASH_ENGINE_SHA384_SELF_TEST_FAILED);
}

/**
 * Run SHA-512 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_run_self_test_sha512 (struct hash_engine *hash)
{
	return hash_run_self_test (hash, HASH_TYPE_SHA512, SHA_KAT_VECTORS_CALCULATE_SHA512_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA512_DIGEST, HASH_ENGINE_SHA512_SELF_TEST_FAILED);
}

/**
 * Run SHA known answer tests (KAT) against the hash engine instance for all supported algorithms.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_run_all_self_tests (struct hash_engine *hash)
{
	int status;

#ifdef HASH_ENABLE_SHA1
	status = hash_run_self_test_sha1 (hash);
	if (status != 0) {
		return status;
	}
#endif

	status = hash_run_self_test_sha256 (hash);
	if (status != 0) {
		return status;
	}

#ifdef HASH_ENABLE_SHA384
	status = hash_run_self_test_sha384 (hash);
	if (status != 0) {
		return status;
	}
#endif

#ifdef HASH_ENABLE_SHA512
	status = hash_run_self_test_sha512 (hash);
	if (status != 0) {
		return status;
	}
#endif

	return 0;
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
			return status;
		}

		key_length = status;
	}
	else {
		memcpy (engine->key, key, key_length);
	}

	/* Start the inner hash. */
	status = hash_start_new_hash (hash, (enum hash_type) hash_type);
	if (status != 0) {
		return status;
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

/**
 * Run HMAC known answer tests (KAT) against the hash engine instance using a specific hash
 * algorithm.
 *
 * In addition to testing the HMAC instantiation, this will also fully self test the provided hash
 * engine for the specified algorithm.
 *
 * @param hash The hash engine to self test.
 * @param hash_algo The hash algorithm to self test.
 * @param calculate_expected The expected output for direct HMAC calculation.
 * @param update_expected Th expected output for init/update/finish HMAC calculation.
 * @param kat_error Error code to report if the KAT fails.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
static int hash_hmac_run_self_test (struct hash_engine *hash, enum hmac_hash hash_algo,
	const uint8_t *calculate_expected, const uint8_t *update_expected, int kat_error)
{
	struct hmac_engine hmac;
	uint8_t mac[HASH_MAX_HASH_LEN];
	size_t mac_length;
	int status;

	mac_length = hash_hmac_get_hmac_length (hash_algo);

	/* Test direct HMAC generation. */
	status = hash_generate_hmac (hash, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, HMAC_KAT_VECTORS_CALCULATE_DATA,
		HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, hash_algo, mac, sizeof (mac));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (mac, calculate_expected, mac_length);
	if (status != 0) {
		return kat_error;
	}

	/* Test init/update/finish HMAC generation. */
	status = hash_hmac_init (&hmac, hash, hash_algo, HMAC_KAT_VECTORS_UPDATE_KEY,
		HMAC_KAT_VECTORS_UPDATE_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = hash_hmac_update (&hmac, HMAC_KAT_VECTORS_UPDATE_DATA_1,
		HMAC_KAT_VECTORS_UPDATE_DATA_1_LEN);
	if (status != 0) {
		hash_hmac_cancel (&hmac);

		return status;
	}

	status = hash_hmac_update (&hmac, HMAC_KAT_VECTORS_UPDATE_DATA_2,
		HMAC_KAT_VECTORS_UPDATE_DATA_2_LEN);
	if (status != 0) {
		hash_hmac_cancel (&hmac);

		return status;
	}

	status = hash_hmac_finish (&hmac, mac, sizeof (mac));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (mac, update_expected, mac_length);
	if (status != 0) {
		return kat_error;
	}

	return 0;
}

/**
 * Run SHA-1 HMAC known answer tests (KAT) against the hash engine instance.
 *
 * In addition to testing the SHA-1 HMAC instantiation, this will also fully self test the provided
 * hash engine for SHA-1.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_hmac_run_self_test_sha1 (struct hash_engine *hash)
{
	return hash_hmac_run_self_test (hash, HMAC_SHA1, HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC,
		HMAC_KAT_VECTORS_UPDATE_SHA1_MAC, HASH_ENGINE_HMAC_SHA1_SELF_TEST_FAILED);
}

/**
 * Run SHA-256 HMAC known answer tests (KAT) against the hash engine instance.
 *
 * In addition to testing the SHA-256 HMAC instantiation, this will also fully self test the
 * provided hash engine for SHA-256.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_hmac_run_self_test_sha256 (struct hash_engine *hash)
{
	return hash_hmac_run_self_test (hash, HMAC_SHA256, HMAC_KAT_VECTORS_CALCULATE_SHA256_MAC,
		HMAC_KAT_VECTORS_UPDATE_SHA256_MAC, HASH_ENGINE_HMAC_SHA256_SELF_TEST_FAILED);
}

/**
 * Run SHA-384 HMAC known answer tests (KAT) against the hash engine instance.
 *
 * In addition to testing the SHA-384 HMAC instantiation, this will also fully self test the
 * provided hash engine for SHA-384.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_hmac_run_self_test_sha384 (struct hash_engine *hash)
{
	return hash_hmac_run_self_test (hash, HMAC_SHA384, HMAC_KAT_VECTORS_CALCULATE_SHA384_MAC,
		HMAC_KAT_VECTORS_UPDATE_SHA384_MAC, HASH_ENGINE_HMAC_SHA384_SELF_TEST_FAILED);
}

/**
 * Run SHA-512 HMAC known answer tests (KAT) against the hash engine instance.
 *
 * In addition to testing the SHA-512 HMAC instantiation, this will also fully self test the
 * provided hash engine for SHA-512.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_hmac_run_self_test_sha512 (struct hash_engine *hash)
{
	return hash_hmac_run_self_test (hash, HMAC_SHA512, HMAC_KAT_VECTORS_CALCULATE_SHA512_MAC,
		HMAC_KAT_VECTORS_UPDATE_SHA512_MAC, HASH_ENGINE_HMAC_SHA512_SELF_TEST_FAILED);
}

/**
 * Run HMAC known answer tests (KAT) against the hash engine instance for all supported algorithms.
 *
 * In addition to testing the HMAC instantiation, this will also fully self test the provided hash
 * engine for all supported algorithms.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_hmac_run_all_self_tests (struct hash_engine *hash)
{
	int status;

#ifdef HASH_ENABLE_SHA1
	status = hash_hmac_run_self_test_sha1 (hash);
	if (status != 0) {
		return status;
	}
#endif

	status = hash_hmac_run_self_test_sha256 (hash);
	if (status != 0) {
		return status;
	}

#ifdef HASH_ENABLE_SHA384
	status = hash_hmac_run_self_test_sha384 (hash);
	if (status != 0) {
		return status;
	}
#endif

#ifdef HASH_ENABLE_SHA512
	status = hash_hmac_run_self_test_sha512 (hash);
	if (status != 0) {
		return status;
	}
#endif

	return 0;
}
