// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include "hash_kat.h"
#include "common/buffer_util.h"
#include "crypto/kat/hash_kat_vectors.h"
#include "crypto/kat/hmac_kat_vectors.h"

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
static int hash_kat_run_self_test (struct hash_engine *hash, enum hash_type hash_algo,
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
int hash_kat_run_self_test_sha1 (struct hash_engine *hash)
{
	return hash_kat_run_self_test (hash, HASH_TYPE_SHA1, SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST, HASH_ENGINE_SHA1_SELF_TEST_FAILED);
}

/**
 * Run SHA-256 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_kat_run_self_test_sha256 (struct hash_engine *hash)
{
	return hash_kat_run_self_test (hash, HASH_TYPE_SHA256, SHA_KAT_VECTORS_CALCULATE_SHA256_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA256_DIGEST, HASH_ENGINE_SHA256_SELF_TEST_FAILED);
}

/**
 * Run SHA-384 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_kat_run_self_test_sha384 (struct hash_engine *hash)
{
	return hash_kat_run_self_test (hash, HASH_TYPE_SHA384, SHA_KAT_VECTORS_CALCULATE_SHA384_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA384_DIGEST, HASH_ENGINE_SHA384_SELF_TEST_FAILED);
}

/**
 * Run SHA-512 known answer tests (KAT) against the hash engine instance.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_kat_run_self_test_sha512 (struct hash_engine *hash)
{
	return hash_kat_run_self_test (hash, HASH_TYPE_SHA512, SHA_KAT_VECTORS_CALCULATE_SHA512_DIGEST,
		SHA_KAT_VECTORS_UPDATE_SHA512_DIGEST, HASH_ENGINE_SHA512_SELF_TEST_FAILED);
}

/**
 * Run SHA known answer tests (KAT) against the hash engine instance for all supported algorithms.
 *
 * @param hash The hash engine to self test.
 *
 * @return 0 if the tests completed successfully or an error code.
 */
int hash_kat_run_all_self_tests (struct hash_engine *hash)
{
	int status;

#ifdef HASH_ENABLE_SHA1
	status = hash_kat_run_self_test_sha1 (hash);
	if (status != 0) {
		return status;
	}
#endif

	status = hash_kat_run_self_test_sha256 (hash);
	if (status != 0) {
		return status;
	}

#ifdef HASH_ENABLE_SHA384
	status = hash_kat_run_self_test_sha384 (hash);
	if (status != 0) {
		return status;
	}
#endif

#ifdef HASH_ENABLE_SHA512
	status = hash_kat_run_self_test_sha512 (hash);
	if (status != 0) {
		return status;
	}
#endif

	return 0;
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
static int hash_kat_hmac_run_self_test (struct hash_engine *hash, enum hmac_hash hash_algo,
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
int hash_kat_hmac_run_self_test_sha1 (struct hash_engine *hash)
{
	return hash_kat_hmac_run_self_test (hash, HMAC_SHA1, HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC,
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
int hash_kat_hmac_run_self_test_sha256 (struct hash_engine *hash)
{
	return hash_kat_hmac_run_self_test (hash, HMAC_SHA256, HMAC_KAT_VECTORS_CALCULATE_SHA256_MAC,
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
int hash_kat_hmac_run_self_test_sha384 (struct hash_engine *hash)
{
	return hash_kat_hmac_run_self_test (hash, HMAC_SHA384, HMAC_KAT_VECTORS_CALCULATE_SHA384_MAC,
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
int hash_kat_hmac_run_self_test_sha512 (struct hash_engine *hash)
{
	return hash_kat_hmac_run_self_test (hash, HMAC_SHA512, HMAC_KAT_VECTORS_CALCULATE_SHA512_MAC,
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
int hash_kat_hmac_run_all_self_tests (struct hash_engine *hash)
{
	int status;

#ifdef HASH_ENABLE_SHA1
	status = hash_kat_hmac_run_self_test_sha1 (hash);
	if (status != 0) {
		return status;
	}
#endif

	status = hash_kat_hmac_run_self_test_sha256 (hash);
	if (status != 0) {
		return status;
	}

#ifdef HASH_ENABLE_SHA384
	status = hash_kat_hmac_run_self_test_sha384 (hash);
	if (status != 0) {
		return status;
	}
#endif

#ifdef HASH_ENABLE_SHA512
	status = hash_kat_hmac_run_self_test_sha512 (hash);
	if (status != 0) {
		return status;
	}
#endif

	return 0;
}
