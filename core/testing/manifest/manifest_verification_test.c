// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform.h"
#include "manifest/manifest_verification.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/manifest/cfm_mock.h"
#include "testing/mock/manifest/pcd_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"


TEST_SUITE_LABEL ("manifest_verification");


/**
 * Set up initialization with no key for manifest verification store in the keystore.
 *
 * @param test The test framework.
 * @param keystore The mock keystore to update.
 * @param manifest_key The key to initialize.
 */
static void manifest_verification_testing_initialize_no_key (CuTest *test,
	struct keystore_mock *keystore, struct manifest_verification_key *manifest_key)
{
	struct manifest_verification_key *stored_key = NULL;
	int status;

	status = keystore_mock_init (keystore);
	CuAssertIntEquals (test, 0, status);

	memset (manifest_key, 0, sizeof (*manifest_key));
	manifest_key->id = 1;
	memcpy (&manifest_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) manifest_key,
		sizeof (*manifest_key) - sizeof (manifest_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key->signature, sizeof (manifest_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &stored_key, sizeof (stored_key), -1);

	status |= mock_expect (&keystore->mock, keystore->base.save_key, keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (manifest_key, sizeof (*manifest_key)),
		MOCK_ARG (sizeof (*manifest_key)));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up initialization with a key for manifest verification stored in the keystore.
 *
 * @param test The test framework.
 * @param keystore The mock keystore to update.
 * @param manifest_key The key to initialize.
 * @param id The version ID for the manifest key.  The stored key will use ID 10.
 */
static void manifest_verification_testing_initialize_stored_key (CuTest *test,
	struct keystore_mock *keystore, struct manifest_verification_key *manifest_key, uint32_t id)
{
	struct manifest_verification_key *stored_key;
	size_t stored_length = sizeof (struct manifest_verification_key);
	int status;

	status = keystore_mock_init (keystore);
	CuAssertIntEquals (test, 0, status);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 10;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	memset (manifest_key, 0, sizeof (*manifest_key));
	manifest_key->id = id;
	memcpy (&manifest_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) manifest_key,
		sizeof (*manifest_key) - sizeof (manifest_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key->signature, sizeof (manifest_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &stored_key, sizeof (stored_key), -1);
	status |= mock_expect_output_tmp (&keystore->mock, 2, &stored_length, sizeof (stored_length),
		-1);

	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void manifest_verification_test_init_no_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base_verify.verify_signature);

	CuAssertPtrEquals (test, NULL, verification.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.base_observer.on_clear_active);

	CuAssertPtrNotNull (test, verification.base_update.on_update_start);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key);
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 2;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);
	status |= mock_expect_output (&keystore.mock, 2, &stored_length, sizeof (stored_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base_verify.verify_signature);

	CuAssertPtrEquals (test, NULL, verification.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.base_observer.on_clear_active);

	CuAssertPtrNotNull (test, verification.base_update.on_update_start);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_bad_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_BAD_KEY,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base_verify.verify_signature);

	CuAssertPtrEquals (test, NULL, verification.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.base_observer.on_clear_active);

	CuAssertPtrNotNull (test, verification.base_update.on_update_start);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_bad_length_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key);
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 2;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	stored_length -= 1;

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);
	status |= mock_expect_output (&keystore.mock, 2, &stored_length, sizeof (stored_length), -1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base_verify.verify_signature);

	CuAssertPtrEquals (test, NULL, verification.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.base_observer.on_clear_active);

	CuAssertPtrNotNull (test, verification.base_update.on_update_start);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_bad_signature_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key);
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY2_DER,
		RSA_PRIVKEY2_DER_LEN, stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 2;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);
	status |= mock_expect_output (&keystore.mock, 2, &stored_length, sizeof (stored_length), -1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base_verify.verify_signature);

	CuAssertPtrEquals (test, NULL, verification.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.base_observer.on_clear_active);

	CuAssertPtrNotNull (test, verification.base_update.on_update_start);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (NULL, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification, NULL, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification, &hash.base, NULL, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, NULL,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, &keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, NULL, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_manifest_key_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY2_DER,
		RSA_PRIVKEY2_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_manifest_key_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;
	size_t hash_length;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	hash_length = sizeof (manifest_key) - sizeof (manifest_key.signature);
	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (&manifest_key, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void manifest_verification_test_init_manifest_key_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, RSA_ENGINE_VERIFY_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_load_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_LOAD_FAILED,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_init_stored_key_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key);
	struct manifest_verification verification;
	int status;
	size_t hash_length = sizeof (manifest_key) - sizeof (manifest_key.signature);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 2;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);
	status |= mock_expect_output (&keystore.mock, 2, &stored_length, sizeof (stored_length), -1);

	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&manifest_key, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST, SIG_HASH_LEN, 3);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_verification_test_init_stored_key_signature_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key);
	struct manifest_verification verification;
	int status;
	size_t hash_length = sizeof (manifest_key) - sizeof (manifest_key.signature);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 2;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);
	status |= mock_expect_output (&keystore.mock, 2, &stored_length, sizeof (stored_length), -1);

	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&manifest_key, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST, SIG_HASH_LEN, 3);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST2, SIG_HASH_LEN, 3);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST2, SIG_HASH_LEN),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, RSA_ENGINE_VERIFY_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_verification_test_init_save_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification_key *stored_key = NULL;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	memset (&manifest_key, 0, sizeof (manifest_key));
	manifest_key.id = 1;
	memcpy (&manifest_key.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) &manifest_key,
		sizeof (manifest_key) - sizeof (manifest_key.signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_key.signature, sizeof (manifest_key.signature));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &stored_key, sizeof (stored_key), -1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_verification_release (NULL);
}

static void manifest_verification_test_get_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;
	struct pfm_observer *pfm;
	struct cfm_observer *cfm;
	struct pcd_observer *pcd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	pfm = manifest_verification_get_pfm_observer (&verification);
	CuAssertPtrNotNull (test, pfm);

	cfm = manifest_verification_get_cfm_observer (&verification);
	CuAssertPtrNotNull (test, cfm);

	pcd = manifest_verification_get_pcd_observer (&verification);
	CuAssertPtrNotNull (test, pcd);

	CuAssertIntEquals (test, sizeof (struct pfm_observer), sizeof (struct cfm_observer));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_activated),
		offsetof (struct cfm_observer, on_cfm_activated));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_verified),
		offsetof (struct cfm_observer, on_cfm_verified));

	CuAssertPtrEquals (test, pfm->on_pfm_activated, cfm->on_cfm_activated);
	CuAssertPtrEquals (test, pfm->on_pfm_verified, cfm->on_cfm_verified);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_get_pfm_observer_null (CuTest *test)
{
	struct pfm_observer *pfm;

	TEST_START;

	pfm = manifest_verification_get_pfm_observer (NULL);
	CuAssertPtrEquals (test, NULL, pfm);
}

static void manifest_verification_test_get_cfm_observer_null (CuTest *test)
{
	struct cfm_observer *cfm;

	TEST_START;

	cfm = manifest_verification_get_cfm_observer (NULL);
	CuAssertPtrEquals (test, NULL, cfm);
}

static void manifest_verification_test_get_pcd_observer_null (CuTest *test)
{
	struct pcd_observer *pcd;

	TEST_START;

	pcd = manifest_verification_get_pcd_observer (NULL);
	CuAssertPtrEquals (test, NULL, pcd);
}

static void manifest_verification_test_verify_signature_no_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_no_key_stored_bad_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST2,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_no_key_stored_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_match_default (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_higher_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 9);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_same_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 10);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_bad_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST2,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_higher_id_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 9);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_same_id_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 10);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (NULL, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, NULL,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, NULL, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, 0);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_no_key_stored_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_VERIFY_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_verify_signature_key_stored_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_VERIFY_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_no_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	uint8_t pfm_hash[SHA384_HASH_LENGTH];

	TEST_START;

	memset (pfm_hash, 0x55, sizeof (pfm_hash));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, sizeof (pfm_hash),
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, pfm_hash, sizeof (pfm_hash), 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (pfm_hash, sizeof (pfm_hash)), MOCK_ARG (sizeof (pfm_hash)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	uint8_t pfm_hash[SHA512_HASH_LENGTH];

	TEST_START;

	memset (pfm_hash, 0x55, sizeof (pfm_hash));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, sizeof (pfm_hash),
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, pfm_hash, sizeof (pfm_hash), 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (pfm_hash, sizeof (pfm_hash)), MOCK_ARG (sizeof (pfm_hash)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_match_default (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_higher_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 9);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_same_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 10);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm,
		MANIFEST_GET_SIGNATURE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_rsa_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pfm_activated_key_stored_save_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_cfm_activated_no_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct cfm_mock cfm;
	int status;
	struct cfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_cfm_observer (&verification);
	observer->on_cfm_activated (observer, &cfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_cfm_activated_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct cfm_mock cfm;
	int status;
	struct cfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_signature, &cfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&cfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_cfm_observer (&verification);
	observer->on_cfm_activated (observer, &cfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_cfm_activated_key_stored_match_default (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct cfm_mock cfm;
	int status;
	struct cfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_signature, &cfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&cfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_cfm_observer (&verification);
	observer->on_cfm_activated (observer, &cfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pcd_activated_no_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pcd_mock pcd;
	int status;
	struct pcd_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pcd_observer (&verification);
	observer->on_pcd_activated (observer, &pcd.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pcd_activated_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pcd_mock pcd;
	int status;
	struct pcd_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_signature, &pcd, RSA_MAX_KEY_LENGTH,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pcd.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pcd_observer (&verification);
	observer->on_pcd_activated (observer, &pcd.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_pcd_activated_key_stored_match_default (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pcd_mock pcd;
	int status;
	struct pcd_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_signature, &pcd, RSA_MAX_KEY_LENGTH,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pcd.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pcd_observer (&verification);
	observer->on_pcd_activated (observer, &pcd.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_update_start_no_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_no_key (test, &keystore, &manifest_key);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_on_update_start_key_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	int status;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_verify_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_on_pfm_activated (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_on_update_start (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_hash_error_verify_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_hash_error_on_update_start (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_signature_error_verify_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm,
		MANIFEST_GET_SIGNATURE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_signature_error_on_update_start (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm,
		MANIFEST_GET_SIGNATURE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_rsa_error_verify_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_rsa_error_on_update_start (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)),
		MOCK_ARG_PTR_CONTAINS (manifest_key.signature, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&rsa.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_VERIFY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3)),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_save_error_verify_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_save_error_on_pfm_activated (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_save_error_twice_on_pfm_activated (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_save_error_on_update_start (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_save_error_on_update_start_save_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, update_status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_save_error_on_update_start_already_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;
	int update_status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN, 1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	update_status = -1;
	verification.base_update.on_update_start (&verification.base_update, &update_status);
	CuAssertIntEquals (test, -1, update_status);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&manifest_key, sizeof (manifest_key)),
		MOCK_ARG (sizeof (manifest_key)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &pfm.base);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_verification_test_after_default_activated_match_stored (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct manifest_verification_key manifest_key;
	struct manifest_verification verification;
	struct pfm_mock pfm;
	int status;
	struct pfm_observer *observer;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_initialize_stored_key (test, &keystore, &manifest_key, 11);

	status = manifest_verification_init (&verification, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		&manifest_key, &keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SIG_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_signature, &pfm, RSA_ENCRYPT_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification);
	observer->on_pfm_activated (observer, &pfm.base);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base_verify.verify_signature (&verification.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


TEST_SUITE_START (manifest_verification);

TEST (manifest_verification_test_init_no_key_stored);
TEST (manifest_verification_test_init_key_stored);
TEST (manifest_verification_test_init_bad_key_stored);
TEST (manifest_verification_test_init_bad_length_stored);
TEST (manifest_verification_test_init_bad_signature_stored);
TEST (manifest_verification_test_init_null);
TEST (manifest_verification_test_init_manifest_key_bad_signature);
TEST (manifest_verification_test_init_manifest_key_hash_error);
TEST (manifest_verification_test_init_manifest_key_signature_error);
TEST (manifest_verification_test_init_load_error);
TEST (manifest_verification_test_init_stored_key_hash_error);
TEST (manifest_verification_test_init_stored_key_signature_error);
TEST (manifest_verification_test_init_save_error);
TEST (manifest_verification_test_release_null);
TEST (manifest_verification_test_get_observers);
TEST (manifest_verification_test_get_pfm_observer_null);
TEST (manifest_verification_test_get_cfm_observer_null);
TEST (manifest_verification_test_get_pcd_observer_null);
TEST (manifest_verification_test_verify_signature_no_key_stored);
TEST (manifest_verification_test_verify_signature_no_key_stored_bad_hash);
TEST (manifest_verification_test_verify_signature_no_key_stored_bad_signature);
TEST (manifest_verification_test_verify_signature_key_stored);
TEST (manifest_verification_test_verify_signature_key_stored_match_default);
TEST (manifest_verification_test_verify_signature_key_stored_higher_id);
TEST (manifest_verification_test_verify_signature_key_stored_same_id);
TEST (manifest_verification_test_verify_signature_key_stored_bad_hash);
TEST (manifest_verification_test_verify_signature_key_stored_bad_signature);
TEST (manifest_verification_test_verify_signature_key_stored_higher_id_bad_signature);
TEST (manifest_verification_test_verify_signature_key_stored_same_id_bad_signature);
TEST (manifest_verification_test_verify_signature_null);
TEST (manifest_verification_test_verify_signature_no_key_stored_signature_error);
TEST (manifest_verification_test_verify_signature_key_stored_signature_error);
TEST (manifest_verification_test_on_pfm_activated_no_key_stored);
TEST (manifest_verification_test_on_pfm_activated_key_stored);
TEST (manifest_verification_test_on_pfm_activated_key_stored_sha384);
TEST (manifest_verification_test_on_pfm_activated_key_stored_sha512);
TEST (manifest_verification_test_on_pfm_activated_key_stored_match_default);
TEST (manifest_verification_test_on_pfm_activated_key_stored_higher_id);
TEST (manifest_verification_test_on_pfm_activated_key_stored_same_id);
TEST (manifest_verification_test_on_pfm_activated_key_stored_hash_error);
TEST (manifest_verification_test_on_pfm_activated_key_stored_signature_error);
TEST (manifest_verification_test_on_pfm_activated_key_stored_rsa_error);
TEST (manifest_verification_test_on_pfm_activated_key_stored_save_error);
TEST (manifest_verification_test_on_cfm_activated_no_key_stored);
TEST (manifest_verification_test_on_cfm_activated_key_stored);
TEST (manifest_verification_test_on_cfm_activated_key_stored_match_default);
TEST (manifest_verification_test_on_pcd_activated_no_key_stored);
TEST (manifest_verification_test_on_pcd_activated_key_stored);
TEST (manifest_verification_test_on_pcd_activated_key_stored_match_default);
TEST (manifest_verification_test_on_update_start_no_key_stored);
TEST (manifest_verification_test_on_update_start_key_stored);
TEST (manifest_verification_test_after_default_activated_verify_signature);
TEST (manifest_verification_test_after_default_activated_on_pfm_activated);
TEST (manifest_verification_test_after_default_activated_on_update_start);
TEST (manifest_verification_test_after_default_activated_hash_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_hash_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_signature_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_signature_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_rsa_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_rsa_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_save_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_save_error_on_pfm_activated);
TEST (manifest_verification_test_after_default_activated_save_error_twice_on_pfm_activated);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start_save_error);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start_already_error);
TEST (manifest_verification_test_after_default_activated_match_stored);

TEST_SUITE_END;
