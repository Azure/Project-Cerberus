// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "manifest/manifest_logging.h"
#include "manifest/manifest_verification.h"
#include "manifest/manifest_verification_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/cfm/cfm_mock.h"
#include "testing/mock/manifest/pcd/pcd_mock.h"
#include "testing/mock/manifest/pfm/pfm_mock.h"


TEST_SUITE_LABEL ("manifest_verification");


/**
 * Dependencies for testing the verification wrapper for manifests.
 */
struct manifest_verification_testing {
	HASH_TESTING_ENGINE hash;							/**< Hash engine for testing. */
	struct hash_engine_mock hash_mock;					/**< Mock for hashing. */
	struct signature_verification_mock verify_mock;		/**< Mock for signature verification. */
	struct keystore_mock keystore;						/**< Mock for the manifest keystore. */
	struct logging_mock log;							/**< Mock for the debug log. */
	struct pfm_mock pfm;								/**< Mock for a PFM. */
	struct cfm_mock cfm;								/**< Mock for a CFM. */
	struct pcd_mock pcd;								/**< Mock for a PCD. */
	struct manifest_verification_key_rsa manifest_rsa;	/**< Default RSA key for verification. */
	struct manifest_verification_key_ecc manifest_ecc;	/**< Default ECC key for verification. */
	struct manifest_verification_key manifest_key;		/**< The default key for verification. */
	uint8_t manifest_key_hash[SHA512_HASH_LENGTH];		/**< Hash of the default verification key. */
	uint8_t stored_key_hash[SHA512_HASH_LENGTH];		/**< Hash of the stored verification key. */
	struct manifest_verification_state state;			/**< Variable state for the verifier. */
	struct manifest_verification test;					/**< The manifest verifier under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param id ID to assign to the default manifest key.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_init_dependencies (CuTest *test,
	struct manifest_verification_testing *verification, uint32_t id, enum hash_type key_hash)
{
	struct manifest_verification_key_rsa *manifest_rsa = &verification->manifest_rsa;
	int status;

	status = HASH_TESTING_ENGINE_INIT (&verification->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&verification->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification->verify_mock);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&verification->keystore);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&verification->log);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&verification->pfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&verification->cfm);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&verification->pcd);
	CuAssertIntEquals (test, 0, status);

	memset (manifest_rsa, 0, sizeof (*manifest_rsa));
	manifest_rsa->id = id;
	memcpy (&manifest_rsa->key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) manifest_rsa,
		sizeof (*manifest_rsa) - sizeof (manifest_rsa->signature), RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, manifest_rsa->signature, sizeof (manifest_rsa->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification->hash.base, key_hash, (uint8_t*) manifest_rsa,
		sizeof (*manifest_rsa) - sizeof (manifest_rsa->signature), verification->manifest_key_hash,
		sizeof (verification->manifest_key_hash));
	CuAssertIntEquals (test, hash_get_hash_length (key_hash), status);

	verification->manifest_key.key_data = (uint8_t*) manifest_rsa;
	verification->manifest_key.key_data_length = sizeof (*manifest_rsa);
	verification->manifest_key.key =
		(struct manifest_verification_key_header*) verification->manifest_key.key_data;
	verification->manifest_key.pub_key_length = sizeof (struct rsa_public_key);
	verification->manifest_key.signature = verification->manifest_key.key_data +
		(sizeof (*manifest_rsa) - sizeof (manifest_rsa->signature));
	verification->manifest_key.sig_length = sizeof (manifest_rsa->signature);
	verification->manifest_key.sig_hash = key_hash;

	debug_log = &verification->log.base;
}

/**
 * Set up expectations for verifying the default manifest key during initialization.
 *
 * @param test The test framework.
 * @param verification Testing dependencies.
 * @param key_hash Hash algorithm to use for signature verification of the key.
 */
static void manifest_verification_testing_init_manifest_key (CuTest *test,
	struct manifest_verification_testing *verification, enum hash_type key_hash)
{
	struct manifest_verification_key_rsa *manifest_rsa = &verification->manifest_rsa;
	int status;

	status = mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.set_verification_key, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.verify_signature, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification->manifest_key_hash, hash_get_hash_length (key_hash)),
		MOCK_ARG (hash_get_hash_length (key_hash)),
		MOCK_ARG_PTR_CONTAINS (manifest_rsa->signature, sizeof (manifest_rsa->signature)),
		MOCK_ARG (sizeof (manifest_rsa->signature)));

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.is_key_valid, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up expectations for verifying the default manifest key during initialization using an ECC
 * key.
 *
 * @param test The test framework.
 * @param verification Testing dependencies.
 * @param id ID to assign to the default manifest key.
 * @param key_hash Hash algorithm to use for signature verification of the key.
 */
static void manifest_verification_testing_init_ecc_manifest_key (CuTest *test,
	struct manifest_verification_testing *verification, uint32_t id, enum hash_type key_hash)
{
	struct manifest_verification_key_ecc *manifest_ecc = &verification->manifest_ecc;
	int status;

	memset (manifest_ecc, 0, sizeof (*manifest_ecc));
	manifest_ecc->id = id;
	memcpy (&manifest_ecc->key, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN);
	memcpy (&manifest_ecc->signature, ECC384_SIGNATURE_TEST2, ECC384_SIG_TEST2_LEN);

	status = hash_calculate (&verification->hash.base, key_hash, (uint8_t*) manifest_ecc,
		sizeof (*manifest_ecc) - sizeof (manifest_ecc->signature), verification->manifest_key_hash,
		sizeof (verification->manifest_key_hash));
	CuAssertIntEquals (test, hash_get_hash_length (key_hash), status);

	verification->manifest_key.key_data = (uint8_t*) manifest_ecc;
	verification->manifest_key.key_data_length = sizeof (*manifest_ecc);
	verification->manifest_key.key =
		(struct manifest_verification_key_header*) verification->manifest_key.key_data;
	verification->manifest_key.pub_key_length = sizeof (manifest_ecc->key);
	verification->manifest_key.signature = verification->manifest_key.key_data +
		(sizeof (*manifest_ecc) - sizeof (manifest_ecc->signature));
	verification->manifest_key.sig_length = sizeof (manifest_ecc->signature);
	verification->manifest_key.sig_hash = key_hash;

	status = mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.set_verification_key, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.verify_signature, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification->manifest_key_hash, hash_get_hash_length (key_hash)),
		MOCK_ARG (hash_get_hash_length (key_hash)),
		MOCK_ARG_PTR_CONTAINS (manifest_ecc->signature, sizeof (manifest_ecc->signature)),
		MOCK_ARG (sizeof (manifest_ecc->signature)));

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.is_key_valid, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (manifest_ecc->key)));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to initialize all dependencies for testing with no key for manifest verification stored in
 * the keystore.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_init_dependencies_no_key (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, enum hash_type key_hash)
{
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = keystore_id,
		.arg2 = KEYSTORE_NO_KEY
	};

	manifest_verification_testing_init_dependencies (test, verification, 1, key_hash);
	manifest_verification_testing_init_manifest_key (test, verification, key_hash);

	status = mock_expect (&verification->keystore.mock, verification->keystore.base.load_key,
		&verification->keystore, KEYSTORE_NO_KEY, MOCK_ARG (keystore_id), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&verification->keystore.mock, 1, &stored_key,
		sizeof (stored_key), -1);

	status |= mock_expect (&verification->log.mock, verification->log.base.create_entry,
		&verification->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification->keystore.mock, verification->keystore.base.save_key,
		&verification->keystore, 0, MOCK_ARG (keystore_id),
		MOCK_ARG_PTR_CONTAINS (&verification->manifest_rsa, sizeof (verification->manifest_rsa)),
		MOCK_ARG (sizeof (verification->manifest_rsa)));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to initialize all dependencies for testing with no key for manifest verification stored in
 * the keystore.  The verification key will be an ECC key.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_init_dependencies_no_key_ecc (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, enum hash_type key_hash)
{
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = keystore_id,
		.arg2 = KEYSTORE_NO_KEY
	};

	manifest_verification_testing_init_dependencies (test, verification, 1, key_hash);
	manifest_verification_testing_init_ecc_manifest_key (test, verification, 1, key_hash);

	status = mock_expect (&verification->keystore.mock, verification->keystore.base.load_key,
		&verification->keystore, KEYSTORE_NO_KEY, MOCK_ARG (keystore_id), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&verification->keystore.mock, 1, &stored_key,
		sizeof (stored_key), -1);

	status |= mock_expect (&verification->log.mock, verification->log.base.create_entry,
		&verification->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification->keystore.mock, verification->keystore.base.save_key,
		&verification->keystore, 0, MOCK_ARG (keystore_id),
		MOCK_ARG_PTR_CONTAINS (&verification->manifest_ecc, sizeof (verification->manifest_ecc)),
		MOCK_ARG (sizeof (verification->manifest_ecc)));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to initialize all dependencies for testing with a key for manifest verification stored in
 * the keystore.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param id The version ID for the manifest key.  The stored key will use ID 10.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_init_dependencies_stored_key (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, uint32_t id,
	enum hash_type key_hash)
{
	struct manifest_verification_key_rsa *stored_key;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	size_t hash_length;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_MANIFEST_KEY_REVOKED,
		.arg1 = keystore_id,
		.arg2 = 10
	};

	manifest_verification_testing_init_dependencies (test, verification, id, key_hash);
	manifest_verification_testing_init_manifest_key (test, verification, key_hash);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 10;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	hash_length = hash_calculate (&verification->hash.base, key_hash, (uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification->stored_key_hash,
		sizeof (verification->stored_key_hash));
	CuAssertIntEquals (test, hash_get_hash_length (key_hash), hash_length);

	status = mock_expect (&verification->keystore.mock, verification->keystore.base.load_key,
		&verification->keystore, 0, MOCK_ARG (keystore_id), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&verification->keystore.mock, 1, &stored_key,
		sizeof (stored_key), -1);
	status |= mock_expect_output_tmp (&verification->keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.verify_signature, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification->stored_key_hash, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.is_key_valid, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	if (id <= 10) {
		status |= mock_expect (&verification->log.mock, verification->log.base.create_entry,
			&verification->log, 0,
			MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
			MOCK_ARG (sizeof (entry)));
	}

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to initialize all dependencies for testing with a key for manifest verification stored in
 * the keystore.  The verification keys are ECC keys.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param id The version ID for the manifest key.  The stored key will use ID 10.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_init_dependencies_ecc_stored_key (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, uint32_t id,
	enum hash_type key_hash)
{
	struct manifest_verification_key_ecc *stored_key;
	size_t stored_length = sizeof (struct manifest_verification_key_ecc);
	size_t hash_length;
	int status;

	manifest_verification_testing_init_dependencies (test, verification, id, key_hash);
	manifest_verification_testing_init_ecc_manifest_key (test, verification, id, key_hash);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 10;
	memcpy (&stored_key->key, ECC_PUBKEY3_DER, ECC_PUBKEY3_DER_LEN);
	memcpy (&stored_key->signature, ECC384_SIGNATURE_NOPE, ECC384_SIG_NOPE_LEN);

	hash_length = hash_calculate (&verification->hash.base, key_hash, (uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification->stored_key_hash,
		sizeof (verification->stored_key_hash));
	CuAssertIntEquals (test, hash_get_hash_length (key_hash), hash_length);

	status = mock_expect (&verification->keystore.mock, verification->keystore.base.load_key,
		&verification->keystore, 0, MOCK_ARG (keystore_id), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&verification->keystore.mock, 1, &stored_key,
		sizeof (stored_key), -1);
	status |= mock_expect_output_tmp (&verification->keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.verify_signature, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification->stored_key_hash, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification->verify_mock.mock,
		verification->verify_mock.base.is_key_valid, &verification->verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY3_DER, ECC_PUBKEY3_DER_LEN),
		MOCK_ARG (sizeof (stored_key->key)));

	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up initialization with no key for manifest verification stored in the keystore.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_initialize_no_key (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, enum hash_type key_hash)
{
	int status;

	manifest_verification_testing_init_dependencies_no_key (test, verification, keystore_id,
		key_hash);

	status = manifest_verification_init (&verification->test, &verification->state,
		&verification->hash.base, &verification->verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification->manifest_key, &verification->keystore.base,
		keystore_id);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification->keystore.mock);
	status |= mock_validate (&verification->verify_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up initialization with no key for manifest verification stored in the keystore.  Verification
 * keys will be ECC keys.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_initialize_no_key_ecc (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, enum hash_type key_hash)
{
	int status;

	manifest_verification_testing_init_dependencies_no_key_ecc (test, verification, keystore_id,
		key_hash);

	status = manifest_verification_init (&verification->test, &verification->state,
		&verification->hash.base, &verification->verify_mock.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &verification->manifest_key, &verification->keystore.base, keystore_id);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification->keystore.mock);
	status |= mock_validate (&verification->verify_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up initialization with a key for manifest verification stored in the keystore.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param id The version ID for the manifest key.  The stored key will use ID 10.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_initialize_stored_key (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, uint32_t id,
	enum hash_type key_hash)
{
	int status;

	manifest_verification_testing_init_dependencies_stored_key (test, verification, keystore_id, id,
		key_hash);

	status = manifest_verification_init (&verification->test, &verification->state,
		&verification->hash.base, &verification->verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification->manifest_key, &verification->keystore.base,
		keystore_id);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification->keystore.mock);
	status |= mock_validate (&verification->verify_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up initialization with a key for manifest verification stored in the keystore.  Verification
 * keys will be ECC keys.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to initialize.
 * @param keystore_id ID of the manifest key in the keystore.
 * @param id The version ID for the manifest key.  The stored key will use ID 10.
 * @param key_hash Hash algorithm to use for signature verification of manifest keys.
 */
static void manifest_verification_testing_initialize_ecc_stored_key (CuTest *test,
	struct manifest_verification_testing *verification, int keystore_id, uint32_t id,
	enum hash_type key_hash)
{
	int status;

	manifest_verification_testing_init_dependencies_ecc_stored_key (test, verification, keystore_id,
		id, key_hash);

	status = manifest_verification_init (&verification->test, &verification->state,
		&verification->hash.base, &verification->verify_mock.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &verification->manifest_key, &verification->keystore.base, keystore_id);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification->keystore.mock);
	status |= mock_validate (&verification->verify_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param verification Testing dependencies to release.
 */
static void manifest_verification_testing_release_dependencies (CuTest *test,
	struct manifest_verification_testing *verification)
{
	int status;

	debug_log = NULL;

	status = keystore_mock_validate_and_release (&verification->keystore);
	status |= hash_mock_validate_and_release (&verification->hash_mock);
	status |= signature_verification_mock_validate_and_release (&verification->verify_mock);
	status |= logging_mock_validate_and_release (&verification->log);
	status |= pfm_mock_validate_and_release (&verification->pfm);
	status |= cfm_mock_validate_and_release (&verification->cfm);
	status |= pcd_mock_validate_and_release (&verification->pcd);

	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&verification->hash);
}

/**
 * Release manifest verification test components and validate all mocks.
 *
 * @param test The test framework.
 * @param verification Testing components to release.
 */
static void manifest_verification_testing_release (CuTest *test,
	struct manifest_verification_testing *verification)
{
	manifest_verification_testing_release_dependencies (test, verification);
	manifest_verification_release (&verification->test);
}

/*******************
 * Test cases
 *******************/

static void manifest_verification_test_init_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA256);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.test.base_verify.verify_signature);
	CuAssertPtrNotNull (test, verification.test.base_verify.set_verification_key);
	CuAssertPtrNotNull (test, verification.test.base_verify.is_key_valid);

	CuAssertPtrEquals (test, NULL, verification.test.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.test.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.test.base_observer.on_clear_active);
	CuAssertPtrEquals (test, NULL, verification.test.base_observer.on_pfm_activation_request);

	CuAssertPtrNotNull (test, verification.test.base_update.on_update_start);
	CuAssertPtrEquals (test, NULL, verification.test.base_update.on_prepare_update);
	CuAssertPtrEquals (test, NULL, verification.test.base_update.on_update_applied);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_no_key_stored_signature_sha384 (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA384);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_no_key_stored_signature_sha512 (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA512);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_no_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key_ecc (test, &verification, 1,
		HASH_TYPE_SHA256);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA256);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.test.base_verify.verify_signature);
	CuAssertPtrNotNull (test, verification.test.base_verify.set_verification_key);
	CuAssertPtrNotNull (test, verification.test.base_verify.is_key_valid);

	CuAssertPtrEquals (test, NULL, verification.test.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, verification.test.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, verification.test.base_observer.on_clear_active);
	CuAssertPtrEquals (test, NULL, verification.test.base_observer.on_pfm_activation_request);

	CuAssertPtrNotNull (test, verification.test.base_update.on_update_start);
	CuAssertPtrEquals (test, NULL, verification.test.base_update.on_prepare_update);
	CuAssertPtrEquals (test, NULL, verification.test.base_update.on_update_applied);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_key_stored_signature_sha384 (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA384);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 2);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_key_stored_signature_sha512 (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA512);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 2);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_ecc_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA256);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&verification.manifest_key, &verification.keystore.base, 2);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_load_bad_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = KEYSTORE_BAD_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, KEYSTORE_BAD_KEY, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_stored_key_wrong_length (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 4,
		.arg2 = MANIFEST_VERIFICATION_INVALID_STORED_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY2_DER, RSA_PRIVKEY2_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	stored_length -= 1;

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (4), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (4),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 4);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_stored_key_bad_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = SIG_VERIFICATION_BAD_SIGNATURE
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY2_DER, RSA_PRIVKEY2_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_stored_key_invalid_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = SIG_VERIFICATION_INVALID_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_init_null (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = manifest_verification_init (NULL, &verification.state,	&verification.hash.base,
		&verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		&verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, NULL, &verification.hash.base,
		&verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		&verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, &verification.state, NULL,
		&verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		&verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, NULL, (const uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		&verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, NULL, sizeof (RSA_PUBLIC_KEY),
		&verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		0, &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), NULL, &verification.keystore.base, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, NULL, 1);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_root_key_invalid_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_root_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_manifest_key_hash_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	size_t hash_length =
		sizeof (verification.manifest_rsa) - sizeof (verification.manifest_rsa.signature);

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.hash_mock.mock,
		verification.hash_mock.base.calculate_sha256, &verification.hash_mock,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, hash_length),
		MOCK_ARG (hash_length),	MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash_mock.base, &verification.verify_mock.base,
		(const uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY), &verification.manifest_key,
		&verification.keystore.base, 1);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_manifest_key_bad_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_manifest_key_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_manifest_key_invalid_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_manifest_key_check_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_CHECK_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_CHECK_KEY_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_load_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, KEYSTORE_LOAD_FAILED, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_stored_key_hash_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	size_t hash_length =
		sizeof (verification.manifest_rsa) - sizeof (verification.manifest_rsa.signature);

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.hash_mock.mock,
		verification.hash_mock.base.calculate_sha256, &verification.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.hash_mock.mock, 2, verification.manifest_key_hash,
		SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&verification.hash_mock.mock,
		verification.hash_mock.base.calculate_sha256, &verification.hash_mock,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS_TMP (stored_key, hash_length),
		MOCK_ARG (hash_length), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash_mock.base, &verification.verify_mock.base,
		(const uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY), &verification.manifest_key,
		&verification.keystore.base, 1);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_stored_key_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_stored_key_check_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_CHECK_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_CHECK_KEY_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_init_save_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = KEYSTORE_NO_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, KEYSTORE_NO_KEY, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init (&verification.test, &verification.state,
		&verification.hash.base, &verification.verify_mock.base, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), &verification.manifest_key, &verification.keystore.base, 1);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, test_static.base_verify.verify_signature);
	CuAssertPtrNotNull (test, test_static.base_verify.set_verification_key);
	CuAssertPtrNotNull (test, test_static.base_verify.is_key_valid);

	CuAssertPtrEquals (test, NULL, test_static.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, test_static.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, test_static.base_observer.on_clear_active);
	CuAssertPtrEquals (test, NULL, test_static.base_observer.on_pfm_activation_request);

	CuAssertPtrNotNull (test, test_static.base_update.on_update_start);
	CuAssertPtrEquals (test, NULL, test_static.base_update.on_prepare_update);
	CuAssertPtrEquals (test, NULL, test_static.base_update.on_update_applied);

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_no_key_stored_signature_sha384 (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA384);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_no_key_stored_signature_sha512 (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA512);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_no_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key_ecc (test, &verification, 1,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 2);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, test_static.base_verify.verify_signature);
	CuAssertPtrNotNull (test, test_static.base_verify.set_verification_key);
	CuAssertPtrNotNull (test, test_static.base_verify.is_key_valid);

	CuAssertPtrEquals (test, NULL, test_static.base_observer.on_pfm_verified);
	CuAssertPtrNotNull (test, test_static.base_observer.on_pfm_activated);
	CuAssertPtrEquals (test, NULL, test_static.base_observer.on_clear_active);
	CuAssertPtrEquals (test, NULL, test_static.base_observer.on_pfm_activation_request);

	CuAssertPtrNotNull (test, test_static.base_update.on_update_start);
	CuAssertPtrEquals (test, NULL, test_static.base_update.on_prepare_update);
	CuAssertPtrEquals (test, NULL, test_static.base_update.on_update_applied);

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_key_stored_signature_sha384 (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 2);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA384);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_key_stored_signature_sha512 (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 2);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA512);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 2);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_ecc_stored_key (test, &verification, 2, 11,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_load_bad_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = KEYSTORE_BAD_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, KEYSTORE_BAD_KEY, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_stored_key_wrong_length (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 4);
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 4,
		.arg2 = MANIFEST_VERIFICATION_INVALID_STORED_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY2_DER, RSA_PRIVKEY2_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	stored_length -= 1;

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (4), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (4),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_stored_key_bad_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = SIG_VERIFICATION_BAD_SIGNATURE
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY2_DER, RSA_PRIVKEY2_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_stored_key_invalid_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = SIG_VERIFICATION_INVALID_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_null (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);

	status = manifest_verification_init_state (NULL, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init_state (&test_static, NULL, sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY, 0);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	test_static.state = &verification.state;
	test_static.hash = NULL;
	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	test_static.hash = &verification.hash.base;
	test_static.manifest_verify = NULL;
	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	test_static.manifest_verify = &verification.verify_mock.base;
	test_static.default_key = NULL;
	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	test_static.default_key = &verification.manifest_key;
	test_static.keystore = NULL;
	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_root_key_invalid_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_root_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_manifest_key_hash_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash_mock.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	size_t hash_length =
		sizeof (verification.manifest_rsa) - sizeof (verification.manifest_rsa.signature);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.hash_mock.mock,
		verification.hash_mock.base.calculate_sha256, &verification.hash_mock,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, hash_length),
		MOCK_ARG (hash_length),	MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_manifest_key_bad_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_manifest_key_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_manifest_key_invalid_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_manifest_key_check_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key *manifest_key = &verification.manifest_key;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.manifest_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (manifest_key->signature, manifest_key->sig_length),
		MOCK_ARG (manifest_key->sig_length));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_CHECK_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_CHECK_KEY_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_load_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, KEYSTORE_LOAD_FAILED, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_stored_key_hash_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash_mock.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	size_t hash_length =
		sizeof (verification.manifest_rsa) - sizeof (verification.manifest_rsa.signature);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.hash_mock.mock,
		verification.hash_mock.base.calculate_sha256, &verification.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, hash_length), MOCK_ARG (hash_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.hash_mock.mock, 2, verification.manifest_key_hash,
		SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&verification.hash_mock.mock,
		verification.hash_mock.base.calculate_sha256, &verification.hash_mock,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS_TMP (stored_key, hash_length),
		MOCK_ARG (hash_length), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_stored_key_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_stored_key_check_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	size_t stored_length = sizeof (struct manifest_verification_key_rsa);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 2, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	stored_key = platform_malloc (stored_length);
	CuAssertPtrNotNull (test, stored_key);

	memset (stored_key, 0, sizeof (*stored_key));
	stored_key->id = 1;
	memcpy (&stored_key->key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	status = RSA_TESTING_ENGINE_SIGN ((uint8_t*) stored_key,
		stored_length - sizeof (stored_key->signature), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		stored_key->signature, sizeof (stored_key->signature));
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&verification.hash.base, HASH_TYPE_SHA256,	(uint8_t*) stored_key,
		sizeof (*stored_key) - sizeof (stored_key->signature), verification.stored_key_hash,
		sizeof (verification.stored_key_hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);
	status |= mock_expect_output (&verification.keystore.mock, 2, &stored_length,
		sizeof (stored_length), -1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (verification.stored_key_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS_TMP (stored_key->signature, sizeof (stored_key->signature)),
		MOCK_ARG (sizeof (stored_key->signature)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.is_key_valid, &verification.verify_mock,
		SIG_VERIFICATION_CHECK_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_CHECK_KEY_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_static_init_save_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	struct manifest_verification_key_rsa *stored_key = NULL;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY,
		.arg1 = 1,
		.arg2 = KEYSTORE_NO_KEY
	};

	TEST_START;

	manifest_verification_testing_init_dependencies (test, &verification, 1, HASH_TYPE_SHA256);
	manifest_verification_testing_init_manifest_key (test, &verification, HASH_TYPE_SHA256);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.load_key,
		&verification.keystore, KEYSTORE_NO_KEY, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&verification.keystore.mock, 1, &stored_key, sizeof (stored_key),
		-1);

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_verification_release (NULL);
}

static void manifest_verification_test_get_observers (CuTest *test)
{
	struct manifest_verification_testing verification;
	const struct pfm_observer *pfm;
	const struct cfm_observer *cfm;
	const struct pcd_observer *pcd;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	pfm = manifest_verification_get_pfm_observer (&verification.test);
	CuAssertPtrNotNull (test, pfm);

	cfm = manifest_verification_get_cfm_observer (&verification.test);
	CuAssertPtrNotNull (test, cfm);

	pcd = manifest_verification_get_pcd_observer (&verification.test);
	CuAssertPtrNotNull (test, pcd);

	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_activated),
		offsetof (struct cfm_observer, on_cfm_activated));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_verified),
		offsetof (struct cfm_observer, on_cfm_verified));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_clear_active),
		offsetof (struct cfm_observer, on_clear_active));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_activation_request),
		offsetof (struct cfm_observer, on_cfm_activation_request));

	CuAssertPtrEquals (test, pfm->on_pfm_activated, cfm->on_cfm_activated);
	CuAssertPtrEquals (test, pfm->on_pfm_verified, cfm->on_cfm_verified);
	CuAssertPtrEquals (test, pfm->on_clear_active, cfm->on_clear_active);
	CuAssertPtrEquals (test, pfm->on_pfm_activation_request, cfm->on_cfm_activation_request);

	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_activated),
		offsetof (struct pcd_observer, on_pcd_activated));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_verified),
		offsetof (struct pcd_observer, on_pcd_verified));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_clear_active),
		offsetof (struct pcd_observer, on_clear_active));
	CuAssertIntEquals (test, offsetof (struct pfm_observer, on_pfm_activation_request),
		offsetof (struct pcd_observer, on_pcd_activation_request));

	CuAssertPtrEquals (test, pfm->on_pfm_activated, pcd->on_pcd_activated);
	CuAssertPtrEquals (test, pfm->on_pfm_verified, pcd->on_pcd_verified);
	CuAssertPtrEquals (test, pfm->on_clear_active, pcd->on_clear_active);
	CuAssertPtrEquals (test, pfm->on_pfm_activation_request, pcd->on_pcd_activation_request);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_get_pfm_observer_null (CuTest *test)
{
	const struct pfm_observer *pfm;

	TEST_START;

	pfm = manifest_verification_get_pfm_observer (NULL);
	CuAssertPtrEquals (test, NULL, (void*) pfm);
}

static void manifest_verification_test_get_cfm_observer_null (CuTest *test)
{
	const struct cfm_observer *cfm;

	TEST_START;

	cfm = manifest_verification_get_cfm_observer (NULL);
	CuAssertPtrEquals (test, NULL, (void*) cfm);
}

static void manifest_verification_test_get_pcd_observer_null (CuTest *test)
{
	const struct pcd_observer *pcd;

	TEST_START;

	pcd = manifest_verification_get_pcd_observer (NULL);
	CuAssertPtrEquals (test, NULL, (void*) pcd);
}

static void manifest_verification_test_verify_signature_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_no_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key_ecc (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_no_key_stored_bad_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_ecc_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY3_DER, ECC_PUBKEY3_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_match_default (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_higher_id (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 9,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_same_id (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 10,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_bad_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_higher_id_bad_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 9,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_same_id_bad_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 10,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_static_init_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_verify.verify_signature (&test_static.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_verify_signature_static_init_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_verify.verify_signature (&test_static.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_verify_signature_static_init_key_stored_higher_id (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 9,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_verify.verify_signature (&test_static.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_verify_signature_static_init_key_stored_same_id (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 10,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_verify.verify_signature (&test_static.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void
manifest_verification_test_verify_signature_static_init_key_stored_higher_id_bad_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 9,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_verify.verify_signature (&test_static.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_verify_signature_static_init_key_stored_same_id_bad_signature
(
	CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 10,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_verify.verify_signature (&test_static.base_verify, SIG_HASH_TEST,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_verify_signature_null (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = verification.test.base_verify.verify_signature (NULL, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify, NULL,
		SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, NULL, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, 0);
	CuAssertIntEquals (test, MANIFEST_VERIFICATION_INVALID_ARGUMENT, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_no_key_stored_set_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_no_key_stored_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_set_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_verify_signature_key_stored_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_set_verification_key (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = verification.test.base_verify.set_verification_key (&verification.test.base_verify,
		(const uint8_t*) &RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key));
	CuAssertIntEquals (test, SIG_VERIFICATION_UNSUPPORTED, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_is_key_valid (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	status = verification.test.base_verify.is_key_valid (&verification.test.base_verify,
		(const uint8_t*) &RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key));
	CuAssertIntEquals (test, SIG_VERIFICATION_UNSUPPORTED, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_ecc_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, ECC384_SIG_TEST_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN, 1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_sha384 (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	uint8_t pfm_hash[SHA384_HASH_LENGTH];

	TEST_START;

	memset (pfm_hash, 0x55, sizeof (pfm_hash));

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, sizeof (pfm_hash), MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, pfm_hash, sizeof (pfm_hash), 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (pfm_hash, sizeof (pfm_hash)),
		MOCK_ARG (sizeof (pfm_hash)), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_sha512 (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	uint8_t pfm_hash[SHA512_HASH_LENGTH];

	TEST_START;

	memset (pfm_hash, 0x55, sizeof (pfm_hash));

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, sizeof (pfm_hash), MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, pfm_hash, sizeof (pfm_hash), 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (pfm_hash, sizeof (pfm_hash)),
		MOCK_ARG (sizeof (pfm_hash)), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_match_default (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_match_default_ecc (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_ecc_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, ECC384_SIG_TEST_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN, 1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_ecc, sizeof (verification.manifest_ecc)),
		MOCK_ARG (sizeof (verification.manifest_ecc)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_higher_id (CuTest *test)
{
	struct manifest_verification_testing verification;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 9,
		HASH_TYPE_SHA256);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_same_id (CuTest *test)
{
	struct manifest_verification_testing verification;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 10,
		HASH_TYPE_SHA256);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_static_init_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	const struct pfm_observer *observer;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_no_key (test, &verification, 1,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&test_static);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_static_init_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	const struct pfm_observer *observer;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&test_static);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_static_init_key_stored_higher_id (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	const struct pfm_observer *observer;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 9,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&test_static);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_static_init_key_stored_same_id (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	struct manifest_verification test_static =
		manifest_verification_static_init (&verification.state, &verification.hash.base,
		&verification.verify_mock.base,	&verification.manifest_key, &verification.keystore.base, 1);
	const struct pfm_observer *observer;
	int status;

	TEST_START;

	manifest_verification_testing_init_dependencies_stored_key (test, &verification, 1, 10,
		HASH_TYPE_SHA256);

	status = manifest_verification_init_state (&test_static, (const uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&test_static);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_release (&test_static);
	manifest_verification_testing_release_dependencies (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_hash_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = MANIFEST_GET_HASH_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, MANIFEST_GET_HASH_FAILED, MOCK_ARG_PTR (&verification.hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_signature_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = MANIFEST_GET_SIGNATURE_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, MANIFEST_GET_SIGNATURE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_MAX_KEY_LENGTH));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_set_key_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = SIG_VERIFICATION_SET_KEY_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_verify_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = SIG_VERIFICATION_VERIFY_SIG_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pfm_activated_key_stored_save_error (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = KEYSTORE_SAVE_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_cfm_activated_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	const struct cfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	observer = manifest_verification_get_cfm_observer (&verification.test);
	observer->on_cfm_activated (observer, &verification.cfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_cfm_activated_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct cfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.cfm.mock, verification.cfm.base.base.get_hash,
		&verification.cfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.cfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.cfm.mock, verification.cfm.base.base.get_signature,
		&verification.cfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.cfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_cfm_observer (&verification.test);
	observer->on_cfm_activated (observer, &verification.cfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_cfm_activated_key_stored_match_default (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct cfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.cfm.mock, verification.cfm.base.base.get_hash,
		&verification.cfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.cfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.cfm.mock, verification.cfm.base.base.get_signature,
		&verification.cfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.cfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_cfm_observer (&verification.test);
	observer->on_cfm_activated (observer, &verification.cfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pcd_activated_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	const struct pcd_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	observer = manifest_verification_get_pcd_observer (&verification.test);
	observer->on_pcd_activated (observer, &verification.pcd.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pcd_activated_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pcd_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pcd.mock, verification.pcd.base.base.get_hash,
		&verification.pcd, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pcd.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pcd.mock, verification.pcd.base.base.get_signature,
		&verification.pcd, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pcd.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pcd_observer (&verification.test);
	observer->on_pcd_activated (observer, &verification.pcd.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_pcd_activated_key_stored_match_default (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pcd_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pcd.mock, verification.pcd.base.base.get_hash,
		&verification.pcd, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pcd.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pcd.mock, verification.pcd.base.base.get_signature,
		&verification.pcd, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pcd.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pcd_observer (&verification.test);
	observer->on_pcd_activated (observer, &verification.pcd.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_update_start_no_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_no_key (test, &verification, 1, HASH_TYPE_SHA256);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_on_update_start_key_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_verify_signature (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_on_pfm_activated (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_on_update_start (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_hash_error_verify_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, MANIFEST_GET_HASH_FAILED, MOCK_ARG_PTR (&verification.hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_hash_error_on_update_start (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, MANIFEST_GET_HASH_FAILED, MOCK_ARG_PTR (&verification.hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_signature_error_verify_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, MANIFEST_GET_SIGNATURE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_MAX_KEY_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_signature_error_on_update_start (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, MANIFEST_GET_SIGNATURE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_MAX_KEY_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_set_key_error_verify_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_set_key_error_on_update_start (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_verify_error_verify_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_verify_error_on_update_start (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_verify_signature (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_on_pfm_activated (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_on_pfm_activated_ecc (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_ecc_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, ECC384_SIG_TEST_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN, 1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_ecc, sizeof (verification.manifest_ecc)),
		MOCK_ARG (sizeof (verification.manifest_ecc)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_ecc, sizeof (verification.manifest_ecc)),
		MOCK_ARG (sizeof (verification.manifest_ecc)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_twice_on_pfm_activated (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = KEYSTORE_SAVE_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_on_update_start (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_on_update_start_ecc (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_ecc_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, ECC384_SIG_TEST_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN, 1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_ecc, sizeof (verification.manifest_ecc)),
		MOCK_ARG (sizeof (verification.manifest_ecc)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_ecc, sizeof (verification.manifest_ecc)),
		MOCK_ARG (sizeof (verification.manifest_ecc)));
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, 0, update_status);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (sizeof (verification.manifest_ecc.key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_save_error_on_update_start_save_error
(
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_KEY_REVOCATION_FAIL,
		.arg1 = 1,
		.arg2 = KEYSTORE_SAVE_FAILED
	};

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	status |= mock_expect (&verification.log.mock, verification.log.base.create_entry,
		&verification.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	update_status = 0;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, update_status);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void
manifest_verification_test_after_default_activated_save_error_on_update_start_already_error (
	CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;
	int update_status;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	debug_log = NULL;

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	update_status = -1;
	verification.test.base_update.on_update_start (&verification.test.base_update, &update_status);
	CuAssertIntEquals (test, -1, update_status);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.keystore.mock, verification.keystore.base.save_key,
		&verification.keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (&verification.manifest_rsa, sizeof (verification.manifest_rsa)),
		MOCK_ARG (sizeof (verification.manifest_rsa)));
	CuAssertIntEquals (test, 0, status);

	observer->on_pfm_activated (observer, &verification.pfm.base);

	manifest_verification_testing_release (test, &verification);
}

static void manifest_verification_test_after_default_activated_match_stored (CuTest *test)
{
	struct manifest_verification_testing verification;
	int status;
	const struct pfm_observer *observer;

	TEST_START;

	manifest_verification_testing_initialize_stored_key (test, &verification, 1, 11,
		HASH_TYPE_SHA256);

	status = mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_hash,
		&verification.pfm, SIG_HASH_LEN, MOCK_ARG_PTR (&verification.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 1, SIG_HASH_TEST, SIG_HASH_LEN, 2);

	status |= mock_expect (&verification.pfm.mock, verification.pfm.base.base.get_signature,
		&verification.pfm, RSA_ENCRYPT_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_MAX_KEY_LENGTH));
	status |= mock_expect_output (&verification.pfm.mock, 0, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN,
		1);

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	observer = manifest_verification_get_pfm_observer (&verification.test);
	observer->on_pfm_activated (observer, &verification.pfm.base);

	status = mock_validate (&verification.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.verify_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY3, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock,
		SIG_VERIFICATION_BAD_SIGNATURE,	MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.set_verification_key, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_PUBLIC_KEY2, sizeof (struct rsa_public_key)),
		MOCK_ARG (sizeof (struct rsa_public_key)));

	status |= mock_expect (&verification.verify_mock.mock,
		verification.verify_mock.base.verify_signature, &verification.verify_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = verification.test.base_verify.verify_signature (&verification.test.base_verify,
		SIG_HASH_TEST, SIG_HASH_LEN, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	manifest_verification_testing_release (test, &verification);
}


// *INDENT-OFF*
TEST_SUITE_START (manifest_verification);

TEST (manifest_verification_test_init_no_key_stored);
TEST (manifest_verification_test_init_no_key_stored_signature_sha384);
TEST (manifest_verification_test_init_no_key_stored_signature_sha512);
TEST (manifest_verification_test_init_no_key_stored_ecc);
TEST (manifest_verification_test_init_key_stored);
TEST (manifest_verification_test_init_key_stored_signature_sha384);
TEST (manifest_verification_test_init_key_stored_signature_sha512);
TEST (manifest_verification_test_init_key_stored_ecc);
TEST (manifest_verification_test_init_load_bad_key);
TEST (manifest_verification_test_init_stored_key_wrong_length);
TEST (manifest_verification_test_init_stored_key_bad_signature);
TEST (manifest_verification_test_init_stored_key_invalid_key);
TEST (manifest_verification_test_init_null);
TEST (manifest_verification_test_init_root_key_invalid_key);
TEST (manifest_verification_test_init_root_key_error);
TEST (manifest_verification_test_init_manifest_key_hash_error);
TEST (manifest_verification_test_init_manifest_key_bad_signature);
TEST (manifest_verification_test_init_manifest_key_verify_error);
TEST (manifest_verification_test_init_manifest_key_invalid_key);
TEST (manifest_verification_test_init_manifest_key_check_key_error);
TEST (manifest_verification_test_init_load_error);
TEST (manifest_verification_test_init_stored_key_hash_error);
TEST (manifest_verification_test_init_stored_key_verify_error);
TEST (manifest_verification_test_init_stored_key_check_key_error);
TEST (manifest_verification_test_init_save_error);
TEST (manifest_verification_test_static_init_no_key_stored);
TEST (manifest_verification_test_static_init_no_key_stored_signature_sha384);
TEST (manifest_verification_test_static_init_no_key_stored_signature_sha512);
TEST (manifest_verification_test_static_init_no_key_stored_ecc);
TEST (manifest_verification_test_static_init_key_stored);
TEST (manifest_verification_test_static_init_key_stored_signature_sha384);
TEST (manifest_verification_test_static_init_key_stored_signature_sha512);
TEST (manifest_verification_test_static_init_key_stored_ecc);
TEST (manifest_verification_test_static_init_load_bad_key);
TEST (manifest_verification_test_static_init_stored_key_wrong_length);
TEST (manifest_verification_test_static_init_stored_key_bad_signature);
TEST (manifest_verification_test_static_init_stored_key_invalid_key);
TEST (manifest_verification_test_static_init_null);
TEST (manifest_verification_test_static_init_root_key_invalid_key);
TEST (manifest_verification_test_static_init_root_key_error);
TEST (manifest_verification_test_static_init_manifest_key_hash_error);
TEST (manifest_verification_test_static_init_manifest_key_bad_signature);
TEST (manifest_verification_test_static_init_manifest_key_verify_error);
TEST (manifest_verification_test_static_init_manifest_key_invalid_key);
TEST (manifest_verification_test_static_init_manifest_key_check_key_error);
TEST (manifest_verification_test_static_init_load_error);
TEST (manifest_verification_test_static_init_stored_key_hash_error);
TEST (manifest_verification_test_static_init_stored_key_verify_error);
TEST (manifest_verification_test_static_init_stored_key_check_key_error);
TEST (manifest_verification_test_static_init_save_error);
TEST (manifest_verification_test_release_null);
TEST (manifest_verification_test_get_observers);
TEST (manifest_verification_test_get_pfm_observer_null);
TEST (manifest_verification_test_get_cfm_observer_null);
TEST (manifest_verification_test_get_pcd_observer_null);
TEST (manifest_verification_test_verify_signature_no_key_stored);
TEST (manifest_verification_test_verify_signature_no_key_stored_ecc);
TEST (manifest_verification_test_verify_signature_no_key_stored_bad_signature);
TEST (manifest_verification_test_verify_signature_key_stored);
TEST (manifest_verification_test_verify_signature_key_stored_ecc);
TEST (manifest_verification_test_verify_signature_key_stored_match_default);
TEST (manifest_verification_test_verify_signature_key_stored_higher_id);
TEST (manifest_verification_test_verify_signature_key_stored_same_id);
TEST (manifest_verification_test_verify_signature_key_stored_bad_signature);
TEST (manifest_verification_test_verify_signature_key_stored_higher_id_bad_signature);
TEST (manifest_verification_test_verify_signature_key_stored_same_id_bad_signature);
TEST (manifest_verification_test_verify_signature_static_init_no_key_stored);
TEST (manifest_verification_test_verify_signature_static_init_key_stored);
TEST (manifest_verification_test_verify_signature_static_init_key_stored_higher_id);
TEST (manifest_verification_test_verify_signature_static_init_key_stored_same_id);
TEST (manifest_verification_test_verify_signature_static_init_key_stored_higher_id_bad_signature);
TEST (manifest_verification_test_verify_signature_static_init_key_stored_same_id_bad_signature);
TEST (manifest_verification_test_verify_signature_null);
TEST (manifest_verification_test_verify_signature_no_key_stored_set_key_error);
TEST (manifest_verification_test_verify_signature_no_key_stored_verify_error);
TEST (manifest_verification_test_verify_signature_key_stored_set_key_error);
TEST (manifest_verification_test_verify_signature_key_stored_verify_error);
TEST (manifest_verification_test_set_verification_key);
TEST (manifest_verification_test_is_key_valid);
TEST (manifest_verification_test_on_pfm_activated_no_key_stored);
TEST (manifest_verification_test_on_pfm_activated_key_stored);
TEST (manifest_verification_test_on_pfm_activated_key_stored_ecc);
TEST (manifest_verification_test_on_pfm_activated_key_stored_sha384);
TEST (manifest_verification_test_on_pfm_activated_key_stored_sha512);
TEST (manifest_verification_test_on_pfm_activated_key_stored_match_default);
TEST (manifest_verification_test_on_pfm_activated_key_stored_match_default_ecc);
TEST (manifest_verification_test_on_pfm_activated_key_stored_higher_id);
TEST (manifest_verification_test_on_pfm_activated_key_stored_same_id);
TEST (manifest_verification_test_on_pfm_activated_static_init_no_key_stored);
TEST (manifest_verification_test_on_pfm_activated_static_init_key_stored);
TEST (manifest_verification_test_on_pfm_activated_static_init_key_stored_higher_id);
TEST (manifest_verification_test_on_pfm_activated_static_init_key_stored_same_id);
TEST (manifest_verification_test_on_pfm_activated_key_stored_hash_error);
TEST (manifest_verification_test_on_pfm_activated_key_stored_signature_error);
TEST (manifest_verification_test_on_pfm_activated_key_stored_set_key_error);
TEST (manifest_verification_test_on_pfm_activated_key_stored_verify_error);
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
TEST (manifest_verification_test_after_default_activated_set_key_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_set_key_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_verify_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_verify_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_save_error_verify_signature);
TEST (manifest_verification_test_after_default_activated_save_error_on_pfm_activated);
TEST (manifest_verification_test_after_default_activated_save_error_on_pfm_activated_ecc);
TEST (manifest_verification_test_after_default_activated_save_error_twice_on_pfm_activated);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start_ecc);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start_save_error);
TEST (manifest_verification_test_after_default_activated_save_error_on_update_start_already_error);
TEST (manifest_verification_test_after_default_activated_match_stored);

TEST_SUITE_END;
// *INDENT-ON*
