// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "crypto/hkdf.h"
#include "crypto/kat/kdf_kat.h"
#include "crypto/kat/kdf_kat_vectors.h"
#include "testing/crypto/kdf_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/hkdf_mock.h"


TEST_SUITE_LABEL ("kdf_kat");


/*******************
 * Test cases
 *******************/

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (&hash.base);
#ifdef HASH_ENABLE_SHA1
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA1
static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1_ko_mismatch (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko_bad[SHA1_HASH_LENGTH];
	int status;

	TEST_START;

	memset (ko_bad, 0x34, sizeof (ko_bad));
	memcpy (ko_bad, KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KO, sizeof (ko_bad));
	ko_bad[5] ^= 0x55;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_testing_expect_nist800_108_counter_mode (&hash, HASH_TYPE_SHA1,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KI_LEN, 1,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_LABEL, KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_CONTEXT_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KO_LEN, ko_bad, sizeof (ko_bad));
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (&hash.base);
	CuAssertIntEquals (test, KDF_NIST800_108_SHA1_KAT_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1_kdf_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha1, &hash, HASH_ENGINE_START_SHA1_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256_ko_mismatch (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko_bad[SHA256_HASH_LENGTH * 2];
	int status;

	TEST_START;

	memset (ko_bad, 0x56, sizeof (ko_bad));
	memcpy (ko_bad, KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KO, sizeof (ko_bad));
	ko_bad[5] ^= 0x55;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_testing_expect_nist800_108_counter_mode (&hash, HASH_TYPE_SHA256,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KI_LEN, 1,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_CONTEXT_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KO_LEN, ko_bad, SHA256_HASH_LENGTH);

	status |= kdf_testing_expect_nist800_108_counter_mode (&hash, HASH_TYPE_SHA256,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KI_LEN, 2,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_CONTEXT_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KO_LEN, &ko_bad[SHA256_HASH_LENGTH],
		SHA256_HASH_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (&hash.base);
	CuAssertIntEquals (test, KDF_NIST800_108_SHA256_KAT_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256_kdf_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (&hash.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA384
static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384_ko_mismatch (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko_bad[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	memset (ko_bad, 0x78, sizeof (ko_bad));
	memcpy (ko_bad, KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KO, sizeof (ko_bad));
	ko_bad[5] ^= 0x55;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_testing_expect_nist800_108_counter_mode (&hash, HASH_TYPE_SHA384,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KI_LEN, 1,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_CONTEXT_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KO_LEN, ko_bad, sizeof (ko_bad));
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (&hash.base);
	CuAssertIntEquals (test, KDF_NIST800_108_SHA384_KAT_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384_kdf_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (&hash.base);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA512
static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512_ko_mismatch (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko_bad[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	memset (ko_bad, 0x9a, sizeof (ko_bad));
	memcpy (ko_bad, KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KO, sizeof (ko_bad));
	ko_bad[5] ^= 0x55;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_testing_expect_nist800_108_counter_mode (&hash, HASH_TYPE_SHA512,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KI_LEN, 1,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_CONTEXT_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KO_LEN, ko_bad, sizeof (ko_bad));
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (&hash.base);
	CuAssertIntEquals (test, KDF_NIST800_108_SHA512_KAT_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512_kdf_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void kdf_test_kat_run_self_test_hkdf_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct hkdf_state state;
	struct hkdf hkdf;
	int status;
	uint8_t zero[HASH_MAX_HASH_LEN] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_init (&hkdf, &state, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
#ifdef HASH_ENABLE_SHA1
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* Make sure the PRK has been zeroized after the self-test. */
	status = testing_validate_array (zero, state.prk, sizeof (state.prk));
	CuAssertIntEquals (test, 0, status);

	hkdf_release (&hkdf);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA1
static void kdf_test_kat_run_self_test_hkdf_sha1_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA1_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha1_null (CuTest *test)
{
	int status;

	TEST_START;

	status = kdf_kat_run_self_test_hkdf_sha1 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha1_extract_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, HKDF_EXTRACT_FAILED,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha1_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha1_clear_prk_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN, 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_CLEAR_PRK_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha1_clear_prk_error_after_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha1_clear_prk_error_after_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_SHA1_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha1 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA1_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void kdf_test_kat_run_self_test_hkdf_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct hkdf_state state;
	struct hkdf hkdf;
	int status;
	uint8_t zero[HASH_MAX_HASH_LEN] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_init (&hkdf, &state, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the PRK has been zeroized after the self-test. */
	status = testing_validate_array (zero, state.prk, sizeof (state.prk));
	CuAssertIntEquals (test, 0, status);

	hkdf_release (&hkdf);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA256_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = kdf_kat_run_self_test_hkdf_sha256 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_extract_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, HKDF_EXTRACT_FAILED,
		MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_clear_prk_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN, 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_CLEAR_PRK_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_clear_prk_error_after_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha256_clear_prk_error_after_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha256 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA256_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct hkdf_state state;
	struct hkdf hkdf;
	int status;
	uint8_t zero[HASH_MAX_HASH_LEN] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_init (&hkdf, &state, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* Make sure the PRK has been zeroized after the self-test. */
	status = testing_validate_array (zero, state.prk, sizeof (state.prk));
	CuAssertIntEquals (test, 0, status);

	hkdf_release (&hkdf);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA384
static void kdf_test_kat_run_self_test_hkdf_sha384_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA384_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384_null (CuTest *test)
{
	int status;

	TEST_START;

	status = kdf_kat_run_self_test_hkdf_sha384 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384_extract_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, HKDF_EXTRACT_FAILED,
		MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384_clear_prk_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN, 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_CLEAR_PRK_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384_clear_prk_error_after_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha384_clear_prk_error_after_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha384 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA384_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void kdf_test_kat_run_self_test_hkdf_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct hkdf_state state;
	struct hkdf hkdf;
	int status;
	uint8_t zero[HASH_MAX_HASH_LEN] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_init (&hkdf, &state, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* Make sure the PRK has been zeroized after the self-test. */
	status = testing_validate_array (zero, state.prk, sizeof (state.prk));
	CuAssertIntEquals (test, 0, status);

	hkdf_release (&hkdf);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA512
static void kdf_test_kat_run_self_test_hkdf_sha512_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA512_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha512_null (CuTest *test)
{
	int status;

	TEST_START;

	status = kdf_kat_run_self_test_hkdf_sha512 (NULL);
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha512_extract_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, HKDF_EXTRACT_FAILED,
		MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha512_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha512_clear_prk_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN, 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_CLEAR_PRK_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha512_clear_prk_error_after_expand_error (CuTest *test)
{
	struct hkdf_mock hkdf;
	int status;

	TEST_START;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_kat_run_self_test_hkdf_sha512_clear_prk_error_after_okm_mismatch (CuTest *test)
{
	struct hkdf_mock hkdf;
	uint8_t okm_bad[KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN];
	int status;

	TEST_START;

	memcpy (okm_bad, KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM, sizeof (okm_bad));
	okm_bad[5] ^= 0x55;

	status = hkdf_mock_init (&hkdf);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hkdf.mock, hkdf.base.extract, &hkdf, 0, MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM,
		KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT,
		KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXTRACT_SALT_LEN));

	status |= mock_expect (&hkdf.mock, hkdf.base.expand, &hkdf, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN), MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN));
	status |= mock_expect_output (&hkdf.mock, 2, okm_bad, sizeof (okm_bad), 3);

	status |= mock_expect (&hkdf.mock, hkdf.base.clear_prk, &hkdf, HKDF_CLEAR_PRK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = kdf_kat_run_self_test_hkdf_sha512 (&hkdf.base);
	CuAssertIntEquals (test, HKDF_SHA512_KAT_FAILED, status);

	status = hkdf_mock_validate_and_release (&hkdf);
	CuAssertIntEquals (test, 0, status);
}
#endif


// *INDENT-OFF*
TEST_SUITE_START (kdf_kat);

TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1);
#ifdef HASH_ENABLE_SHA1
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1_ko_mismatch);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1_null);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha1_kdf_fail);
#endif
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256_ko_mismatch);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256_null);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha256_kdf_fail);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384_ko_mismatch);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384_null);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha384_kdf_fail);
#endif
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512_ko_mismatch);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512_null);
TEST (kdf_test_kat_run_self_test_nist800_108_counter_mode_sha512_kdf_fail);
#endif
TEST (kdf_test_kat_run_self_test_hkdf_sha1);
#ifdef HASH_ENABLE_SHA1
TEST (kdf_test_kat_run_self_test_hkdf_sha1_okm_mismatch);
TEST (kdf_test_kat_run_self_test_hkdf_sha1_null);
TEST (kdf_test_kat_run_self_test_hkdf_sha1_extract_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha1_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha1_clear_prk_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha1_clear_prk_error_after_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha1_clear_prk_error_after_okm_mismatch);
#endif
TEST (kdf_test_kat_run_self_test_hkdf_sha256);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_okm_mismatch);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_null);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_extract_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_clear_prk_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_clear_prk_error_after_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha256_clear_prk_error_after_okm_mismatch);
TEST (kdf_test_kat_run_self_test_hkdf_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (kdf_test_kat_run_self_test_hkdf_sha384_okm_mismatch);
TEST (kdf_test_kat_run_self_test_hkdf_sha384_null);
TEST (kdf_test_kat_run_self_test_hkdf_sha384_extract_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha384_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha384_clear_prk_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha384_clear_prk_error_after_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha384_clear_prk_error_after_okm_mismatch);
#endif
TEST (kdf_test_kat_run_self_test_hkdf_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (kdf_test_kat_run_self_test_hkdf_sha512_okm_mismatch);
TEST (kdf_test_kat_run_self_test_hkdf_sha512_null);
TEST (kdf_test_kat_run_self_test_hkdf_sha512_extract_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha512_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha512_clear_prk_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha512_clear_prk_error_after_expand_error);
TEST (kdf_test_kat_run_self_test_hkdf_sha512_clear_prk_error_after_okm_mismatch);
#endif

TEST_SUITE_END;
// *INDENT-ON*
