// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_ecdsa.h"
#include "asn1/ecc_der_util.h"
#include "crypto/crypto_logging.h"
#include "crypto/signature_verification.h"
#include "mbedtls/ecp.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/ecc_hw_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_ecdsa");


/**
 * ECDSA test data message.
 */
const char *ecdsa_test_data_msg = "Test";


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * ECDSA ECC key types for testing.
 */
enum ecdsa_test_ecc_key_type {
	ECDSA_TEST_ECC_KEY_TYPE_256 = 0,
	ECDSA_TEST_ECC_KEY_TYPE_384,
	ECDSA_TEST_ECC_KEY_TYPE_521,
	ECDSA_TEST_ECC_KEY_TYPE_INVALID,
};

/**
 * ECDSA test types.
 */
enum ecdsa_test_type {
	ECDSA_TEST_TYPE_KEYGEN = 0,
	ECDSA_TEST_TYPE_KEYGEN_EXTRA,
	ECDSA_TEST_TYPE_PKVVER,
	ECDSA_TEST_TYPE_SIGGEN,
	ECDSA_TEST_TYPE_SIGVER,
};

/**
 * ECDSA test data.
 */
union ecdsa_testing_data {
	struct ecdsa_keygen_data keygen;				/**< ECDSA key generation for B.4.2 (testing candidates) test data. */
	struct ecdsa_keygen_extra_data keygen_extra;	/**< ECC key generation for B.4.1 (extra entropy) test data. */
	struct ecdsa_pkvver_data pkvver;				/**< ECDSA key verification test data. */
	struct ecdsa_siggen_data siggen;				/**< ECDSA signature generation test data. */
	struct ecdsa_sigver_data sigver;				/**< ECDSA signature verification test data. */
};

/**
 * Dependencies for testing.
 */
struct backend_ecdsa_testing {
	enum ecdsa_test_type type;		/**< ECDSA test type. */
	union ecdsa_testing_data data;	/**< ECDSA test data. */
	struct ecc_engine_mock engine;	/**< Mock for ECC engine. */
	struct ecc_hw_mock hw;			/**< Mock for ECC hardware engine. */
	struct hash_engine_mock hash;	/**< Mock for hash engine. */
	struct logging_mock logger;		/**< Mock for debug logging. */
};


/**
 * Get the ACVP ECDSA test cipher value for the specified key and hash types.
 *
 * @param test The test framework.
 * @param key_type The key type to use for the test.
 * @param hash_type The hash type to use for the test.
 *
 * @return The ACVP cipher value for the specified key and hash types.
 */
static uint64_t backend_ecdsa_testing_get_cipher (CuTest *test,
	enum ecdsa_test_ecc_key_type key_type, enum hash_type hash_type)
{
	uint64_t cipher;

	switch (key_type) {
		case ECDSA_TEST_ECC_KEY_TYPE_256:
			cipher = ACVP_NISTP256;
			break;

		case ECDSA_TEST_ECC_KEY_TYPE_384:
			cipher = ACVP_NISTP384;
			break;

		case ECDSA_TEST_ECC_KEY_TYPE_521:
			cipher = ACVP_NISTP521;
			break;

		case ECDSA_TEST_ECC_KEY_TYPE_INVALID:
			// Use unsupported cipher
			cipher = ACVP_NISTB571;
			break;

		default:
			CuFail (test, "Invalid key type.");

			return 0;
	}

	switch (hash_type) {
#ifdef HASH_ENABLE_SHA1
		case HASH_TYPE_SHA1:
			cipher |= ACVP_SHA1;
			break;
#endif

		case HASH_TYPE_SHA256:
			cipher |= ACVP_SHA256;
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			cipher |= ACVP_SHA384;
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			cipher |= ACVP_SHA512;
			break;
#endif

		case HASH_TYPE_INVALID:
			// Use unsupported cipher
			cipher |= ACVP_SHA3_512;
			break;

		default:
			CuFail (test, "Invalid hash type.");

			return 0;
	}

	return cipher;
}

/**
 * Set the buffers for the ECDSA signature generation test data.
 *
 * @param test The test framework.
 * @param data The ECDSA signature generation test data.
 * @param key_type The ECC key type.
 *
 * @return 0 if the buffers were set successfully, or an error code if there was a failure.
 */
static void backend_ecdsa_testing_set_siggen_buffers (CuTest *test,	struct ecdsa_siggen_data *data,
	enum ecdsa_test_ecc_key_type key_type)
{
	switch (key_type) {
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECDSA_TEST_ECC_KEY_TYPE_384:
			data->Qx.buf =
				(unsigned char*) platform_malloc (sizeof (ECC384_PUBKEY_POINT.x));
			CuAssertPtrNotNull (test, data->Qx.buf);

			memcpy (data->Qx.buf, ECC384_PUBKEY_POINT.x, sizeof (ECC384_PUBKEY_POINT.x));
			data->Qx.len = sizeof (ECC384_PUBKEY_POINT.x);

			data->Qy.buf =
				(unsigned char*) platform_malloc (sizeof (ECC384_PUBKEY_POINT.y));
			CuAssertPtrNotNull (test, data->Qy.buf);

			memcpy (data->Qy.buf, ECC384_PUBKEY_POINT.y, sizeof (ECC384_PUBKEY_POINT.y));
			data->Qy.len = sizeof (ECC384_PUBKEY_POINT.y);

			data->privkey = (void*) ECC384_PRIVKEY;
			break;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECDSA_TEST_ECC_KEY_TYPE_521:
			data->Qx.buf =
				(unsigned char*) platform_malloc (sizeof (ECC521_PUBKEY_POINT.x));
			CuAssertPtrNotNull (test, data->Qx.buf);

			memcpy (data->Qx.buf, ECC521_PUBKEY_POINT.x, sizeof (ECC521_PUBKEY_POINT.x));
			data->Qx.len = sizeof (ECC521_PUBKEY_POINT.x);

			data->Qy.buf =
				(unsigned char*) platform_malloc (sizeof (ECC521_PUBKEY_POINT.y));
			CuAssertPtrNotNull (test, data->Qy.buf);

			memcpy (data->Qy.buf, ECC521_PUBKEY_POINT.y, sizeof (ECC521_PUBKEY_POINT.y));
			data->Qy.len = sizeof (ECC521_PUBKEY_POINT.y);

			data->privkey = (void*) ECC521_PRIVKEY;
			break;
#endif

		default:
			/* By default, set ECC256 buffers.  Invalid curve test cases are handled at a higher
			* level by the cipher value. */
			data->Qx.buf =
				(unsigned char*) platform_malloc (sizeof (ECC_PUBKEY_POINT.x));
			CuAssertPtrNotNull (test, data->Qx.buf);

			memcpy (data->Qx.buf, ECC_PUBKEY_POINT.x, sizeof (ECC_PUBKEY_POINT.x));
			data->Qx.len = sizeof (ECC_PUBKEY_POINT.x);

			data->Qy.buf =
				(unsigned char*) platform_malloc (sizeof (ECC_PUBKEY_POINT.y));
			CuAssertPtrNotNull (test, data->Qy.buf);

			memcpy (data->Qy.buf, ECC_PUBKEY_POINT.y, sizeof (ECC_PUBKEY_POINT.y));
			data->Qy.len = sizeof (ECC_PUBKEY_POINT.y);

			data->privkey = (void*) ECC_PRIVKEY;
			break;
	}
}

/**
 * Set the buffers for the ECDSA signature verification test data.
 *
 * @param test The test framework.
 * @param data The ECDSA signature verification test data.
 * @param key_type The ECC key type.
 *
 * @return 0 if the buffers were set successfully, or an error code if there was a failure.
 */
static void backend_ecdsa_testing_set_sigver_buffers (CuTest *test,	struct ecdsa_sigver_data *data,
	enum ecdsa_test_ecc_key_type key_type)
{
	switch (key_type) {
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECDSA_TEST_ECC_KEY_TYPE_384:
			data->Qx.buf =
				(unsigned char*) platform_malloc (sizeof (ECC384_PUBKEY_POINT.x));
			CuAssertPtrNotNull (test, data->Qx.buf);

			memcpy (data->Qx.buf, ECC384_PUBKEY_POINT.x, sizeof (ECC384_PUBKEY_POINT.x));
			data->Qx.len = sizeof (ECC384_PUBKEY_POINT.x);

			data->Qy.buf =
				(unsigned char*) platform_malloc (sizeof (ECC384_PUBKEY_POINT.y));
			CuAssertPtrNotNull (test, data->Qy.buf);

			memcpy (data->Qy.buf, ECC384_PUBKEY_POINT.y, sizeof (ECC384_PUBKEY_POINT.y));
			data->Qy.len = sizeof (ECC384_PUBKEY_POINT.y);

			data->R.buf =
				(unsigned char*) platform_malloc (sizeof (ECC384_SIGNATURE_TEST_STRUCT.r));
			CuAssertPtrNotNull (test, data->R.buf);

			memcpy (data->R.buf, ECC384_SIGNATURE_TEST_STRUCT.r,
				sizeof (ECC384_SIGNATURE_TEST_STRUCT.r));
			data->R.len = sizeof (ECC384_SIGNATURE_TEST_STRUCT.r);

			data->S.buf =
				(unsigned char*) platform_malloc (sizeof (ECC384_SIGNATURE_TEST_STRUCT.s));
			CuAssertPtrNotNull (test, data->S.buf);

			memcpy (data->S.buf, ECC384_SIGNATURE_TEST_STRUCT.s,
				sizeof (ECC384_SIGNATURE_TEST_STRUCT.s));
			data->S.len = sizeof (ECC384_SIGNATURE_TEST_STRUCT.s);
			break;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECDSA_TEST_ECC_KEY_TYPE_521:
			data->Qx.buf =
				(unsigned char*) platform_malloc (sizeof (ECC521_PUBKEY_POINT.x));
			CuAssertPtrNotNull (test, data->Qx.buf);

			memcpy (data->Qx.buf, ECC521_PUBKEY_POINT.x, sizeof (ECC521_PUBKEY_POINT.x));
			data->Qx.len = sizeof (ECC521_PUBKEY_POINT.x);

			data->Qy.buf =
				(unsigned char*) platform_malloc (sizeof (ECC521_PUBKEY_POINT.y));
			CuAssertPtrNotNull (test, data->Qy.buf);

			memcpy (data->Qy.buf, ECC521_PUBKEY_POINT.y, sizeof (ECC521_PUBKEY_POINT.y));
			data->Qy.len = sizeof (ECC521_PUBKEY_POINT.y);

			data->R.buf =
				(unsigned char*) platform_malloc (sizeof (ECC521_SIGNATURE_TEST_STRUCT.r));
			CuAssertPtrNotNull (test, data->R.buf);

			memcpy (data->R.buf, ECC521_SIGNATURE_TEST_STRUCT.r,
				sizeof (ECC521_SIGNATURE_TEST_STRUCT.r));
			data->R.len = sizeof (ECC521_SIGNATURE_TEST_STRUCT.r);

			data->S.buf =
				(unsigned char*) platform_malloc (sizeof (ECC521_SIGNATURE_TEST_STRUCT.s));
			CuAssertPtrNotNull (test, data->S.buf);

			memcpy (data->S.buf, ECC521_SIGNATURE_TEST_STRUCT.s,
				sizeof (ECC521_SIGNATURE_TEST_STRUCT.s));
			data->S.len = sizeof (ECC521_SIGNATURE_TEST_STRUCT.s);
			break;
#endif

		default:
			/* By default, set ECC256 buffers.  Invalid curve test cases are handled at a higher
			 * level by the cipher value. */
			data->Qx.buf =
				(unsigned char*) platform_malloc (sizeof (ECC_PUBKEY_POINT.x));
			CuAssertPtrNotNull (test, data->Qx.buf);

			memcpy (data->Qx.buf, ECC_PUBKEY_POINT.x, sizeof (ECC_PUBKEY_POINT.x));
			data->Qx.len = sizeof (ECC_PUBKEY_POINT.x);

			data->Qy.buf =
				(unsigned char*) platform_malloc (sizeof (ECC_PUBKEY_POINT.y));
			CuAssertPtrNotNull (test, data->Qy.buf);

			memcpy (data->Qy.buf, ECC_PUBKEY_POINT.y, sizeof (ECC_PUBKEY_POINT.y));
			data->Qy.len = sizeof (ECC_PUBKEY_POINT.y);

			data->R.buf =
				(unsigned char*) platform_malloc (sizeof (ECC_SIGNATURE_TEST_STRUCT.r));
			CuAssertPtrNotNull (test, data->R.buf);

			memcpy (data->R.buf, ECC_SIGNATURE_TEST_STRUCT.r, sizeof (ECC_SIGNATURE_TEST_STRUCT.r));
			data->R.len = sizeof (ECC_SIGNATURE_TEST_STRUCT.r);

			data->S.buf =
				(unsigned char*) platform_malloc (sizeof (ECC_SIGNATURE_TEST_STRUCT.s));
			CuAssertPtrNotNull (test, data->S.buf);

			memcpy (data->S.buf, ECC_SIGNATURE_TEST_STRUCT.s, sizeof (ECC_SIGNATURE_TEST_STRUCT.s));
			data->S.len = sizeof (ECC_SIGNATURE_TEST_STRUCT.s);
			break;
	}
}

/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 * @param type The ECDSA test type.
 */
static void backend_ecdsa_testing_init (CuTest *test, struct backend_ecdsa_testing *backend,
	enum ecdsa_test_type type, enum ecdsa_test_ecc_key_type key_type, enum hash_type hash_type)
{
	size_t msg_len = strlen ((char*) ecdsa_test_data_msg);
	uint64_t cipher;
	union ecdsa_testing_data data;
	int status;

	cipher = backend_ecdsa_testing_get_cipher (test, key_type, hash_type);

	switch (type) {
		case ECDSA_TEST_TYPE_KEYGEN:
			data.keygen.d.buf = NULL;
			data.keygen.Qx.buf = NULL;
			data.keygen.Qy.buf = NULL;
			data.keygen.cipher = cipher;
			break;

		case ECDSA_TEST_TYPE_KEYGEN_EXTRA:
			data.keygen_extra.d.buf = NULL;
			data.keygen_extra.Qx.buf = NULL;
			data.keygen_extra.Qy.buf = NULL;
			data.keygen_extra.cipher = cipher;
			break;

		case ECDSA_TEST_TYPE_SIGGEN:
			data.siggen.msg.buf = (unsigned char*) platform_malloc (msg_len);
			CuAssertPtrNotNull (test, data.siggen.msg.buf);

			memcpy (data.siggen.msg.buf, ecdsa_test_data_msg, msg_len);
			data.siggen.msg.len = msg_len;

			backend_ecdsa_testing_set_siggen_buffers (test, &data.siggen, key_type);

			data.siggen.R.buf = NULL;

			data.siggen.S.buf = NULL;

			data.siggen.component = BACKEND_ECDSA_COMPONENT_TYPE_FULL;
			data.siggen.cipher = cipher;
			break;

		case ECDSA_TEST_TYPE_SIGVER:
			data.sigver.msg.buf = (unsigned char*) platform_malloc (msg_len);
			CuAssertPtrNotNull (test, data.sigver.msg.buf);

			memcpy (data.sigver.msg.buf, ecdsa_test_data_msg, msg_len);
			data.sigver.msg.len = msg_len;

			backend_ecdsa_testing_set_sigver_buffers (test, &data.sigver, key_type);

			data.sigver.component = BACKEND_ECDSA_COMPONENT_TYPE_FULL;

			data.sigver.cipher = cipher;
			break;

		default:
			CuFail (test, "Unsupported ECDSA test type");

			return;
	}

	status = ecc_mock_init (&backend->engine);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&backend->hw);
	CuAssertIntEquals (test, 0, status);

	backend->type = type;
	backend->data = data;

	status = hash_mock_init (&backend->hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&backend->logger);
	CuAssertIntEquals (test, 0, status);

	debug_log = &backend->logger.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param backend The testing dependencies to release.
 */
static void backend_ecdsa_testing_release (CuTest *test, struct backend_ecdsa_testing *backend)
{
	int status;

	switch (backend->type) {
		case ECDSA_TEST_TYPE_KEYGEN:
			if (backend->data.keygen.d.buf != NULL) {
				platform_free (backend->data.keygen.d.buf);
			}

			if (backend->data.keygen.Qx.buf != NULL) {
				platform_free (backend->data.keygen.Qx.buf);
			}

			if (backend->data.keygen.Qy.buf != NULL) {
				platform_free (backend->data.keygen.Qy.buf);
			}
			break;

		case ECDSA_TEST_TYPE_KEYGEN_EXTRA:
			if (backend->data.keygen_extra.d.buf != NULL) {
				platform_free (backend->data.keygen_extra.d.buf);
			}

			if (backend->data.keygen_extra.Qx.buf != NULL) {
				platform_free (backend->data.keygen_extra.Qx.buf);
			}

			if (backend->data.keygen_extra.Qy.buf != NULL) {
				platform_free (backend->data.keygen_extra.Qy.buf);
			}
			break;

		case ECDSA_TEST_TYPE_PKVVER:
			if (backend->data.pkvver.Qx.buf != NULL) {
				platform_free (backend->data.pkvver.Qx.buf);
			}

			if (backend->data.pkvver.Qy.buf != NULL) {
				platform_free (backend->data.pkvver.Qy.buf);
			}
			break;

		case ECDSA_TEST_TYPE_SIGGEN:
			if (backend->data.siggen.msg.buf != NULL) {
				platform_free (backend->data.siggen.msg.buf);
			}

			if (backend->data.siggen.Qx.buf != NULL) {
				platform_free (backend->data.siggen.Qx.buf);
			}

			if (backend->data.siggen.Qy.buf != NULL) {
				platform_free (backend->data.siggen.Qy.buf);
			}

			if (backend->data.siggen.R.buf != NULL) {
				platform_free (backend->data.siggen.R.buf);
			}

			if (backend->data.siggen.S.buf != NULL) {
				platform_free (backend->data.siggen.S.buf);
			}
			break;

		case ECDSA_TEST_TYPE_SIGVER:
			if (backend->data.sigver.msg.buf != NULL) {
				platform_free (backend->data.sigver.msg.buf);
			}

			if (backend->data.sigver.Qx.buf != NULL) {
				platform_free (backend->data.sigver.Qx.buf);
			}

			if (backend->data.sigver.Qy.buf != NULL) {
				platform_free (backend->data.sigver.Qy.buf);
			}

			if (backend->data.sigver.R.buf != NULL) {
				platform_free (backend->data.sigver.R.buf);
			}

			if (backend->data.sigver.S.buf != NULL) {
				platform_free (backend->data.sigver.S.buf);
			}
			break;

		default:
			CuFail (test, "Invalid ECDSA test type");

			return;
	}

	backend_ecdsa_register_engines (NULL, 0);

	status = ecc_mock_validate_and_release (&backend->engine);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&backend->hw);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&backend->hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void backend_ecdsa_test_init (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;

	TEST_START;

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);
	CuAssertPtrNotNull (test, ecdsa_impl->ecdsa_keygen);
	CuAssertPtrNotNull (test, ecdsa_impl->ecdsa_keygen_extra);
	CuAssertPtrEquals (test, NULL, ecdsa_impl->ecdsa_pkvver);
	CuAssertPtrNotNull (test, ecdsa_impl->ecdsa_siggen);
	CuAssertPtrNotNull (test, ecdsa_impl->ecdsa_sigver);
	CuAssertPtrNotNull (test, ecdsa_impl->ecdsa_keygen_en);
	CuAssertPtrNotNull (test, ecdsa_impl->ecdsa_free_key);
}

static void backend_ecdsa_test_keygen_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC_PRIVKEY_LEN, backend.data.keygen.d.len);
	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);

	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen.Qx.len);
	CuAssertPtrNotNull (test, backend.data.keygen.Qx.buf);

	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen.Qy.len);
	CuAssertPtrNotNull (test, backend.data.keygen.Qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_hw_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC_PRIVKEY, ECC_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT),
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen.Qy.buf);
	CuAssertIntEquals (test, ECC_PRIVKEY_LEN, backend.data.keygen.d.len);
	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen.Qx.len);
	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen.Qy.len);

	status = testing_validate_array (ECC_PRIVKEY, backend.data.keygen.d.buf, ECC_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PUBKEY_POINT.x, backend.data.keygen.Qx.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PUBKEY_POINT.y, backend.data.keygen.Qy.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
static void backend_ecdsa_test_keygen_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC384_PRIVKEY_LEN, backend.data.keygen.d.len);
	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);

	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen.Qx.len);
	CuAssertPtrNotNull (test, backend.data.keygen.Qx.buf);

	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen.Qy.len);
	CuAssertPtrNotNull (test, backend.data.keygen.Qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}


static void backend_ecdsa_test_keygen_hw_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC384_PRIVKEY, ECC384_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC384_PUBKEY_POINT,
		sizeof (ECC384_PUBKEY_POINT), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen.Qy.buf);
	CuAssertIntEquals (test, ECC384_PRIVKEY_LEN, backend.data.keygen.d.len);
	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen.Qx.len);
	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen.Qy.len);

	status = testing_validate_array (ECC384_PRIVKEY, backend.data.keygen.d.buf, ECC384_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_PUBKEY_POINT.x, backend.data.keygen.Qx.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_PUBKEY_POINT.y, backend.data.keygen.Qy.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
static void backend_ecdsa_test_keygen_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, backend.data.keygen.d.len);
	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);

	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen.Qx.len);
	CuAssertPtrNotNull (test, backend.data.keygen.Qx.buf);

	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen.Qy.len);
	CuAssertPtrNotNull (test, backend.data.keygen.Qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_hw_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC521_PRIVKEY, ECC521_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC521_PUBKEY_POINT,
		sizeof (ECC521_PUBKEY_POINT), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN,
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen.Qy.buf);
	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, backend.data.keygen.d.len);
	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen.Qx.len);
	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen.Qy.len);

	status = testing_validate_array (ECC521_PRIVKEY, backend.data.keygen.d.buf, ECC521_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_PUBKEY_POINT.x, backend.data.keygen.Qx.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_PUBKEY_POINT.y, backend.data.keygen.Qy.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

static void backend_ecdsa_test_keygen_null (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_no_engine (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation + 1;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_unsupported_type (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_KEYGEN_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_unsupported_curve (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_CURVE_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN,
		ECDSA_TEST_ECC_KEY_TYPE_INVALID, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_gen_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_GENERATE_KEY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key_pair,
		&backend.engine, ECC_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_ANY, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_hw_gen_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_HW_ECC_GENERATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,
		ECC_HW_ECC_GENERATE_FAILED,	MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 1;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen_extra.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qy.buf);
	CuAssertIntEquals (test, ECC_PRIVKEY_LEN, backend.data.keygen_extra.d.len);
	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qx.len);
	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qy.len);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_hw_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC_PRIVKEY, ECC_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT),
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen_extra.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qy.buf);
	CuAssertIntEquals (test, ECC_PRIVKEY_LEN, backend.data.keygen_extra.d.len);
	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qx.len);
	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qy.len);

	status = testing_validate_array (ECC_PRIVKEY, backend.data.keygen_extra.d.buf, ECC_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PUBKEY_POINT.x, backend.data.keygen_extra.Qx.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PUBKEY_POINT.y, backend.data.keygen_extra.Qy.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
static void backend_ecdsa_test_keygen_extra_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 1;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen_extra.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qy.buf);
	CuAssertIntEquals (test, ECC384_PRIVKEY_LEN, backend.data.keygen_extra.d.len);
	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qx.len);
	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qy.len);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_hw_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC384_PRIVKEY, ECC384_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC384_PUBKEY_POINT,
		sizeof (ECC384_PUBKEY_POINT), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen_extra.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qy.buf);
	CuAssertIntEquals (test, ECC384_PRIVKEY_LEN, backend.data.keygen_extra.d.len);
	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qx.len);
	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qy.len);

	status = testing_validate_array (ECC384_PRIVKEY, backend.data.keygen_extra.d.buf,
		ECC384_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_PUBKEY_POINT.x, backend.data.keygen_extra.Qx.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_PUBKEY_POINT.y, backend.data.keygen_extra.Qy.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
static void backend_ecdsa_test_keygen_extra_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 1;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen_extra.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qy.buf);
	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, backend.data.keygen_extra.d.len);
	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qx.len);
	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qy.len);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_hw_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC521_PRIVKEY, ECC521_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC521_PUBKEY_POINT,
		sizeof (ECC521_PUBKEY_POINT), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN,
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, backend.data.keygen_extra.d.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qx.buf);
	CuAssertPtrNotNull (test, backend.data.keygen_extra.Qy.buf);
	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, backend.data.keygen_extra.d.len);
	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qx.len);
	CuAssertIntEquals (test, ECC521_PUBKEY_POINT.key_length, backend.data.keygen_extra.Qy.len);

	status = testing_validate_array (ECC521_PRIVKEY, backend.data.keygen_extra.d.buf,
		ECC521_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_PUBKEY_POINT.x, backend.data.keygen_extra.Qx.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_PUBKEY_POINT.y, backend.data.keygen_extra.Qy.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

static void backend_ecdsa_test_keygen_extra_null (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN_EXTRA,
		ECDSA_TEST_ECC_KEY_TYPE_256, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_extra (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_no_engine (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN_EXTRA,
		ECDSA_TEST_ECC_KEY_TYPE_256, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN_EXTRA,
		ECDSA_TEST_ECC_KEY_TYPE_256, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation + 1;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_extra_unsupported_type (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_KEYGEN_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN_EXTRA,
		ECDSA_TEST_ECC_KEY_TYPE_256, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_keygen_extra (&backend.data.keygen_extra, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hash_and_finish_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_KEYGEN_UNSUPPORTED,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct ecc_ecdsa_signature sig_ex;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	memset (&sig_ex, 0, sizeof (struct ecc_ecdsa_signature));
	memcpy (sig_ex.r, ECC_SIGNATURE_TEST_STRUCT.r, ECC_KEY_LENGTH_256);
	memcpy (sig_ex.s, ECC_SIGNATURE_TEST_STRUCT.s, ECC_KEY_LENGTH_256);
	sig_ex.length = ECC_KEY_LENGTH_256;

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_ptr_tmp (&backend.hw.mock, 5, &sig_ex,
		sizeof (struct ecc_ecdsa_signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST_STRUCT.r, backend.data.siggen.R.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST_STRUCT.s, backend.data.siggen.S.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_hash_and_finish_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	struct ecc_ecdsa_signature sig_ex;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	memset (&sig_ex, 0, sizeof (struct ecc_ecdsa_signature));
	memcpy (sig_ex.r, ECC_SIGNATURE_TEST_STRUCT.r, ECC_KEY_LENGTH_256);
	memcpy (sig_ex.s, ECC_SIGNATURE_TEST_STRUCT.s, ECC_KEY_LENGTH_256);
	sig_ex.length = ECC_KEY_LENGTH_256;

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_ptr_tmp (&backend.hw.mock, 5, &sig_ex,
		sizeof (struct ecc_ecdsa_signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST_STRUCT.r, backend.data.siggen.R.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST_STRUCT.s, backend.data.siggen.S.buf,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
static void backend_ecdsa_test_siggen_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hash_and_finish_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_KEYGEN_UNSUPPORTED,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct ecc_ecdsa_signature sig_ex;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	memset (&sig_ex, 0, sizeof (struct ecc_ecdsa_signature));
	memcpy (sig_ex.r, ECC384_SIGNATURE_TEST_STRUCT.r, ECC_KEY_LENGTH_384);
	memcpy (sig_ex.s, ECC384_SIGNATURE_TEST_STRUCT.s, ECC_KEY_LENGTH_384);
	sig_ex.length = ECC_KEY_LENGTH_384;

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_ptr_tmp (&backend.hw.mock, 5, &sig_ex,
		sizeof (struct ecc_ecdsa_signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_SIGNATURE_TEST_STRUCT.r, backend.data.siggen.R.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_SIGNATURE_TEST_STRUCT.s, backend.data.siggen.S.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_hash_and_finish_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	struct ecc_ecdsa_signature sig_ex;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	memset (&sig_ex, 0, sizeof (struct ecc_ecdsa_signature));
	memcpy (sig_ex.r, ECC384_SIGNATURE_TEST_STRUCT.r, ECC_KEY_LENGTH_384);
	memcpy (sig_ex.s, ECC384_SIGNATURE_TEST_STRUCT.s, ECC_KEY_LENGTH_384);
	sig_ex.length = ECC_KEY_LENGTH_384;

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_ptr_tmp (&backend.hw.mock, 5, &sig_ex,
		sizeof (struct ecc_ecdsa_signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_SIGNATURE_TEST_STRUCT.r, backend.data.siggen.R.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_SIGNATURE_TEST_STRUCT.s, backend.data.siggen.S.buf,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
static void backend_ecdsa_test_siggen_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hash_and_finish_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_KEYGEN_UNSUPPORTED,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct ecc_ecdsa_signature sig_ex;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	memset (&sig_ex, 0, sizeof (struct ecc_ecdsa_signature));
	memcpy (sig_ex.r, ECC521_SIGNATURE_TEST_STRUCT.r, ECC_KEY_LENGTH_521);
	memcpy (sig_ex.s, ECC521_SIGNATURE_TEST_STRUCT.s, ECC_KEY_LENGTH_521);
	sig_ex.length = ECC_KEY_LENGTH_521;

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_ptr_tmp (&backend.hw.mock, 5, &sig_ex,
		sizeof (struct ecc_ecdsa_signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_SIGNATURE_TEST_STRUCT.r, backend.data.siggen.R.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_SIGNATURE_TEST_STRUCT.s, backend.data.siggen.S.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_hash_and_finish_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	struct ecc_ecdsa_signature sig_ex;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	memset (&sig_ex, 0, sizeof (struct ecc_ecdsa_signature));
	memcpy (sig_ex.r, ECC521_SIGNATURE_TEST_STRUCT.r, ECC_KEY_LENGTH_521);
	memcpy (sig_ex.s, ECC521_SIGNATURE_TEST_STRUCT.s, ECC_KEY_LENGTH_521);
	sig_ex.length = ECC_KEY_LENGTH_521;

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_ptr_tmp (&backend.hw.mock, 5, &sig_ex,
		sizeof (struct ecc_ecdsa_signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_SIGNATURE_TEST_STRUCT.r, backend.data.siggen.R.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_SIGNATURE_TEST_STRUCT.s, backend.data.siggen.S.buf,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

static void backend_ecdsa_test_siggen_null (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	// Testing five null cases.
	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null private key.
	backend.data.siggen.privkey = NULL;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.siggen.privkey = (void*) ECC384_PRIVKEY;

	// Test null msg buffer.
	platform_free (backend.data.siggen.msg.buf);
	backend.data.siggen.msg.buf = NULL;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.siggen.msg.buf =
		(unsigned char*) platform_malloc (strlen ((char*) ecdsa_test_data_msg));
	CuAssertPtrNotNull (test, backend.data.siggen.msg.buf);

	// Test null Qx buffer.
	platform_free (backend.data.siggen.Qx.buf);
	backend.data.siggen.Qx.buf = NULL;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.siggen.Qx.buf =
		(unsigned char*) platform_malloc (sizeof (ECC_PUBKEY_POINT.x));
	CuAssertPtrNotNull (test, backend.data.siggen.Qx.buf);

	// Test null Qy buffer.
	platform_free (backend.data.siggen.Qy.buf);
	backend.data.siggen.Qy.buf = NULL;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_invalid_component_type (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	// Test invalid component type value.
	backend.data.siggen.component = BACKEND_ECDSA_COMPONENT_TYPE_COMPONENT;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_no_engine (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation + 1;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_unsupported_hash (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_HASH_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_INVALID);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_unsupported_curve (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_CURVE_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN,
		ECDSA_TEST_ECC_KEY_TYPE_INVALID, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hash_and_finish_hash_start_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hash_and_finish_hash_update_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UPDATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash, 0);

	status |= mock_expect (&backend.hash.mock, backend.hash.base.update, &backend.hash,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ecdsa_test_data_msg, strlen (ecdsa_test_data_msg)),
		MOCK_ARG (strlen (ecdsa_test_data_msg)));

	status |= mock_expect (&backend.hash.mock, backend.hash.base.cancel, &backend.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_sign_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_KEY_PAIR_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.engine.mock, backend.engine.base.init_key_pair, &backend.engine,
		ECC_ENGINE_KEY_PAIR_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_DER_P256_PRIVATE_LENGTH),
		MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_hash_and_finish_hash_start_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_hash_and_finish_hash_update_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UPDATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash, 0);

	status |= mock_expect (&backend.hash.mock, backend.hash.base.update, &backend.hash,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ecdsa_test_data_msg, strlen (ecdsa_test_data_msg)),
		MOCK_ARG (strlen (ecdsa_test_data_msg)));

	status |= mock_expect (&backend.hash.mock, backend.hash.base.cancel, &backend.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_hw_sign_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_HW_ECDSA_SIGN_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw,
		ECC_HW_ECDSA_SIGN_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_siggen_decode_sig_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_DER_UTIL_MALFORMED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	uint8_t bad_signature[ECC_SIG_TEST_LEN];
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	memset (bad_signature, 1, ECC_SIG_TEST_LEN);

	status = mock_expect (&backend.engine.mock, backend.engine.base.init_key_pair, &backend.engine,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_DER_P256_PRIVATE_LENGTH), MOCK_ARG_ANY,	MOCK_ARG_ANY);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.sign, &backend.engine,	0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= mock_expect_output (&backend.engine.mock, 4, bad_signature, ECC_SIG_TEST_LEN, -1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_siggen (&backend.data.siggen, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hash_and_finish_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_hash_and_finish_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
static void backend_ecdsa_test_sigver_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hash_and_finish_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA384_TEST_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_hash_and_finish_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC384_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA384_TEST_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
static void backend_ecdsa_test_sigver_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hash_and_finish_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA512_TEST_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_hash_and_finish_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC521_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC521_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA512_TEST_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

static void backend_ecdsa_test_sigver_bad_signature (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CRYPTO,
		.msg_index = CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC,
		.arg1 = MBEDTLS_ERR_ECP_VERIFY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	// Testing engine used produces log message on verification failure.
	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	// Corrupt the signature to trigger signature verification failure.
	memcpy (backend.data.sigver.S.buf, ECC_SIGNATURE_TEST2_STRUCT.s,
		ECC_SIGNATURE_TEST2_STRUCT.length);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.sigver.sigver_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw,
		ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.sigver.sigver_success);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_null (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	// Testing six null cases.
	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null R buffer.
	platform_free (backend.data.sigver.R.buf);
	backend.data.sigver.R.buf = NULL;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.sigver.R.buf =
		(unsigned char*) platform_malloc (sizeof (ECC_SIGNATURE_TEST_STRUCT.r));
	CuAssertPtrNotNull (test, backend.data.sigver.R.buf);

	// Test null S buffer.
	platform_free (backend.data.sigver.S.buf);
	backend.data.sigver.S.buf = NULL;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.sigver.S.buf =
		(unsigned char*) platform_malloc (sizeof (ECC_SIGNATURE_TEST_STRUCT.s));
	CuAssertPtrNotNull (test, backend.data.sigver.S.buf);

	// Test null msg buffer.
	platform_free (backend.data.sigver.msg.buf);
	backend.data.sigver.msg.buf = NULL;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.sigver.msg.buf =
		(unsigned char*) platform_malloc (strlen ((char*) ecdsa_test_data_msg));
	CuAssertPtrNotNull (test, backend.data.sigver.msg.buf);

	// Test null Qx buffer.
	platform_free (backend.data.sigver.Qx.buf);
	backend.data.sigver.Qx.buf = NULL;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.sigver.Qx.buf =
		(unsigned char*) platform_malloc (sizeof (ECC_PUBKEY_POINT.x));
	CuAssertPtrNotNull (test, backend.data.sigver.Qx.buf);

	// Test null Qy buffer.
	platform_free (backend.data.sigver.Qy.buf);
	backend.data.sigver.Qy.buf = NULL;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_invalid_component_type (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	// Test invalid component type value.
	backend.data.sigver.component = BACKEND_ECDSA_COMPONENT_TYPE_COMPONENT;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_no_engine (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation + 1;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_unsupported_hash (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_HASH_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_INVALID);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_unsupported_curve (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_CURVE_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER,
		ECDSA_TEST_ECC_KEY_TYPE_INVALID, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hash_and_finish_hash_start_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hash_and_finish_hash_update_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UPDATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash, 0);

	status |= mock_expect (&backend.hash.mock, backend.hash.base.update, &backend.hash,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ecdsa_test_data_msg, strlen (ecdsa_test_data_msg)),
		MOCK_ARG (strlen (ecdsa_test_data_msg)));

	status |= mock_expect (&backend.hash.mock, backend.hash.base.cancel, &backend.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = SIG_VERIFICATION_INVALID_ARGUMENT,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = NULL,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	acvp_implementation = implementation;

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_hash_and_finish_hash_start_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_hash_and_finish_hash_update_error (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UPDATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &backend.hash.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_HASH_AND_FINISH
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash, 0);

	status |= mock_expect (&backend.hash.mock, backend.hash.base.update, &backend.hash,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ecdsa_test_data_msg, strlen (ecdsa_test_data_msg)),
		MOCK_ARG (strlen (ecdsa_test_data_msg)));

	status |= mock_expect (&backend.hash.mock, backend.hash.base.cancel, &backend.hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_sigver_hw_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_HW_ECDSA_VERIFY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_SIGVER, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw,
		ECC_HW_ECDSA_VERIFY_FAILED,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature, &ECC_SIGNATURE_TEST_STRUCT,
		sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_sigver (&backend.data.sigver, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_p256 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, qx.buf);
	CuAssertPtrNotNull (test, qy.buf);
	CuAssertPtrNotNull (test, privkey);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_hw_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC_PRIVKEY, ECC_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC_PUBKEY_POINT, sizeof (ECC_PUBKEY_POINT),
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (qx.buf, ECC_PUBKEY_POINT.x, ECC_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (qy.buf, ECC_PUBKEY_POINT.y, ECC_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (privkey, ECC_PRIVKEY, ECC_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
static void backend_ecdsa_test_keygen_en_p384 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, qx.buf);
	CuAssertPtrNotNull (test, qy.buf);
	CuAssertPtrNotNull (test, privkey);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_hw_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_384,
		HASH_TYPE_SHA384);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC384_PRIVKEY, ECC384_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC384_PUBKEY_POINT,
		sizeof (ECC384_PUBKEY_POINT), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (qx.buf, ECC384_PUBKEY_POINT.x, ECC384_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (qy.buf, ECC384_PUBKEY_POINT.y, ECC384_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (privkey, ECC384_PRIVKEY, ECC384_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
static void backend_ecdsa_test_keygen_en_p521 (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, qx.buf);
	CuAssertPtrNotNull (test, qy.buf);
	CuAssertPtrNotNull (test, privkey);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_hw_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_521,
		HASH_TYPE_SHA512);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,	0,
		MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, ECC521_PRIVKEY, ECC521_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC521_PUBKEY_POINT,
		sizeof (ECC521_PUBKEY_POINT), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_sign, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY, ECC521_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 5, ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN,
		-1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdsa_verify, &backend.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (qx.buf, ECC521_PUBKEY_POINT.x, ECC521_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (qy.buf, ECC521_PUBKEY_POINT.y, ECC521_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (privkey, ECC521_PRIVKEY, ECC521_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}
#endif

static void backend_ecdsa_test_keygen_en_null (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	int status;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_INVALID_ARGUMENT,
		.arg2 = 0
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, NULL, &qy, (void**) &privkey);
	CuAssertIntEquals (test, -1, status);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, NULL, (void**) &privkey);
	CuAssertIntEquals (test, -1, status);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, NULL);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_no_engine (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_NO_ENGINE,
		.arg2 = 0
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, -1, status);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation + 1;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_keygen_en_unsupported_curve (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDSA_CURVE_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN,
		ECDSA_TEST_ECC_KEY_TYPE_INVALID, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_free_key (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	HASH_TESTING_ENGINE (hash_engine);
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdsa_engine ecdsa_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base,
			.hash = &hash_engine.base,
			.keygen_type = BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES,
			.api_type = BACKEND_ECDSA_API_TYPE_MESSAGE
		}
	};
	struct buffer qx;
	struct buffer qy;
	uint8_t *privkey = NULL;
	int status;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_ecdsa_register_engines (ecdsa_engines, 1);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	status = ecdsa_impl->ecdsa_keygen_en (backend.data.keygen.cipher, &qx, &qy, (void**) &privkey);
	CuAssertIntEquals (test, 0, status);

	ecdsa_impl->ecdsa_free_key (privkey);
	platform_free (qx.buf);
	platform_free (qy.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);
	HASH_TESTING_ENGINE_RELEASE (&hash_engine);

	backend_ecdsa_testing_release (test, &backend);
}

static void backend_ecdsa_test_free_key_null (CuTest *test)
{
	const struct ecdsa_backend *ecdsa_impl;
	struct backend_ecdsa_testing backend;

	TEST_START;

	backend_ecdsa_testing_init (test, &backend, ECDSA_TEST_TYPE_KEYGEN, ECDSA_TEST_ECC_KEY_TYPE_256,
		HASH_TYPE_SHA256);

	ecdsa_impl = backend_ecdsa_get_impl ();
	CuAssertPtrNotNull (test, ecdsa_impl);

	ecdsa_impl->ecdsa_free_key (NULL);

	backend_ecdsa_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_ecdsa);

TEST (backend_ecdsa_test_init);
TEST (backend_ecdsa_test_keygen_p256);
TEST (backend_ecdsa_test_keygen_hw_p256);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
TEST (backend_ecdsa_test_keygen_p384);
TEST (backend_ecdsa_test_keygen_hw_p384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
TEST (backend_ecdsa_test_keygen_p521);
TEST (backend_ecdsa_test_keygen_hw_p521);
#endif
TEST (backend_ecdsa_test_keygen_null);
TEST (backend_ecdsa_test_keygen_no_engine);
TEST (backend_ecdsa_test_keygen_engine_not_found);
TEST (backend_ecdsa_test_keygen_unsupported_type);
TEST (backend_ecdsa_test_keygen_unsupported_curve);
TEST (backend_ecdsa_test_keygen_gen_error);
TEST (backend_ecdsa_test_keygen_hw_gen_error);
TEST (backend_ecdsa_test_keygen_extra_p256);
TEST (backend_ecdsa_test_keygen_extra_hw_p256);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
TEST (backend_ecdsa_test_keygen_extra_p384);
TEST (backend_ecdsa_test_keygen_extra_hw_p384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
TEST (backend_ecdsa_test_keygen_extra_p521);
TEST (backend_ecdsa_test_keygen_extra_hw_p521);
#endif
TEST (backend_ecdsa_test_keygen_extra_null);
TEST (backend_ecdsa_test_keygen_extra_no_engine);
TEST (backend_ecdsa_test_keygen_extra_engine_not_found);
TEST (backend_ecdsa_test_keygen_extra_unsupported_type);
TEST (backend_ecdsa_test_siggen_p256);
TEST (backend_ecdsa_test_siggen_hash_and_finish_p256);
TEST (backend_ecdsa_test_siggen_hw_p256);
TEST (backend_ecdsa_test_siggen_hw_hash_and_finish_p256);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
TEST (backend_ecdsa_test_siggen_p384);
TEST (backend_ecdsa_test_siggen_hash_and_finish_p384);
TEST (backend_ecdsa_test_siggen_hw_p384);
TEST (backend_ecdsa_test_siggen_hw_hash_and_finish_p384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
TEST (backend_ecdsa_test_siggen_p521);
TEST (backend_ecdsa_test_siggen_hash_and_finish_p521);
TEST (backend_ecdsa_test_siggen_hw_p521);
TEST (backend_ecdsa_test_siggen_hw_hash_and_finish_p521);
#endif
TEST (backend_ecdsa_test_siggen_null);
TEST (backend_ecdsa_test_siggen_invalid_component_type);
TEST (backend_ecdsa_test_siggen_no_engine);
TEST (backend_ecdsa_test_siggen_engine_not_found);
TEST (backend_ecdsa_test_siggen_unsupported_hash);
TEST (backend_ecdsa_test_siggen_unsupported_curve);
TEST (backend_ecdsa_test_siggen_hash_and_finish_hash_start_error);
TEST (backend_ecdsa_test_siggen_hash_and_finish_hash_update_error);
TEST (backend_ecdsa_test_siggen_sign_error);
TEST (backend_ecdsa_test_siggen_hw_hash_and_finish_hash_start_error);
TEST (backend_ecdsa_test_siggen_hw_hash_and_finish_hash_update_error);
TEST (backend_ecdsa_test_siggen_hw_sign_error);
TEST (backend_ecdsa_test_siggen_decode_sig_error);
TEST (backend_ecdsa_test_sigver_p256);
TEST (backend_ecdsa_test_sigver_hash_and_finish_p256);
TEST (backend_ecdsa_test_sigver_hw_p256);
TEST (backend_ecdsa_test_sigver_hw_hash_and_finish_p256);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
TEST (backend_ecdsa_test_sigver_p384);
TEST (backend_ecdsa_test_sigver_hash_and_finish_p384);
TEST (backend_ecdsa_test_sigver_hw_p384);
TEST (backend_ecdsa_test_sigver_hw_hash_and_finish_p384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
TEST (backend_ecdsa_test_sigver_p521);
TEST (backend_ecdsa_test_sigver_hash_and_finish_p521);
TEST (backend_ecdsa_test_sigver_hw_p521);
TEST (backend_ecdsa_test_sigver_hw_hash_and_finish_p521);
#endif
TEST (backend_ecdsa_test_sigver_bad_signature);
TEST (backend_ecdsa_test_sigver_hw_bad_signature);
TEST (backend_ecdsa_test_sigver_null);
TEST (backend_ecdsa_test_sigver_invalid_component_type);
TEST (backend_ecdsa_test_sigver_no_engine);
TEST (backend_ecdsa_test_sigver_engine_not_found);
TEST (backend_ecdsa_test_sigver_unsupported_hash);
TEST (backend_ecdsa_test_sigver_unsupported_curve);
TEST (backend_ecdsa_test_sigver_hash_and_finish_hash_start_error);
TEST (backend_ecdsa_test_sigver_hash_and_finish_hash_update_error);
TEST (backend_ecdsa_test_sigver_verify_error);
TEST (backend_ecdsa_test_sigver_hw_hash_and_finish_hash_start_error);
TEST (backend_ecdsa_test_sigver_hw_hash_and_finish_hash_update_error);
TEST (backend_ecdsa_test_sigver_hw_verify_error);
TEST (backend_ecdsa_test_keygen_en_p256);
TEST (backend_ecdsa_test_keygen_en_hw_p256);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && (defined HASH_ENABLE_SHA384)
TEST (backend_ecdsa_test_keygen_en_p384);
TEST (backend_ecdsa_test_keygen_en_hw_p384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && (defined HASH_ENABLE_SHA512)
TEST (backend_ecdsa_test_keygen_en_p521);
TEST (backend_ecdsa_test_keygen_en_hw_p521);
#endif
TEST (backend_ecdsa_test_keygen_en_null);
TEST (backend_ecdsa_test_keygen_en_no_engine);
TEST (backend_ecdsa_test_keygen_en_engine_not_found);
TEST (backend_ecdsa_test_keygen_en_unsupported_curve);
TEST (backend_ecdsa_test_free_key);
TEST (backend_ecdsa_test_free_key_null);

TEST_SUITE_END;
// *INDENT-ON*
