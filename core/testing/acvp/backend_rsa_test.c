// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_rsa.h"
#include "mbedtls/pk.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_rsa");


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * RSA test types.
 */
enum rsa_test_type {
	RSA_TEST_TYPE_KEYGEN = 0,			/**< RSA key generation test for B.3.4/5/6 (CAVS test specification section 6.2.2.1). */
	RSA_TEST_TYPE_SIGGEN,				/**< RSA signature generation test. */
	RSA_TEST_TYPE_SIGVER,				/**< RSA signature verification test. */
	RSA_TEST_TYPE_KEYGEN_PRIME,			/**< RSA key generation with prime test for B.3.3 (CAVS test specification section 6.2.2.2). */
	RSA_TEST_TYPE_KEYGEN_PROV_PRIME,	/**< RSA key generation with provable prime test for B.3.2 (CAVS test specification section 6.2.1). */
	RSA_TEST_TYPE_SIGNATURE_PRIMITIVE,	/**< RSA signature primitive test. */
	RSA_TEST_TYPE_DECRYPTION_PRIMITIVE,	/**< RSA decryption primitive test. */
};

/**
 * RSA test data.
 */
union rsa_testing_data {
	struct rsa_keygen_data keygen;								/**< RSA key generation test data. */
	struct rsa_siggen_data siggen;								/**< RSA signature generation test data. */
	struct rsa_sigver_data sigver;								/**< RSA signature verification test data. */
	struct rsa_keygen_prime_data keygen_prime;					/**< RSA key generation with prime test data. */
	struct rsa_keygen_prov_prime_data keygen_prov_prime;		/**< RSA key generation with provable prime test data. */
	struct rsa_signature_primitive_data signature_primitive;	/**< RSA signature primitive test data. */
	struct rsa_decryption_primitive_data decryption_primitive;	/**< RSA decryption primitive test data. */
};

/**
 * Dependencies for testing.
 */
struct backend_rsa_testing {
	enum rsa_test_type type;		/**< RSA test type. */
	union rsa_testing_data data;	/**< RSA test data. */
	struct rsa_engine_mock engine;	/**< Mock for the RSA engine. */
	struct logging_mock logger;		/**< Mock for debug logging. */
};


/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_rsa_testing_init (CuTest *test, struct backend_rsa_testing *backend,
	enum rsa_test_type type)
{
	union rsa_testing_data data;
	int status;

	switch (type) {
		case RSA_TEST_TYPE_KEYGEN:
			data.keygen.modulus = RSA_KEY_LENGTH_2K * 8;

			data.keygen.n.buf = NULL;
			data.keygen.d.buf = NULL;
			data.keygen.p.buf = NULL;
			data.keygen.q.buf = NULL;

			data.keygen.e.buf = platform_malloc (RSA_PUBKEY_EXPONENT_LEN);
			CuAssertPtrNotNull (test, data.keygen.e.buf);

			memcpy (data.keygen.e.buf, RSA_PUBKEY_EXPONENT, RSA_PUBKEY_EXPONENT_LEN);
			data.keygen.e.len = RSA_PUBKEY_EXPONENT_LEN;

			break;

		default:
			CuFail (test, "Unsupported RSA test type");

			return;
	}

	backend->type = RSA_TEST_TYPE_KEYGEN;
	backend->data = data;

	status = rsa_mock_init (&backend->engine);
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
static void backend_rsa_testing_release (CuTest *test, struct backend_rsa_testing *backend)
{
	int status;

	switch (backend->type) {
		case RSA_TEST_TYPE_KEYGEN:
			if (backend->data.keygen.n.buf != NULL) {
				platform_free (backend->data.keygen.n.buf);
			}

			if (backend->data.keygen.d.buf != NULL) {
				platform_free (backend->data.keygen.d.buf);
			}

			if (backend->data.keygen.p.buf != NULL) {
				platform_free (backend->data.keygen.p.buf);
			}

			if (backend->data.keygen.q.buf != NULL) {
				platform_free (backend->data.keygen.q.buf);
			}

			if (backend->data.keygen.e.buf != NULL) {
				platform_free (backend->data.keygen.e.buf);
			}

			break;

		default:
			CuFail (test, "Invalid RSA test type");

			return;
	}

	backend_rsa_register_engines (NULL, 0);

	status = rsa_mock_validate_and_release (&backend->engine);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void backend_rsa_test_init (CuTest *test)
{
	const struct rsa_backend *rsa_impl;

	TEST_START;

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);
	CuAssertPtrNotNull (test, rsa_impl->rsa_keygen);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_siggen);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_sigver);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_keygen_prime);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_keygen_prov_prime);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_keygen_en);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_free_key);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_signature_primitive);
	CuAssertPtrEquals (test, NULL, rsa_impl->rsa_decryption_primitive);
}

static void backend_rsa_test_rsa_keygen (CuTest *test)
{
	RSA_TESTING_ENGINE (engine);
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	acvp_implementation = implementation;

	status = RSA_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	// Verify components of the generated key.
	CuAssertPtrNotNull (test, backend.data.keygen.n.buf);
	CuAssertIntEquals (test, RSA_KEY_LENGTH_2K, backend.data.keygen.n.len);
	CuAssertPtrNotNull (test, backend.data.keygen.p.buf);
	CuAssertTrue (test, (backend.data.keygen.p.len <= (RSA_KEY_LENGTH_2K / 2)));
	CuAssertPtrNotNull (test, backend.data.keygen.q.buf);
	CuAssertTrue (test, (backend.data.keygen.q.len <= (RSA_KEY_LENGTH_2K / 2)));
	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);
	CuAssertTrue (test, (backend.data.keygen.d.len <= RSA_KEY_LENGTH_2K));
	CuAssertPtrNotNull (test, backend.data.keygen.e.buf);
	CuAssertIntEquals (test, RSA_PUBKEY_EXPONENT_LEN, backend.data.keygen.e.len);

	// The exponent was set on input, but verify that it hasn't changed.
	status = testing_validate_array (RSA_PUBKEY_EXPONENT, backend.data.keygen.e.buf,
		RSA_PUBKEY_EXPONENT_LEN);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&engine);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_3k (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &backend.engine.base
		}
	};
	uint8_t *key_der = NULL;
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key, &backend.engine,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_KEY_LENGTH_2K * 8));
	status |= mock_expect_save_arg (&backend.engine.mock, 0, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_private_key_der,
		&backend.engine, 0,	MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.engine.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&backend.engine.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key, &backend.engine,
		0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	// Verify components of the generated key.
	CuAssertPtrNotNull (test, backend.data.keygen.n.buf);
	CuAssertIntEquals (test, RSA_KEY_LENGTH_3K, backend.data.keygen.n.len);
	CuAssertPtrNotNull (test, backend.data.keygen.p.buf);
	CuAssertTrue (test, (backend.data.keygen.p.len <= (RSA_KEY_LENGTH_3K / 2)));
	CuAssertPtrNotNull (test, backend.data.keygen.q.buf);
	CuAssertTrue (test, (backend.data.keygen.q.len <= (RSA_KEY_LENGTH_3K / 2)));
	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);
	CuAssertTrue (test, (backend.data.keygen.d.len <= RSA_KEY_LENGTH_3K));
	CuAssertPtrNotNull (test, backend.data.keygen.e.buf);
	CuAssertIntEquals (test, RSA_PUBKEY_EXPONENT_LEN, backend.data.keygen.e.len);

	status = testing_validate_array (RSA3K_PUBLIC_KEY.modulus, backend.data.keygen.n.buf,
		RSA3K_PUBLIC_KEY.mod_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA3K_PRIVKEY_D, backend.data.keygen.d.buf,
		RSA3K_PRIVKEY_D_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA3K_PRIVKEY_P, backend.data.keygen.p.buf,
		RSA3K_PRIVKEY_P_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA3K_PRIVKEY_Q, backend.data.keygen.q.buf,
		RSA3K_PRIVKEY_Q_LEN);
	CuAssertIntEquals (test, 0, status);

	// The exponent was set on input, but verify that it hasn't changed.
	status = testing_validate_array (RSA_PUBKEY_EXPONENT, backend.data.keygen.e.buf,
		RSA_PUBKEY_EXPONENT_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_4k (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &backend.engine.base
		}
	};
	uint8_t *key_der = NULL;
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	key_der = platform_malloc (RSA4K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA4K_PRIVKEY_DER, RSA4K_PRIVKEY_DER_LEN);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key, &backend.engine,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_KEY_LENGTH_2K * 8));
	status |= mock_expect_save_arg (&backend.engine.mock, 0, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_private_key_der,
		&backend.engine, 0,	MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.engine.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&backend.engine.mock, 2, &RSA4K_PRIVKEY_DER_LEN,
		sizeof (RSA4K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key, &backend.engine,
		0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, 0, status);

	// Verify components of the generated key.
	CuAssertPtrNotNull (test, backend.data.keygen.n.buf);
	CuAssertIntEquals (test, RSA_KEY_LENGTH_4K, backend.data.keygen.n.len);
	CuAssertPtrNotNull (test, backend.data.keygen.p.buf);
	CuAssertTrue (test, (backend.data.keygen.p.len <= (RSA_KEY_LENGTH_4K / 2)));
	CuAssertPtrNotNull (test, backend.data.keygen.q.buf);
	CuAssertTrue (test, (backend.data.keygen.q.len <= (RSA_KEY_LENGTH_4K / 2)));
	CuAssertPtrNotNull (test, backend.data.keygen.d.buf);
	CuAssertTrue (test, (backend.data.keygen.d.len <= RSA_KEY_LENGTH_4K));
	CuAssertPtrNotNull (test, backend.data.keygen.e.buf);
	CuAssertIntEquals (test, RSA_PUBKEY_EXPONENT_LEN, backend.data.keygen.e.len);

	status = testing_validate_array (RSA4K_PUBLIC_KEY.modulus, backend.data.keygen.n.buf,
		RSA4K_PUBLIC_KEY.mod_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA4K_PRIVKEY_D, backend.data.keygen.d.buf,
		RSA4K_PRIVKEY_D_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA4K_PRIVKEY_P, backend.data.keygen.p.buf,
		RSA4K_PRIVKEY_P_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA4K_PRIVKEY_Q, backend.data.keygen.q.buf,
		RSA4K_PRIVKEY_Q_LEN);
	CuAssertIntEquals (test, 0, status);

	// The exponent was set on input, but verify that it hasn't changed.
	status = testing_validate_array (RSA_PUBKEY_EXPONENT, backend.data.keygen.e.buf,
		RSA_PUBKEY_EXPONENT_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_null (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_RSA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	rsa_impl = backend_rsa_get_impl ();

	status = rsa_impl->rsa_keygen (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_no_engine (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_RSA_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_engine_not_found (CuTest *test)
{
	RSA_TESTING_ENGINE (engine);
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_RSA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	acvp_implementation = implementation + 1;

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	RSA_TESTING_ENGINE_RELEASE (&engine);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_modulus_too_large (CuTest *test)
{
	RSA_TESTING_ENGINE (engine);
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_RSA_KEY_LEN_TOO_LARGE,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	backend.data.keygen.modulus = (RSA_MAX_KEY_LENGTH * 8) + 1;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	acvp_implementation = implementation;

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	RSA_TESTING_ENGINE_RELEASE (&engine);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_random_e_unsupported (CuTest *test)
{
	RSA_TESTING_ENGINE (engine);
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_RSA_RANDOM_E_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

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

	status = RSA_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	acvp_implementation = implementation;

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	// Re-register engine with E generation unsupported, then test E buffer input checks.
	rsa_engines[0].random_e_supported = false;
	backend_rsa_register_engines (rsa_engines, 1);

	backend.data.keygen.e.len = 0;

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.keygen.e.len = RSA_PUBKEY_EXPONENT_LEN;

	platform_free (backend.data.keygen.e.buf);
	backend.data.keygen.e.buf = NULL;

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	RSA_TESTING_ENGINE_RELEASE (&engine);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_generate_key_error (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = RSA_ENGINE_GENERATE_KEY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key, &backend.engine,
		RSA_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_KEY_LENGTH_2K * 8));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_get_private_key_der_error (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = RSA_ENGINE_PRIVATE_KEY_DER_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key, &backend.engine,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_KEY_LENGTH_2K * 8));
	status |= mock_expect_save_arg (&backend.engine.mock, 0, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_private_key_der,
		&backend.engine, RSA_ENGINE_PRIVATE_KEY_DER_FAILED,	MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key, &backend.engine,
		0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	backend_rsa_testing_release (test, &backend);
}

static void backend_rsa_test_rsa_keygen_parse_key_error (CuTest *test)
{
	const struct rsa_backend *rsa_impl;
	struct backend_rsa_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_rsa_engine rsa_engines[] = {
		{
			.impl_id = implementation,
			.random_e_supported = false,
			.engine = &backend.engine.base
		}
	};
	uint8_t *key_der = NULL;
	size_t bad_key_len = 0;
	int status;

	TEST_START;

	backend_rsa_testing_init (test, &backend, RSA_TEST_TYPE_KEYGEN);

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key, &backend.engine,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_KEY_LENGTH_2K * 8));
	status |= mock_expect_save_arg (&backend.engine.mock, 0, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_private_key_der,
		&backend.engine, 0,	MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.engine.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&backend.engine.mock, 2, &bad_key_len, sizeof (bad_key_len), -1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key, &backend.engine,
		0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_rsa_register_engines (rsa_engines, 1);

	rsa_impl = backend_rsa_get_impl ();
	CuAssertPtrNotNull (test, rsa_impl);

	status = rsa_impl->rsa_keygen (&backend.data.keygen, 0);
	CuAssertIntEquals (test, -1, status);

	CuAssertPtrEquals (test, NULL, backend.data.keygen.n.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.d.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.p.buf);
	CuAssertPtrEquals (test, NULL, backend.data.keygen.q.buf);

	backend_rsa_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_rsa);

TEST (backend_rsa_test_init);
TEST (backend_rsa_test_rsa_keygen);
TEST (backend_rsa_test_rsa_keygen_3k);
TEST (backend_rsa_test_rsa_keygen_4k);
TEST (backend_rsa_test_rsa_keygen_null);
TEST (backend_rsa_test_rsa_keygen_no_engine);
TEST (backend_rsa_test_rsa_keygen_engine_not_found);
TEST (backend_rsa_test_rsa_keygen_modulus_too_large);
TEST (backend_rsa_test_rsa_keygen_random_e_unsupported);
TEST (backend_rsa_test_rsa_keygen_generate_key_error);
TEST (backend_rsa_test_rsa_keygen_get_private_key_der_error);
TEST (backend_rsa_test_rsa_keygen_parse_key_error);

TEST_SUITE_END;
// *INDENT-ON*
