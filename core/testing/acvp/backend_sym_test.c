// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_sym.h"
#include "crypto/crypto_logging.h"
#include "crypto/kat/aes_key_wrap_kat_vectors.h"
#include "parser/cipher_definitions.h"
#include "parser/common.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/aes_key_wrap_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_sym");


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * AES-KW test type.
 */
enum backend_sym_test_type {
	BACKEND_SYM_TEST_TYPE_ENCRYPT,	/**< Symmetric cipher encryption test. */
	BACKEND_SYM_TEST_TYPE_DECRYPT,	/**< Symmetric cipher decryption test. */
};

/**
 * Dependencies for testing.
 */
struct backend_sym_testing {
	struct sym_data data;				/**< Symmetric cipher test data. */
	struct aes_key_wrap_mock aes_kw;	/**< Mock for AES-KW and AES-KWP testing. */
	struct logging_mock logger;			/**< Mock for debug logging. */
};


/**
 * Initialize the testing dependencies for an AES-KW test.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 * @param type The type of AES-KW test to run.
 */
static void backend_sym_testing_init_aes_kw (CuTest *test, struct backend_sym_testing *backend,
	enum backend_sym_test_type type)
{
	struct sym_data data;

	memset (&data, 0, sizeof (data));

	data.key.buf = (unsigned char*) AES_KEY_WRAP_KAT_VECTORS_KW_KEY;
	data.key.len = AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN;

	data.cipher = ACVP_CIPHERTYPE_AES;

	switch (type) {
		case BACKEND_SYM_TEST_TYPE_ENCRYPT:
			data.data.buf =
				(unsigned char*) platform_malloc (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN);
			CuAssertPtrNotNull (test, data.data.buf);

			memcpy (data.data.buf, AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
				AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN);
			data.data.len = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;

			data.cipher |= ACVP_KW;

			break;

		case BACKEND_SYM_TEST_TYPE_DECRYPT:
			data.data.buf =
				(unsigned char*) platform_malloc (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN);
			CuAssertPtrNotNull (test, data.data.buf);

			memcpy (data.data.buf, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
				AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN);
			data.data.len = AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN;

			data.cipher |= ACVP_KW_INV;

			break;

		default:
			CuFail (test, "Invalid AES-KW test type");

			return;
	}

	backend->data = data;
}

/**
 * Initialize the testing dependencies for an AES-KWP test.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 * @param type The type of AES-KW test to run.
 */
static void backend_sym_testing_init_aes_kwp (CuTest *test, struct backend_sym_testing *backend,
	enum backend_sym_test_type type)
{
	struct sym_data data;

	memset (&data, 0, sizeof (data));

	data.key.buf = (unsigned char*) AES_KEY_WRAP_KAT_VECTORS_KWP_KEY;
	data.key.len = AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN;

	data.cipher = ACVP_CIPHERTYPE_AES;

	switch (type) {
		case BACKEND_SYM_TEST_TYPE_ENCRYPT:
			data.data.buf =
				(unsigned char*) platform_malloc (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);
			CuAssertPtrNotNull (test, data.data.buf);

			memcpy (data.data.buf, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
				AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);
			data.data.len = AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN;

			data.cipher |= ACVP_KWP;

			break;

		case BACKEND_SYM_TEST_TYPE_DECRYPT:
			data.data.buf =
				(unsigned char*) platform_malloc (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN);
			CuAssertPtrNotNull (test, data.data.buf);

			memcpy (data.data.buf, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
				AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN);
			data.data.len = AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN;

			data.cipher |= ACVP_KWP_INV;

			break;

		default:
			CuFail (test, "Invalid AES-KWP test type");

			return;
	}

	backend->data = data;
}

/**
 * Initialize the testing dependencies for a backend symmetric cipher test.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 * @param type The type of backend symmetric cipher test to run.
 * @param engine_type The type of symmetric cipher engine to use.
 */
static void backend_sym_testing_init (CuTest *test, struct backend_sym_testing *backend,
	enum backend_sym_test_type test_type, enum backend_sym_engine_type engine_type)
{
	int status;

	switch (engine_type) {
		case BACKEND_SYM_ENGINE_TYPE_AES_KW:
			backend_sym_testing_init_aes_kw (test, backend, test_type);
			break;

		case BACKEND_SYM_ENGINE_TYPE_AES_KWP:
			backend_sym_testing_init_aes_kwp (test, backend, test_type);
			break;

		default:
			CuFail (test, "Invalid symmetric cipher engine type");

			return;
	}

	status = aes_key_wrap_mock_init (&backend->aes_kw);
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
static void backend_sym_testing_release (CuTest *test, struct backend_sym_testing *backend)
{
	int status;

	if (backend->data.data.buf != NULL) {
		platform_free (backend->data.data.buf);
	}

	backend_sym_register_engines (NULL, 0);

	status = aes_key_wrap_mock_validate_and_release (&backend->aes_kw);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void backend_sym_test_init (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;

	TEST_START;

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);
	CuAssertPtrNotNull (test, sym_impl->encrypt);
	CuAssertPtrNotNull (test, sym_impl->decrypt);
	CuAssertPtrEquals (test, NULL, sym_impl->mct_init);
	CuAssertPtrEquals (test, NULL, sym_impl->mct_update);
	CuAssertPtrEquals (test, NULL, sym_impl->mct_fini);
}

static void backend_sym_test_encrypt_aes_kw (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KW,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KW);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.wrap, &backend.aes_kw,	0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.aes_kw.mock, 2, &AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN, backend.data.data.len);

	status = testing_validate_array (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED, backend.data.data.buf,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_aes_kwp (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.wrap, &backend.aes_kw,	0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.aes_kw.mock, 2, &AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN, backend.data.data.len);

	status = testing_validate_array (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED, backend.data.data.buf,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_null (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_INVALID_ARGUMENT,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

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

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null data.
	platform_free (backend.data.data.buf);
	backend.data.data.buf = NULL;

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.data.buf = platform_malloc (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);
	CuAssertPtrNotNull (test, backend.data.data.buf);

	memcpy (backend.data.data.buf, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);

	backend.data.data.len = 0;

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null key.
	backend.data.key.buf = NULL;

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.key.buf = (unsigned char*) AES_KEY_WRAP_KAT_VECTORS_KWP_KEY;

	backend.data.key.len = 0;

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_no_engine (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_engine_not_found (CuTest *test)
{
	AES_ECB_TESTING_ENGINE (engine);
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = AES_ECB_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation + 1;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	AES_ECB_TESTING_ENGINE_RELEASE (&engine);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_unsupported_type (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KW
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_UNSUPPORTED_CIPHER_TYPE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_aes_kwp_set_kek_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_KEY_WRAP_SET_KEK_FAILED,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw,
		AES_KEY_WRAP_SET_KEK_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_encrypt_aes_kwp_wrap_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_KEY_WRAP_WRAP_FAILED,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_ENCRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.wrap, &backend.aes_kw,
		AES_KEY_WRAP_WRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kw (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KW,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KW);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.unwrap, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.aes_kw.mock, 2, &AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.integrity_error);
	CuAssertTrue (test, backend.data.data.len >= AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN);

	status = testing_validate_array (AES_KEY_WRAP_KAT_VECTORS_KW_DATA, backend.data.data.buf,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kwp (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.unwrap, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.aes_kw.mock, 2, &AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.integrity_error);
	CuAssertTrue (test, backend.data.data.len >= AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);

	status = testing_validate_array (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA, backend.data.data.buf,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kwp_integrity_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.unwrap, &backend.aes_kw,
		AES_KEY_WRAP_INTEGRITY_CHECK_FAIL,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.integrity_error);
	CuAssertIntEquals (test, CIPHER_DECRYPTION_FAILED_LEN, backend.data.data.len);

	status = testing_validate_array (CIPHER_DECRYPTION_FAILED, backend.data.data.buf,
		backend.data.data.len);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kwp_integrity_length_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.unwrap, &backend.aes_kw,
		AES_KEY_WRAP_LENGTH_CHECK_FAIL,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.integrity_error);
	CuAssertIntEquals (test, CIPHER_DECRYPTION_FAILED_LEN, backend.data.data.len);

	status = testing_validate_array (CIPHER_DECRYPTION_FAILED, backend.data.data.buf,
		backend.data.data.len);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kwp_integrity_padding_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP,
		}
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.unwrap, &backend.aes_kw,
		AES_KEY_WRAP_PADDING_CHECK_FAIL,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.integrity_error);
	CuAssertIntEquals (test, CIPHER_DECRYPTION_FAILED_LEN, backend.data.data.len);

	status = testing_validate_array (CIPHER_DECRYPTION_FAILED, backend.data.data.buf,
		backend.data.data.len);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_null (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_INVALID_ARGUMENT,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

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

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null data.
	platform_free (backend.data.data.buf);
	backend.data.data.buf = NULL;

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.data.buf = platform_malloc (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN);
	CuAssertPtrNotNull (test, backend.data.data.buf);

	memcpy (backend.data.data.buf, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN);

	backend.data.data.len = 0;

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null key.
	backend.data.key.buf = NULL;

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.key.buf = (unsigned char*) AES_KEY_WRAP_KAT_VECTORS_KWP_KEY;

	backend.data.key.len = 0;

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_no_engine (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_engine_not_found (CuTest *test)
{
	AES_ECB_TESTING_ENGINE (engine);
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = AES_ECB_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation + 1;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	AES_ECB_TESTING_ENGINE_RELEASE (&engine);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_unsupported_type (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KW
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SYM_UNSUPPORTED_CIPHER_TYPE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kwp_set_kek_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_KEY_WRAP_SET_KEK_FAILED,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw,
		AES_KEY_WRAP_SET_KEK_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}

static void backend_sym_test_decrypt_aes_kwp_unwrap_error (CuTest *test)
{
	const struct sym_backend *sym_impl = NULL;
	struct backend_sym_testing backend;
	uint32_t implementation = 0;
	struct backend_sym_engine sym_engines[] = {
		{
			.impl_id = implementation,
			.aes_kw = &backend.aes_kw.base,
			.type = BACKEND_SYM_ENGINE_TYPE_AES_KWP
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_KEY_WRAP_UNWRAP_FAILED,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sym_testing_init (test, &backend, BACKEND_SYM_TEST_TYPE_DECRYPT,
		BACKEND_SYM_ENGINE_TYPE_AES_KWP);

	status = mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.set_kek, &backend.aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&backend.aes_kw.mock, backend.aes_kw.base.unwrap, &backend.aes_kw,
		AES_KEY_WRAP_UNWRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	acvp_implementation = implementation;

	backend_sym_register_engines (sym_engines, 1);

	sym_impl = backend_sym_get_impl ();
	CuAssertPtrNotNull (test, sym_impl);

	status = sym_impl->decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sym_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_sym);

TEST (backend_sym_test_init);
TEST (backend_sym_test_encrypt_aes_kw);
TEST (backend_sym_test_encrypt_aes_kwp);
TEST (backend_sym_test_encrypt_null);
TEST (backend_sym_test_encrypt_no_engine);
TEST (backend_sym_test_encrypt_engine_not_found);
TEST (backend_sym_test_encrypt_unsupported_type);
TEST (backend_sym_test_encrypt_aes_kwp_set_kek_error);
TEST (backend_sym_test_encrypt_aes_kwp_wrap_error);
TEST (backend_sym_test_decrypt_aes_kw);
TEST (backend_sym_test_decrypt_aes_kwp);
TEST (backend_sym_test_decrypt_aes_kwp_integrity_error);
TEST (backend_sym_test_decrypt_aes_kwp_integrity_length_error);
TEST (backend_sym_test_decrypt_aes_kwp_integrity_padding_error);
TEST (backend_sym_test_decrypt_null);
TEST (backend_sym_test_decrypt_unsupported_type);
TEST (backend_sym_test_decrypt_no_engine);
TEST (backend_sym_test_decrypt_engine_not_found);
TEST (backend_sym_test_decrypt_aes_kwp_set_kek_error);
TEST (backend_sym_test_decrypt_aes_kwp_unwrap_error);

TEST_SUITE_END;
// *INDENT-ON*
