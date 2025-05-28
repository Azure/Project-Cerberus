// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_aead.h"
#include "crypto/crypto_logging.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/aes_gcm_testing.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/aes_gcm_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_aead");


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * Dependencies for testing.
 */
struct backend_aead_testing {
	struct aead_data data;					/**< AEAD test data. */
	struct aes_gcm_engine_mock gcm_engine;	/**< Mock for AES-GCM. */
	struct logging_mock logger;				/**< Mock for debug logging. */
	struct rng_engine_mock rng_engine;		/**< Mock for RNG. */
};


/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_aead_testing_init_common (CuTest *test, struct backend_aead_testing *backend)
{
	int status;

	status = aes_gcm_mock_init (&backend->gcm_engine);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&backend->logger);
	CuAssertIntEquals (test, 0, status);

	debug_log = &backend->logger.base;

	status = rng_mock_init (&backend->rng_engine);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the testing dependencies for a GCM encrypt test.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_aead_testing_init_gcm_encrypt (CuTest *test,
	struct backend_aead_testing *backend)
{
	struct aead_data data;

	data.data.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_PLAINTEXT_LEN);
	CuAssertPtrNotNull (test, data.data.buf);

	memcpy (data.data.buf, AES_GCM_TESTING_PLAINTEXT, AES_GCM_TESTING_PLAINTEXT_LEN);
	data.data.len = AES_GCM_TESTING_PLAINTEXT_LEN;

	data.cipher = ACVP_GCM;
	data.key.buf = (unsigned char*) AES_GCM_TESTING_KEY;
	data.key.len = AES_GCM_TESTING_KEY_LEN;

	data.iv.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_IV_LEN);
	CuAssertPtrNotNull (test, data.iv.buf);

	memcpy (data.iv.buf, AES_GCM_TESTING_IV, AES_GCM_TESTING_IV_LEN);
	data.iv.len = AES_GCM_TESTING_IV_LEN;

	data.iv.len = AES_GCM_TESTING_IV_LEN;
	data.ivlen = 0;
	data.assoc.buf = (unsigned char*) AES_GCM_TESTING_ADD_DATA;
	data.assoc.len = AES_GCM_TESTING_ADD_DATA_LEN;
	data.tag.buf = NULL;
	data.tag.len = 0;
	data.taglen = AES_GCM_TESTING_TAG_LEN * 8;
	data.ptlen = AES_GCM_TESTING_PLAINTEXT_LEN;
	data.integrity_error = 0;
	data.priv = NULL;

	backend->data = data;

	backend_aead_testing_init_common (test, backend);
}

/**
 * Initialize the testing dependencies for a GCM encrypt test with IV generation.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_aead_testing_init_gcm_encrypt_generate_iv (CuTest *test,
	struct backend_aead_testing *backend)
{
	struct aead_data data;

	data.data.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_PLAINTEXT_LEN);
	CuAssertPtrNotNull (test, data.data.buf);

	memcpy (data.data.buf, AES_GCM_TESTING_PLAINTEXT, AES_GCM_TESTING_PLAINTEXT_LEN);
	data.data.len = AES_GCM_TESTING_PLAINTEXT_LEN;

	data.cipher = ACVP_GCM;
	data.key.buf = (unsigned char*) AES_GCM_TESTING_KEY;
	data.key.len = AES_GCM_TESTING_KEY_LEN;
	data.iv.buf = NULL;
	data.iv.len = 0;
	data.ivlen = AES_GCM_TESTING_IV_LEN * 8;
	data.assoc.buf = (unsigned char*) AES_GCM_TESTING_ADD_DATA;
	data.assoc.len = AES_GCM_TESTING_ADD_DATA_LEN;
	data.tag.buf = NULL;
	data.tag.len = 0;
	data.taglen = AES_GCM_TESTING_TAG_LEN * 8;
	data.ptlen = AES_GCM_TESTING_PLAINTEXT_LEN;
	data.integrity_error = 0;
	data.priv = NULL;

	backend->data = data;

	backend_aead_testing_init_common (test, backend);
}

/**
 * Initialize the testing dependencies for a GCM decrypt test.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_aead_testing_init_gcm_decrypt (CuTest *test,
	struct backend_aead_testing *backend)
{
	struct aead_data data;

	data.data.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_CIPHERTEXT_LEN);
	CuAssertPtrNotNull (test, data.data.buf);

	memcpy (data.data.buf, AES_GCM_TESTING_CIPHERTEXT, AES_GCM_TESTING_CIPHERTEXT_LEN);
	data.data.len = AES_GCM_TESTING_CIPHERTEXT_LEN;

	data.cipher = ACVP_GCM;
	data.key.buf = (unsigned char*) AES_GCM_TESTING_KEY;
	data.key.len = AES_GCM_TESTING_KEY_LEN;

	data.iv.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_IV_LEN);
	CuAssertPtrNotNull (test, data.iv.buf);

	memcpy (data.iv.buf, AES_GCM_TESTING_IV, AES_GCM_TESTING_IV_LEN);
	data.iv.len = AES_GCM_TESTING_IV_LEN;

	data.ivlen = 0;
	data.assoc.buf = (unsigned char*) AES_GCM_TESTING_ADD_DATA;
	data.assoc.len = AES_GCM_TESTING_ADD_DATA_LEN;

	data.tag.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_TAG_LEN);
	CuAssertPtrNotNull (test, data.tag.buf);

	memcpy (data.tag.buf, AES_GCM_TESTING_ADD_DATA_TAG, AES_GCM_TESTING_TAG_LEN);
	data.tag.len = AES_GCM_TESTING_TAG_LEN;

	data.taglen = 0;
	data.ptlen = AES_GCM_TESTING_PLAINTEXT_LEN;
	data.integrity_error = 0;
	data.priv = NULL;

	backend->data = data;

	backend_aead_testing_init_common (test, backend);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param backend The testing dependencies to release.
 */
static void backend_aead_testing_release (CuTest *test, struct backend_aead_testing *backend)
{
	int status;

	if (backend->data.data.buf != NULL) {
		platform_free (backend->data.data.buf);
	}

	if (backend->data.iv.buf != NULL) {
		platform_free (backend->data.iv.buf);
	}

	if (backend->data.tag.buf != NULL) {
		platform_free (backend->data.tag.buf);
	}

	backend_aead_register_engines (NULL, 0);

	status = aes_gcm_mock_validate_and_release (&backend->gcm_engine);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&backend->rng_engine);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void backend_aead_test_init (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;

	TEST_START;

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);
	CuAssertPtrNotNull (test, aead_impl->gcm_encrypt);
	CuAssertPtrNotNull (test, aead_impl->gcm_decrypt);
	CuAssertPtrEquals (test, NULL, aead_impl->ccm_encrypt);
	CuAssertPtrEquals (test, NULL, aead_impl->ccm_decrypt);
}

static void backend_aead_test_gcm_encrypt (CuTest *test)
{
	AES_GCM_TESTING_ENGINE (engine);
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

	status = AES_GCM_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_GCM_TESTING_ADD_DATA_TAG, backend.data.tag.buf,
		AES_GCM_TESTING_TAG_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_GCM_TESTING_CIPHERTEXT, backend.data.data.buf,
		AES_GCM_TESTING_CIPHERTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&engine);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_generate_iv (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &backend.gcm_engine.base,
			.rng = &backend.rng_engine.base
		}
	};
	const uint8_t test_iv[AES_GCM_TESTING_IV_LEN] = {
		0x34, 0x78, 0x12, 0x56, 0x9A, 0xBC, 0xDE, 0xF0, 0xBA, 0xDC, 0xFE, 0x98,
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt_generate_iv (test, &backend);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.set_key,
		&backend.gcm_engine, 0,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_KEY, AES_GCM_TESTING_KEY_LEN),
		MOCK_ARG (AES_GCM_TESTING_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.rng_engine.mock, backend.rng_engine.base.generate_random_buffer,
		&backend.rng_engine, 0, MOCK_ARG (AES_GCM_TESTING_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.rng_engine.mock, 1, test_iv, AES_GCM_TESTING_IV_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.encrypt_with_add_data,
		&backend.gcm_engine, 0,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_PLAINTEXT, AES_GCM_TESTING_PLAINTEXT_LEN),
		MOCK_ARG (AES_GCM_TESTING_PLAINTEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (test_iv, AES_GCM_TESTING_IV_LEN), MOCK_ARG (AES_GCM_TESTING_IV_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_ADD_DATA, AES_GCM_TESTING_ADD_DATA_LEN),
		MOCK_ARG (AES_GCM_TESTING_ADD_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TESTING_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TESTING_TAG_LEN));
	status |= mock_expect_output (&backend.gcm_engine.mock, 6, AES_GCM_TESTING_CIPHERTEXT,
		AES_GCM_TESTING_CIPHERTEXT_LEN, -1);
	status |= mock_expect_output (&backend.gcm_engine.mock, 8, AES_GCM_TESTING_ADD_DATA_TAG,
		AES_GCM_TESTING_TAG_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_GCM_TESTING_ADD_DATA_TAG, backend.data.tag.buf,
		AES_GCM_TESTING_TAG_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_GCM_TESTING_CIPHERTEXT, backend.data.data.buf,
		AES_GCM_TESTING_CIPHERTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, AES_GCM_TESTING_IV_LEN, backend.data.iv.len);

	status = testing_validate_array (test_iv, backend.data.iv.buf, AES_GCM_TESTING_IV_LEN);
	CuAssertIntEquals (test, 0, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_null (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_INVALID_ARGUMENT,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

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
	CuAssertIntEquals (test, 0, status);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null key.
	backend.data.key.buf = NULL;

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.key.buf = (unsigned char*) AES_GCM_TESTING_KEY;

	// Test null IV with no generated IV length provided.
	platform_free (backend.data.iv.buf);
	backend.data.iv.buf = NULL;
	backend.data.ivlen = 0;

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.iv.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_IV_LEN);
	CuAssertPtrNotNull (test, backend.data.iv.buf);

	memcpy (backend.data.iv.buf, AES_GCM_TESTING_IV, AES_GCM_TESTING_IV_LEN);
	backend.data.iv.len = AES_GCM_TESTING_IV_LEN;

	// Test null plaintext data.
	platform_free (backend.data.data.buf);
	backend.data.data.buf = NULL;

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_invalid_tag (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_INVALID_ARGUMENT,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	backend.data.tag.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_TAG_LEN);
	CuAssertPtrNotNull (test, backend.data.tag.buf);

	memcpy (backend.data.tag.buf, AES_GCM_TESTING_TAG, AES_GCM_TESTING_TAG_LEN);
	backend.data.tag.len = AES_GCM_TESTING_TAG_LEN;

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	platform_free (backend.data.tag.buf);
	backend.data.tag.buf = NULL;
	backend.data.taglen = 2;

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_no_engine (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_NO_ENGINE,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_engine_not_found (CuTest *test)
{
	AES_GCM_TESTING_ENGINE (engine);
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_ENGINE_NOT_FOUND,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = AES_GCM_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation + 1;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&engine);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_generate_iv_no_rng (CuTest *test)
{
	AES_GCM_TESTING_ENGINE (engine);
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &engine.base,
			.rng = NULL
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_NO_RNG,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt_generate_iv (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = AES_GCM_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&engine);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_generate_iv_rng_error (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &backend.gcm_engine.base,
			.rng = &backend.rng_engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = RNG_ENGINE_RANDOM_FAILED,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt_generate_iv (test, &backend);

	status = mock_expect (&backend.rng_engine.mock, backend.rng_engine.base.generate_random_buffer,
		&backend.rng_engine, RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (AES_GCM_TESTING_IV_LEN),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_set_key_error (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &backend.gcm_engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_GCM_ENGINE_INVALID_KEY_LENGTH,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	size_t key_len = 3;
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.set_key,
		&backend.gcm_engine, AES_GCM_ENGINE_INVALID_KEY_LENGTH,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_KEY, AES_GCM_TESTING_KEY_LEN), MOCK_ARG (key_len));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	backend.data.key.len = key_len;

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_encrypt_encrypt_error (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &backend.gcm_engine.base,
			.rng = &backend.rng_engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_GCM_ENGINE_ENCRYPT_ADD_DATA_FAILED,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_encrypt (test, &backend);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.set_key,
		&backend.gcm_engine, 0,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_KEY, AES_GCM_TESTING_KEY_LEN),
		MOCK_ARG (AES_GCM_TESTING_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.encrypt_with_add_data,
		&backend.gcm_engine, AES_GCM_ENGINE_ENCRYPT_ADD_DATA_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_PLAINTEXT, AES_GCM_TESTING_PLAINTEXT_LEN),
		MOCK_ARG (AES_GCM_TESTING_PLAINTEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_IV, AES_GCM_TESTING_IV_LEN),
		MOCK_ARG (AES_GCM_TESTING_IV_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_ADD_DATA, AES_GCM_TESTING_ADD_DATA_LEN),
		MOCK_ARG (AES_GCM_TESTING_ADD_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TESTING_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TESTING_TAG_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_encrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt (CuTest *test)
{
	AES_GCM_TESTING_ENGINE (engine);
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = AES_GCM_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.integrity_error);

	status = testing_validate_array (AES_GCM_TESTING_PLAINTEXT, backend.data.data.buf,
		AES_GCM_TESTING_PLAINTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&engine);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_integrity_error (CuTest *test)
{
	AES_GCM_TESTING_ENGINE (engine);
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CRYPTO,
		.msg_index = CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_AUTH_DECRYPT_EC,
		.arg1 = MBEDTLS_ERR_GCM_AUTH_FAILED,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = AES_GCM_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	memcpy (backend.data.tag.buf, AES_GCM_TESTING_TAG, AES_GCM_TESTING_TAG_LEN);

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.integrity_error);

	AES_GCM_TESTING_ENGINE_RELEASE (&engine);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_null (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_INVALID_ARGUMENT,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

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
	CuAssertIntEquals (test, 0, status);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_decrypt (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null key.
	backend.data.key.buf = NULL;

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.key.buf = (unsigned char*) AES_GCM_TESTING_KEY;

	// Test null IV.
	platform_free (backend.data.iv.buf);
	backend.data.iv.buf = NULL;

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.iv.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_IV_LEN);
	CuAssertPtrNotNull (test, backend.data.iv.buf);

	memcpy (backend.data.iv.buf, AES_GCM_TESTING_IV, AES_GCM_TESTING_IV_LEN);
	backend.data.iv.len = AES_GCM_TESTING_IV_LEN;

	// Test null encrypted data.
	platform_free (backend.data.data.buf);
	backend.data.data.buf = NULL;

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_invalid_tag (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_INVALID_ARGUMENT,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	platform_free (backend.data.tag.buf);
	backend.data.tag.buf = NULL;

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.tag.buf = (unsigned char*) platform_malloc (AES_GCM_TESTING_TAG_LEN);
	CuAssertPtrNotNull (test, backend.data.tag.buf);

	memcpy (backend.data.tag.buf, AES_GCM_TESTING_ADD_DATA_TAG, AES_GCM_TESTING_TAG_LEN);
	backend.data.tag.len = AES_GCM_TESTING_TAG_LEN;

	backend.data.tag.len = 3;

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_no_engine (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_NO_ENGINE,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_engine_not_found (CuTest *test)
{
	AES_GCM_TESTING_ENGINE (engine);
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_AEAD_ENGINE_NOT_FOUND,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = AES_GCM_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation + 1;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&engine);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_set_key_error (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &backend.gcm_engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_GCM_ENGINE_INVALID_KEY_LENGTH,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	size_t key_len = 2;
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.set_key,
		&backend.gcm_engine, AES_GCM_ENGINE_INVALID_KEY_LENGTH,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_KEY, AES_GCM_TESTING_KEY_LEN), MOCK_ARG (key_len));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	backend.data.key.len = key_len;

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}

static void backend_aead_test_gcm_decrypt_decrypt_error (CuTest *test)
{
	struct aead_backend *aead_impl = NULL;
	struct backend_aead_testing backend;
	uint32_t implementation = 0;
	struct backend_aead_engine aead_engines[] = {
		{
			.impl_id = implementation,
			.gcm_engine = &backend.gcm_engine.base,
			.rng = &backend.rng_engine.base
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = AES_GCM_ENGINE_DECRYPT_ADD_DATA_FAILED,
		.arg2 = ACVP_ALGORITHM_AEAD
	};
	int status;

	TEST_START;

	backend_aead_testing_init_gcm_decrypt (test, &backend);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.set_key,
		&backend.gcm_engine, 0,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_KEY, AES_GCM_TESTING_KEY_LEN),
		MOCK_ARG (AES_GCM_TESTING_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.gcm_engine.mock, backend.gcm_engine.base.decrypt_with_add_data,
		&backend.gcm_engine, AES_GCM_ENGINE_DECRYPT_ADD_DATA_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_CIPHERTEXT, AES_GCM_TESTING_CIPHERTEXT_LEN),
		MOCK_ARG (AES_GCM_TESTING_CIPHERTEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_ADD_DATA_TAG, AES_GCM_TESTING_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_IV, AES_GCM_TESTING_IV_LEN),
		MOCK_ARG (AES_GCM_TESTING_IV_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_GCM_TESTING_ADD_DATA, AES_GCM_TESTING_ADD_DATA_LEN),
		MOCK_ARG (AES_GCM_TESTING_ADD_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_TESTING_PLAINTEXT_LEN));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	acvp_implementation = implementation;

	backend_aead_register_engines (aead_engines, 1);

	aead_impl = backend_aead_get_impl ();
	CuAssertPtrNotNull (test, aead_impl);

	status = aead_impl->gcm_decrypt (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_aead_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_aead);

TEST (backend_aead_test_init);
TEST (backend_aead_test_gcm_encrypt);
TEST (backend_aead_test_gcm_encrypt_generate_iv);
TEST (backend_aead_test_gcm_encrypt_null);
TEST (backend_aead_test_gcm_encrypt_invalid_tag);
TEST (backend_aead_test_gcm_encrypt_no_engine);
TEST (backend_aead_test_gcm_encrypt_engine_not_found);
TEST (backend_aead_test_gcm_encrypt_generate_iv_no_rng);
TEST (backend_aead_test_gcm_encrypt_generate_iv_rng_error);
TEST (backend_aead_test_gcm_encrypt_set_key_error);
TEST (backend_aead_test_gcm_encrypt_encrypt_error);
TEST (backend_aead_test_gcm_decrypt);
TEST (backend_aead_test_gcm_decrypt_integrity_error);
TEST (backend_aead_test_gcm_decrypt_null);
TEST (backend_aead_test_gcm_decrypt_invalid_tag);
TEST (backend_aead_test_gcm_decrypt_no_engine);
TEST (backend_aead_test_gcm_decrypt_engine_not_found);
TEST (backend_aead_test_gcm_decrypt_set_key_error);
TEST (backend_aead_test_gcm_decrypt_decrypt_error);

TEST_SUITE_END;
// *INDENT-ON*
