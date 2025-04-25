// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_hmac.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_hmac");


/**
 * HMAC test data message.
 */
const char *hmac_test_data_msg = "Test";


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * Dependencies for testing.
 */
struct backend_hmac_testing {
	struct hmac_data data;			/**< HMAC test data. */
	struct hash_engine_mock hash;	/**< Mock for hash engine. */
	struct logging_mock logger;		/**< Mock for debug logging. */
};


/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_hmac_testing_init (CuTest *test, struct backend_hmac_testing *backend,
	enum hash_type type)
{
	struct hmac_data data;
	int status;

	memset (&data, 0, sizeof (data));

	data.msg.buf = (unsigned char*) hmac_test_data_msg;
	data.msg.len = strlen (hmac_test_data_msg);

	data.maclen = 0;

	switch (type) {
		case HASH_TYPE_SHA1:
			data.key.buf = (unsigned char*) SHA1_HMAC_KEY;
			data.key.len = SHA1_HASH_LENGTH;

			data.cipher = ACVP_HMACSHA1;
			break;

		case HASH_TYPE_SHA256:
			data.key.buf = (unsigned char*) SHA256_HMAC_KEY;
			data.key.len = SHA256_HASH_LENGTH;

			data.cipher = ACVP_HMACSHA2_256;
			break;

		case HASH_TYPE_SHA384:
			data.key.buf = (unsigned char*) SHA384_HMAC_KEY;
			data.key.len = SHA384_HASH_LENGTH;

			data.cipher = ACVP_HMACSHA2_384;
			break;

		case HASH_TYPE_SHA512:
			data.key.buf = (unsigned char*) SHA512_HMAC_KEY;
			data.key.len = SHA512_HASH_LENGTH;

			data.cipher = ACVP_HMACSHA2_512;
			break;

		default:
			data.key.buf = (unsigned char*) SHA256_HMAC_KEY;
			data.key.len = SHA256_HASH_LENGTH;

			// By default, use unsupported cipher type.
			data.cipher = ACVP_SHA3_512;
	}

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
static void backend_hmac_testing_release (CuTest *test, struct backend_hmac_testing *backend)
{
	int status;

	if (backend->data.mac.buf != NULL) {
		platform_free (backend->data.mac.buf);
	}

	backend_hmac_register_engines (NULL, 0);

	status = hash_mock_validate_and_release (&backend->hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void backend_hmac_test_init (CuTest *test)
{
	const struct hmac_backend *hmac_impl;

	TEST_START;

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);
	CuAssertPtrNotNull (test, hmac_impl->hmac_generate);
	CuAssertPtrEquals (test, NULL, hmac_impl->cmac_verify);
}

#ifdef HASH_ENABLE_SHA1
static void backend_hmac_test_hmac_generate_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	uint32_t implementation = 0;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA1);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hmac_register_engines (hmac_engines, 1);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA1_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA1_TEST_HMAC, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_hmac_testing_release (test, &backend);
}
#endif

static void backend_hmac_test_hmac_generate_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	uint32_t implementation = 0;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA256);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hmac_register_engines (hmac_engines, 1);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA256_TEST_HMAC, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_hmac_testing_release (test, &backend);
}

#ifdef HASH_ENABLE_SHA384
static void backend_hmac_test_hmac_generate_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	uint32_t implementation = 0;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA384);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hmac_register_engines (hmac_engines, 1);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA384_TEST_HMAC, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_hmac_testing_release (test, &backend);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void backend_hmac_test_hmac_generate_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	uint32_t implementation = 0;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA512);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hmac_register_engines (hmac_engines, 1);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA512_TEST_HMAC, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_hmac_testing_release (test, &backend);
}
#endif

static void backend_hmac_test_hmac_generate_null (CuTest *test)
{
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HMAC_INVALID_ARGUMENT,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA256);

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
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	status = hmac_impl->hmac_generate (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test with a null key.
	backend.data.key.len = 0;
	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.key.len = strlen (hmac_test_data_msg);
	backend.data.key.buf = NULL;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.key.buf = (unsigned char*) hmac_test_data_msg;

	// Test with a null message.
	backend.data.msg.buf = NULL;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.msg.buf = (unsigned char*) hmac_test_data_msg;
	backend.data.msg.len = 0;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	// Test non-null MAC output buffer.
	backend.data.mac.buf = (unsigned char*) platform_malloc (SHA256_HASH_LENGTH);
	CuAssertPtrNotNull (test, backend.data.mac.buf);

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	platform_free (backend.data.mac.buf);
	backend.data.mac.buf = NULL;
	backend.data.mac.len = SHA256_HASH_LENGTH;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hmac_testing_release (test, &backend);
}

static void backend_hmac_test_hmac_generate_no_engine (CuTest *test)
{
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HMAC_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hmac_testing_release (test, &backend);
}

static void backend_hmac_test_hmac_generate_engine_not_found (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HMAC_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_hmac_register_engines (hmac_engines, 1);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	acvp_implementation = implementation + 1;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_hmac_testing_release (test, &backend);
}

static void backend_hmac_test_hmac_generate_unsupported_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HMAC_HASH_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_INVALID);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	backend_hmac_register_engines (hmac_engines, 1);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	acvp_implementation = implementation;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_hmac_testing_release (test, &backend);
}

static void backend_hmac_test_hmac_generate_generate_error (CuTest *test)
{
	const struct hmac_backend *hmac_impl;
	struct backend_hmac_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 3;
	struct backend_hmac_engine hmac_engines[] = {
		{
			.impl_id = implementation,
			.engine = &backend.hash.base
		}
	};
	int status;

	TEST_START;

	backend_hmac_testing_init (test, &backend, HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.hash.mock, backend.hash.base.start_sha256, &backend.hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	hmac_impl = backend_hmac_get_impl ();
	CuAssertPtrNotNull (test, hmac_impl);

	backend_hmac_register_engines (hmac_engines, 1);

	acvp_implementation = implementation;

	status = hmac_impl->hmac_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hmac_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_hmac);

TEST (backend_hmac_test_init);
#ifdef HASH_ENABLE_SHA1
TEST (backend_hmac_test_hmac_generate_sha1);
#endif
TEST (backend_hmac_test_hmac_generate_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (backend_hmac_test_hmac_generate_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (backend_hmac_test_hmac_generate_sha512);
#endif
TEST (backend_hmac_test_hmac_generate_null);
TEST (backend_hmac_test_hmac_generate_no_engine);
TEST (backend_hmac_test_hmac_generate_engine_not_found);
TEST (backend_hmac_test_hmac_generate_unsupported_hash);
TEST (backend_hmac_test_hmac_generate_generate_error);

TEST_SUITE_END;
// *INDENT-ON*
