// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_sha.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_sha");


/**
 * SHA test data message.
 */
const char *sha_test_data_msg = "Test";


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * Dependencies for testing.
 */
struct backend_sha_testing {
	struct sha_data data;		/**< SHA test data. */
	struct logging_mock logger;	/**< Mock for debug logging. */
};


/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 */
static void backend_sha_testing_init (CuTest *test, struct backend_sha_testing *backend)
{
	size_t msg_len = strlen ((char*) sha_test_data_msg);
	struct sha_data data;
	int status;

	data.msg.buf = (unsigned char*) platform_malloc (msg_len);
	CuAssertPtrNotNull (test, data.msg.buf);

	memcpy (data.msg.buf, sha_test_data_msg, msg_len);

	data.msg.len = msg_len;
	data.bitlen = 0;
	data.ldt_expansion_size = 0;
	data.outlen = 0;
	data.minoutlen = 0;
	data.maxoutlen = 0;
	data.mac.buf = NULL;
	data.mac.len = 0;
	data.cipher = 0;

	backend->data = data;

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
static void backend_sha_testing_release (CuTest *test, struct backend_sha_testing *backend)
{
	int status;

	if (backend->data.msg.buf != NULL) {
		platform_free (backend->data.msg.buf);
	}

	if (backend->data.mac.buf != NULL) {
		platform_free (backend->data.mac.buf);
	}

	backend_sha_register_engines (NULL, 0);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void backend_sha_test_init (CuTest *test)
{
	const struct sha_backend *sha_impl;

	TEST_START;

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);
	CuAssertPtrNotNull (test, sha_impl->hash_generate);
	CuAssertPtrEquals (test, NULL, sha_impl->hash_mct_inner_loop);
}

#ifdef HASH_ENABLE_SHA1
static void backend_sha_test_hash_generate_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA1;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA1_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA1_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_sha1_oneshot (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA1;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA1_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA1_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}
#endif

static void backend_sha_test_hash_generate_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA256_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_sha256_oneshot (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA256_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

#ifdef HASH_ENABLE_SHA384
static void backend_sha_test_hash_generate_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA384;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA384_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_sha384_oneshot (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA384;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA384_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void backend_sha_test_hash_generate_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA512;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA512_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_sha512_oneshot (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA512;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, backend.data.mac.len);

	status = testing_validate_array (SHA512_TEST_HASH, backend.data.mac.buf, backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}
#endif

static void backend_sha_test_hash_generate_sha_multiple_engines (CuTest *test)
{
	// Use mock engines to ensure the correct engine is selected
	struct hash_engine_mock engine1;
	struct hash_engine_mock engine2;
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation1 = 5;
	uint32_t implementation2 = 10;
	const uint8_t implementation1_out[SHA256_HASH_LENGTH] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
		0x1F, 0x20
	};
	const uint8_t implementation2_out[SHA256_HASH_LENGTH] = {
		0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
		0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
		0xFF, 0x00
	};
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation1,
			.is_one_shot = false,
			.engine = &engine1.base
		},
		{
			.impl_id = implementation2,
			.is_one_shot = true,
			.engine = &engine2.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = hash_mock_init (&engine1);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&engine2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine1.mock, engine1.base.start_sha256, &engine1, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&engine1.mock, engine1.base.update, &engine1, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)));

	status |= mock_expect (&engine1.mock, engine1.base.finish, &engine1, 0,	MOCK_ARG_NOT_NULL,
		MOCK_ARG (HASH_MAX_HASH_LEN));
	status |= mock_expect_output (&engine1.mock, 0, implementation1_out, SHA256_HASH_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine2.mock, engine2.base.calculate_sha256, &engine2, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine2.mock, 2, implementation2_out,
		sizeof (implementation2_out), 3);
	CuAssertIntEquals (test, 0, status);

	backend_sha_register_engines (sha_engines, 2);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	acvp_implementation = implementation1;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (implementation1_out), backend.data.mac.len);

	status = testing_validate_array (implementation1_out, backend.data.mac.buf,
		backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	platform_free (backend.data.mac.buf);

	acvp_implementation = implementation2;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (implementation2_out), backend.data.mac.len);

	status = testing_validate_array (implementation2_out, backend.data.mac.buf,
		backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine1);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine2);
	CuAssertIntEquals (test, 0, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_sha_reregister_engine (CuTest *test)
{
	// Use mock engines to ensure the correct engine is selected
	struct hash_engine_mock engine1;
	struct hash_engine_mock engine2;
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	uint32_t implementation = 2;
	const uint8_t implementation1_out[SHA256_HASH_LENGTH] = {
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
		0x2F, 0x30
	};
	const uint8_t implementation2_out[SHA256_HASH_LENGTH] = {
		0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
		0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE,
		0xEF, 0xF0
	};
	struct backend_sha_engine sha_engines1[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine1.base
		}
	};
	struct backend_sha_engine sha_engines2[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine2.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = hash_mock_init (&engine1);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&engine2);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&engine1.mock, engine1.base.calculate_sha256, &engine1, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine1.mock, 2, implementation1_out,
		sizeof (implementation1_out), 3);

	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&engine2.mock, engine2.base.calculate_sha256, &engine2, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine2.mock, 2, implementation2_out,
		sizeof (implementation2_out), 3);

	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	backend_sha_register_engines (sha_engines1, 1);

	acvp_implementation = implementation;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (implementation1_out), backend.data.mac.len);

	status = testing_validate_array (implementation1_out, backend.data.mac.buf,
		backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	platform_free (backend.data.mac.buf);

	backend_sha_register_engines (sha_engines2, 1);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (implementation2_out), backend.data.mac.len);

	status = testing_validate_array (implementation2_out, backend.data.mac.buf,
		backend.data.mac.len);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine1);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine2);
	CuAssertIntEquals (test, 0, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_null (CuTest *test)
{
	const struct sha_backend *sha_impl;
	int status;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SHA_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_no_engine (CuTest *test)
{
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SHA_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA384;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_engine_not_found (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SHA_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	acvp_implementation = implementation + 1;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_oneshot_calculate_error (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UNKNOWN_HASH,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_UNKNOWN;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_sha_register_engines (sha_engines, 1);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	acvp_implementation = implementation;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_start_error (CuTest *test)
{
	struct hash_engine_mock engine;
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UNSUPPORTED_HASH,
		.arg2 = 0
	};
	uint32_t implementation = 3;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine,
		HASH_ENGINE_UNSUPPORTED_HASH,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	backend_sha_register_engines (sha_engines, 1);

	acvp_implementation = implementation;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_update_error (CuTest *test)
{
	struct hash_engine_mock engine;
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_UPDATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 4;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	backend_sha_register_engines (sha_engines, 1);

	acvp_implementation = implementation;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_finish_error (CuTest *test)
{
	struct hash_engine_mock engine;
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HASH_ENGINE_FINISH_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 3;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = false,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_MAX_HASH_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	backend_sha_register_engines (sha_engines, 1);

	acvp_implementation = implementation;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_sha_testing_release (test, &backend);
}

static void backend_sha_test_hash_generate_length_error (CuTest *test)
{
	struct hash_engine_mock engine;
	const struct sha_backend *sha_impl;
	struct backend_sha_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_SHA_UNEXPECTED_HASH_LENGTH,
		.arg2 = 0
	};
	uint32_t implementation = 3;
	struct backend_sha_engine sha_engines[] = {
		{
			.impl_id = implementation,
			.is_one_shot = true,
			.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_sha_testing_init (test, &backend);
	backend.data.cipher = ACVP_SHA256;

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		SHA256_HASH_LENGTH - 1,
		MOCK_ARG_PTR_CONTAINS (sha_test_data_msg, strlen (sha_test_data_msg)),
		MOCK_ARG (strlen (sha_test_data_msg)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	sha_impl = backend_sha_get_impl ();
	CuAssertPtrNotNull (test, sha_impl);

	backend_sha_register_engines (sha_engines, 1);

	acvp_implementation = implementation;

	status = sha_impl->hash_generate (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_sha_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_sha);

TEST (backend_sha_test_init);
#ifdef HASH_ENABLE_SHA1
TEST (backend_sha_test_hash_generate_sha1);
TEST (backend_sha_test_hash_generate_sha1_oneshot);
#endif
TEST (backend_sha_test_hash_generate_sha256);
TEST (backend_sha_test_hash_generate_sha256_oneshot);
#ifdef HASH_ENABLE_SHA384
TEST (backend_sha_test_hash_generate_sha384);
TEST (backend_sha_test_hash_generate_sha384_oneshot);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (backend_sha_test_hash_generate_sha512);
TEST (backend_sha_test_hash_generate_sha512_oneshot);
#endif
TEST (backend_sha_test_hash_generate_sha_multiple_engines);
TEST (backend_sha_test_hash_generate_sha_reregister_engine);
TEST (backend_sha_test_hash_generate_null);
TEST (backend_sha_test_hash_generate_no_engine);
TEST (backend_sha_test_hash_generate_engine_not_found);
TEST (backend_sha_test_hash_generate_oneshot_calculate_error);
TEST (backend_sha_test_hash_generate_start_error);
TEST (backend_sha_test_hash_generate_update_error);
TEST (backend_sha_test_hash_generate_finish_error);
TEST (backend_sha_test_hash_generate_length_error);

TEST_SUITE_END;
// *INDENT-ON*
