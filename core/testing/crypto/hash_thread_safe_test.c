// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "crypto/hash_thread_safe.h"
#include "crypto/hash_thread_safe_static.h"
#include "testing/mock/crypto/hash_mock.h"


TEST_SUITE_LABEL ("hash_thread_safe");


/*******************
 * Test cases
 *******************/

static void hash_thread_safe_test_init (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.calculate_sha1);
	CuAssertPtrNotNull (test, engine.base.start_sha1);
	CuAssertPtrNotNull (test, engine.base.calculate_sha256);
	CuAssertPtrNotNull (test, engine.base.start_sha256);
	CuAssertPtrNotNull (test, engine.base.calculate_sha384);
	CuAssertPtrNotNull (test, engine.base.start_sha384);
	CuAssertPtrNotNull (test, engine.base.calculate_sha512);
	CuAssertPtrNotNull (test, engine.base.start_sha512);
	CuAssertPtrNotNull (test, engine.base.update);
	CuAssertPtrNotNull (test, engine.base.get_hash);
	CuAssertPtrNotNull (test, engine.base.finish);
	CuAssertPtrNotNull (test, engine.base.cancel);

	status = hash_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_init_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (NULL, &state, &mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_thread_safe_init (&engine, NULL, &mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_thread_safe_init (&engine, &state, NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void hash_thread_safe_test_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, engine.base.calculate_sha1);
	CuAssertPtrNotNull (test, engine.base.start_sha1);
	CuAssertPtrNotNull (test, engine.base.calculate_sha256);
	CuAssertPtrNotNull (test, engine.base.start_sha256);
	CuAssertPtrNotNull (test, engine.base.calculate_sha384);
	CuAssertPtrNotNull (test, engine.base.start_sha384);
	CuAssertPtrNotNull (test, engine.base.calculate_sha512);
	CuAssertPtrNotNull (test, engine.base.start_sha512);
	CuAssertPtrNotNull (test, engine.base.update);
	CuAssertPtrNotNull (test, engine.base.get_hash);
	CuAssertPtrNotNull (test, engine.base.finish);
	CuAssertPtrNotNull (test, engine.base.cancel);

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_static_init_null (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe null_state = hash_thread_safe_static_init (NULL, &mock.base);
	struct hash_engine_thread_safe null_target = hash_thread_safe_static_init (&state, NULL);
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_thread_safe_init_state (&null_state);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_thread_safe_init_state (&null_target);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void hash_thread_safe_test_release_null (CuTest *test)
{
	TEST_START;

	hash_thread_safe_release (NULL);
}

static void hash_thread_safe_test_calculate_sha1 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha1, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha1_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha1, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha1_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha1, &mock, HASH_ENGINE_SHA1_FAILED,
		MOCK_ARG_PTR (message), MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha1_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha1 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha1, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha1_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha1, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha1_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha1, &mock, HASH_ENGINE_START_SHA1_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha1_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha256 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha256, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha256_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha256, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha256_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha256, &mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR (message), MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha256_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha256 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha256_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha256_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha256_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha384 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha384, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha384_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha384, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha384_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha384, &mock, HASH_ENGINE_SHA384_FAILED,
		MOCK_ARG_PTR (message), MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha384_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha384 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha384, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha384_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha384, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha384_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha384, &mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha384_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha512 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha512, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha512_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha512, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha512_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha512, &mock, HASH_ENGINE_SHA512_FAILED,
		MOCK_ARG_PTR (message), MOCK_ARG (strlen (message)), MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_calculate_sha512_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha512 (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha512, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha512_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha512, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha512_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha512, &mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_start_sha512_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_update (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.update, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_update_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.update, &mock, 0, MOCK_ARG_PTR (message),
		MOCK_ARG (strlen (message)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_update_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.update, &mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR (message), MOCK_ARG (strlen (message)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_update_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (NULL, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_finish (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.finish, &mock, 0, MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_finish_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.finish, &mock, 0, MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_finish_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.finish, &mock, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_finish_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (NULL, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_cancel_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (NULL);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_get_hash (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.get_hash, &mock, 0, MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_get_hash_static_init (CuTest *test)
{
	struct hash_engine_mock mock;
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine = hash_thread_safe_static_init (&state, &mock.base);
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.get_hash, &mock, 0, MOCK_ARG_PTR (hash),
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_get_hash_error (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.get_hash, &mock, HASH_ENGINE_GET_HASH_FAILED,
		MOCK_ARG_PTR (hash), MOCK_ARG (sizeof (hash)));
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_GET_HASH_FAILED, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_get_hash_null (CuTest *test)
{
	struct hash_engine_thread_safe_state state;
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.cancel, &mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (NULL, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	engine.base.cancel (&engine.base);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.start_sha256 (&engine.base);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}


// *INDENT-OFF*
TEST_SUITE_START (hash_thread_safe);

TEST (hash_thread_safe_test_init);
TEST (hash_thread_safe_test_init_null);
TEST (hash_thread_safe_test_static_init);
TEST (hash_thread_safe_test_static_init_null);
TEST (hash_thread_safe_test_release_null);
TEST (hash_thread_safe_test_calculate_sha1);
TEST (hash_thread_safe_test_calculate_sha1_static_init);
TEST (hash_thread_safe_test_calculate_sha1_error);
TEST (hash_thread_safe_test_calculate_sha1_null);
TEST (hash_thread_safe_test_start_sha1);
TEST (hash_thread_safe_test_start_sha1_static_init);
TEST (hash_thread_safe_test_start_sha1_error);
TEST (hash_thread_safe_test_start_sha1_null);
TEST (hash_thread_safe_test_calculate_sha256);
TEST (hash_thread_safe_test_calculate_sha256_static_init);
TEST (hash_thread_safe_test_calculate_sha256_error);
TEST (hash_thread_safe_test_calculate_sha256_null);
TEST (hash_thread_safe_test_start_sha256);
TEST (hash_thread_safe_test_start_sha256_static_init);
TEST (hash_thread_safe_test_start_sha256_error);
TEST (hash_thread_safe_test_start_sha256_null);
TEST (hash_thread_safe_test_calculate_sha384);
TEST (hash_thread_safe_test_calculate_sha384_static_init);
TEST (hash_thread_safe_test_calculate_sha384_error);
TEST (hash_thread_safe_test_calculate_sha384_null);
TEST (hash_thread_safe_test_start_sha384);
TEST (hash_thread_safe_test_start_sha384_static_init);
TEST (hash_thread_safe_test_start_sha384_error);
TEST (hash_thread_safe_test_start_sha384_null);
TEST (hash_thread_safe_test_calculate_sha512);
TEST (hash_thread_safe_test_calculate_sha512_static_init);
TEST (hash_thread_safe_test_calculate_sha512_error);
TEST (hash_thread_safe_test_calculate_sha512_null);
TEST (hash_thread_safe_test_start_sha512);
TEST (hash_thread_safe_test_start_sha512_static_init);
TEST (hash_thread_safe_test_start_sha512_error);
TEST (hash_thread_safe_test_start_sha512_null);
TEST (hash_thread_safe_test_update);
TEST (hash_thread_safe_test_update_static_init);
TEST (hash_thread_safe_test_update_error);
TEST (hash_thread_safe_test_update_null);
TEST (hash_thread_safe_test_finish);
TEST (hash_thread_safe_test_finish_static_init);
TEST (hash_thread_safe_test_finish_error);
TEST (hash_thread_safe_test_finish_null);
TEST (hash_thread_safe_test_cancel_null);
TEST (hash_thread_safe_test_get_hash);
TEST (hash_thread_safe_test_get_hash_static_init);
TEST (hash_thread_safe_test_get_hash_error);
TEST (hash_thread_safe_test_get_hash_null);

TEST_SUITE_END;
// *INDENT-ON*
