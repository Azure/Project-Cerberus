// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/hash_thread_safe.h"
#include "mock/hash_mock.h"


static const char *SUITE = "hash_thread_safe";


/*******************
 * Test cases
 *******************/

static void hash_thread_safe_test_init (CuTest *test)
{
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.calculate_sha1);
	CuAssertPtrNotNull (test, engine.base.calculate_sha256);
	CuAssertPtrNotNull (test, engine.base.start_sha1);
	CuAssertPtrNotNull (test, engine.base.start_sha256);
	CuAssertPtrNotNull (test, engine.base.update);
	CuAssertPtrNotNull (test, engine.base.finish);
	CuAssertPtrNotNull (test, engine.base.cancel);

	status = hash_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	hash_thread_safe_release (&engine);
}

static void hash_thread_safe_test_init_null (CuTest *test)
{
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (NULL, &mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_thread_safe_init (&engine, NULL);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha1, &mock, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)), MOCK_ARG (hash), MOCK_ARG (sizeof (hash)));
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha1, &mock, HASH_ENGINE_SHA1_FAILED,
		MOCK_ARG (message), MOCK_ARG (strlen (message)), MOCK_ARG (hash), MOCK_ARG (sizeof (hash)));
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha256, &mock, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)), MOCK_ARG (hash), MOCK_ARG (sizeof (hash)));
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.calculate_sha256, &mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG (message), MOCK_ARG (strlen (message)), MOCK_ARG (hash), MOCK_ARG (sizeof (hash)));
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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

static void hash_thread_safe_test_update (CuTest *test)
{
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.update, &mock, 0, MOCK_ARG (message),
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.update, &mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG (message), MOCK_ARG (strlen (message)));
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status |= mock_expect (&mock.mock, mock.base.finish, &mock, 0, MOCK_ARG (hash),
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.start_sha256, &mock, 0);
	status = mock_expect (&mock.mock, mock.base.finish, &mock, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hash), MOCK_ARG (sizeof (hash)));
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
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
	struct hash_engine_thread_safe engine;
	struct hash_engine_mock mock;
	int status;

	TEST_START;

	status = hash_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (NULL);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	hash_mock_release (&mock);
	hash_thread_safe_release (&engine);
}


CuSuite* get_hash_thread_safe_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, hash_thread_safe_test_init);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_init_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_release_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_calculate_sha1);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_calculate_sha1_error);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_calculate_sha1_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_start_sha1);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_start_sha1_error);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_start_sha1_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_calculate_sha256);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_calculate_sha256_error);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_calculate_sha256_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_start_sha256);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_start_sha256_error);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_start_sha256_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_update);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_update_error);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_update_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_finish);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_finish_error);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_finish_null);
	SUITE_ADD_TEST (suite, hash_thread_safe_test_cancel_null);

	return suite;
}
