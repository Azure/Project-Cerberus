// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "keystore/ephemeral_key_manager.h"
#include "keystore/ephemeral_key_manager_static.h"
#include "keystore/key_cache.h"
#include "keystore/keystore_logging.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/ephemeral_key_generation_mock.h"
#include "testing/mock/flash/flash_store_mock.h"
#include "testing/mock/keystore/key_cache_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("ephemeral_key_manager");


/**
 * Max timeout for the periodic task in milliseconds.
 */
#define EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT	(30000)

/**
 * RSA Key Size in Bytes
 */
#define EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE	(2048)

/**
 * RSA Key Size in Bytes
 */
#define EPHEMERAL_KEY_MANAGER_RSA_3K_KEY_SIZE	(3072)

/**
 * RSA Key Size in Bytes
 */
#define EPHEMERAL_KEY_MANAGER_RSA_4K_KEY_SIZE	(4096)

/*
 * Maximum length of data stored in the flash block for DER encoded RSA 2K key
 */
#define RSA_EPHEMERAL_KEY_MAX_LENGTH			(4096)


/**
 * Dependencies for testing the ephemeral key manager
 */
struct ephemeral_key_manager_testing {
	struct ephemeral_key_manager key_manager;			/**< ephemeral key manager object */
	struct ephemeral_key_manager_state state;			/**< ephemeral key state object */
	struct ephemeral_key_generation_mock key_gen_mock;	/**< ephemeral key generation object */
	struct key_cache_mock key_cache_mock;				/**< Key cache object */
	struct logging_mock debug;							/**< Debug log mock object */
	uint8_t key_buffer[RSA_EPHEMERAL_KEY_MAX_LENGTH];	/**< Key buffer */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The testing framework.
 * @param manager_test Testing dependencies to initialize.
 */
static void ephemeral_key_manager_testing_init_dependencies (CuTest *test,
	struct ephemeral_key_manager_testing *manager_test)
{
	int status;

	debug_log = NULL;

	/* Key cache mock init */
	status = key_cache_mock_init (&manager_test->key_cache_mock);
	CuAssertIntEquals (test, 0, status);

	/* Ephemeral Key Generation mock init */
	status = ephemeral_key_generation_mock_init (&manager_test->key_gen_mock);
	CuAssertIntEquals (test, 0, status);

	/* Debug log mock init */
	status = logging_mock_init (&manager_test->debug);
	CuAssertIntEquals (test, 0, status);

	debug_log = &manager_test->debug.base;
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param manager_test Testing dependencies to initialize.
 */
static void ephemeral_key_manager_testing_release_dependencies (CuTest *test,
	struct ephemeral_key_manager_testing *manager_test)
{
	int status = 0;

	debug_log = NULL;

	status = key_cache_mock_validate_and_release (&manager_test->key_cache_mock);
	CuAssertIntEquals (test, 0, status);

	status = ephemeral_key_generation_mock_validate_and_release (&manager_test->key_gen_mock);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&manager_test->debug);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an ephemeral key manager for testing.
 *
 * @param test The test framework.
 * @param manager_test Testing components to initialize.
 */
static void ephemeral_key_manager_testing_init (CuTest *test,
	struct ephemeral_key_manager_testing *manager_test)
{
	int status;

	ephemeral_key_manager_testing_init_dependencies (test, manager_test);

	status = ephemeral_key_manager_init (&manager_test->key_manager, &manager_test->state,
		&manager_test->key_cache_mock.base, &manager_test->key_gen_mock.base,
		EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
		manager_test->key_buffer, sizeof (manager_test->key_buffer));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release ephemeral key manager components and validate all mocks.
 *
 * @param test The test framework.
 * @param manager_test Testing components to release.
 */
static void ephemeral_key_manager_testing_release (CuTest *test,
	struct ephemeral_key_manager_testing *manager_test)
{
	ephemeral_key_manager_release (&manager_test->key_manager);

	ephemeral_key_manager_testing_release_dependencies (test, manager_test);
}

/*******************
 * Test cases
 *******************/

static void ephemeral_key_manager_test_init (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test;
	int status;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	status = ephemeral_key_manager_init (&manager_test.key_manager, &manager_test.state,
		&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
		EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
		manager_test.key_buffer, sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager_test.key_manager.base.prepare);
	CuAssertPtrNotNull (test, manager_test.key_manager.base.get_next_execution);
	CuAssertPtrNotNull (test, manager_test.key_manager.base.execute);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_init_null (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test;
	int status;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	status = ephemeral_key_manager_init (NULL, &manager_test.state,
		&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
		EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
		manager_test.key_buffer, sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_init (&manager_test.key_manager, NULL,
		&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
		EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
		manager_test.key_buffer, sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_init (&manager_test.key_manager, &manager_test.state, NULL,
		&manager_test.key_gen_mock.base, EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT,
		EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE, manager_test.key_buffer,
		sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_init (&manager_test.key_manager, &manager_test.state,
		&manager_test.key_cache_mock.base, NULL, EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT,
		EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE, manager_test.key_buffer,
		sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_init (NULL, NULL, NULL, NULL,
		EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE, NULL,
		sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_init (NULL, NULL, NULL, NULL,
		EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE, NULL,
		sizeof (manager_test.key_buffer));
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	ephemeral_key_manager_testing_release_dependencies (test, &manager_test);
}

static void ephemeral_key_manager_test_static_init (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, manager_test.key_manager.base.prepare);
	CuAssertPtrNotNull (test, manager_test.key_manager.base.get_next_execution);
	CuAssertPtrNotNull (test, manager_test.key_manager.base.execute);

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (&manager_test.key_manager);
	CuAssertIntEquals (test, 0, status);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_static_init_null (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};
	int status;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_key (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test;
	int requestor_id = 0;
	size_t key_length;
	uint8_t key_out[4096];
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	/* Mock setup for remove API */
	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.remove, &manager_test.key_cache_mock, 0,
		MOCK_ARG (requestor_id), MOCK_ARG_PTR (key_out), MOCK_ARG (sizeof (key_out)),
		MOCK_ARG_PTR (&key_length));
	status |= mock_expect_output (&manager_test.key_cache_mock.mock, 1, RSA_PRIVKEY2_DER,
		RSA_PRIVKEY2_DER_LEN, -1);
	status |= mock_expect_output (&manager_test.key_cache_mock.mock, 3, &RSA_PRIVKEY2_DER_LEN,
		sizeof (RSA_PRIVKEY2_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = ephemeral_key_manager_get_key (&manager_test.key_manager, requestor_id, key_out,
		sizeof (key_out), &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_out);
	CuAssertIntEquals (test, RSA_PRIVKEY2_DER_LEN, key_length);

	status = testing_validate_array (RSA_PRIVKEY2_DER, key_out, key_length);
	CuAssertIntEquals (test, 0, status);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_key_with_static_init (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_3K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};

	int requestor_id = 0;
	size_t key_length = 0;
	uint8_t key_out[4096];
	int status;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (&manager_test.key_manager);
	CuAssertIntEquals (test, 0, status);

	/* Mock setup for remove API */
	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.remove, &manager_test.key_cache_mock, 0,
		MOCK_ARG (requestor_id), MOCK_ARG_PTR (key_out), MOCK_ARG (sizeof (key_out)),
		MOCK_ARG_PTR (&key_length));
	status |= mock_expect_output (&manager_test.key_cache_mock.mock, 1, RSA3K_PRIVKEY_DER,
		RSA3K_PRIVKEY_DER_LEN, -1);
	status |= mock_expect_output (&manager_test.key_cache_mock.mock, 3, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = ephemeral_key_manager_get_key (&manager_test.key_manager, requestor_id, key_out,
		sizeof (key_out), &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_out);
	CuAssertIntEquals (test, RSA3K_PRIVKEY_DER_LEN, key_length);

	status = testing_validate_array (RSA3K_PRIVKEY_DER, key_out, key_length);
	CuAssertIntEquals (test, 0, status);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_key_null_input (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	int requestor_id = 0;
	uint8_t key_out[4096];
	size_t key_length = 0;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	/* Get key Test */
	status = ephemeral_key_manager_get_key (NULL, requestor_id, key_out, sizeof (key_out),
		&key_length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_get_key (&manager_test.key_manager, requestor_id, NULL,
		sizeof (key_out), &key_length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	status = ephemeral_key_manager_get_key (&manager_test.key_manager, requestor_id, key_out,
		sizeof (key_out), NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT, status);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_key_return_error (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	int requestor_id = 0;
	uint8_t key_out[4096];
	size_t key_length = 0;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	/* Mock setup for remove API */
	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.remove, &manager_test.key_cache_mock,
		KEY_CACHE_REMOVE_KEY_FAILED, MOCK_ARG (requestor_id), MOCK_ARG_PTR (key_out),
		MOCK_ARG (sizeof (key_out)), MOCK_ARG_PTR (&key_length));
	CuAssertIntEquals (test, 0, status);

	/* Get key Test */
	status = ephemeral_key_manager_get_key (&manager_test.key_manager, requestor_id, key_out,
		sizeof (key_out), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_REMOVE_KEY_FAILED, status);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_prepare (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.prepare (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_prepare_with_static_init (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_4K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (&manager_test.key_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.prepare (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_next_execution (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	/* Required API Testing */
	const platform_clock *next_time;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.prepare (&manager_test.key_manager.base);

	next_time = manager_test.key_manager.base.get_next_execution (&manager_test.key_manager.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_next_execution_flash_full (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	/* Required API Testing */
	const platform_clock *next_time;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, true);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.prepare (&manager_test.key_manager.base);

	next_time = manager_test.key_manager.base.get_next_execution (&manager_test.key_manager.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_next_execution_with_static_init (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};
	/* Required API Testing */
	const platform_clock *next_time;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (&manager_test.key_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.prepare (&manager_test.key_manager.base);

	next_time = manager_test.key_manager.base.get_next_execution (&manager_test.key_manager.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_get_next_execution_with_static_init_flash_full (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};
	/* Required API Testing */
	const platform_clock *next_time;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (&manager_test.key_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, true);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.prepare (&manager_test.key_manager.base);

	next_time = manager_test.key_manager.base.get_next_execution (&manager_test.key_manager.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_execute (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);

	/* Mock setup for add API */
	status |= mock_expect (&manager_test.key_gen_mock.mock,
		manager_test.key_gen_mock.base.generate_key, &manager_test.key_gen_mock, 0,
		MOCK_ARG (EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager_test.key_gen_mock.mock, 1, RSA_PRIVKEY2_DER,
		RSA_PRIVKEY2_DER_LEN, -1);
	status |= mock_expect_output (&manager_test.key_gen_mock.mock, 3, &RSA_PRIVKEY2_DER_LEN,
		sizeof (RSA_PRIVKEY2_DER_LEN), -1);

	status |= mock_expect (&manager_test.key_cache_mock.mock, manager_test.key_cache_mock.base.add,
		&manager_test.key_cache_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA_PRIVKEY2_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.execute (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_execute_static_init (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {
		.key_manager = ephemeral_key_manager_static_init (&manager_test.state,
			&manager_test.key_cache_mock.base, &manager_test.key_gen_mock.base,
			EPHEMERAL_KEY_MANAGER_MAX_TASK_TIMEOUT, EPHEMERAL_KEY_MANAGER_RSA_4K_KEY_SIZE,
			manager_test.key_buffer, sizeof (manager_test.key_buffer)),
	};
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init_dependencies (test, &manager_test);

	/* State initialization */
	status = ephemeral_key_manager_init_state (&manager_test.key_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);

	/* Mock setup for add API */
	status |= mock_expect (&manager_test.key_gen_mock.mock,
		manager_test.key_gen_mock.base.generate_key, &manager_test.key_gen_mock, 0,
		MOCK_ARG (EPHEMERAL_KEY_MANAGER_RSA_4K_KEY_SIZE), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager_test.key_gen_mock.mock, 1, RSA4K_PRIVKEY_DER,
		RSA4K_PRIVKEY_DER_LEN, -1);
	status |= mock_expect_output (&manager_test.key_gen_mock.mock, 3, &RSA4K_PRIVKEY_DER_LEN,
		sizeof (RSA4K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&manager_test.key_cache_mock.mock, manager_test.key_cache_mock.base.add,
		&manager_test.key_cache_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (RSA4K_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.execute (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_execute_with_queue_is_full (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test;
	int status = 0;

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, true);
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.execute (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_execute_with_generate_key_error_response (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	int status = 0;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_KEY_GENERATION_FAIL,
		.arg1 = EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE,
		.arg2 = EPHEMERAL_KEY_GEN_GENERATE_KEY_FAILED
	};

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	/* Mock setup for add API */
	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);

	status |= mock_expect (&manager_test.key_gen_mock.mock,
		manager_test.key_gen_mock.base.generate_key, &manager_test.key_gen_mock,
		EPHEMERAL_KEY_GEN_GENERATE_KEY_FAILED, MOCK_ARG (EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager_test.debug.mock, manager_test.debug.base.create_entry,
		&manager_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.execute (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}

static void ephemeral_key_manager_test_execute_with_add_failed (CuTest *test)
{
	struct ephemeral_key_manager_testing manager_test = {0};
	int status = 0;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_ADD_KEY_FAIL,
		.arg1 = RSA_PRIVKEY2_DER_LEN,
		.arg2 = KEY_CACHE_ADD_KEY_FAILED
	};

	TEST_START;

	ephemeral_key_manager_testing_init (test, &manager_test);

	status = mock_expect (&manager_test.key_cache_mock.mock,
		manager_test.key_cache_mock.base.is_full, &manager_test.key_cache_mock, 0);

	/* Mock setup for add API */
	status |= mock_expect (&manager_test.key_gen_mock.mock,
		manager_test.key_gen_mock.base.generate_key, &manager_test.key_gen_mock, 0,
		MOCK_ARG (EPHEMERAL_KEY_MANAGER_RSA_2K_KEY_SIZE), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager_test.key_gen_mock.mock, 1, RSA_PRIVKEY2_DER,
		RSA_PRIVKEY2_DER_LEN, -1);
	status |= mock_expect_output (&manager_test.key_gen_mock.mock, 3, &RSA_PRIVKEY2_DER_LEN,
		sizeof (RSA_PRIVKEY2_DER_LEN), -1);

	status |= mock_expect (&manager_test.key_cache_mock.mock, manager_test.key_cache_mock.base.add,
		&manager_test.key_cache_mock, KEY_CACHE_ADD_KEY_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (RSA_PRIVKEY2_DER_LEN));

	status |= mock_expect (&manager_test.debug.mock, manager_test.debug.base.create_entry,
		&manager_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	manager_test.key_manager.base.execute (&manager_test.key_manager.base);

	ephemeral_key_manager_testing_release (test, &manager_test);
}


// *INDENT-OFF*
TEST_SUITE_START (ephemeral_key_manager);

TEST (ephemeral_key_manager_test_init);
TEST (ephemeral_key_manager_test_init_null);
TEST (ephemeral_key_manager_test_static_init);
TEST (ephemeral_key_manager_test_static_init_null);
TEST (ephemeral_key_manager_test_get_key);
TEST (ephemeral_key_manager_test_get_key_with_static_init);
TEST (ephemeral_key_manager_test_get_key_null_input);
TEST (ephemeral_key_manager_test_get_key_return_error);
TEST (ephemeral_key_manager_test_prepare);
TEST (ephemeral_key_manager_test_prepare_with_static_init);
TEST (ephemeral_key_manager_test_get_next_execution);
TEST (ephemeral_key_manager_test_get_next_execution_flash_full);
TEST (ephemeral_key_manager_test_get_next_execution_with_static_init);
TEST (ephemeral_key_manager_test_get_next_execution_with_static_init_flash_full);
TEST (ephemeral_key_manager_test_execute);
TEST (ephemeral_key_manager_test_execute_static_init);
TEST (ephemeral_key_manager_test_execute_with_queue_is_full);
TEST (ephemeral_key_manager_test_execute_with_generate_key_error_response);
TEST (ephemeral_key_manager_test_execute_with_add_failed);

TEST_SUITE_END;
// *INDENT-ON*
