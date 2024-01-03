// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/secure_device_unlock_policy.h"
#include "system/secure_device_unlock_policy_static.h"
#include "system/system_logging.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/common/auth_token_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/security_manager_mock.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/riot/riot_core_testing.h"
#include "testing/system/device_unlock_token_testing.h"


TEST_SUITE_LABEL ("secure_device_unlock_policy");


/**
 * Size of the token buffer to use for testing.
 */
#define	SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH		512


/**
 * An unlock counter value that has used all the counter bits.
 */
const uint8_t SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED[] = {
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

const size_t SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED_LEN =
	sizeof (SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED);


/**
 * Dependencies for testing.
 */
struct secure_device_unlock_policy_testing {
	struct auth_token_mock auth;				/**< Mock for the authorization token. */
	struct cmd_device_mock uuid;				/**< Mock for the device UUID interface. */
	struct device_unlock_token token;			/**< Unlock token handler for testing. */
	struct security_manager_mock manager;		/**< Mock for the security manager. */
	struct logging_mock log;					/**< Mock for the debug log. */
	struct secure_device_unlock_policy test;	/**< Unlock handler being tested. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param unlock The testing components to initialize.
 * @param counter_len Length of the unlock counter.
 */
static void secure_device_unlock_policy_testing_init_dependencies (CuTest *test,
	struct secure_device_unlock_policy_testing *unlock, size_t counter_len)
{
	int status;

	status = auth_token_mock_init (&unlock->auth);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&unlock->uuid);
	CuAssertIntEquals (test, 0, status);

	status = security_manager_mock_init (&unlock->manager);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&unlock->log);
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_init (&unlock->token, &unlock->auth.base, &unlock->uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, counter_len, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	debug_log = &unlock->log.base;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param unlock The testing components to release.
 */
static void secure_device_unlock_policy_testing_release_dependencies (CuTest *test,
	struct secure_device_unlock_policy_testing *unlock)
{
	int status;

	debug_log = NULL;

	device_unlock_token_release (&unlock->token);

	status = auth_token_mock_validate_and_release (&unlock->auth);
	status |= cmd_device_mock_validate_and_release (&unlock->uuid);
	status |= security_manager_mock_validate_and_release (&unlock->manager);
	status |= logging_mock_validate_and_release (&unlock->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a secure device unlock handler for testing.
 *
 * @param test The test framework.
 * @param unlock Testing components to initialize.
 * @param counter_len Length of the unlock counter.
 */
static void secure_device_unlock_policy_testing_init (CuTest *test,
	struct secure_device_unlock_policy_testing *unlock, size_t counter_len)
{
	int status;

	secure_device_unlock_policy_testing_init_dependencies (test, unlock, counter_len);

	status = secure_device_unlock_policy_init (&unlock->test, &unlock->token,
		&unlock->manager.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param unlock Testing components to release.
 * @param test_unlock The test handler to release.
 */
static void secure_device_unlock_policy_testing_release (CuTest *test,
	struct secure_device_unlock_policy_testing *unlock,
	struct secure_device_unlock_policy *test_unlock)
{
	secure_device_unlock_policy_release (test_unlock);
	secure_device_unlock_policy_testing_release_dependencies (test, unlock);
}


/*******************
 * Test cases
 *******************/

static void secure_device_unlock_policy_test_init (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init_dependencies (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	status = secure_device_unlock_policy_init (&unlock.test, &unlock.token, &unlock.manager.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, unlock.test.base.get_unlock_token);
	CuAssertPtrNotNull (test, unlock.test.base.apply_unlock_policy);
	CuAssertPtrNotNull (test, unlock.test.base.clear_unlock_policy);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_init_null (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init_dependencies (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	status = secure_device_unlock_policy_init (NULL, &unlock.token, &unlock.manager.base);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = secure_device_unlock_policy_init (&unlock.test, NULL, &unlock.manager.base);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = secure_device_unlock_policy_init (&unlock.test, &unlock.token, NULL);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_static_init (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	struct secure_device_unlock_policy test_static =
		secure_device_unlock_policy_static_init (&unlock.token, &unlock.manager.base);

	TEST_START;

	CuAssertPtrNotNull (test, test_static.base.get_unlock_token);
	CuAssertPtrNotNull (test, test_static.base.apply_unlock_policy);
	CuAssertPtrNotNull (test, test_static.base.clear_unlock_policy);

	secure_device_unlock_policy_testing_init_dependencies (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	secure_device_unlock_policy_testing_release (test, &unlock, &test_static);
}

static void secure_device_unlock_policy_test_release_null (CuTest *test)
{
	TEST_START;

	secure_device_unlock_policy_release (NULL);
}

static void secure_device_unlock_policy_test_get_unlock_token (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *token;
	size_t token_length;
	size_t context_length;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	device_unlock_token_testing_allocate_token (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, &token, &token_length, &context_length);
	CuAssertTrue (test, (token_length < sizeof (out)));

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN,
		1);

	/* Build the unlock token. */
	status |= mock_expect (&unlock.uuid.mock, unlock.uuid.base.get_uuid, &unlock.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&unlock.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&unlock.auth.mock, unlock.auth.base.new_token, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token, context_length), MOCK_ARG (context_length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&unlock.auth.mock, 2, &token, sizeof (token), -1);
	status |= mock_expect_output (&unlock.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, token_length, status);

	status = testing_validate_array (token, out, token_length);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (token);
}

static void secure_device_unlock_policy_test_get_unlock_token_different_counter (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *token;
	size_t token_length;
	size_t context_length;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	device_unlock_token_testing_allocate_token (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, &token, &token_length, &context_length);
	CuAssertTrue (test, (token_length < sizeof (out)));

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 1);

	/* Build the unlock token. */
	status |= mock_expect (&unlock.uuid.mock, unlock.uuid.base.get_uuid, &unlock.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&unlock.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&unlock.auth.mock, unlock.auth.base.new_token, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token, context_length), MOCK_ARG (context_length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&unlock.auth.mock, 2, &token, sizeof (token), -1);
	status |= mock_expect_output (&unlock.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, token_length, status);

	status = testing_validate_array (token, out, token_length);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (token);
}

static void secure_device_unlock_policy_test_get_unlock_token_static_init (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	struct secure_device_unlock_policy test_static =
		secure_device_unlock_policy_static_init (&unlock.token, &unlock.manager.base);
	uint8_t *token;
	size_t token_length;
	size_t context_length;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	device_unlock_token_testing_allocate_token (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, &token, &token_length, &context_length);
	CuAssertTrue (test, (token_length < sizeof (out)));

	secure_device_unlock_policy_testing_init_dependencies (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN,
		1);

	/* Build the unlock token. */
	status |= mock_expect (&unlock.uuid.mock, unlock.uuid.base.get_uuid, &unlock.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&unlock.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&unlock.auth.mock, unlock.auth.base.new_token, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token, context_length), MOCK_ARG (context_length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&unlock.auth.mock, 2, &token, sizeof (token), -1);
	status |= mock_expect_output (&unlock.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_unlock_token (&test_static.base, out, sizeof (out));
	CuAssertIntEquals (test, token_length, status);

	status = testing_validate_array (token, out, token_length);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &test_static);

	platform_free (token);
}

static void secure_device_unlock_policy_test_get_unlock_token_null (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	status = unlock.test.base.get_unlock_token (NULL, out, sizeof (out));
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, NULL, sizeof (out));
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_get_unlock_token_counter_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, SECURITY_MANAGER_GET_COUNTER_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN));

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, SECURITY_MANAGER_GET_COUNTER_FAILED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_get_unlock_token_unlocked (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_NOT_LOCKED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_get_unlock_token_counter_exhausted (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED_LEN,
		MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED,
		SECURE_DEVICE_UNLOCK_POLICY_TESTING_COUNTER_EXHAUSTED_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_COUNTER_EXHAUSTED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_get_unlock_token_generate_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN,
		1);

	/* Build the unlock token. */
	status |= mock_expect (&unlock.uuid.mock, unlock.uuid.base.get_uuid, &unlock.uuid,
		CMD_DEVICE_UUID_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, CMD_DEVICE_UUID_FAILED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_get_unlock_token_mismatch_counter_lengths (
	CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;
	uint8_t out[SECURE_DEVICE_UNLOCK_POLICY_TESTING_BUFFER_LENGTH];

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN);

	/* Get the current unlock counter. */
	status = mock_expect (&unlock.manager.mock, unlock.manager.base.get_unlock_counter,
		&unlock.manager, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN));
	status |= mock_expect_output (&unlock.manager.mock, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_COUNTER, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_apply_unlock_policy (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *unlock_policy;
	size_t unlock_length;
	size_t token_offset;
	int status;

	TEST_START;

	device_unlock_token_testing_allocate_authorized_data (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 0, &unlock_policy, &unlock_length,
		&token_offset, NULL);

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	/* Authenticate the unlock policy. */
	status = mock_expect (&unlock.auth.mock, unlock.auth.base.verify_data, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length),
		MOCK_ARG (token_offset), MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN),
		MOCK_ARG (HASH_TYPE_SHA256));

	/* Apply the unlock policy. */
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.unlock_device, &unlock.manager,
		0, MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length));

	/* Invalidate the unlock token. */
	status |= mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth, 0);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base, unlock_policy, unlock_length);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (unlock_policy);
}

static void secure_device_unlock_policy_test_apply_unlock_policy_static_init (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	struct secure_device_unlock_policy test_static =
		secure_device_unlock_policy_static_init (&unlock.token, &unlock.manager.base);
	uint8_t *unlock_policy;
	size_t unlock_length;
	size_t token_offset;
	int status;

	TEST_START;

	device_unlock_token_testing_allocate_authorized_data (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 0, &unlock_policy, &unlock_length,
		&token_offset, NULL);

	secure_device_unlock_policy_testing_init_dependencies (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	/* Authenticate the unlock policy. */
	status = mock_expect (&unlock.auth.mock, unlock.auth.base.verify_data, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length),
		MOCK_ARG (token_offset), MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN),
		MOCK_ARG (HASH_TYPE_SHA256));

	/* Apply the unlock policy. */
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.unlock_device, &unlock.manager,
		0, MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length));

	/* Invalidate the unlock token. */
	status |= mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.apply_unlock_policy (&test_static.base, unlock_policy, unlock_length);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &test_static);

	platform_free (unlock_policy);
}

static void secure_device_unlock_policy_test_apply_unlock_policy_null (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *unlock_policy;
	size_t unlock_length;
	size_t token_offset;
	int status;

	TEST_START;

	device_unlock_token_testing_allocate_authorized_data (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 0, &unlock_policy, &unlock_length,
		&token_offset, NULL);

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	status = unlock.test.base.apply_unlock_policy (NULL, unlock_policy, unlock_length);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base, NULL, unlock_length);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (unlock_policy);
}

static void secure_device_unlock_policy_test_apply_unlock_policy_authenticate_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *unlock_policy;
	size_t unlock_length;
	size_t token_offset;
	int status;

	TEST_START;

	device_unlock_token_testing_allocate_authorized_data (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 0, &unlock_policy, &unlock_length,
		&token_offset, NULL);

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	/* Authenticate the unlock policy. */
	status = mock_expect (&unlock.auth.mock, unlock.auth.base.verify_data, &unlock.auth,
		AUTH_TOKEN_NOT_VALID, MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length),
		MOCK_ARG (unlock_length), MOCK_ARG (token_offset),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA256));

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base, unlock_policy, unlock_length);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (unlock_policy);
}

static void secure_device_unlock_policy_test_apply_unlock_policy_unlock_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *unlock_policy;
	size_t unlock_length;
	size_t token_offset;
	int status;

	TEST_START;

	device_unlock_token_testing_allocate_authorized_data (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 0, &unlock_policy, &unlock_length,
		&token_offset, NULL);

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	/* Authenticate the unlock policy. */
	status = mock_expect (&unlock.auth.mock, unlock.auth.base.verify_data, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length),
		MOCK_ARG (token_offset), MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN),
		MOCK_ARG (HASH_TYPE_SHA256));

	/* Apply the unlock policy. */
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.unlock_device, &unlock.manager,
		SECURITY_MANAGER_UNLOCK_FAILED, MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length),
		MOCK_ARG (unlock_length));

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base, unlock_policy, unlock_length);
	CuAssertIntEquals (test, SECURITY_MANAGER_UNLOCK_FAILED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (unlock_policy);
}

static void secure_device_unlock_policy_test_apply_unlock_policy_invalidate_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	uint8_t *unlock_policy;
	size_t unlock_length;
	size_t token_offset;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_TOKEN_INVALIDATE_FAIL,
		.arg1 = AUTH_TOKEN_INVALIDATE_FAILED,
		.arg2 = 0
	};

	TEST_START;

	device_unlock_token_testing_allocate_authorized_data (test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, 0, &unlock_policy, &unlock_length,
		&token_offset, NULL);

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	/* Authenticate the unlock policy. */
	status = mock_expect (&unlock.auth.mock, unlock.auth.base.verify_data, &unlock.auth, 0,
		MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length),
		MOCK_ARG (token_offset), MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN),
		MOCK_ARG (HASH_TYPE_SHA256));

	/* Apply the unlock policy. */
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.unlock_device, &unlock.manager,
		0, MOCK_ARG_PTR_CONTAINS (unlock_policy, unlock_length), MOCK_ARG (unlock_length));

	/* Invalidate the unlock token. */
	status |= mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth,
		AUTH_TOKEN_INVALIDATE_FAILED);

	status |= mock_expect (&unlock.log.mock, unlock.log.base.create_entry, &unlock.log,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base, unlock_policy, unlock_length);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);

	platform_free (unlock_policy);
}

static void secure_device_unlock_policy_test_clear_unlock_policy (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	status = mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth, 0);
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.lock_device, &unlock.manager,
		0);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.clear_unlock_policy (&unlock.test.base);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_clear_unlock_policy_static_init (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	struct secure_device_unlock_policy test_static =
		secure_device_unlock_policy_static_init (&unlock.token, &unlock.manager.base);
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init_dependencies (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	status = mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth, 0);
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.lock_device, &unlock.manager,
		0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.clear_unlock_policy (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &test_static);
}

static void secure_device_unlock_policy_test_clear_unlock_policy_null (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	status = unlock.test.base.clear_unlock_policy (NULL);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_clear_unlock_policy_invalidate_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	status = mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth,
		AUTH_TOKEN_INVALIDATE_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.clear_unlock_policy (&unlock.test.base);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALIDATE_FAILED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}

static void secure_device_unlock_policy_test_clear_unlock_policy_lock_error (CuTest *test)
{
	struct secure_device_unlock_policy_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_policy_testing_init (test, &unlock,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	status = mock_expect (&unlock.auth.mock, unlock.auth.base.invalidate, &unlock.auth, 0);
	status |= mock_expect (&unlock.manager.mock, unlock.manager.base.lock_device, &unlock.manager,
		SECURITY_MANAGER_LOCK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.clear_unlock_policy (&unlock.test.base);
	CuAssertIntEquals (test, SECURITY_MANAGER_LOCK_FAILED, status);

	secure_device_unlock_policy_testing_release (test, &unlock, &unlock.test);
}


TEST_SUITE_START (secure_device_unlock_policy);

TEST (secure_device_unlock_policy_test_init);
TEST (secure_device_unlock_policy_test_init_null);
TEST (secure_device_unlock_policy_test_static_init);
TEST (secure_device_unlock_policy_test_release_null);
TEST (secure_device_unlock_policy_test_get_unlock_token);
TEST (secure_device_unlock_policy_test_get_unlock_token_different_counter);
TEST (secure_device_unlock_policy_test_get_unlock_token_static_init);
TEST (secure_device_unlock_policy_test_get_unlock_token_null);
TEST (secure_device_unlock_policy_test_get_unlock_token_counter_error);
TEST (secure_device_unlock_policy_test_get_unlock_token_unlocked);
TEST (secure_device_unlock_policy_test_get_unlock_token_counter_exhausted);
TEST (secure_device_unlock_policy_test_get_unlock_token_generate_error);
TEST (secure_device_unlock_policy_test_get_unlock_token_mismatch_counter_lengths);
TEST (secure_device_unlock_policy_test_apply_unlock_policy);
TEST (secure_device_unlock_policy_test_apply_unlock_policy_static_init);
TEST (secure_device_unlock_policy_test_apply_unlock_policy_null);
TEST (secure_device_unlock_policy_test_apply_unlock_policy_authenticate_error);
TEST (secure_device_unlock_policy_test_apply_unlock_policy_unlock_error);
TEST (secure_device_unlock_policy_test_apply_unlock_policy_invalidate_error);
TEST (secure_device_unlock_policy_test_clear_unlock_policy);
TEST (secure_device_unlock_policy_test_clear_unlock_policy_static_init);
TEST (secure_device_unlock_policy_test_clear_unlock_policy_null);
TEST (secure_device_unlock_policy_test_clear_unlock_policy_invalidate_error);
TEST (secure_device_unlock_policy_test_clear_unlock_policy_lock_error);

TEST_SUITE_END;
