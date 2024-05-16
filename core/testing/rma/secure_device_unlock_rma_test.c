// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "rma/secure_device_unlock_rma.h"
#include "rma/secure_device_unlock_rma_static.h"
#include "testing/mock/rma/device_rma_transition_mock.h"
#include "testing/mock/rma/rma_unlock_token_mock.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("secure_device_unlock_rma");


/**
 * RMA authorization token data to use for testing.
 */
static const uint8_t SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN[] = {
	0x88, 0x7a, 0xf6, 0x07, 0x95, 0x7f, 0xa3, 0x10, 0x8a, 0x75, 0x90, 0x53, 0x45, 0x4c, 0x42, 0x3e,
	0xae, 0x3f, 0x26, 0xb5, 0xd6, 0xec, 0x3c, 0xcc, 0xec, 0x6a, 0x5d, 0x0e, 0xf7, 0xab, 0x5f, 0x39,
	0xf9, 0x27, 0x7c, 0xca, 0xc1, 0x9b, 0x56, 0x43, 0x8c, 0xf8, 0x46, 0x0e, 0xea, 0xe6, 0x5f, 0xd5,
	0x12, 0xf4, 0x79, 0xa5, 0xc0, 0xd6, 0x58, 0xf6, 0x64, 0xcd, 0x92, 0xfd, 0xcd, 0x9c, 0x02, 0xc2
};

static const size_t SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN =
	sizeof (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN);


/**
 * Dependencies for testing the device unlock token handler.
 */
struct secure_device_unlock_rma_testing {
	struct rma_unlock_token_mock token;		/**< Mock for the RMA authorization token. */
	struct device_rma_transition_mock rma;	/**< Mock for the RMA transition handler. */
	struct secure_device_unlock_rma test;	/**< RMA handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param unlock Testing dependencies to initialize.
 */
static void secure_device_unlock_rma_testing_init_dependencies (CuTest *test,
	struct secure_device_unlock_rma_testing *unlock)
{
	int status;

	status = rma_unlock_token_mock_init (&unlock->token);
	CuAssertIntEquals (test, 0, status);

	status = device_rma_transition_mock_init (&unlock->rma);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param unlock Testing dependencies to release.
 */
static void secure_device_unlock_rma_testing_release_dependencies (CuTest *test,
	struct secure_device_unlock_rma_testing *unlock)
{
	int status;

	status = rma_unlock_token_mock_validate_and_release (&unlock->token);
	status |= device_rma_transition_mock_validate_and_release (&unlock->rma);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an authenticated RMA handler for testing.
 *
 * @param test The test framework.
 * @param unlock Testing components to initialize.
 */
static void secure_device_unlock_rma_testing_init (CuTest *test,
	struct secure_device_unlock_rma_testing *unlock)
{
	int status;

	secure_device_unlock_rma_testing_init_dependencies (test, unlock);

	status = secure_device_unlock_rma_init (&unlock->test, &unlock->token.base, &unlock->rma.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param unlock Testing components to release.
 */
static void secure_device_unlock_rma_testing_release (CuTest *test,
	struct secure_device_unlock_rma_testing *unlock)
{
	secure_device_unlock_rma_release (&unlock->test);
	secure_device_unlock_rma_testing_release_dependencies (test, unlock);
}


/*******************
 * Test cases
 *******************/

static void secure_device_unlock_rma_test_init (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init_dependencies (test, &unlock);

	status = secure_device_unlock_rma_init (&unlock.test, &unlock.token.base, &unlock.rma.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, unlock.test.base.get_unlock_token);
	CuAssertPtrNotNull (test, unlock.test.base.apply_unlock_policy);
	CuAssertPtrNotNull (test, unlock.test.base.clear_unlock_policy);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_init_null (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init_dependencies (test, &unlock);

	status = secure_device_unlock_rma_init (NULL, &unlock.token.base, &unlock.rma.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = secure_device_unlock_rma_init (&unlock.test, NULL, &unlock.rma.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = secure_device_unlock_rma_init (&unlock.test, &unlock.token.base, NULL,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = secure_device_unlock_rma_init (&unlock.test, &unlock.token.base, &unlock.rma.base,
		NULL, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = secure_device_unlock_rma_init (&unlock.test, &unlock.token.base, &unlock.rma.base,
		RIOT_CORE_DEVID_CSR, 0);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_rma_testing_release_dependencies (test, &unlock);
}

static void secure_device_unlock_rma_test_static_init (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock = {
		.test = secure_device_unlock_rma_static_init (&unlock.token.base, &unlock.rma.base,
			RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN)
	};

	TEST_START;

	CuAssertPtrNotNull (test, unlock.test.base.get_unlock_token);
	CuAssertPtrNotNull (test, unlock.test.base.apply_unlock_policy);
	CuAssertPtrNotNull (test, unlock.test.base.clear_unlock_policy);

	secure_device_unlock_rma_testing_init_dependencies (test, &unlock);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_release_null (CuTest *test)
{
	TEST_START;

	secure_device_unlock_rma_release (NULL);
}

static void secure_device_unlock_rma_test_get_unlock_token (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;
	uint8_t out[RIOT_CORE_DEVID_CSR_LEN];

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_LEN, status);

	status = testing_validate_array (RIOT_CORE_DEVID_CSR, out, RIOT_CORE_DEVID_CSR_LEN);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_get_unlock_token_static_init (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock = {
		.test = secure_device_unlock_rma_static_init (&unlock.token.base, &unlock.rma.base,
			RIOT_CORE_DEVID_CSR_384, RIOT_CORE_DEVID_CSR_384_LEN)
	};
	int status;
	uint8_t out[RIOT_CORE_DEVID_CSR_384_LEN];

	TEST_START;

	secure_device_unlock_rma_testing_init_dependencies (test, &unlock);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out, sizeof (out));
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_384_LEN, status);

	status = testing_validate_array (RIOT_CORE_DEVID_CSR_384, out, RIOT_CORE_DEVID_CSR_384_LEN);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_get_unlock_token_null (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;
	uint8_t out[RIOT_CORE_DEVID_CSR_LEN];

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = unlock.test.base.get_unlock_token (NULL, out, sizeof (out));
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, NULL, sizeof (out));
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_get_unlock_token_small_token_buffer (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;
	uint8_t out[RIOT_CORE_DEVID_CSR_LEN];

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = unlock.test.base.get_unlock_token (&unlock.test.base, out,
		RIOT_CORE_DEVID_CSR_LEN - 1);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_SMALL_BUFFER, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_apply_unlock_policy (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = mock_expect (&unlock.token.mock, unlock.token.base.authenticate, &unlock.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&unlock.rma.mock, unlock.rma.base.config_rma, &unlock.rma, 0);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_apply_unlock_policy_static_init (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock = {
		.test = secure_device_unlock_rma_static_init (&unlock.token.base, &unlock.rma.base,
			RIOT_CORE_DEVID_CSR_384, RIOT_CORE_DEVID_CSR_384_LEN)
	};
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init_dependencies (test, &unlock);

	status = mock_expect (&unlock.token.mock, unlock.token.base.authenticate, &unlock.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&unlock.rma.mock, unlock.rma.base.config_rma, &unlock.rma, 0);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, 0, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_apply_unlock_policy_null (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = unlock.test.base.apply_unlock_policy (NULL, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_apply_unlock_policy_token_authenticate_fail (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = mock_expect (&unlock.token.mock, unlock.token.base.authenticate, &unlock.token,
		RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_apply_unlock_policy_rma_transition_error (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = mock_expect (&unlock.token.mock, unlock.token.base.authenticate, &unlock.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&unlock.rma.mock, unlock.rma.base.config_rma, &unlock.rma,
		DEVICE_RMA_TRANSITION_CONFIG_FAIL);

	CuAssertIntEquals (test, 0, status);

	status = unlock.test.base.apply_unlock_policy (&unlock.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, DEVICE_RMA_TRANSITION_CONFIG_FAIL, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_clear_unlock_policy (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = unlock.test.base.clear_unlock_policy (&unlock.test.base);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_UNSUPPORTED, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_clear_unlock_policy_static_init (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock = {
		.test = secure_device_unlock_rma_static_init (&unlock.token.base, &unlock.rma.base,
			RIOT_CORE_DEVID_CSR_384, RIOT_CORE_DEVID_CSR_384_LEN)
	};
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init_dependencies (test, &unlock);

	status = unlock.test.base.clear_unlock_policy (&unlock.test.base);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_UNSUPPORTED, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}

static void secure_device_unlock_rma_test_clear_unlock_policy_null (CuTest *test)
{
	struct secure_device_unlock_rma_testing unlock;
	int status;

	TEST_START;

	secure_device_unlock_rma_testing_init (test, &unlock);

	status = unlock.test.base.clear_unlock_policy (NULL);
	CuAssertIntEquals (test, SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT, status);

	secure_device_unlock_rma_testing_release (test, &unlock);
}


// *INDENT-OFF*
TEST_SUITE_START (secure_device_unlock_rma);

TEST (secure_device_unlock_rma_test_init);
TEST (secure_device_unlock_rma_test_init_null);
TEST (secure_device_unlock_rma_test_static_init);
TEST (secure_device_unlock_rma_test_release_null);
TEST (secure_device_unlock_rma_test_get_unlock_token);
TEST (secure_device_unlock_rma_test_get_unlock_token_static_init);
TEST (secure_device_unlock_rma_test_get_unlock_token_null);
TEST (secure_device_unlock_rma_test_get_unlock_token_small_token_buffer);
TEST (secure_device_unlock_rma_test_apply_unlock_policy);
TEST (secure_device_unlock_rma_test_apply_unlock_policy_static_init);
TEST (secure_device_unlock_rma_test_apply_unlock_policy_null);
TEST (secure_device_unlock_rma_test_apply_unlock_policy_token_authenticate_fail);
TEST (secure_device_unlock_rma_test_apply_unlock_policy_rma_transition_error);
TEST (secure_device_unlock_rma_test_clear_unlock_policy);
TEST (secure_device_unlock_rma_test_clear_unlock_policy_static_init);
TEST (secure_device_unlock_rma_test_clear_unlock_policy_null);

TEST_SUITE_END;
// *INDENT-ON*
