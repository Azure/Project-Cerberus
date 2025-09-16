// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include "testing.h"
#include "spdm/impactful_check_spdm_static.h"
#include "testing/mock/spdm/spdm_secure_session_manager_mock.h"


TEST_SUITE_LABEL ("impactful_check_spdm");


/**
 * Dependencies for testing.
 */
struct impactful_check_spdm_testing {
	struct impactful_check_spdm test;					/**< Impactful check under test. */
	struct spdm_secure_session_manager_mock spdm_mock;	/**< Mock for the SPDM secure session manager interface. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param impactful The testing components to initialize.
 */
static void impactful_check_spdm_testing_init_dependencies (CuTest *test,
	struct impactful_check_spdm_testing *impactful)
{
	int status;

	status = spdm_secure_session_manager_mock_init (&impactful->spdm_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param impactful The testing dependencies to release.
 */
static void impactful_check_spdm_testing_release_dependencies (CuTest *test,
	struct impactful_check_spdm_testing *impactful)
{
	int status;

	status = spdm_secure_session_manager_mock_validate_and_release (&impactful->spdm_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param impactful The testing components to initialize.
 */
static void impactful_check_spdm_testing_init (CuTest *test,
	struct impactful_check_spdm_testing *impactful)
{
	int status;

	impactful_check_spdm_testing_init_dependencies (test, impactful);

	status = impactful_check_spdm_init (&impactful->test, &impactful->spdm_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param impactful The testing components to release.
 */
static void impactful_check_spdm_testing_release (CuTest *test,
	struct impactful_check_spdm_testing *impactful)
{
	impactful_check_spdm_testing_release_dependencies (test, impactful);
	impactful_check_spdm_release (&impactful->test);
}


/*******************
 * Test cases
 *******************/

static void impactful_check_spdm_test_init (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init_dependencies (test, &impactful);

	status = impactful_check_spdm_init (&impactful.test, &impactful.spdm_mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, impactful.test.base.is_not_impactful);
	CuAssertPtrNotNull (test, impactful.test.base.is_authorization_allowed);

	impactful_check_spdm_testing_release (test, &impactful);
}

static void impactful_check_spdm_test_init_null (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init_dependencies (test, &impactful);

	status = impactful_check_spdm_init (NULL, &impactful.spdm_mock.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_INVALID_ARGUMENT, status);

	status = impactful_check_spdm_init (&impactful.test, NULL);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_INVALID_ARGUMENT, status);

	impactful_check_spdm_testing_release_dependencies (test, &impactful);
}

static void impactful_check_spdm_test_static_init (CuTest *test)
{
	struct impactful_check_spdm_testing impactful = {
		.test = impactful_check_spdm_static_init (&impactful.spdm_mock.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, impactful.test.base.is_not_impactful);
	CuAssertPtrNotNull (test, impactful.test.base.is_authorization_allowed);

	impactful_check_spdm_testing_init_dependencies (test, &impactful);

	impactful_check_spdm_testing_release (test, &impactful);
}

static void impactful_check_spdm_test_release_null (CuTest *test)
{
	TEST_START;

	impactful_check_spdm_release (NULL);
}

static void impactful_check_spdm_test_is_not_impactful (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init (test, &impactful);

	status = mock_expect (&impactful.spdm_mock.mock,
		impactful.spdm_mock.base.is_termination_policy_set,	&impactful.spdm_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_check_spdm_testing_release (test, &impactful);
}

static void impactful_check_spdm_test_is_not_impactful_is_impactful (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init (test, &impactful);

	status = mock_expect (&impactful.spdm_mock.mock,
		impactful.spdm_mock.base.is_termination_policy_set,	&impactful.spdm_mock.base,
		SPDM_SECURE_SESSION_MANAGER_TERMINATION_POLICY_NOT_SET);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_TERMINATION_POLICY_NOT_SET, status);

	impactful_check_spdm_testing_release (test, &impactful);
}

static void impactful_check_spdm_test_is_not_impactful_null (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init (test, &impactful);

	status = impactful.test.base.is_not_impactful (NULL);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_INVALID_ARGUMENT, status);

	impactful_check_spdm_testing_release (test, &impactful);
}

static void impactful_check_spdm_test_is_not_impactful_spdm_error (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init (test, &impactful);

	status = mock_expect (&impactful.spdm_mock.mock,
		impactful.spdm_mock.base.is_termination_policy_set,	&impactful.spdm_mock.base,
		SPDM_SECURE_SESSION_MANAGER_IS_TERMINATION_POLICY_SET_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_IS_TERMINATION_POLICY_SET_FAILED, status);

	impactful_check_spdm_testing_release (test, &impactful);
}

static void impactful_check_spdm_test_is_authorization_allowed (CuTest *test)
{
	struct impactful_check_spdm_testing impactful;
	int status;

	TEST_START;

	impactful_check_spdm_testing_init (test, &impactful);

	status = impactful.test.base.is_authorization_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_check_spdm_testing_release (test, &impactful);
}

// *INDENT-OFF*
TEST_SUITE_START (impactful_check_spdm);

TEST (impactful_check_spdm_test_init);
TEST (impactful_check_spdm_test_init_null);
TEST (impactful_check_spdm_test_static_init);
TEST (impactful_check_spdm_test_release_null);
TEST (impactful_check_spdm_test_is_not_impactful);
TEST (impactful_check_spdm_test_is_not_impactful_is_impactful);
TEST (impactful_check_spdm_test_is_not_impactful_null);
TEST (impactful_check_spdm_test_is_not_impactful_spdm_error);
TEST (impactful_check_spdm_test_is_authorization_allowed);

TEST_SUITE_END;
// *INDENT-ON*
