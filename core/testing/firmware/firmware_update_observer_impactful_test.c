// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "firmware/firmware_update_observer_impactful.h"
#include "firmware/firmware_update_observer_impactful_static.h"
#include "testing/mock/firmware/impactful_update_mock.h"


TEST_SUITE_LABEL ("firmware_update_observer_impactful");


/**
 * Dependencies for testing.
 */
struct firmware_update_observer_impactful_testing {
	struct impactful_update_mock impactful;			/**< Mock for the impactful update handler. */
	struct firmware_update_observer_impactful test;	/**< Observer under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param observer The testing components to initialize.
 */
static void firmware_update_observer_impactful_testing_init_dependencies (CuTest *test,
	struct firmware_update_observer_impactful_testing *observer)
{
	int status;

	status = impactful_update_mock_init (&observer->impactful);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param observer The testing dependencies to release.
 */
static void firmware_update_observer_impactful_testing_release_dependencies (CuTest *test,
	struct firmware_update_observer_impactful_testing *observer)
{
	int status;

	status = impactful_update_mock_validate_and_release (&observer->impactful);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param observer The testing components to initialize.
 */
static void firmware_update_observer_impactful_testing_init (CuTest *test,
	struct firmware_update_observer_impactful_testing *observer)
{
	int status;

	firmware_update_observer_impactful_testing_init_dependencies (test, observer);

	status = firmware_update_observer_impactful_init (&observer->test, &observer->impactful.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param observer The testing components to release.
 */
static void firmware_update_observer_impactful_testing_release (CuTest *test,
	struct firmware_update_observer_impactful_testing *observer)
{
	firmware_update_observer_impactful_testing_release_dependencies (test, observer);
	firmware_update_observer_impactful_release (&observer->test);
}


/*******************
 * Test cases
 *******************/

static void firmware_update_observer_impactful_test_init (CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer;
	int status;

	TEST_START;

	firmware_update_observer_impactful_testing_init_dependencies (test, &observer);

	status = firmware_update_observer_impactful_init (&observer.test, &observer.impactful.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, observer.test.base.on_update_start);
	CuAssertPtrEquals (test, NULL, observer.test.base.on_prepare_update);
	CuAssertPtrEquals (test, NULL, observer.test.base.on_update_applied);

	firmware_update_observer_impactful_testing_release (test, &observer);
}

static void firmware_update_observer_impactful_test_init_null (CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer;
	int status;

	TEST_START;

	firmware_update_observer_impactful_testing_init_dependencies (test, &observer);

	status = firmware_update_observer_impactful_init (NULL, &observer.impactful.base);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_observer_impactful_init (&observer.test, NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_observer_impactful_testing_release_dependencies (test, &observer);
}

static void firmware_update_observer_impactful_test_static_init (CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer = {
		.test = firmware_update_observer_impactful_static_init (&observer.impactful.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, observer.test.base.on_update_start);
	CuAssertPtrEquals (test, NULL, observer.test.base.on_prepare_update);
	CuAssertPtrEquals (test, NULL, observer.test.base.on_update_applied);

	firmware_update_observer_impactful_testing_init_dependencies (test, &observer);

	firmware_update_observer_impactful_testing_release (test, &observer);
}

static void firmware_update_observer_impactful_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_update_observer_impactful_release (NULL);
}

static void firmware_update_observer_impactful_test_on_update_start_allowed (CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer;
	int status;
	int update_allowed = 0;

	TEST_START;

	firmware_update_observer_impactful_testing_init (test, &observer);

	status = mock_expect (&observer.impactful.mock, observer.impactful.base.is_update_allowed,
		&observer.impactful, 0);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_update_start (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 0, update_allowed);

	firmware_update_observer_impactful_testing_release (test, &observer);
}

static void firmware_update_observer_impactful_test_on_update_start_not_allowed (CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer;
	int status;
	int update_allowed = 0;

	TEST_START;

	firmware_update_observer_impactful_testing_init (test, &observer);

	status = mock_expect (&observer.impactful.mock, observer.impactful.base.is_update_allowed,
		&observer.impactful, IMPACTFUL_UPDATE_NOT_ALLOWED);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_update_start (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_NOT_ALLOWED, update_allowed);

	firmware_update_observer_impactful_testing_release (test, &observer);
}

static void firmware_update_observer_impactful_test_on_update_start_other_context_disallowed (
	CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer;
	int update_allowed = 1;

	TEST_START;

	firmware_update_observer_impactful_testing_init (test, &observer);

	observer.test.base.on_update_start (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 1, update_allowed);

	firmware_update_observer_impactful_testing_release (test, &observer);
}

static void firmware_update_observer_impactful_test_on_update_start_static_init (CuTest *test)
{
	struct firmware_update_observer_impactful_testing observer = {
		.test = firmware_update_observer_impactful_static_init (&observer.impactful.base)
	};
	int status;
	int update_allowed = 0;

	TEST_START;

	firmware_update_observer_impactful_testing_init_dependencies (test, &observer);

	status = mock_expect (&observer.impactful.mock, observer.impactful.base.is_update_allowed,
		&observer.impactful, IMPACTFUL_UPDATE_NOT_ALLOWED);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_update_start (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_NOT_ALLOWED, update_allowed);

	firmware_update_observer_impactful_testing_release (test, &observer);
}


// *INDENT-OFF*
TEST_SUITE_START (firmware_update_observer_impactful);

TEST (firmware_update_observer_impactful_test_init);
TEST (firmware_update_observer_impactful_test_init_null);
TEST (firmware_update_observer_impactful_test_static_init);
TEST (firmware_update_observer_impactful_test_release_null);
TEST (firmware_update_observer_impactful_test_on_update_start_allowed);
TEST (firmware_update_observer_impactful_test_on_update_start_not_allowed);
TEST (firmware_update_observer_impactful_test_on_update_start_other_context_disallowed);
TEST (firmware_update_observer_impactful_test_on_update_start_static_init);

TEST_SUITE_END;
// *INDENT-ON*
