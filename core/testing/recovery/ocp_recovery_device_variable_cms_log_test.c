// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "recovery/ocp_recovery_device_variable_cms_log.h"
#include "recovery/ocp_recovery_device_variable_cms_log_static.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("ocp_recovery_device_variable_cms_log");


/**
 * Dependencies for testing a variable CMS log wrapper.
 */
struct ocp_recovery_device_variable_cms_log_testing {
	struct logging_mock log;							/**< Mock for the logging interface. */
	struct ocp_recovery_device_variable_cms_log test;	/**< CMS wrapper under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param recovery Testing dependencies to initialize.
 */
static void ocp_recovery_device_variable_cms_log_testing_init_dependencies (CuTest *test,
	struct ocp_recovery_device_variable_cms_log_testing *cms)
{
	int status;

	status = logging_mock_init (&cms->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param recovery Testing dependencies to release.
 */
static void ocp_recovery_device_variable_cms_log_testing_release_dependencies (CuTest *test,
	struct ocp_recovery_device_variable_cms_log_testing *cms)
{
	int status;

	status = logging_mock_validate_and_release (&cms->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a variable CMS log handler for testing.
 *
 * @param test The test framework.
 * @param cms Testing components to initialize.
 */
static void ocp_recovery_device_variable_cms_log_testing_init (CuTest *test,
	struct ocp_recovery_device_variable_cms_log_testing *cms)
{
	int status;

	ocp_recovery_device_variable_cms_log_testing_init_dependencies (test, cms);

	status = ocp_recovery_device_variable_cms_log_init (&cms->test, &cms->log.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release CMS log handler test components and validate all mocks.
 *
 * @param test The test framework.
 * @param recovery Testing components to release.
 */
static void ocp_recovery_device_variable_cms_log_testing_release (CuTest *test,
	struct ocp_recovery_device_variable_cms_log_testing *cms)
{
	ocp_recovery_device_variable_cms_log_testing_release_dependencies (test, cms);
	ocp_recovery_device_variable_cms_log_release (&cms->test);
}


/*******************
 * Test cases
 *******************/

static void ocp_recovery_device_variable_cms_log_test_init (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init_dependencies (test, &cms);

	status = ocp_recovery_device_variable_cms_log_init (&cms.test, &cms.log.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cms.test.base.get_size);
	CuAssertPtrNotNull (test, cms.test.base.get_data);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_init_null (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init_dependencies (test, &cms);

	status = ocp_recovery_device_variable_cms_log_init (NULL, &cms.log.base);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_variable_cms_log_init (&cms.test, NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_variable_cms_log_testing_release_dependencies (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_static_init (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	struct ocp_recovery_device_variable_cms_log test_static =
		ocp_recovery_device_variable_cms_log_static_init (&cms.log.base);

	TEST_START;

	CuAssertPtrNotNull (test, test_static.base.get_size);
	CuAssertPtrNotNull (test, test_static.base.get_data);

	ocp_recovery_device_variable_cms_log_release (&test_static);
}

static void ocp_recovery_device_variable_cms_log_test_release_null (CuTest *test)
{
	TEST_START;

	ocp_recovery_device_variable_cms_log_release (NULL);
}

static void ocp_recovery_device_variable_cms_log_test_get_size (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;
	int length = 100;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.get_size, &cms.log, length);
	CuAssertIntEquals (test, 0, status);

	status = cms.test.base.get_size (&cms.test.base);
	CuAssertIntEquals (test, length, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_get_size_static_init (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	struct ocp_recovery_device_variable_cms_log test_static =
		ocp_recovery_device_variable_cms_log_static_init (&cms.log.base);
	int status;
	int length = 100;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init_dependencies (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.get_size, &cms.log, length);
	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_size (&test_static.base);
	CuAssertIntEquals (test, length, status);

	ocp_recovery_device_variable_cms_log_testing_release_dependencies (test, &cms);
	ocp_recovery_device_variable_cms_log_release (&test_static);
}

static void ocp_recovery_device_variable_cms_log_test_get_size_null (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = cms.test.base.get_size (NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_get_size_error (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.get_size, &cms.log, LOGGING_GET_SIZE_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = cms.test.base.get_size (&cms.test.base);
	CuAssertIntEquals (test, LOGGING_GET_SIZE_FAILED, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_get_data (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;
	uint8_t data[1];
	int length = 100;
	size_t offset = 0;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.read_contents, &cms.log, length,
		MOCK_ARG (offset), MOCK_ARG (data), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = cms.test.base.get_data (&cms.test.base, offset, data, length);
	CuAssertIntEquals (test, length, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_get_data_non_zero_offset (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;
	uint8_t data[1];
	int length = 110;
	size_t offset = 10;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.read_contents, &cms.log, length,
		MOCK_ARG (offset), MOCK_ARG (data), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = cms.test.base.get_data (&cms.test.base, offset, data, length);
	CuAssertIntEquals (test, length, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_get_data_static_init (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	struct ocp_recovery_device_variable_cms_log test_static =
		ocp_recovery_device_variable_cms_log_static_init (&cms.log.base);
	int status;
	uint8_t data[1];
	int length = 100;
	size_t offset = 0;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init_dependencies (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.read_contents, &cms.log, length,
		MOCK_ARG (offset), MOCK_ARG (data), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_data (&test_static.base, offset, data, length);
	CuAssertIntEquals (test, length, status);

	ocp_recovery_device_variable_cms_log_testing_release_dependencies (test, &cms);
	ocp_recovery_device_variable_cms_log_release (&test_static);
}

static void ocp_recovery_device_variable_cms_log_test_get_data_null (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;
	uint8_t data[1];
	int length = 100;
	size_t offset = 0;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = cms.test.base.get_data (NULL, offset, data, length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}

static void ocp_recovery_device_variable_cms_log_test_get_data_error (CuTest *test)
{
	struct ocp_recovery_device_variable_cms_log_testing cms;
	int status;
	uint8_t data[1];
	int length = 100;
	size_t offset = 0;

	TEST_START;

	ocp_recovery_device_variable_cms_log_testing_init (test, &cms);

	status = mock_expect (&cms.log.mock, cms.log.base.read_contents, &cms.log,
		LOGGING_READ_CONTENTS_FAILED, MOCK_ARG (offset), MOCK_ARG (data), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = cms.test.base.get_data (&cms.test.base, offset, data, length);
	CuAssertIntEquals (test, LOGGING_READ_CONTENTS_FAILED, status);

	ocp_recovery_device_variable_cms_log_testing_release (test, &cms);
}


TEST_SUITE_START (ocp_recovery_device_variable_cms_log);

TEST (ocp_recovery_device_variable_cms_log_test_init);
TEST (ocp_recovery_device_variable_cms_log_test_init_null);
TEST (ocp_recovery_device_variable_cms_log_test_static_init);
TEST (ocp_recovery_device_variable_cms_log_test_release_null);
TEST (ocp_recovery_device_variable_cms_log_test_get_size);
TEST (ocp_recovery_device_variable_cms_log_test_get_size_static_init);
TEST (ocp_recovery_device_variable_cms_log_test_get_size_null);
TEST (ocp_recovery_device_variable_cms_log_test_get_size_error);
TEST (ocp_recovery_device_variable_cms_log_test_get_data);
TEST (ocp_recovery_device_variable_cms_log_test_get_data_non_zero_offset);
TEST (ocp_recovery_device_variable_cms_log_test_get_data_static_init);
TEST (ocp_recovery_device_variable_cms_log_test_get_data_null);
TEST (ocp_recovery_device_variable_cms_log_test_get_data_error);


TEST_SUITE_END;
