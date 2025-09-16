// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "pcisig/tdisp/firmware_update_observer_tdisp_static.h"
#include "testing/mock/pcisig/tdisp/tdisp_driver_mock.h"
#include "testing/mock/pcisig/tdisp/tdisp_tdi_context_manager_mock.h"


TEST_SUITE_LABEL ("firmware_update_observer_tdisp");


/**
 * Dependencies for testing.
 */
struct firmware_update_observer_tdisp_testing {
	struct firmware_update_observer_tdisp test;			/**< Observer under test. */
	struct tdisp_driver_interface_mock tdisp;			/**< Mock for the TDISP interface. */
	struct tdisp_tdi_context_manager_mock tdi_context;	/**< Mock for the TDI context manager. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param observer The testing components to initialize.
 */
static void firmware_update_observer_tdisp_testing_init_dependencies (CuTest *test,
	struct firmware_update_observer_tdisp_testing *observer)
{
	int status;

	status = tdisp_driver_interface_mock_init (&observer->tdisp);
	CuAssertIntEquals (test, 0, status);

	status = tdisp_tdi_context_manager_mock_init (&observer->tdi_context);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param observer The testing dependencies to release.
 */
static void firmware_update_observer_tdisp_testing_release_dependencies (CuTest *test,
	struct firmware_update_observer_tdisp_testing *observer)
{
	int status;

	status = tdisp_driver_interface_mock_validate_and_release (&observer->tdisp);
	CuAssertIntEquals (test, 0, status);

	status = tdisp_tdi_context_manager_mock_validate_and_release (&observer->tdi_context);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param observer The testing components to initialize.
 */
static void firmware_update_observer_tdisp_testing_init (CuTest *test,
	struct firmware_update_observer_tdisp_testing *observer, uint32_t max_tdi_context_count)
{
	int status;

	firmware_update_observer_tdisp_testing_init_dependencies (test, observer);

	status = firmware_update_observer_tdisp_init (&observer->test, &observer->tdisp.base,
		&observer->tdi_context.base, max_tdi_context_count);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param observer The testing components to release.
 */
static void firmware_update_observer_tdisp_testing_release (CuTest *test,
	struct firmware_update_observer_tdisp_testing *observer)
{
	firmware_update_observer_tdisp_testing_release_dependencies (test, observer);
	firmware_update_observer_tdisp_release (&observer->test);
}


/*******************
 * Test cases
 *******************/

static void firmware_update_observer_tdisp_test_init (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;

	TEST_START;

	firmware_update_observer_tdisp_testing_init_dependencies (test, &observer);

	status = firmware_update_observer_tdisp_init (&observer.test, &observer.tdisp.base,
		&observer.tdi_context.base, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.test.base.on_update_start);
	CuAssertPtrNotNull (test, observer.test.base.on_prepare_update);
	CuAssertPtrEquals (test, NULL, observer.test.base.on_update_applied);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_init_null (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;

	TEST_START;

	firmware_update_observer_tdisp_testing_init_dependencies (test, &observer);

	status = firmware_update_observer_tdisp_init (NULL, &observer.tdisp.base,
		&observer.tdi_context.base,	3);
	CuAssertIntEquals (test, TDISP_DRIVER_INVALID_ARGUMENT, status);

	status = firmware_update_observer_tdisp_init (&observer.test, NULL, &observer.tdi_context.base,
		4);
	CuAssertIntEquals (test, TDISP_DRIVER_INVALID_ARGUMENT, status);

	status = firmware_update_observer_tdisp_init (&observer.test, &observer.tdisp.base, NULL, 5);
	CuAssertIntEquals (test, TDISP_DRIVER_INVALID_ARGUMENT, status);

	firmware_update_observer_tdisp_testing_release_dependencies (test, &observer);
}

static void firmware_update_observer_tdisp_test_static_init (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer = {
		.test = firmware_update_observer_tdisp_static_init (&observer.tdisp.base,
			&observer.tdi_context.base, 5)
	};

	TEST_START;

	CuAssertPtrEquals (test, NULL, observer.test.base.on_update_start);
	CuAssertPtrNotNull (test, observer.test.base.on_prepare_update);
	CuAssertPtrEquals (test, NULL, observer.test.base.on_update_applied);

	firmware_update_observer_tdisp_testing_init_dependencies (test, &observer);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_update_observer_tdisp_release (NULL);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_allowed_state (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;
	int update_allowed = 0;
	uint32_t function_index = 0;
	uint8_t tdi_hw_state_unlocked = TDISP_TDI_STATE_CONFIG_UNLOCKED;

	TEST_START;

	firmware_update_observer_tdisp_testing_init (test, &observer, 1);

	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (function_index), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_unlocked,
		sizeof (tdi_hw_state_unlocked), -1);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 0, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_allowed_lock_flag (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;
	int update_allowed = 0;
	uint8_t tdi_hw_state_run = TDISP_TDI_STATE_RUN;
	struct tdisp_tdi_context tdi_context = {
		.lock_flags = 0
	};

	TEST_START;

	firmware_update_observer_tdisp_testing_init (test, &observer, 2);

	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_run,
		sizeof (tdi_hw_state_run), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.tdi_context.mock, observer.tdi_context.base.get_tdi_context,
		&observer.tdi_context, 0, MOCK_ARG (0),	MOCK_ARG (TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdi_context.mock, 2, &tdi_context, sizeof (tdi_context),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_run,
		sizeof (tdi_hw_state_run), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.tdi_context.mock, observer.tdi_context.base.get_tdi_context,
		&observer.tdi_context, 0, MOCK_ARG (1),	MOCK_ARG (TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdi_context.mock, 2, &tdi_context, sizeof (tdi_context),
		-1);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 0, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_not_allowed (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;
	int update_allowed = 0;
	uint8_t tdi_hw_state_locked = TDISP_TDI_STATE_CONFIG_LOCKED;
	struct tdisp_tdi_context tdi_context = {
		.lock_flags = 1
	};

	TEST_START;

	firmware_update_observer_tdisp_testing_init (test, &observer, 5);

	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_locked,
		sizeof (tdi_hw_state_locked), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.tdi_context.mock, observer.tdi_context.base.get_tdi_context,
		&observer.tdi_context, 0, MOCK_ARG (0),	MOCK_ARG (TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdi_context.mock, 2, &tdi_context, sizeof (tdi_context),
		-1);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, TDISP_DRIVER_UPDATE_NOT_ALLOWED, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_other_context_disallowed (
	CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int update_allowed = 1;

	TEST_START;

	firmware_update_observer_tdisp_testing_init (test, &observer, 2);

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 1, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_static_init (CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer = {
		.test = firmware_update_observer_tdisp_static_init (&observer.tdisp.base,
			&observer.tdi_context.base, 3)
	};
	int status;
	int update_allowed = 0;
	uint8_t tdi_hw_state_locked = TDISP_TDI_STATE_CONFIG_LOCKED;
	struct tdisp_tdi_context tdi_context = {
		.lock_flags = 0
	};
	uint32_t function_index;

	TEST_START;

	firmware_update_observer_tdisp_testing_init_dependencies (test, &observer);

	for (function_index = 0; function_index < 3; function_index++) {
		status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
			&observer.tdisp, 0, MOCK_ARG (function_index), MOCK_ARG_NOT_NULL);
		status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_locked,
			sizeof (tdi_hw_state_locked), -1);
		CuAssertIntEquals (test, 0, status);

		status = mock_expect (&observer.tdi_context.mock, observer.tdi_context.base.get_tdi_context,
			&observer.tdi_context, 0, MOCK_ARG (function_index),
			MOCK_ARG (TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS), MOCK_ARG_NOT_NULL);
		status |= mock_expect_output (&observer.tdi_context.mock, 2, &tdi_context,
			sizeof (tdi_context), -1);
		CuAssertIntEquals (test, 0, status);
	}

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 0, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_get_device_interface_state_failed
(
	CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;
	int update_allowed = 0;
	uint8_t tdi_hw_state_unlocked = TDISP_TDI_STATE_CONFIG_UNLOCKED;

	TEST_START;

	firmware_update_observer_tdisp_testing_init (test, &observer, 2);

	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, TDISP_DRIVER_GET_DEVICE_INTERFACE_STATE_FAILED, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	/* Mock an additional function index check to ensure the previous error does not prevent other
	 * TDI contexts from being checked. */
	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_unlocked,
		sizeof (tdi_hw_state_unlocked), -1);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 0, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}

static void firmware_update_observer_tdisp_test_on_prepare_update_get_tdi_context_failed (
	CuTest *test)
{
	struct firmware_update_observer_tdisp_testing observer;
	int status;
	int update_allowed = 0;
	uint8_t tdi_hw_state_run = TDISP_TDI_STATE_RUN;
	struct tdisp_tdi_context tdi_context = {
		.lock_flags = 0
	};

	TEST_START;

	firmware_update_observer_tdisp_testing_init (test, &observer, 2);

	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_run,
		sizeof (tdi_hw_state_run), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.tdi_context.mock, observer.tdi_context.base.get_tdi_context,
		&observer.tdi_context, TDISP_TDI_CONTEXT_MANAGER_GET_TDI_CONTEXT_FAILED, MOCK_ARG (0),
		MOCK_ARG (TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	/* Mock an additional function index check to ensure the previous error does not prevent other
	 * TDI contexts from being checked. */
	status = mock_expect (&observer.tdisp.mock, observer.tdisp.base.get_device_interface_state,
		&observer.tdisp, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdisp.mock, 1, &tdi_hw_state_run,
		sizeof (tdi_hw_state_run), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.tdi_context.mock, observer.tdi_context.base.get_tdi_context,
		&observer.tdi_context, 0, MOCK_ARG (1),	MOCK_ARG (TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&observer.tdi_context.mock, 2, &tdi_context, sizeof (tdi_context),
		-1);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_prepare_update (&observer.test.base, &update_allowed);
	CuAssertIntEquals (test, 0, update_allowed);

	firmware_update_observer_tdisp_testing_release (test, &observer);
}


// *INDENT-OFF*
TEST_SUITE_START (firmware_update_observer_tdisp);

TEST (firmware_update_observer_tdisp_test_init);
TEST (firmware_update_observer_tdisp_test_init_null);
TEST (firmware_update_observer_tdisp_test_static_init);
TEST (firmware_update_observer_tdisp_test_release_null);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_allowed_state);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_allowed_lock_flag);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_not_allowed);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_other_context_disallowed);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_static_init);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_get_device_interface_state_failed);
TEST (firmware_update_observer_tdisp_test_on_prepare_update_get_tdi_context_failed);

TEST_SUITE_END;
// *INDENT-ON*
