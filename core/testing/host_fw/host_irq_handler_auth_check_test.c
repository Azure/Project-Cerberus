// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "host_irq_handler_testing.h"
#include "testing.h"
#include "host_fw/host_irq_handler_auth_check.h"
#include "host_fw/host_irq_handler_auth_check_static.h"
#include "host_fw/host_state_manager.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"


TEST_SUITE_LABEL ("host_irq_handler_auth_check");


/**
 * Dependencies for testing.
 */
struct host_irq_handler_auth_check_testing {
	struct host_control_mock control;			/**< Mock for host control. */
	struct host_irq_handler_testing common;		/**< Common host interrupt handler dependencies. */
	struct host_irq_handler_auth_check test;	/**< Host interrupt handler under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_auth_check_testing_init_dependencies (CuTest *test,
	struct host_irq_handler_auth_check_testing *host)
{
	int status;

	host_irq_handler_testing_init_dependencies (test, &host->common);

	status = host_control_mock_init (&host->control);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host interrupt handler that uses notify reset control for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_auth_check_testing_init (CuTest *test,
	struct host_irq_handler_auth_check_testing *host)
{
	int status;

	host_irq_handler_testing_init_dependencies (test, &host->common);

	status = host_irq_handler_auth_check_init (&host->test, &host->common.host.base,
		&host->common.hash.base, &host->common.rsa.base, &host->common.recovery.base,
		&host->control.base, &host->common.irq.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release testing dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_irq_handler_auth_check_testing_release_dependencies (CuTest *test,
	struct host_irq_handler_auth_check_testing *host)
{
	int status;

	status = host_control_mock_validate_and_release (&host->control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_release_dependencies (test, &host->common);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_irq_handler_auth_check_testing_validate_and_release (CuTest *test,
	struct host_irq_handler_auth_check_testing *host)
{
	host_irq_handler_auth_check_release (&host->test);

	host_irq_handler_auth_check_testing_release_dependencies (test, host);
}


/*******************
 * Test cases
 *******************/

static void host_irq_handler_auth_check_test_init (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base.power_on);
	CuAssertPtrNotNull (test, handler.test.base.enter_reset);
	CuAssertPtrNotNull (test, handler.test.base.exit_reset);
	CuAssertPtrNotNull (test, handler.test.base.assert_cs0);
	CuAssertPtrNotNull (test, handler.test.base.assert_cs1);
	CuAssertPtrNotNull (test, handler.test.base.force_recovery);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_auth_check_test_init_no_recovery (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, NULL, &handler.control.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_auth_check_test_init_null (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = host_irq_handler_auth_check_init (NULL, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler.test, NULL, &handler.common.hash.base,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.control.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base, NULL,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.control.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, NULL, &handler.common.recovery.base, &handler.control.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base, NULL,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_init_error_irq (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, status);

	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_static_init (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	struct host_irq_handler_auth_check test_static =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, test_static.base.power_on);
	CuAssertPtrNotNull (test, test_static.base.enter_reset);
	CuAssertPtrNotNull (test, test_static.base.exit_reset);
	CuAssertPtrNotNull (test, test_static.base.assert_cs0);
	CuAssertPtrNotNull (test, test_static.base.assert_cs1);
	CuAssertPtrNotNull (test, test_static.base.force_recovery);

	status = host_irq_handler_auth_check_config_interrupts (&test_static.base, test_static.control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&test_static);
	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_static_init_no_recovery (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	struct host_irq_handler_auth_check test_static =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, NULL, &handler.control.base,
		&handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static.base, test_static.control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&test_static);
	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_static_init_null (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	struct host_irq_handler_auth_check test_static =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	struct host_irq_handler_auth_check test_static_null_host =
		host_irq_handler_auth_check_static_init (NULL, &handler.common.hash.base,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.control.base,
		&handler.common.irq.base);
	struct host_irq_handler_auth_check test_static_null_hash =
		host_irq_handler_auth_check_static_init (&handler.common.host.base, NULL,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.control.base,
		&handler.common.irq.base);
	struct host_irq_handler_auth_check test_static_null_rsa =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, NULL, &handler.common.recovery.base, &handler.control.base,
		&handler.common.irq.base);
	struct host_irq_handler_auth_check test_static_null_host_ctrl =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base, NULL,
		&handler.common.irq.base);
	struct host_irq_handler_auth_check test_static_null_irq_ctrl =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, NULL);
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = host_irq_handler_auth_check_config_interrupts (NULL, test_static.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static_null_host.base,
		test_static_null_host.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static_null_hash.base,
		test_static_null_hash.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static_null_rsa.base,
		test_static_null_rsa.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static_null_host_ctrl.base,
		test_static_null_host_ctrl.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static_null_irq_ctrl.base,
		test_static_null_irq_ctrl.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_static_init_error_irq (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	struct host_irq_handler_auth_check test_static =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static.base, test_static.control);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, status);

	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_release_null (CuTest *test)
{
	TEST_START;

	host_irq_handler_auth_check_release (NULL);
}

static void host_irq_handler_auth_check_test_release_error_irq (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_auth_check_test_release_error_irq_static_init (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	struct host_irq_handler_auth_check test_static =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static.base, test_static.control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&test_static);
	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_exit_reset_no_pending_auth (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_out_of_reset, &handler.common.recovery, 0);
	status |= mock_expect (&handler.common.host.mock,
		handler.common.host.base.get_next_reset_verification_actions, &handler.common.host,
		HOST_PROCESSOR_ACTION_NONE);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.exit_reset (&handler.test.base);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_auth_check_test_exit_reset_no_pending_auth_static_init (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	struct host_irq_handler_auth_check test_static =
		host_irq_handler_auth_check_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_config_interrupts (&test_static.base, test_static.control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_out_of_reset, &handler.common.recovery, 0);
	status |= mock_expect (&handler.common.host.mock,
		handler.common.host.base.get_next_reset_verification_actions, &handler.common.host,
		HOST_PROCESSOR_ACTION_NONE);

	CuAssertIntEquals (test, 0, status);

	test_static.base.exit_reset (&test_static.base);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&test_static);
	host_irq_handler_auth_check_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_auth_check_test_exit_reset_with_pending_auth (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_out_of_reset, &handler.common.recovery, 0);
	status |= mock_expect (&handler.common.host.mock,
		handler.common.host.base.get_next_reset_verification_actions, &handler.common.host,
		HOST_PROCESSOR_ACTION_VERIFY_UPDATE);

	status |= mock_expect (&handler.control.mock, handler.control.base.hold_processor_in_reset,
		&handler.control, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.exit_reset (&handler.test.base);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_auth_check_test_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_auth_check_testing handler;
	int status;

	TEST_START;

	host_irq_handler_auth_check_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.control.base, &handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	handler.test.base.exit_reset (NULL);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_testing_validate_and_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (host_irq_handler_auth_check);

TEST (host_irq_handler_auth_check_test_init);
TEST (host_irq_handler_auth_check_test_init_no_recovery);
TEST (host_irq_handler_auth_check_test_init_null);
TEST (host_irq_handler_auth_check_test_init_error_irq);
TEST (host_irq_handler_auth_check_test_static_init);
TEST (host_irq_handler_auth_check_test_static_init_no_recovery);
TEST (host_irq_handler_auth_check_test_static_init_null);
TEST (host_irq_handler_auth_check_test_static_init_error_irq);
TEST (host_irq_handler_auth_check_test_release_null);
TEST (host_irq_handler_auth_check_test_release_error_irq);
TEST (host_irq_handler_auth_check_test_release_error_irq_static_init);
TEST (host_irq_handler_auth_check_test_exit_reset_no_pending_auth);
TEST (host_irq_handler_auth_check_test_exit_reset_no_pending_auth_static_init);
TEST (host_irq_handler_auth_check_test_exit_reset_with_pending_auth);
TEST (host_irq_handler_auth_check_test_exit_reset_null);

TEST_SUITE_END;
// *INDENT-ON*
