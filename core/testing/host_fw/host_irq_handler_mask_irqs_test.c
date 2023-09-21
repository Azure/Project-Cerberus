// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_irq_handler_testing.h"
#include "host_fw/host_irq_handler_mask_irqs.h"
#include "host_fw/host_irq_handler_mask_irqs_static.h"


TEST_SUITE_LABEL ("host_irq_handler_mask_irqs");


/**
 * Dependencies for testing.
 */
struct host_irq_handler_mask_irqs_testing {
	struct host_irq_handler_testing common;			/**< Common host interrupt handler dependencies. */
	struct host_irq_handler_mask_irqs test;			/**< Host interrupt handler under test. */
};


/**
 * Initialize a host interrupt handler that masks notifications for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_mask_irqs_testing_init (CuTest *test,
	struct host_irq_handler_mask_irqs_testing *host)
{
    int status;

	host_irq_handler_testing_init_dependencies (test, &host->common);

	status = host_irq_handler_mask_irqs_init (&host->test, &host->common.host.base,
		&host->common.hash.base, &host->common.rsa.base, &host->common.recovery.base,
		&host->common.irq.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host interrupt handler that masks notifications without recovery for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_mask_irqs_testing_init_no_recovery (CuTest *test,
	struct host_irq_handler_mask_irqs_testing *host)
{
    int status;

	host_irq_handler_testing_init_dependencies (test, &host->common);

	status = host_irq_handler_mask_irqs_init (&host->test, &host->common.host.base,
		&host->common.hash.base, &host->common.rsa.base, NULL, &host->common.irq.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_irq_handler_mask_irqs_testing_validate_and_release (CuTest *test,
	struct host_irq_handler_mask_irqs_testing *host)
{
	host_irq_handler_mask_irqs_release (&host->test);

	host_irq_handler_testing_release_dependencies (test, &host->common);
}


/*******************
 * Test cases
 *******************/

static void host_irq_handler_mask_irqs_test_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	CuAssertPtrNotNull (test, handler.test.base.power_on);
	CuAssertPtrNotNull (test, handler.test.base.enter_reset);
	CuAssertPtrNotNull (test, handler.test.base.exit_reset);
	CuAssertPtrNotNull (test, handler.test.base.assert_cs0);
	CuAssertPtrNotNull (test, handler.test.base.assert_cs1);
	CuAssertPtrNotNull (test, handler.test.base.force_recovery);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_init_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init_no_recovery (test, &handler);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_init_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = host_irq_handler_mask_irqs_init (NULL, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler.test, NULL, &handler.common.hash.base,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler.test, &handler.common.host.base, NULL,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, NULL, &handler.common.recovery.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler.test, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_static_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = host_irq_handler_mask_irqs_static_init (
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	CuAssertPtrNotNull (test, test_static.base.power_on);
	CuAssertPtrNotNull (test, test_static.base.enter_reset);
	CuAssertPtrNotNull (test, test_static.base.exit_reset);
	CuAssertPtrNotNull (test, test_static.base.assert_cs0);
	CuAssertPtrNotNull (test, test_static.base.assert_cs1);
	CuAssertPtrNotNull (test, test_static.base.force_recovery);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_static_init_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = host_irq_handler_mask_irqs_static_init (
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base, NULL,
		&handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_static_init_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static_null_host = 
		host_irq_handler_mask_irqs_static_init (NULL, &handler.common.hash.base,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.common.irq.base);
	struct host_irq_handler_mask_irqs test_static_null_hash = 
		host_irq_handler_mask_irqs_static_init (&handler.common.host.base, NULL,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.common.irq.base);
	struct host_irq_handler_mask_irqs test_static_null_rsa = 
		host_irq_handler_mask_irqs_static_init (&handler.common.host.base,
		&handler.common.hash.base, NULL, &handler.common.recovery.base, &handler.common.irq.base);
	struct host_irq_handler_mask_irqs test_static_null_irq_ctrl = 
		host_irq_handler_mask_irqs_static_init (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base, NULL);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = host_irq_handler_mask_irqs_config_interrupts (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_host.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_hash.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_rsa.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_irq_ctrl.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_init_enable_exit_reset (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
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

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_init_enable_exit_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base, NULL,
		&handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_init_enable_exit_reset_irq_error (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, status);

	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_init_enable_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (NULL, &handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test, NULL,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, NULL, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, &handler.common.hash.base, NULL, &handler.common.recovery.base,
		&handler.common.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_static_init_enable_exit_reset (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, test_static.base.power_on);
	CuAssertPtrNotNull (test, test_static.base.enter_reset);
	CuAssertPtrNotNull (test, test_static.base.exit_reset);
	CuAssertPtrNotNull (test, test_static.base.assert_cs0);
	CuAssertPtrNotNull (test, test_static.base.assert_cs1);
	CuAssertPtrNotNull (test, test_static.base.force_recovery);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_static_init_enable_exit_reset_no_recovery
	(CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, NULL, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_static_init_enable_exit_reset_irq_error (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_static_init_enable_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static_null_host = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (NULL, &handler.common.hash.base,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.common.irq.base);
	struct host_irq_handler_mask_irqs test_static_null_hash = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base, NULL,
		&handler.common.rsa.base, &handler.common.recovery.base, &handler.common.irq.base);
	struct host_irq_handler_mask_irqs test_static_null_rsa = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base,
		&handler.common.hash.base, NULL, &handler.common.recovery.base, &handler.common.irq.base);
	struct host_irq_handler_mask_irqs test_static_null_irq_ctrl = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base, NULL);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = host_irq_handler_mask_irqs_config_interrupts (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_host.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_hash.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_rsa.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static_null_irq_ctrl.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_release_null (CuTest *test)
{
	TEST_START;

	host_irq_handler_mask_irqs_release (NULL);
}

static void host_irq_handler_mask_irqs_test_release_irq_error (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init_enable_exit_reset (&handler.test,
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_release_irq_error_static_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = 
		host_irq_handler_mask_irqs_static_init_enable_exit_reset (&handler.common.host.base,
		&handler.common.hash.base, &handler.common.rsa.base, &handler.common.recovery.base,
		&handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_exit_reset,
		&handler.common.irq, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_enter_reset (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_reset, &handler.common.recovery, 0);
	status |= mock_expect (&handler.common.host.mock, handler.common.host.base.soft_reset,
		&handler.common.host, 0, MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.enter_reset (&handler.test.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_enter_reset_static_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = host_irq_handler_mask_irqs_static_init (
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_reset, &handler.common.recovery, 0);
	status |= mock_expect (&handler.common.host.mock, handler.common.host.base.soft_reset,
		&handler.common.host, 0, MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	status = test_static.base.enter_reset (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_enter_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init_no_recovery (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.host.mock, handler.common.host.base.soft_reset,
		&handler.common.host, 0, MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.enter_reset (&handler.test.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_enter_reset_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = handler.test.base.enter_reset (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_enter_reset_host_error (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_reset, &handler.common.recovery, 0);

	status |= mock_expect (&handler.common.host.mock, handler.common.host.base.soft_reset,
		&handler.common.host, HOST_PROCESSOR_SOFT_RESET_FAILED, MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.enter_reset (&handler.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_SOFT_RESET_FAILED, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_exit_reset (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_out_of_reset, &handler.common.recovery, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.exit_reset (&handler.test.base);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_exit_reset_static_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = host_irq_handler_mask_irqs_static_init (
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.recovery.mock,
		handler.common.recovery.base.on_host_out_of_reset, &handler.common.recovery, 0);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	test_static.base.exit_reset (&test_static.base);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_exit_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init_no_recovery (test, &handler);

	handler.test.base.exit_reset (&handler.test.base);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	handler.test.base.exit_reset (NULL);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs0 (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.recovery.mock, handler.common.recovery.base.on_host_cs0,
		&handler.common.recovery, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.assert_cs0 (&handler.test.base);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs0_static_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = host_irq_handler_mask_irqs_static_init (
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.recovery.mock, handler.common.recovery.base.on_host_cs0,
		&handler.common.recovery, 0);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	test_static.base.assert_cs0 (&test_static.base);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_assert_cs0_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;

	host_irq_handler_mask_irqs_testing_init_no_recovery (test, &handler);

	handler.test.base.assert_cs0 (&handler.test.base);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs0_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	handler.test.base.assert_cs0 (NULL);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs1 (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.recovery.mock, handler.common.recovery.base.on_host_cs1,
		&handler.common.recovery, 0,MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.assert_cs1 (&handler.test.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_static_init (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	struct host_irq_handler_mask_irqs test_static = host_irq_handler_mask_irqs_static_init (
		&handler.common.host.base, &handler.common.hash.base, &handler.common.rsa.base,
		&handler.common.recovery.base, &handler.common.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler.common);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.recovery.mock, handler.common.recovery.base.on_host_cs1,
		&handler.common.recovery, 0, MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_config_interrupts (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	status = test_static.base.assert_cs1 (&test_static.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler.common);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_no_recovery (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init_no_recovery (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));
	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.assert_cs1 (&handler.test.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_null (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = handler.test.base.assert_cs1 (NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_recovery_error (CuTest *test)
{
	struct host_irq_handler_mask_irqs_testing handler;
	int status;

	TEST_START;

	host_irq_handler_mask_irqs_testing_init (test, &handler);

	status = mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (false));

	status |= mock_expect (&handler.common.recovery.mock, handler.common.recovery.base.on_host_cs1,
		&handler.common.recovery, BMC_RECOVERY_CS1_FAILED, MOCK_ARG_PTR (&handler.common.hash),
		MOCK_ARG_PTR (&handler.common.rsa));

	status |= mock_expect (&handler.common.irq.mock, handler.common.irq.base.enable_notifications,
		&handler.common.irq, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.assert_cs1 (&handler.test.base);
	CuAssertIntEquals (test, BMC_RECOVERY_CS1_FAILED, status);

	host_irq_handler_mask_irqs_testing_validate_and_release (test, &handler);
}


TEST_SUITE_START (host_irq_handler_mask_irqs);

TEST (host_irq_handler_mask_irqs_test_init);
TEST (host_irq_handler_mask_irqs_test_init_no_recovery);
TEST (host_irq_handler_mask_irqs_test_init_null);
TEST (host_irq_handler_mask_irqs_test_static_init);
TEST (host_irq_handler_mask_irqs_test_static_init_no_recovery);
TEST (host_irq_handler_mask_irqs_test_static_init_null);
TEST (host_irq_handler_mask_irqs_test_init_enable_exit_reset);
TEST (host_irq_handler_mask_irqs_test_init_enable_exit_reset_no_recovery);
TEST (host_irq_handler_mask_irqs_test_init_enable_exit_reset_irq_error);
TEST (host_irq_handler_mask_irqs_test_init_enable_exit_reset_null);
TEST (host_irq_handler_mask_irqs_test_static_init_enable_exit_reset);
TEST (host_irq_handler_mask_irqs_test_static_init_enable_exit_reset_no_recovery);
TEST (host_irq_handler_mask_irqs_test_static_init_enable_exit_reset_irq_error);
TEST (host_irq_handler_mask_irqs_test_static_init_enable_exit_reset_null);
TEST (host_irq_handler_mask_irqs_test_release_null);
TEST (host_irq_handler_mask_irqs_test_release_irq_error);
TEST (host_irq_handler_mask_irqs_test_release_irq_error_static_init);
TEST (host_irq_handler_mask_irqs_test_enter_reset);
TEST (host_irq_handler_mask_irqs_test_enter_reset_static_init);
TEST (host_irq_handler_mask_irqs_test_enter_reset_no_recovery);
TEST (host_irq_handler_mask_irqs_test_enter_reset_null);
TEST (host_irq_handler_mask_irqs_test_enter_reset_host_error);
TEST (host_irq_handler_mask_irqs_test_exit_reset);
TEST (host_irq_handler_mask_irqs_test_exit_reset_static_init);
TEST (host_irq_handler_mask_irqs_test_exit_reset_no_recovery);
TEST (host_irq_handler_mask_irqs_test_exit_reset_null);
TEST (host_irq_handler_mask_irqs_test_assert_cs0);
TEST (host_irq_handler_mask_irqs_test_assert_cs0_static_init);
TEST (host_irq_handler_mask_irqs_test_assert_cs0_no_recovery);
TEST (host_irq_handler_mask_irqs_test_assert_cs0_null);
TEST (host_irq_handler_mask_irqs_test_assert_cs1);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_static_init);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_no_recovery);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_null);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_recovery_error);

TEST_SUITE_END;
