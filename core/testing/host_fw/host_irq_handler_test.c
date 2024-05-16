// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "host_irq_handler_testing.h"
#include "testing.h"
#include "host_fw/host_irq_handler_static.h"
#include "host_fw/host_logging.h"
#include "logging/debug_log.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("host_irq_handler");


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_testing_init_dependencies (CuTest *test,
	struct host_irq_handler_testing *host)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&host->hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&host->rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host->host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&host->recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&host->irq);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&host->logger);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host interrupt handler for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_testing_init (CuTest *test, struct host_irq_handler_testing *host)
{
	int status;

	host_irq_handler_testing_init_dependencies (test, host);

	status = host_irq_handler_init (&host->test, &host->host.base, &host->hash.base,
		&host->rsa.base, &host->recovery.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host interrupt handler without recovery for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_irq_handler_testing_init_no_recovery (CuTest *test, struct host_irq_handler_testing *host)
{
	int status;

	host_irq_handler_testing_init_dependencies (test, host);

	status = host_irq_handler_init (&host->test, &host->host.base, &host->hash.base,
		&host->rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release testing dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_irq_handler_testing_release_dependencies (CuTest *test,
	struct host_irq_handler_testing *host)
{
	int status;

	status = host_processor_mock_validate_and_release (&host->host);
	status |= bmc_recovery_mock_validate_and_release (&host->recovery);
	status |= host_irq_control_mock_validate_and_release (&host->irq);
	status |= logging_mock_validate_and_release (&host->logger);

	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&host->hash);
	RSA_TESTING_ENGINE_RELEASE (&host->rsa);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_irq_handler_testing_validate_and_release (CuTest *test,
	struct host_irq_handler_testing *host)
{
	host_irq_handler_release (&host->test);

	host_irq_handler_testing_release_dependencies (test, host);
}


/*******************
 * Test cases
 *******************/

static void host_irq_handler_test_init (CuTest *test)
{
	struct host_irq_handler_testing handler;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	CuAssertPtrNotNull (test, handler.test.power_on);
	CuAssertPtrNotNull (test, handler.test.enter_reset);
	CuAssertPtrNotNull (test, handler.test.exit_reset);
	CuAssertPtrNotNull (test, handler.test.assert_cs0);
	CuAssertPtrNotNull (test, handler.test.assert_cs1);
	CuAssertPtrNotNull (test, handler.test.force_recovery);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_init_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;

	TEST_START;

	host_irq_handler_testing_init_no_recovery (test, &handler);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_init_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_init (NULL, &handler.host.base, &handler.hash.base, &handler.rsa.base,
		&handler.recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init (&handler.test, NULL, &handler.hash.base, &handler.rsa.base,
		&handler.recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init (&handler.test, &handler.host.base, NULL, &handler.rsa.base,
		&handler.recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init (&handler.test, &handler.host.base, &handler.hash.base, NULL,
		&handler.recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrNotNull (test, test_static.power_on);
	CuAssertPtrNotNull (test, test_static.enter_reset);
	CuAssertPtrNotNull (test, test_static.exit_reset);
	CuAssertPtrNotNull (test, test_static.assert_cs0);
	CuAssertPtrNotNull (test, test_static.assert_cs1);
	CuAssertPtrNotNull (test, test_static.force_recovery);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, NULL);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static_null_host = host_irq_handler_static_init (NULL,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	struct host_irq_handler test_static_null_hash =
		host_irq_handler_static_init (&handler.host.base, NULL, &handler.rsa.base,
		&handler.recovery.base);
	struct host_irq_handler test_static_null_rsa = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, NULL, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_config_interrupts (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_host);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_hash);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_rsa);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_release (&test_static_null_host);
	host_irq_handler_release (&test_static_null_hash);
	host_irq_handler_release (&test_static_null_rsa);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_init_with_irq_ctrl (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_init_with_irq_ctrl (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.power_on);
	CuAssertPtrNotNull (test, handler.test.enter_reset);
	CuAssertPtrNotNull (test, handler.test.exit_reset);
	CuAssertPtrNotNull (test, handler.test.assert_cs0);
	CuAssertPtrNotNull (test, handler.test.assert_cs1);
	CuAssertPtrNotNull (test, handler.test.force_recovery);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_init_with_irq_ctrl_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_init_with_irq_ctrl (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, NULL, &handler.irq.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_init_with_irq_ctrl_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_init_with_irq_ctrl (NULL, &handler.host.base, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_with_irq_ctrl (&handler.test, NULL, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_with_irq_ctrl (&handler.test, &handler.host.base, NULL,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_with_irq_ctrl (&handler.test, &handler.host.base,
		&handler.hash.base, NULL, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_with_irq_ctrl (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_with_irq_ctrl (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init_irq_ctrl (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrNotNull (test, test_static.power_on);
	CuAssertPtrNotNull (test, test_static.enter_reset);
	CuAssertPtrNotNull (test, test_static.exit_reset);
	CuAssertPtrNotNull (test, test_static.assert_cs0);
	CuAssertPtrNotNull (test, test_static.assert_cs1);
	CuAssertPtrNotNull (test, test_static.force_recovery);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_with_irq_ctrl_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init_irq_ctrl (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, NULL, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_with_irq_ctrl_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static_null_host = host_irq_handler_static_init_irq_ctrl (NULL,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	struct host_irq_handler test_static_null_hash =
		host_irq_handler_static_init_irq_ctrl (&handler.host.base, NULL, &handler.rsa.base,
		&handler.recovery.base, &handler.irq.base);
	struct host_irq_handler test_static_null_rsa =
		host_irq_handler_static_init_irq_ctrl (&handler.host.base, &handler.hash.base, NULL,
		&handler.recovery.base, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_config_interrupts (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_host);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_hash);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_rsa);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_release (&test_static_null_host);
	host_irq_handler_release (&test_static_null_hash);
	host_irq_handler_release (&test_static_null_rsa);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_init_enable_exit_reset (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (true));
	status |= mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.power_on);
	CuAssertPtrNotNull (test, handler.test.enter_reset);
	CuAssertPtrNotNull (test, handler.test.exit_reset);
	CuAssertPtrNotNull (test, handler.test.assert_cs0);
	CuAssertPtrNotNull (test, handler.test.assert_cs1);
	CuAssertPtrNotNull (test, handler.test.force_recovery);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_init_enable_exit_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (true));
	status |= mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, NULL, &handler.irq.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_init_enable_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_init_enable_exit_reset (NULL, &handler.host.base, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, NULL, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base, NULL,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base,
		&handler.hash.base, NULL, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_init_enable_exit_reset_irq_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq,
		HOST_IRQ_CTRL_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, HOST_IRQ_CTRL_EXIT_RESET_FAILED, status);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_enable_exit_reset (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (true));
	status |= mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, test_static.power_on);
	CuAssertPtrNotNull (test, test_static.enter_reset);
	CuAssertPtrNotNull (test, test_static.exit_reset);
	CuAssertPtrNotNull (test, test_static.assert_cs0);
	CuAssertPtrNotNull (test, test_static.assert_cs1);
	CuAssertPtrNotNull (test, test_static.force_recovery);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_enable_exit_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, &handler.hash.base,
		&handler.rsa.base, NULL, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (true));
	status |= mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_enable_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static_null_host =
		host_irq_handler_static_init_enable_exit_reset (NULL, &handler.hash.base, &handler.rsa.base,
		&handler.recovery.base, &handler.irq.base);
	struct host_irq_handler test_static_null_hash =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, NULL, &handler.rsa.base,
		&handler.recovery.base, &handler.irq.base);
	struct host_irq_handler test_static_null_rsa =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, &handler.hash.base,
		NULL, &handler.recovery.base, &handler.irq.base);
	struct host_irq_handler test_static_null_irq_ctrl =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, NULL);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_irq_handler_config_interrupts (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_host);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_hash);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_rsa);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_config_interrupts (&test_static_null_irq_ctrl);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));
	status |= mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));
	status |= mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static_null_host);
	host_irq_handler_release (&test_static_null_hash);
	host_irq_handler_release (&test_static_null_rsa);
	host_irq_handler_release (&test_static_null_irq_ctrl);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_static_init_enable_exit_reset_irq_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq,
		HOST_IRQ_CTRL_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, HOST_IRQ_CTRL_EXIT_RESET_FAILED, status);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);

	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_release_null (CuTest *test)
{
	TEST_START;

	host_irq_handler_release (NULL);
}

static void host_irq_handler_test_release_irq_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init_enable_exit_reset (&handler.test, &handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq,
		HOST_IRQ_CTRL_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_release_irq_error_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static =
		host_irq_handler_static_init_enable_exit_reset (&handler.host.base, &handler.hash.base,
		&handler.rsa.base, &handler.recovery.base, &handler.irq.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_config_interrupts (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.irq.mock, handler.irq.base.enable_exit_reset, &handler.irq,
		HOST_IRQ_CTRL_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_enter_reset (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_reset,
		&handler.recovery, 0);
	status |= mock_expect (&handler.host.mock, handler.host.base.soft_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.enter_reset (&handler.test);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_enter_reset_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_reset,
		&handler.recovery, 0);
	status |= mock_expect (&handler.host.mock, handler.host.base.soft_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = test_static.enter_reset (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_enter_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_no_recovery (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.soft_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.enter_reset (&handler.test);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_enter_reset_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = handler.test.enter_reset (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_enter_reset_host_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_reset,
		&handler.recovery, 0);
	status |= mock_expect (&handler.host.mock, handler.host.base.soft_reset, &handler.host,
		HOST_PROCESSOR_SOFT_RESET_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.enter_reset (&handler.test);
	CuAssertIntEquals (test, HOST_PROCESSOR_SOFT_RESET_FAILED, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_exit_reset (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_out_of_reset,
		&handler.recovery, 0);
	CuAssertIntEquals (test, 0, status);

	handler.test.exit_reset (&handler.test);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_exit_reset_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_out_of_reset,
		&handler.recovery, 0);
	CuAssertIntEquals (test, 0, status);

	test_static.exit_reset (&test_static);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_exit_reset_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;

	TEST_START;

	host_irq_handler_testing_init_no_recovery (test, &handler);

	handler.test.exit_reset (&handler.test);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_exit_reset_null (CuTest *test)
{
	struct host_irq_handler_testing handler;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	handler.test.exit_reset (NULL);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs0 (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_cs0,
		&handler.recovery, 0);
	CuAssertIntEquals (test, 0, status);

	handler.test.assert_cs0 (&handler.test);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs0_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_cs0,
		&handler.recovery, 0);
	CuAssertIntEquals (test, 0, status);

	test_static.assert_cs0 (&test_static);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_assert_cs0_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;

	TEST_START;

	host_irq_handler_testing_init_no_recovery (test, &handler);

	handler.test.assert_cs0 (&handler.test);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs0_null (CuTest *test)
{
	struct host_irq_handler_testing handler;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	handler.test.assert_cs0 (NULL);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs1 (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_cs1,
		&handler.recovery, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.assert_cs1 (&handler.test);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs1_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_cs1,
		&handler.recovery, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = test_static.assert_cs1 (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_assert_cs1_no_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init_no_recovery (test, &handler);

	status = handler.test.assert_cs1 (&handler.test);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs1_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = handler.test.assert_cs1 (NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_assert_cs1_recovery_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_cs1,
		&handler.recovery, BMC_RECOVERY_CS1_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.assert_cs1 (&handler.test);
	CuAssertIntEquals (test, BMC_RECOVERY_CS1_FAILED, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = test_static.power_on (&test_static, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_power_on_alternate_hash (CuTest *test)
{
	struct host_irq_handler_testing handler;
	HASH_TESTING_ENGINE hash2;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = HASH_TESTING_ENGINE_INIT (&hash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, &hash2.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);

	HASH_TESTING_ENGINE_RELEASE (&hash2);
}

static void host_irq_handler_test_power_on_validation_fail (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_blank_fail (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_unknown_version (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback_alternate_hash (CuTest *test)
{
	struct host_irq_handler_testing handler;
	HASH_TESTING_ENGINE hash2;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = HASH_TESTING_ENGINE_INIT (&hash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host, 0,
		MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, &hash2.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);

	HASH_TESTING_ENGINE_RELEASE (&hash2);
}

static void host_irq_handler_test_power_on_flash_rollback_validation_fail (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback_blank_fail (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback_unknown_version (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback_no_rollback (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_NO_ROLLBACK, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_flash_rollback_rollback_dirty (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_DIRTY, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image_alternate_hash (CuTest *test)
{
	struct host_irq_handler_testing handler;
	HASH_TESTING_ENGINE hash2;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = HASH_TESTING_ENGINE_INIT (&hash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&hash2), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, &hash2.base);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);

	HASH_TESTING_ENGINE_RELEASE (&hash2);
}

static void host_irq_handler_test_power_on_apply_recovery_image_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image_retry_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image_unsupported (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image_no_image (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_NO_RECOVERY_IMAGE, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, false, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_RECOVERY_IMAGE, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image_unsupported_allow_unsecure (
	CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, true, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_apply_recovery_image_no_image_allow_unsecure (
	CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_NO_RECOVERY_IMAGE, MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, true, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_bypass_mode (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, true, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_bypass_mode_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host,
		HOST_PROCESSOR_BYPASS_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host, 0,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, true, NULL);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_bypass_mode_retry_error (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	status |= mock_expect (&handler.host.mock, handler.host.base.power_on_reset, &handler.host,
		HOST_PROCESSOR_POR_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.flash_rollback, &handler.host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa),
		MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host,
		HOST_PROCESSOR_BYPASS_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.bypass_mode, &handler.host,
		HOST_PROCESSOR_BYPASS_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.power_on (&handler.test, true, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_BYPASS_FAILED, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_power_on_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = handler.test.power_on (NULL, false, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_set_host (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_processor_mock host_new;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = host_processor_mock_init (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_set_host (&handler.test, &host_new.base);
	CuAssertIntEquals (test, 0, status);

	/* Check that the new instance will be called in response to an event. */
	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_reset,
		&handler.recovery, 0);
	status |= mock_expect (&host_new.mock, host_new.base.soft_reset, &host_new, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.enter_reset (&handler.test);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_new);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_set_host_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	struct host_processor_mock host_new;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_processor_mock_init (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_set_host (&test_static, &host_new.base);
	CuAssertIntEquals (test, 0, status);

	/* Check that the new instance will be called in response to an event. */
	status = mock_expect (&handler.recovery.mock, handler.recovery.base.on_host_reset,
		&handler.recovery, 0);
	status |= mock_expect (&host_new.mock, host_new.base.soft_reset, &host_new, 0,
		MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	status = test_static.enter_reset (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_new);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_set_host_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_processor_mock host_new;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = host_processor_mock_init (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_set_host (NULL, &host_new.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_set_host (&handler.test, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host_new);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_set_host_null_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	struct host_processor_mock host_new;
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = host_processor_mock_init (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_set_host (NULL, &host_new.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_set_host (&test_static, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host_new);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_force_recovery (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image, &handler.host,
		0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.force_recovery (&handler.test);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_force_recovery_static_init (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct host_irq_handler test_static = host_irq_handler_static_init (&handler.host.base,
		&handler.hash.base, &handler.rsa.base, &handler.recovery.base);
	int status;

	TEST_START;

	host_irq_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image, &handler.host,
		0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = test_static.force_recovery (&test_static);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&test_static);
	host_irq_handler_testing_release_dependencies (test, &handler);
}

static void host_irq_handler_test_force_recovery_img_failed (CuTest *test)
{
	struct host_irq_handler_testing handler;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_RECOVERY_RETRIES,
		.arg1 = 1,
		.arg2 = 4
	};
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	host_processor_set_port (&handler.host.base, 1);

	status = mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image, &handler.host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image,
		&handler.host, 0, MOCK_ARG (true));
	status |= mock_expect (&handler.logger.mock, handler.logger.base.create_entry, &handler.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &handler.logger.base;

	status = handler.test.force_recovery (&handler.test);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_force_recovery_unsupported (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image, &handler.host,
		HOST_PROCESSOR_RECOVERY_UNSUPPORTED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.force_recovery (&handler.test);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_force_recovery_no_image (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.apply_recovery_image, &handler.host,
		HOST_PROCESSOR_NO_RECOVERY_IMAGE, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.force_recovery (&handler.test);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_RECOVERY_IMAGE, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}

static void host_irq_handler_test_force_recovery_null (CuTest *test)
{
	struct host_irq_handler_testing handler;
	int status;

	TEST_START;

	host_irq_handler_testing_init (test, &handler);

	status = handler.test.force_recovery (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	host_irq_handler_testing_validate_and_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (host_irq_handler);

TEST (host_irq_handler_test_init);
TEST (host_irq_handler_test_init_no_recovery);
TEST (host_irq_handler_test_init_null);
TEST (host_irq_handler_test_static_init);
TEST (host_irq_handler_test_static_init_no_recovery);
TEST (host_irq_handler_test_static_init_null);
TEST (host_irq_handler_test_init_with_irq_ctrl);
TEST (host_irq_handler_test_init_with_irq_ctrl_no_recovery);
TEST (host_irq_handler_test_init_with_irq_ctrl_null);
TEST (host_irq_handler_test_static_init_with_irq_ctrl);
TEST (host_irq_handler_test_static_init_with_irq_ctrl_no_recovery);
TEST (host_irq_handler_test_static_init_with_irq_ctrl_null);
TEST (host_irq_handler_test_init_enable_exit_reset);
TEST (host_irq_handler_test_init_enable_exit_reset_no_recovery);
TEST (host_irq_handler_test_init_enable_exit_reset_null);
TEST (host_irq_handler_test_init_enable_exit_reset_irq_error);
TEST (host_irq_handler_test_static_init_enable_exit_reset);
TEST (host_irq_handler_test_static_init_enable_exit_reset_no_recovery);
TEST (host_irq_handler_test_static_init_enable_exit_reset_null);
TEST (host_irq_handler_test_static_init_enable_exit_reset_irq_error);
TEST (host_irq_handler_test_release_null);
TEST (host_irq_handler_test_release_irq_error);
TEST (host_irq_handler_test_release_irq_error_static_init);
TEST (host_irq_handler_test_enter_reset);
TEST (host_irq_handler_test_enter_reset_static_init);
TEST (host_irq_handler_test_enter_reset_no_recovery);
TEST (host_irq_handler_test_enter_reset_null);
TEST (host_irq_handler_test_enter_reset_host_error);
TEST (host_irq_handler_test_exit_reset);
TEST (host_irq_handler_test_exit_reset_static_init);
TEST (host_irq_handler_test_exit_reset_no_recovery);
TEST (host_irq_handler_test_exit_reset_null);
TEST (host_irq_handler_test_assert_cs0);
TEST (host_irq_handler_test_assert_cs0_static_init);
TEST (host_irq_handler_test_assert_cs0_no_recovery);
TEST (host_irq_handler_test_assert_cs0_null);
TEST (host_irq_handler_test_assert_cs1);
TEST (host_irq_handler_test_assert_cs1_static_init);
TEST (host_irq_handler_test_assert_cs1_no_recovery);
TEST (host_irq_handler_test_assert_cs1_null);
TEST (host_irq_handler_test_assert_cs1_recovery_error);
TEST (host_irq_handler_test_power_on);
TEST (host_irq_handler_test_power_on_static_init);
TEST (host_irq_handler_test_power_on_alternate_hash);
TEST (host_irq_handler_test_power_on_validation_fail);
TEST (host_irq_handler_test_power_on_blank_fail);
TEST (host_irq_handler_test_power_on_unknown_version);
TEST (host_irq_handler_test_power_on_error);
TEST (host_irq_handler_test_power_on_flash_rollback);
TEST (host_irq_handler_test_power_on_flash_rollback_alternate_hash);
TEST (host_irq_handler_test_power_on_flash_rollback_validation_fail);
TEST (host_irq_handler_test_power_on_flash_rollback_blank_fail);
TEST (host_irq_handler_test_power_on_flash_rollback_unknown_version);
TEST (host_irq_handler_test_power_on_flash_rollback_error);
TEST (host_irq_handler_test_power_on_flash_rollback_no_rollback);
TEST (host_irq_handler_test_power_on_flash_rollback_rollback_dirty);
TEST (host_irq_handler_test_power_on_apply_recovery_image);
TEST (host_irq_handler_test_power_on_apply_recovery_image_alternate_hash);
TEST (host_irq_handler_test_power_on_apply_recovery_image_error);
TEST (host_irq_handler_test_power_on_apply_recovery_image_retry_error);
TEST (host_irq_handler_test_power_on_apply_recovery_image_unsupported);
TEST (host_irq_handler_test_power_on_apply_recovery_image_no_image);
TEST (host_irq_handler_test_power_on_apply_recovery_image_unsupported_allow_unsecure);
TEST (host_irq_handler_test_power_on_apply_recovery_image_no_image_allow_unsecure);
TEST (host_irq_handler_test_power_on_bypass_mode);
TEST (host_irq_handler_test_power_on_bypass_mode_error);
TEST (host_irq_handler_test_power_on_bypass_mode_retry_error);
TEST (host_irq_handler_test_power_on_null);
TEST (host_irq_handler_test_set_host);
TEST (host_irq_handler_test_set_host_static_init);
TEST (host_irq_handler_test_set_host_null);
TEST (host_irq_handler_test_set_host_null_static_init);
TEST (host_irq_handler_test_force_recovery);
TEST (host_irq_handler_test_force_recovery_static_init);
TEST (host_irq_handler_test_force_recovery_img_failed);
TEST (host_irq_handler_test_force_recovery_unsupported);
TEST (host_irq_handler_test_force_recovery_no_image);
TEST (host_irq_handler_test_force_recovery_null);

TEST_SUITE_END;
// *INDENT-ON*
