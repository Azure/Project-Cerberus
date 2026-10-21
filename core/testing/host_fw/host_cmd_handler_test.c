// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_cmd_handler.h"
#include "host_fw/host_cmd_handler_static.h"
#include "host_fw/host_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/event_task_mock.h"


TEST_SUITE_LABEL ("host_cmd_handler");


/**
 * Dependencies for testing.
 */
struct host_cmd_handler_testing {
	struct host_processor_mock host;		/**< Mock for the host processor. */
	struct logging_mock log;				/**< Mock for debug logging. */
	struct event_task_mock task;			/**< Mock for the command task. */
	struct event_task_context context;		/**< Event context for event processing. */
	struct event_task_context *context_ptr;	/**< Pointer to the event context. */
	struct host_cmd_handler_state state;	/**< Context for the host command handler. */
	struct host_cmd_handler test;			/**< Host command handler under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void host_cmd_handler_testing_init_dependencies (CuTest *test,
	struct host_cmd_handler_testing *handler)
{
	int status;

	status = host_processor_mock_init (&handler->host);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	memset (&handler->context, 0, sizeof (handler->context));
	handler->context_ptr = &handler->context;

	debug_log = &handler->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void host_cmd_handler_testing_release_dependencies (CuTest *test,
	struct host_cmd_handler_testing *handler)
{
	int status;

	debug_log = NULL;

	status = host_processor_mock_validate_and_release (&handler->host);
	status |= logging_mock_validate_and_release (&handler->log);
	status |= event_task_mock_validate_and_release (&handler->task);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void host_cmd_handler_testing_init (CuTest *test, struct host_cmd_handler_testing *handler)
{
	int status;

	host_cmd_handler_testing_init_dependencies (test, handler);

	status = host_cmd_handler_init (&handler->test, &handler->state, &handler->host.base,
		&handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void host_cmd_handler_testing_init_static (CuTest *test,
	struct host_cmd_handler_testing *handler)
{
	int status;

	host_cmd_handler_testing_init_dependencies (test, handler);

	status = host_cmd_handler_init_state (&handler->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void host_cmd_handler_testing_release (CuTest *test,
	struct host_cmd_handler_testing *handler)
{
	host_cmd_handler_release (&handler->test);

	host_cmd_handler_testing_release_dependencies (test, handler);
}

/*******************
 * Test cases
 *******************/

static void host_cmd_handler_test_init (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;

	TEST_START;

	host_cmd_handler_testing_init_dependencies (test, &handler);

	status = host_cmd_handler_init (&handler.test, &handler.state, &handler.host.base,
		&handler.task.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base_cmd.get_next_host_verification);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_flash_configuration);
	CuAssertPtrNotNull (test, handler.test.base_cmd.set_flash_configuration);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_init_null (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;

	TEST_START;

	host_cmd_handler_testing_init_dependencies (test, &handler);

	status = host_cmd_handler_init (NULL, &handler.state, &handler.host.base, &handler.task.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_cmd_handler_init (&handler.test, NULL, &handler.host.base, &handler.task.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_cmd_handler_init (&handler.test, &handler.state, NULL, &handler.task.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_cmd_handler_init (&handler.test, &handler.state, &handler.host.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_cmd_handler_testing_release_dependencies (test, &handler);
}

static void host_cmd_handler_test_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, handler.test.base_cmd.get_next_host_verification);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_flash_configuration);
	CuAssertPtrNotNull (test, handler.test.base_cmd.set_flash_configuration);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	host_cmd_handler_testing_init_dependencies (test, &handler);

	status = host_cmd_handler_init_state (&handler.test);
	CuAssertIntEquals (test, 0, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_static_init_null (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	struct host_cmd_handler null_state = host_cmd_handler_static_init (NULL, &handler.host.base,
		&handler.task.base);
	struct host_cmd_handler null_host = host_cmd_handler_static_init (&handler.state, NULL,
		&handler.task.base);
	struct host_cmd_handler null_task = host_cmd_handler_static_init (&handler.state,
		&handler.host.base, NULL);
	int status;

	TEST_START;

	host_cmd_handler_testing_init_dependencies (test, &handler);

	status = host_cmd_handler_init_state (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_cmd_handler_init_state (&null_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_cmd_handler_init_state (&null_host);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_cmd_handler_init_state (&null_task);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_cmd_handler_testing_release_dependencies (test, &handler);
}

static void host_cmd_handler_test_release_null (CuTest *test)
{
	TEST_START;

	host_cmd_handler_release (NULL);
}

static void host_cmd_handler_test_get_status (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_status_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	int status;

	TEST_START;

	host_cmd_handler_testing_init_static (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_status_null (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_status (NULL);
	CuAssertIntEquals (test, HOST_CMD_STATUS_UNKNOWN, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_next_host_verification (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	enum host_processor_reset_actions out;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.get_next_reset_verification_actions,
		&handler.host, HOST_PROCESSOR_ACTION_VERIFY_UPDATE);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_next_host_verification (&handler.test.base_cmd, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_UPDATE, out);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_next_host_verification_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	int status;
	enum host_processor_reset_actions out;

	TEST_START;

	host_cmd_handler_testing_init_static (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.get_next_reset_verification_actions,
		&handler.host, HOST_PROCESSOR_ACTION_VERIFY_PFM);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_next_host_verification (&handler.test.base_cmd, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM, out);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_next_host_verification_null (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	enum host_processor_reset_actions out;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_next_host_verification (NULL, &out);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.get_next_host_verification (&handler.test.base_cmd, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_next_host_verification_error (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	enum host_processor_reset_actions out;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.get_next_reset_verification_actions,
		&handler.host, HOST_PROCESSOR_NEXT_ACTIONS_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_next_host_verification (&handler.test.base_cmd, &out);
	CuAssertIntEquals (test, HOST_PROCESSOR_NEXT_ACTIONS_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_flash_configuration (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_BYPASS_CS0;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	int status;
	spi_filter_flash_mode out_mode;
	spi_filter_cs out_current;
	spi_filter_cs out_next;
	enum host_read_only_activation out_apply_next;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.get_flash_config, &handler.host, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler.host.mock, 0, &mode, sizeof (mode), -1);
	status |= mock_expect_output_tmp (&handler.host.mock, 1, &current, sizeof (current), -1);
	status |= mock_expect_output_tmp (&handler.host.mock, 2, &next, sizeof (next), -1);
	status |= mock_expect_output_tmp (&handler.host.mock, 3, &apply_next, sizeof (apply_next), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_flash_configuration (&handler.test.base_cmd, &out_mode,
		&out_current, &out_next, &out_apply_next);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mode, out_mode);
	CuAssertIntEquals (test, current, out_current);
	CuAssertIntEquals (test, next, out_next);
	CuAssertIntEquals (test, apply_next, out_apply_next);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_flash_configuration_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_cs current = SPI_FILTER_CS_1;
	spi_filter_cs next = SPI_FILTER_CS_0;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY;
	int status;
	spi_filter_flash_mode out_mode;
	spi_filter_cs out_current;
	spi_filter_cs out_next;
	enum host_read_only_activation out_apply_next;

	TEST_START;

	host_cmd_handler_testing_init_static (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.get_flash_config, &handler.host, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler.host.mock, 0, &mode, sizeof (mode), -1);
	status |= mock_expect_output_tmp (&handler.host.mock, 1, &current, sizeof (current), -1);
	status |= mock_expect_output_tmp (&handler.host.mock, 2, &next, sizeof (next), -1);
	status |= mock_expect_output_tmp (&handler.host.mock, 3, &apply_next, sizeof (apply_next), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_flash_configuration (&handler.test.base_cmd, &out_mode,
		&out_current, &out_next, &out_apply_next);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mode, out_mode);
	CuAssertIntEquals (test, current, out_current);
	CuAssertIntEquals (test, next, out_next);
	CuAssertIntEquals (test, apply_next, out_apply_next);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_flash_configuration_null (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_flash_mode out_mode;
	spi_filter_cs out_current;
	spi_filter_cs out_next;
	enum host_read_only_activation out_apply_next;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_flash_configuration (NULL, &out_mode, &out_current,
		&out_next, &out_apply_next);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	/* Other arguments are not verified at this layer. */

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_get_flash_configuration_error (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_flash_mode out_mode;
	spi_filter_cs out_current;
	spi_filter_cs out_next;
	enum host_read_only_activation out_apply_next;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.get_flash_config, &handler.host,
		HOST_PROCESSOR_GET_CONFIG_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_flash_configuration (&handler.test.base_cmd, &out_mode,
		&out_current, &out_next, &out_apply_next);
	CuAssertIntEquals (test, HOST_PROCESSOR_GET_CONFIG_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	uint8_t expected[] = {current, next, apply_next};
	int status;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.set_flash_configuration (&handler.test.base_cmd, current, next,
		apply_next);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG, handler.context.action);
	CuAssertIntEquals (test, sizeof (expected), handler.context.buffer_length);

	status = testing_validate_array (expected, handler.context.event_buffer, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_STARTING, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	spi_filter_cs current = SPI_FILTER_CS_1;
	spi_filter_cs next = SPI_FILTER_CS_0;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY;
	uint8_t expected[] = {current, next, apply_next};
	int status;

	TEST_START;

	host_cmd_handler_testing_init_static (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.set_flash_configuration (&handler.test.base_cmd, current, next,
		apply_next);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG, handler.context.action);
	CuAssertIntEquals (test, sizeof (expected), handler.context.buffer_length);

	status = testing_validate_array (expected, handler.context.event_buffer, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_STARTING, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration_null (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	int status;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.set_flash_configuration (NULL, current, next, apply_next);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration_no_task (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.set_flash_configuration (&handler.test.base_cmd, current, next,
		apply_next);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_TASK_NOT_RUNNING, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration_task_busy (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.set_flash_configuration (&handler.test.base_cmd, current, next,
		apply_next);
	CuAssertIntEquals (test, HOST_PROCESSOR_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_NONE_STARTED, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration_get_context_error (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.set_flash_configuration (&handler.test.base_cmd, current, next,
		apply_next);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_INTERNAL_ERROR, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_set_flash_configuration_notify_error (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	int status;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.set_flash_configuration (&handler.test.base_cmd, current, next,
		apply_next);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, HOST_CMD_STATUS_INTERNAL_ERROR, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_set_flash_configuration (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	bool reset = false;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: HOST_CMD_STATUS_START_FLASH_CONFIG */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.host.mock, handler.host.base.config_read_only_flash,
		&handler.host.base, 0, MOCK_ARG_PTR_CONTAINS (&current, sizeof (current)),
		MOCK_ARG_PTR_CONTAINS (&next, sizeof (next)),
		MOCK_ARG_PTR_CONTAINS (&apply_next, sizeof (apply_next)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG;
	handler.context.buffer_length = 3;
	handler.context.event_buffer[0] = current;
	handler.context.event_buffer[1] = next;
	handler.context.event_buffer[2] = apply_next;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_set_flash_configuration_no_current_ro (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_cs next = SPI_FILTER_CS_0;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_ALL;
	bool reset = false;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: HOST_CMD_STATUS_START_FLASH_CONFIG */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.host.mock, handler.host.base.config_read_only_flash,
		&handler.host.base, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_PTR_CONTAINS (&next, sizeof (next)),
		MOCK_ARG_PTR_CONTAINS (&apply_next, sizeof (apply_next)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG;
	handler.context.buffer_length = 3;
	handler.context.event_buffer[0] = 0xff;
	handler.context.event_buffer[1] = next;
	handler.context.event_buffer[2] = apply_next;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_set_flash_configuration_no_next_ro (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_cs current = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY;
	bool reset = false;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: HOST_CMD_STATUS_START_FLASH_CONFIG */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.host.mock, handler.host.base.config_read_only_flash,
		&handler.host.base, 0, MOCK_ARG_PTR_CONTAINS (&current, sizeof (current)),
		MOCK_ARG_PTR (NULL), MOCK_ARG_PTR_CONTAINS (&apply_next, sizeof (apply_next)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG;
	handler.context.buffer_length = 3;
	handler.context.event_buffer[0] = current;
	handler.context.event_buffer[1] = 0xff;
	handler.context.event_buffer[2] = apply_next;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_set_flash_configuration_no_apply_next_ro (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	bool reset = false;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: HOST_CMD_STATUS_START_FLASH_CONFIG */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.host.mock, handler.host.base.config_read_only_flash,
		&handler.host.base, 0, MOCK_ARG_PTR_CONTAINS (&current, sizeof (current)),
		MOCK_ARG_PTR_CONTAINS (&next, sizeof (next)), MOCK_ARG_PTR (NULL));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG;
	handler.context.buffer_length = 3;
	handler.context.event_buffer[0] = current;
	handler.context.event_buffer[1] = next;
	handler.context.event_buffer[2] = 0xff;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_set_flash_configuration_failure (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	bool reset = false;

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: HOST_CMD_STATUS_START_FLASH_CONFIG */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.host.mock, handler.host.base.config_read_only_flash,
		&handler.host.base, HOST_PROCESSOR_CONFIG_RO_FAILED,
		MOCK_ARG_PTR_CONTAINS (&current, sizeof (current)),
		MOCK_ARG_PTR_CONTAINS (&next, sizeof (next)),
		MOCK_ARG_PTR_CONTAINS (&apply_next, sizeof (apply_next)));

	/* Lock for state update: HOST_CMD_STATUS_FLASH_CONFIG_FAILED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG;
	handler.context.buffer_length = 3;
	handler.context.event_buffer[0] = current;
	handler.context.event_buffer[1] = next;
	handler.context.event_buffer[2] = apply_next;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((HOST_PROCESSOR_CONFIG_RO_FAILED & 0x00ffffff) <<
			8) | HOST_CMD_STATUS_FLASH_CONFIG_FAILED), status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_set_flash_configuration_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	int status;
	spi_filter_cs current = SPI_FILTER_CS_0;
	spi_filter_cs next = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;
	bool reset = false;

	TEST_START;

	host_cmd_handler_testing_init_static (test, &handler);

	/* Lock for state update: HOST_CMD_STATUS_START_FLASH_CONFIG */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.host.mock, handler.host.base.config_read_only_flash,
		&handler.host.base, 0, MOCK_ARG_PTR_CONTAINS (&current, sizeof (current)),
		MOCK_ARG_PTR_CONTAINS (&next, sizeof (next)),
		MOCK_ARG_PTR_CONTAINS (&apply_next, sizeof (apply_next)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG;
	handler.context.buffer_length = 3;
	handler.context.event_buffer[0] = current;
	handler.context.event_buffer[1] = next;
	handler.context.event_buffer[2] = apply_next;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_unknown_action (CuTest *test)
{
	struct host_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 2,
		.arg2 = 0x10
	};

	TEST_START;

	host_cmd_handler_testing_init (test, &handler);

	handler.context.action = 0x10;

	host_processor_set_port (&handler.host.base, 2);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: HOST_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((HOST_PROCESSOR_UNSUPPORTED_CMD & 0x00ffffff) << 8) |
			HOST_CMD_STATUS_INTERNAL_ERROR), status);

	host_cmd_handler_testing_release (test, &handler);
}

static void host_cmd_handler_test_execute_unknown_action_static_init (CuTest *test)
{
	struct host_cmd_handler_testing handler = {
		.test =
			host_cmd_handler_static_init (&handler.state, &handler.host.base, &handler.task.base)
	};
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 3,
		.arg2 = 0x20
	};

	TEST_START;

	host_cmd_handler_testing_init_static (test, &handler);

	handler.context.action = 0x20;

	host_processor_set_port (&handler.host.base, 3);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: HOST_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((HOST_PROCESSOR_UNSUPPORTED_CMD & 0x00ffffff) << 8) |
			HOST_CMD_STATUS_INTERNAL_ERROR), status);

	host_cmd_handler_testing_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (host_cmd_handler);

TEST (host_cmd_handler_test_init);
TEST (host_cmd_handler_test_init_null);
TEST (host_cmd_handler_test_static_init);
TEST (host_cmd_handler_test_static_init_null);
TEST (host_cmd_handler_test_release_null);
TEST (host_cmd_handler_test_get_status);
TEST (host_cmd_handler_test_get_status_static_init);
TEST (host_cmd_handler_test_get_status_null);
TEST (host_cmd_handler_test_get_next_host_verification);
TEST (host_cmd_handler_test_get_next_host_verification_static_init);
TEST (host_cmd_handler_test_get_next_host_verification_null);
TEST (host_cmd_handler_test_get_next_host_verification_error);
TEST (host_cmd_handler_test_get_flash_configuration);
TEST (host_cmd_handler_test_get_flash_configuration_static_init);
TEST (host_cmd_handler_test_get_flash_configuration_null);
TEST (host_cmd_handler_test_get_flash_configuration_error);
TEST (host_cmd_handler_test_set_flash_configuration);
TEST (host_cmd_handler_test_set_flash_configuration_static_init);
TEST (host_cmd_handler_test_set_flash_configuration_null);
TEST (host_cmd_handler_test_set_flash_configuration_no_task);
TEST (host_cmd_handler_test_set_flash_configuration_task_busy);
TEST (host_cmd_handler_test_set_flash_configuration_get_context_error);
TEST (host_cmd_handler_test_set_flash_configuration_notify_error);
TEST (host_cmd_handler_test_execute_set_flash_configuration);
TEST (host_cmd_handler_test_execute_set_flash_configuration_no_current_ro);
TEST (host_cmd_handler_test_execute_set_flash_configuration_no_next_ro);
TEST (host_cmd_handler_test_execute_set_flash_configuration_no_apply_next_ro);
TEST (host_cmd_handler_test_execute_set_flash_configuration_failure);
TEST (host_cmd_handler_test_execute_set_flash_configuration_static_init);
TEST (host_cmd_handler_test_execute_unknown_action);
TEST (host_cmd_handler_test_execute_unknown_action_static_init);

TEST_SUITE_END;
// *INDENT-ON*
