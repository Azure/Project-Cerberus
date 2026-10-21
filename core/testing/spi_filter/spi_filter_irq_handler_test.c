// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/spi_flash.h"
#include "host_fw/host_state_manager.h"
#include "spi_filter/spi_filter_irq_handler.h"
#include "spi_filter/spi_filter_irq_handler_static.h"
#include "state_manager/state_manager.h"
#include "testing/host_fw/host_state_manager_testing.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"


TEST_SUITE_LABEL ("spi_filter_irq_handler");


/*******************
 * Test cases
 *******************/

static void spi_filter_irq_handler_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_context, &flash,
		true);

	status = spi_filter_irq_handler_init (&handler, &host_state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.ro_flash_dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
}

static void spi_filter_irq_handler_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_context, &flash,
		true);

	status = spi_filter_irq_handler_init (NULL, &host_state);
	CuAssertIntEquals (test, SPI_FILTER_IRQ_INVALID_ARGUMENT, status);

	status = spi_filter_irq_handler_init (&handler, NULL);
	CuAssertIntEquals (test, SPI_FILTER_IRQ_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
}

static void spi_filter_irq_handler_test_static_init (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler = spi_filter_irq_handler_static_init (&host_state);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, handler.ro_flash_dirty);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_context, &flash,
		true);

	spi_filter_irq_handler_release (&handler);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
}

static void spi_filter_irq_handler_test_release_null (CuTest *test)
{
	TEST_START;

	spi_filter_irq_handler_release (NULL);
}

static void spi_filter_irq_handler_test_ro_flash_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_context, &flash,
		true);

	status = spi_filter_irq_handler_init (&handler, &host_state);
	CuAssertIntEquals (test, 0, status);

	handler.ro_flash_dirty (&handler);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
}

static void spi_filter_irq_handler_test_ro_flash_dirty_static_init (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler = spi_filter_irq_handler_static_init (&host_state);
	int status;

	TEST_START;

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_context, &flash,
		true);

	handler.ro_flash_dirty (&handler);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
}

static void spi_filter_irq_handler_test_ro_flash_dirty_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_context, &flash,
		true);

	status = spi_filter_irq_handler_init (&handler, &host_state);
	CuAssertIntEquals (test, 0, status);

	handler.ro_flash_dirty (NULL);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
}


// *INDENT-OFF*
TEST_SUITE_START (spi_filter_irq_handler);

TEST (spi_filter_irq_handler_test_init);
TEST (spi_filter_irq_handler_test_init_null);
TEST (spi_filter_irq_handler_test_static_init);
TEST (spi_filter_irq_handler_test_release_null);
TEST (spi_filter_irq_handler_test_ro_flash_dirty);
TEST (spi_filter_irq_handler_test_ro_flash_dirty_static_init);
TEST (spi_filter_irq_handler_test_ro_flash_dirty_null);

TEST_SUITE_END;
// *INDENT-ON*
