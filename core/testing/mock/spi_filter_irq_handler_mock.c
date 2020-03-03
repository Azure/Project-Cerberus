// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "spi_filter_irq_handler_mock.h"


static void spi_filter_irq_handler_mock_ro_flash_dirty (struct spi_filter_irq_handler *handler)
{
	struct spi_filter_irq_handler_mock *mock = (struct spi_filter_irq_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, spi_filter_irq_handler_mock_ro_flash_dirty, handler);
}

static int spi_filter_irq_handler_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* spi_filter_irq_handler_mock_func_name_map (void *func)
{
	if (func == spi_filter_irq_handler_mock_ro_flash_dirty) {
		return "ro_flash_dirty";
	}
	else {
		return "unknown";
	}
}

static const char* spi_filter_irq_handler_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock handler for SPI filter interrupts.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spi_filter_irq_handler_mock_init (struct spi_filter_irq_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spi_filter_irq_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spi_filter_irq_handler");

	mock->base.ro_flash_dirty = spi_filter_irq_handler_mock_ro_flash_dirty;

	mock->mock.func_arg_count = spi_filter_irq_handler_mock_func_arg_count;
	mock->mock.func_name_map = spi_filter_irq_handler_mock_func_name_map;
	mock->mock.arg_name_map = spi_filter_irq_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock IRQ handler.
 *
 * @param mock The mock to release.
 */
void spi_filter_irq_handler_mock_release (struct spi_filter_irq_handler_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify a mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int spi_filter_irq_handler_mock_validate_and_release (struct spi_filter_irq_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spi_filter_irq_handler_mock_release (mock);
	}

	return status;
}
