// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_ALL_TESTS_H_
#define SPI_FILTER_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'spi_filter' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_spi_filter_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_SPI_FILTER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPI_FILTER_SUITE
	TESTING_RUN_SUITE (spi_filter);
#endif
#if (defined TESTING_RUN_SPI_FILTER_IRQ_HANDLER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPI_FILTER_IRQ_HANDLER_SUITE
	TESTING_RUN_SUITE (spi_filter_irq_handler);
#endif
#if (defined TESTING_RUN_SPI_FILTER_IRQ_HANDLER_DIRTY_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPI_FILTER_IRQ_HANDLER_DIRTY_SUITE
	TESTING_RUN_SUITE (spi_filter_irq_handler_dirty);
#endif
}


#endif /* SPI_FILTER_ALL_TESTS_H_ */
