// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_ALL_TESTS_H_
#define FLASH_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'flash' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_flash_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_FLASH_COMMON_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FLASH_COMMON_SUITE
	TESTING_RUN_SUITE (flash_common);
#endif
#if (defined TESTING_RUN_FLASH_STORE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FLASH_STORE_SUITE
	TESTING_RUN_SUITE (flash_store);
#endif
#if (defined TESTING_RUN_FLASH_STORE_ENCRYPTED_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FLASH_STORE_ENCRYPTED_SUITE
	TESTING_RUN_SUITE (flash_store_encrypted);
#endif
#if (defined TESTING_RUN_FLASH_UPDATER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FLASH_UPDATER_SUITE
	TESTING_RUN_SUITE (flash_updater);
#endif
#if (defined TESTING_RUN_FLASH_UTIL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FLASH_UTIL_SUITE
	TESTING_RUN_SUITE (flash_util);
#endif
#if (defined TESTING_RUN_SPI_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPI_FLASH_SUITE
	TESTING_RUN_SUITE (spi_flash);
#endif
#if (defined TESTING_RUN_SPI_FLASH_SFDP_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPI_FLASH_SFDP_SUITE
	TESTING_RUN_SUITE (spi_flash_sfdp);
#endif
}


#endif /* FLASH_ALL_TESTS_H_ */
