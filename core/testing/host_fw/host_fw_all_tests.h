// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FW_ALL_TESTS_H_
#define HOST_FW_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'host_fw' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_host_fw_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_BMC_RECOVERY_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BMC_RECOVERY_SUITE
	TESTING_RUN_SUITE (bmc_recovery);
#endif
#if (defined TESTING_RUN_HOST_FLASH_INITIALIZATION_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_FLASH_INITIALIZATION_SUITE
	TESTING_RUN_SUITE (host_flash_initialization);
#endif
#if (defined TESTING_RUN_HOST_FLASH_MANAGER_DUAL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_FLASH_MANAGER_DUAL_SUITE
	TESTING_RUN_SUITE (host_flash_manager_dual);
#endif
#if (defined TESTING_RUN_HOST_FLASH_MANAGER_SINGLE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_FLASH_MANAGER_SINGLE_SUITE
	TESTING_RUN_SUITE (host_flash_manager_single);
#endif
#if (defined TESTING_RUN_HOST_FW_UTIL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_FW_UTIL_SUITE
	TESTING_RUN_SUITE (host_fw_util);
#endif
#if (defined TESTING_RUN_HOST_IRQ_HANDLER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_IRQ_HANDLER_SUITE
	TESTING_RUN_SUITE (host_irq_handler);
#endif
#if (defined TESTING_RUN_HOST_IRQ_HANDLER_AUTH_CHECK_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_IRQ_HANDLER_AUTH_CHECK_SUITE
	TESTING_RUN_SUITE (host_irq_handler_auth_check);
#endif
#if (defined TESTING_RUN_HOST_IRQ_HANDLER_MASK_IRQS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_IRQ_HANDLER_MASK_IRQS_SUITE
	TESTING_RUN_SUITE (host_irq_handler_mask_irqs);
#endif
#if (defined TESTING_RUN_HOST_PROCESSOR_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_PROCESSOR_SUITE
	TESTING_RUN_SUITE (host_processor);
#endif
#if (defined TESTING_RUN_HOST_PROCESSOR_DUAL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_PROCESSOR_DUAL_SUITE
	TESTING_RUN_SUITE (host_processor_dual);
	TESTING_RUN_SUITE (host_processor_dual_power_on_reset);
	TESTING_RUN_SUITE (host_processor_dual_soft_reset);
	TESTING_RUN_SUITE (host_processor_dual_run_time_verification);
	TESTING_RUN_SUITE (host_processor_dual_flash_rollback);
	TESTING_RUN_SUITE (host_processor_dual_recover_active_read_write_data);
	TESTING_RUN_SUITE (host_processor_dual_apply_recovery_image);
	TESTING_RUN_SUITE (host_processor_dual_bypass_mode);
#endif
#if (defined TESTING_RUN_HOST_PROCESSOR_DUAL_FULL_BYPASS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_PROCESSOR_DUAL_FULL_BYPASS_SUITE
	TESTING_RUN_SUITE (host_processor_dual_full_bypass);
#endif
#if (defined TESTING_RUN_HOST_PROCESSOR_OBSERVER_PCR_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_PROCESSOR_OBSERVER_PCR_SUITE
	TESTING_RUN_SUITE (host_processor_observer_pcr);
#endif
#if (defined TESTING_RUN_HOST_PROCESSOR_SINGLE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_PROCESSOR_SINGLE_SUITE
	TESTING_RUN_SUITE (host_processor_single);
	TESTING_RUN_SUITE (host_processor_single_power_on_reset);
	TESTING_RUN_SUITE (host_processor_single_soft_reset);
	TESTING_RUN_SUITE (host_processor_single_run_time_verification);
	TESTING_RUN_SUITE (host_processor_single_flash_rollback);
	TESTING_RUN_SUITE (host_processor_single_recover_active_read_write_data);
	TESTING_RUN_SUITE (host_processor_single_apply_recovery_image);
	TESTING_RUN_SUITE (host_processor_single_bypass_mode);
#endif
#if (defined TESTING_RUN_HOST_PROCESSOR_SINGLE_FULL_BYPASS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_PROCESSOR_SINGLE_FULL_BYPASS_SUITE
	TESTING_RUN_SUITE (host_processor_single_full_bypass);
#endif
#if (defined TESTING_RUN_HOST_STATE_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_STATE_MANAGER_SUITE
	TESTING_RUN_SUITE (host_state_manager);
#endif
#if (defined TESTING_RUN_HOST_STATE_OBSERVER_DIRTY_RESET_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HOST_STATE_OBSERVER_DIRTY_RESET_SUITE
	TESTING_RUN_SUITE (host_state_observer_dirty_reset);
#endif
}


#endif /* HOST_FW_ALL_TESTS_H_ */
