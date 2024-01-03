// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CORE_ALL_TESTS_H_
#define CORE_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "asn1/asn1_all_tests.h"
#include "attestation/attestation_all_tests.h"
#include "cmd_interface/cmd_interface_all_tests.h"
#include "common/common_all_tests.h"
#include "crypto/crypto_all_tests.h"
#include "firmware/firmware_all_tests.h"
#include "flash/flash_all_tests.h"
#include "host_fw/host_fw_all_tests.h"
#include "intrusion/intrusion_all_tests.h"
#include "keystore/keystore_all_tests.h"
#include "logging/logging_all_tests.h"
#include "manifest/manifest_all_tests.h"
#include "mctp/mctp_all_tests.h"
#include "memory_mgmt/memory_mgmt_all_tests.h"
#include "pcisig/pcisig_all_tests.h"
#include "recovery/recovery_all_tests.h"
#include "riot/riot_all_tests.h"
#include "rma/rma_all_tests.h"
#include "spi_filter/spi_filter_all_tests.h"
#include "state_manager/state_manager_all_tests.h"
#include "system/system_all_tests.h"
#include "tpm/tpm_all_tests.h"


/**
 * Add all tests for platform agnostic components.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
void add_all_core_tests (CuSuite *suite)
{
	add_all_asn1_tests (suite);
	add_all_attestation_tests (suite);
	add_all_cmd_interface_tests (suite);
	add_all_common_tests (suite);
	add_all_crypto_tests (suite);
	add_all_firmware_tests (suite);
	add_all_flash_tests (suite);
	add_all_host_fw_tests (suite);
	add_all_intrusion_tests (suite);
	add_all_keystore_tests (suite);
	add_all_logging_tests (suite);
	add_all_manifest_tests (suite);
	add_all_mctp_tests (suite);
	add_all_memory_mgmt_tests (suite);
	add_all_pcisig_tests (suite);
	add_all_recovery_tests (suite);
	add_all_riot_tests (suite);
	add_all_rma_tests (suite);
	add_all_spi_filter_tests (suite);
	add_all_state_manager_tests (suite);
	add_all_system_tests (suite);
	add_all_tpm_tests (suite);

	/* Test coverage for platform abstractions. */
#if (defined TESTING_RUN_PLATFORM_CLOCK_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PLATFORM_CLOCK_SUITE
	TESTING_RUN_SUITE (platform_clock);
#endif
#if (defined TESTING_RUN_PLATFORM_SEMAPHORE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PLATFORM_SEMAPHORE_SUITE
	TESTING_RUN_SUITE (platform_semaphore);
#endif
#if (defined TESTING_RUN_PLATFORM_TIMER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PLATFORM_TIMER_SUITE
	TESTING_RUN_SUITE (platform_timer);
#endif
}


#endif /* CORE_ALL_TESTS_H_ */
