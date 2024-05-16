// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_SINGLE_FULL_BYPASS_TESTING_H_
#define HOST_PROCESSOR_SINGLE_FULL_BYPASS_TESTING_H_

#include "host_fw/host_fw_util.h"
#include "host_fw/host_processor_single_full_bypass.h"
#include "host_fw/host_state_manager.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/host_fw/host_flash_manager_single_mock.h"
#include "testing/mock/host_fw/host_processor_observer_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/pfm/pfm_manager_mock.h"
#include "testing/mock/manifest/pfm/pfm_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"


/**
 * Dependencies for testing.
 */
struct host_processor_single_full_bypass_testing {
	HASH_TESTING_ENGINE hash;							/**< Hash engine for API arguments. */
	RSA_TESTING_ENGINE rsa;								/**< RSA engine for API arguments. */
	struct flash_master_mock flash_mock_state;			/**< Flash mock for host state information. */
	struct spi_flash_state flash_context;				/**< Host state flash context. */
	struct spi_flash flash_state;						/**< Host state flash. */
	struct host_state_manager host_state;				/**< Host state manager. */
	struct spi_filter_interface_mock filter;			/**< Mock for the SPI filter. */
	struct host_flash_manager_single_mock flash_mgr;	/**< Mock for flash management. */
	struct host_control_mock control;					/**< Mock for host control. */
	struct pfm_manager_mock pfm_mgr;					/**< Mock for PFM management. */
	struct pfm_mock pfm;								/**< Mock for a valid PFM. */
	struct pfm_mock pfm_next;							/**< Mock for a valid pending PFM. */
	struct host_processor_observer_mock observer;		/**< Mock for host notifications. */
	struct host_processor_filtered test;				/**< Host instance being tested. */
	struct logging_mock logger;							/**< Mock for debug logging. */
};


void host_processor_single_full_bypass_testing_init_dependencies (CuTest *test,
	struct host_processor_single_full_bypass_testing *host);
void host_processor_single_full_bypass_testing_init_reset_flash (CuTest *test,
	struct host_processor_single_full_bypass_testing *host);
void host_processor_single_full_bypass_testing_init_reset_flash_pulse_reset (CuTest *test,
	struct host_processor_single_full_bypass_testing *host);

void host_processor_single_full_bypass_testing_validate_and_release (CuTest *test,
	struct host_processor_single_full_bypass_testing *host);


#endif	/* HOST_PROCESSOR_SINGLE_FULL_BYPASS_TESTING_H_ */
