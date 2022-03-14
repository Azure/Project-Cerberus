// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_DUAL_TESTING_H_
#define HOST_PROCESSOR_DUAL_TESTING_H_

#include "testing.h"
#include "host_fw/host_processor_dual.h"
#include "host_fw/host_state_manager.h"
#include "flash/spi_flash.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/host_fw/host_flash_manager_dual_mock.h"
#include "testing/mock/host_fw/host_processor_observer_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"


/**
 * Dependencies for testing.
 */
struct host_processor_dual_testing {
	HASH_TESTING_ENGINE hash;								/**< Hash engine for API arguments. */
	RSA_TESTING_ENGINE rsa;									/**< RSA engine for API arguments. */
	struct flash_master_mock flash_mock_state;				/**< Flash mock for host state information. */
	struct spi_flash_state flash_context;					/**< Host state flash context. */
	struct spi_flash flash_state;							/**< Host state flash. */
	struct host_state_manager host_state;					/**< Host state manager. */
	struct spi_filter_interface_mock filter;				/**< Mock for the SPI filter. */
	struct host_flash_manager_dual_mock flash_mgr;			/**< Mock for flash management. */
	struct host_control_mock control;						/**< Mock for host control. */
	struct pfm_manager_mock pfm_mgr;						/**< Mock for PFM management. */
	struct pfm_mock pfm;									/**< Mock for a valid PFM. */
	struct pfm_mock pfm_next;								/**< Mock for a valid pending PFM. */
	struct recovery_image_manager_mock recovery_manager;	/**< Mock for recovery image management. */
	struct recovery_image_mock image;						/**< Mock for a valid recovery image. */
	struct host_processor_observer_mock observer;			/**< Mock for host notifications. */
	struct host_processor_filtered test;					/**< Host instance being tested. */
};


void host_processor_dual_testing_init (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_no_recovery (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_no_recovery_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host);

void host_processor_dual_testing_validate_and_release (CuTest *test,
	struct host_processor_dual_testing *host);

void host_processor_dual_testing_init_host_state (CuTest *test, struct host_state_manager *state,
	struct flash_master_mock *flash_mock, struct spi_flash *flash,
	struct spi_flash_state *flash_state);


#endif /* HOST_PROCESSOR_DUAL_TESTING_H_ */
