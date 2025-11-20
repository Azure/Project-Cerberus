// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_DUAL_TESTING_H_
#define HOST_PROCESSOR_DUAL_TESTING_H_

#include "testing.h"
#include "flash/spi_flash.h"
#include "host_fw/host_processor_dual.h"
#include "host_fw/host_processor_dual_static.h"
#include "host_fw/host_state_manager.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/host_fw/host_flash_manager_dual_mock.h"
#include "testing/mock/host_fw/host_processor_observer_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/pfm/pfm_manager_mock.h"
#include "testing/mock/manifest/pfm/pfm_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"


/**
 * Dependencies for testing.
 */
struct host_processor_dual_testing {
	HASH_TESTING_ENGINE (hash);								/**< Hash engine for API arguments. */
	RSA_TESTING_ENGINE (rsa);								/**< RSA engine for API arguments. */
	struct flash_master_mock flash_mock_state;				/**< Flash mock for host state information. */
	struct spi_flash_state flash_context;					/**< Host state flash context. */
	struct spi_flash flash_state;							/**< Host state flash. */
	struct host_state_manager_state host_state_context;		/**< Host state manager context. */
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
	struct host_processor_filtered_state state;				/**< Variable context for the host instance. */
	struct host_processor_filtered test;					/**< Host instance being tested. */
	struct logging_mock logger;								/**< Mock for debug logging. */
};

/**
 * Container for the calling context of flash_manager actions.
 */
struct host_processor_dual_testing_flash_mgr_action {
	bool override;								/**< Expected state of the RO flash override flag. */
	spi_filter_cs ro;							/**< Expected state of the RO flash device. */
	spi_filter_cs nv_ro;						/**< Expected state of the non-volatile RO flash device. */
	bool used_pending;							/**< Indicate if a pending PFM is activated. */
	struct host_processor_dual_testing *host;	/**< Testing dependencies. */
	CuTest *test;								/**< Test case instance. */
};


void host_processor_dual_testing_init_dependencies (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_release_dependencies (CuTest *test,
	struct host_processor_dual_testing *host);

void host_processor_dual_testing_init (CuTest *test, struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_reset_flash (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_reset_flash_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_no_recovery (CuTest *test,
	struct host_processor_dual_testing *host);
void host_processor_dual_testing_init_no_recovery_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host);

void host_processor_dual_testing_init_static (CuTest *test,
	struct host_processor_dual_testing *host);

void host_processor_dual_testing_validate_and_release (CuTest *test,
	struct host_processor_dual_testing *host);

void host_processor_dual_testing_init_host_state (CuTest *test, struct host_state_manager *state,
	struct host_state_manager_state *state_ctx, struct flash_master_mock *flash_mock,
	struct spi_flash *flash, struct spi_flash_state *flash_state);

int host_processor_dual_testing_expect_filtered_bypass_mode (
	struct host_processor_dual_testing *host, spi_filter_cs ro_cs);
void host_processor_dual_testing_log_filter_config (CuTest *test,
	struct host_processor_dual_testing *host);

int64_t host_processor_dual_testing_validate_read_only_flash (const struct mock_call *expected,
	const struct mock_call *called);
int64_t host_processor_dual_testing_validate_read_write_flash (const struct mock_call *expected,
	const struct mock_call *called);
int64_t host_processor_dual_testing_get_flash_read_write_regions (const struct mock_call *expected,
	const struct mock_call *called);
int64_t host_processor_dual_testing_initialize_flash_protection (const struct mock_call *expected,
	const struct mock_call *called);
int64_t host_processor_dual_testing_swap_flash_devices (const struct mock_call *expected,
	const struct mock_call *called);
int64_t host_processor_dual_testing_activate_pending_manifest (const struct mock_call *expected,
	const struct mock_call *called);


#endif	/* HOST_PROCESSOR_DUAL_TESTING_H_ */
