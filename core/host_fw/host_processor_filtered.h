// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_FILTERED_H_
#define HOST_PROCESSOR_FILTERED_H_

#include "platform.h"
#include "host_processor.h"
#include "host_control.h"
#include "host_flash_manager.h"
#include "host_state_manager.h"
#include "spi_filter/spi_filter_interface.h"
#include "manifest/pfm/pfm_manager.h"
#include "recovery/recovery_image_manager.h"


/**
 * Defines the common components and handling used with a host connected to flash through a SPI
 * filter.
 *
 * This is not a stand-alone implementation of the host processor API.  It provides common routines
 * that can be used by a complete implementation.
 */
struct host_processor_filtered {
	struct host_processor base;					/**< Base host processor interface. */
	struct host_control *control;				/**< The interface for hardware control of the host. */
	struct host_flash_manager *flash;			/**< The manager for host processor flash devices. */
	struct host_state_manager *state;			/**< State information for the host processor. */
	struct spi_filter_interface *filter;		/**< The SPI filter connected to host flash devices. */
	struct pfm_manager *pfm;					/**< The manager for host processor PFMs. */
	struct recovery_image_manager *recovery;	/**< The manager for recovery of the host processor. */
	int reset_pulse;							/**< The length of the reset pulse for the host. */
	platform_mutex lock;						/**< Synchronization for verification routines. */

	/**
	 * Private functions for customizing internal flows.
	 */
	struct {
		/**
		 * Configure the SPI filter to run in bypass mode.
		 *
		 * @param host The instance for the processor to run in bypass mode.
		 *
		 * @return 0 if bypass mode was configured successfully or an error code.
		 */
		int (*enable_bypass_mode) (struct host_processor_filtered *host);
	} internal;
};


/* Internal functions for use by derived types. */
int host_processor_filtered_init (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int reset_pulse);
void host_processor_filtered_release (struct host_processor_filtered *host);

void host_processor_filtered_set_host_flash_access (struct host_processor_filtered *host);
void host_processor_filtered_config_bypass (struct host_processor_filtered *host);
void host_processor_filtered_swap_flash (struct host_processor_filtered *host,
	struct host_flash_manager_rw_regions *rw_list, struct pfm_manager *pfm, bool no_migrate);
int host_processor_filtered_restore_read_write_data (struct host_processor_filtered *host,
	struct host_flash_manager_rw_regions *rw_list, struct pfm *pfm);

int host_processor_filtered_power_on_reset (struct host_processor_filtered *host,
	struct hash_engine *hash, struct rsa_engine *rsa, bool single);
int host_processor_filtered_update_verification (struct host_processor_filtered *host,
	struct hash_engine *hash, struct rsa_engine *rsa, bool single, bool reset, int bypass_status);

int host_processor_filtered_get_next_reset_verification_actions (struct host_processor *host);
int host_processor_filtered_needs_config_recovery (struct host_processor *host);
int host_processor_filtered_apply_recovery_image (struct host_processor *host, bool no_reset);


#endif /* HOST_PROCESSOR_FILTERED_H_ */
