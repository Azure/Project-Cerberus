// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_FILTERED_H_
#define HOST_PROCESSOR_FILTERED_H_

#include "host_control.h"
#include "host_flash_manager.h"
#include "host_processor.h"
#include "host_state_manager.h"
#include "platform_api.h"
#include "manifest/pfm/pfm_manager.h"
#include "recovery/recovery_image_manager.h"
#include "spi_filter/spi_filter_interface.h"


/**
 * Variable context for host connected to a SPI filter.
 */
struct host_processor_filtered_state {
	struct host_processor_state base;	/**< Base host processor context. */
	platform_mutex lock;				/**< Synchronization for verification routines. */
};

/**
 * Defines the common components and handling used with a host connected to flash through a SPI
 * filter.
 *
 * This is not a stand-alone implementation of the host processor API.  It provides common routines
 * that can be used by a complete implementation.
 */
struct host_processor_filtered {
	struct host_processor base;						/**< Base host processor interface. */
	struct host_processor_filtered_state *state;	/**< Variable context for host processing.  */
	const struct host_control *control;				/**< The interface for hardware control of the host. */
	const struct host_flash_manager *flash;			/**< The manager for host processor flash devices. */
	const struct host_state_manager *host_state;	/**< State information for the host processor. */
	const struct spi_filter_interface *filter;		/**< The SPI filter connected to host flash devices. */
	const struct pfm_manager *pfm;					/**< The manager for host processor PFMs. */
	struct recovery_image_manager *recovery;		/**< The manager for recovery of the host processor. */
	int reset_pulse;								/**< The length of the reset pulse for the host. */
	bool reset_flash;								/**< The flag to indicate that the host flash should
														be reset based on every host processor reset. */

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
		int (*enable_bypass_mode) (const struct host_processor_filtered *host);
	} internal;
};


/* Internal functions for use by derived types. */
int host_processor_filtered_init (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int reset_pulse, bool reset_flash);
int host_processor_filtered_init_state (const struct host_processor_filtered *host);
void host_processor_filtered_release (const struct host_processor_filtered *host);

void host_processor_filtered_set_host_flash_access (const struct host_processor_filtered *host);
void host_processor_filtered_config_bypass (const struct host_processor_filtered *host);
void host_processor_filtered_swap_flash (const struct host_processor_filtered *host,
	const struct host_flash_manager_rw_regions *rw_list, const struct pfm_manager *pfm,
	bool no_migrate);
int host_processor_filtered_restore_read_write_data (const struct host_processor_filtered *host,
	struct host_flash_manager_rw_regions *rw_list, const struct pfm *pfm);

int host_processor_filtered_power_on_reset (const struct host_processor_filtered *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool single);
int host_processor_filtered_update_verification (const struct host_processor_filtered *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool single, bool reset,
	int bypass_status);

int host_processor_filtered_get_next_reset_verification_actions (const struct host_processor *host);
int host_processor_filtered_needs_config_recovery (const struct host_processor *host);
int host_processor_filtered_apply_recovery_image (const struct host_processor *host, bool no_reset);


#endif	/* HOST_PROCESSOR_FILTERED_H_ */
