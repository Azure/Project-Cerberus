// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_DUAL_H_
#define HOST_PROCESSOR_DUAL_H_

#include "platform.h"
#include "host_processor.h"
#include "host_control.h"
#include "host_flash_manager.h"
#include "state_manager/state_manager.h"
#include "spi_filter/spi_filter_interface.h"
#include "manifest/pfm/pfm_manager.h"
#include "recovery/recovery_image_manager.h"


/**
 * Defines the core interface for protecting the firmware of a single host processor.  The host
 * has two flash devices available for storing firmware.
 */
struct host_processor_dual {
	struct host_processor base;					/**< Base host processor interface. */
	struct host_control *control;				/**< The interface for hardware control of the host. */
	struct host_flash_manager *flash;			/**< The manager for host processor flash devices. */
	struct state_manager *state;				/**< State information for the host processor. */
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
		int (*enable_bypass_mode) (struct host_processor_dual *host);
	} internal;
};


int host_processor_dual_init (struct host_processor_dual *host, struct host_control *control,
	struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);
int host_processor_dual_init_pulse_reset (struct host_processor_dual *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);
void host_processor_dual_release (struct host_processor_dual *host);

/* Internal functions for use by derived types. */
int host_processor_dual_init_internal (struct host_processor_dual *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);
int host_processor_dual_init_pulse_reset_internal (struct host_processor_dual *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);


#endif /* HOST_PROCESSOR_DUAL_H_ */
