// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_SINGLE_H_
#define HOST_PROCESSOR_SINGLE_H_

#include "platform.h"
#include "host_processor.h"
#include "host_processor_filtered.h"
#include "host_flash_manager_single.h"


/**
 * Defines the core interface for protecting the firmware of a single host processor.  The host
 * has a single flash devices available for storing firmware.
 */
/* Re-uses the common type of struct host_processor_filtered to allow for more efficient memory
 * allocation. */


int host_processor_single_init (struct host_processor_filtered *host, struct host_control *control,
	struct host_flash_manager_single *flash, struct host_state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);
int host_processor_single_init_pulse_reset (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width);
void host_processor_single_release (struct host_processor_filtered *host);

/* Internal functions for use by derived types. */
int host_processor_single_init_internal (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int reset_pulse);


#endif /* HOST_PROCESSOR_SINGLE_H_ */
