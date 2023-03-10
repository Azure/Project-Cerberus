// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_SINGLE_FULL_BYPASS_RESET_FLASH_H_
#define HOST_PROCESSOR_SINGLE_FULL_BYPASS_RESET_FLASH_H_

#include "host_processor_single.h"


/**
 * Protection for firmware on a single host processor that uses a single flash devices.  When no
 * protection is enabled, bypass mode to the host flash uses full bypass (no commands are filtered).
 *
 * The host flash device will reset when the host resets.
 */
/* Re-uses the common type of struct host_processor_filtered to allow for more efficient memory
 * allocation. */


int host_processor_single_full_bypass_reset_flash_init (struct host_processor_filtered *host,
	const struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, const struct spi_filter_interface *filter,
	struct pfm_manager *pfm, struct recovery_image_manager *recovery);
int host_processor_single_full_bypass_reset_flash_init_pulse_reset (
	struct host_processor_filtered *host, const struct host_control *control,
	struct host_flash_manager_single *flash, struct host_state_manager *state,
	const struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width);
void host_processor_single_full_bypass_reset_flash_release (struct host_processor_filtered *host);


#endif /* HOST_PROCESSOR_SINGLE_FULL_BYPASS_RESET_FLASH_H_ */
