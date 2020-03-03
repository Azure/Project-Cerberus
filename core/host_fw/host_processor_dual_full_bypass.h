// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_DUAL_FULL_BYPASS_H_
#define HOST_PROCESSOR_DUAL_FULL_BYPASS_H_

#include "host_processor_dual.h"


/**
 * Protection for firmware on a single host processor that uses two flash devices.  When no
 * protection is enabled, bypass mode to the host flash uses full bypass (no commands are filtered).
 */
struct host_processor_dual_full_bypass {
	struct host_processor_dual base;			/**< Base host management instance. */
};


int host_processor_dual_full_bypass_init (struct host_processor_dual_full_bypass *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);
int host_processor_dual_full_bypass_init_pulse_reset (struct host_processor_dual_full_bypass *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery);
void host_processor_dual_full_bypass_release (struct host_processor_dual_full_bypass *host);


#endif /* HOST_PROCESSOR_DUAL_FULL_BYPASS_H_ */
