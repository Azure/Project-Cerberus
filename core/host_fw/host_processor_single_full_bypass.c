// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_processor_single_full_bypass.h"
#include "host_state_manager.h"


static int host_processor_single_full_bypass_enable_bypass_mode (
	struct host_processor_filtered *host)
{
	return host->filter->set_filter_mode (host->filter, SPI_FILTER_FLASH_BYPASS_CS0);
}

/**
 * Initialize the interface for executing host processor actions.  Unprotected flash will be
 * accessible in full bypass mode.
 *
 * @param host The host processor instance to initialize.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The recovery image manager for the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_full_bypass_init (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status = host_processor_single_init_internal (host, control, flash, state, filter, pfm,
		recovery, 0);
	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_single_full_bypass_enable_bypass_mode;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions.  Unprotected flash will be
 * accessible in full bypass mode.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * @param host The host processor instance to initialize.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The recovery image manager for the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_full_bypass_init_pulse_reset (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	int status;

	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = host_processor_single_init_internal (host, control, flash, state, filter, pfm,
		recovery, pulse_width);
	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_single_full_bypass_enable_bypass_mode;

	return 0;
}

/**
 * Release the resources used by the host processor interface.
 *
 * @param host The host processor instance to release.
 */
void host_processor_single_full_bypass_release (struct host_processor_filtered *host)
{
	host_processor_single_release (host);
}
