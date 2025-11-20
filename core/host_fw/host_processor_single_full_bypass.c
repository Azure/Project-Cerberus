// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_processor_single_full_bypass.h"
#include "host_state_manager.h"


int host_processor_single_full_bypass_enable_bypass_mode (
	const struct host_processor_filtered *host)
{
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_BYPASS_CS0;

	if (host->flash->has_two_flash_devices (host->flash)) {
		/* If there are two physical flash devices, use the current setting to determine which
		 * should be accessible. */
		if (host_state_manager_get_read_only_flash (host->host_state) == SPI_FILTER_CS_1) {
			mode = SPI_FILTER_FLASH_BYPASS_CS1;
		}
	}
	else {
		/* If there is only a single flash device, ensure the state represents a valid
		 * configuration. */
		host_state_manager_save_read_only_flash_nv_config (host->host_state, SPI_FILTER_CS_0);
		host_state_manager_clear_read_only_flash_override (host->host_state);
	}

	return host->filter->set_filter_mode (host->filter, mode);
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 * Unprotected flash will be accessible in full bypass mode.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The recovery image manager for the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_full_bypass_init (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status = host_processor_single_init_internal (host, state, control, flash, host_state,
		filter, pfm, recovery, 0, false);

	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_single_full_bypass_enable_bypass_mode;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 * Unprotected flash will be accessible in full bypass mode.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The recovery image manager for the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_full_bypass_init_pulse_reset (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	int status;

	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = host_processor_single_init_internal (host, state, control, flash, host_state, filter,
		pfm, recovery, pulse_width, false);
	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_single_full_bypass_enable_bypass_mode;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 * Unprotected flash will be accessible in full bypass mode.
 *
 * The host flash device will be reset when the host resets.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The recovery image manager for the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_full_bypass_init_reset_flash (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status = host_processor_single_init_internal (host, state, control, flash, host_state,
		filter, pfm, recovery, 0, true);

	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_single_full_bypass_enable_bypass_mode;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 * Unprotected flash will be accessible in full bypass mode.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * The host flash device will be reset when the host resets.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The recovery image manager for the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_full_bypass_init_reset_flash_pulse_reset (
	struct host_processor_filtered *host, struct host_processor_filtered_state *state,
	const struct host_control *control, const struct host_flash_manager_single *flash,
	const struct host_state_manager *host_state, const struct spi_filter_interface *filter,
	const struct pfm_manager *pfm, struct recovery_image_manager *recovery, int pulse_width)
{
	int status;

	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = host_processor_single_init_internal (host, state, control, flash, host_state, filter,
		pfm, recovery, pulse_width, true);
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
void host_processor_single_full_bypass_release (const struct host_processor_filtered *host)
{
	host_processor_single_release (host);
}
