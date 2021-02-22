// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_processor_single.h"


static int host_processor_single_power_on_reset (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	struct host_processor_filtered *single = (struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_power_on_reset (single, hash, rsa, true);
}

static int host_processor_single_soft_reset (struct host_processor *host, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	struct host_processor_filtered *single = (struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (single, hash, rsa, true, true, 0);
}

static int host_processor_single_run_time_verification (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	struct host_processor_filtered *single = (struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (single, hash, rsa, true, false,
		HOST_PROCESSOR_NOTHING_TO_VERIFY);
}

static int host_processor_single_flash_rollback (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa, bool disable_bypass, bool no_reset)
{
	if ((host == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return HOST_PROCESSOR_NO_ROLLBACK;
}

static int host_processor_single_recover_active_read_write_data (struct host_processor *host)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return HOST_PROCESSOR_NO_ACTIVE_RW_DATA;
}

static int host_processor_single_bypass_mode (struct host_processor *host, bool swap_flash)
{
	struct host_processor_filtered *single = (struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&single->lock);
	host_state_manager_save_read_only_flash (single->state, SPI_FILTER_CS_0);
	host_processor_filtered_config_bypass (single);
	host_processor_filtered_set_host_flash_access (single);
	platform_mutex_unlock (&single->lock);

	return 0;
}

/**
 * Configure the SPI filter to allow full read/write access to the host flash.  This is effectively
 * a bypass mode, but while blocking undesirable flash commands.
 *
 * @param host The host processor instance.
 *
 * @return 0 if the SPI filter was successfully configured or an error code.
 */
static int host_processor_single_full_read_write_flash (struct host_processor_filtered *host)
{
	struct flash_region rw;
	struct pfm_read_write_regions writable;
	int status;

	rw.start_addr = 0;
	rw.length = 0xffff0000;
	writable.regions = &rw;
	writable.count = 1;

	status = host_fw_config_spi_filter_read_write_regions (host->filter, &writable);
	if (status != 0) {
		return status;
	}

	return host->filter->set_filter_mode (host->filter, SPI_FILTER_FLASH_SINGLE_CS0);
}

/**
 * Internal function to initialize the core components for host processor actions using a single
 * flash.
 *
 * @param host The host processor instance to initialize.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param reset_pulse The length of the reset pulse to apply to the processor, in milliseconds.  Set
 * this to 0 to hold the processor instead of using a pulse.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init_internal (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int reset_pulse)
{
	int status;

	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = host_processor_filtered_init (host, control, &flash->base, state, filter, pfm,
		recovery, reset_pulse);
	if (status != 0) {
		return status;
	}

	host->base.power_on_reset = host_processor_single_power_on_reset;
	host->base.soft_reset = host_processor_single_soft_reset;
	host->base.run_time_verification = host_processor_single_run_time_verification;
	host->base.flash_rollback = host_processor_single_flash_rollback;
	host->base.recover_active_read_write_data = host_processor_single_recover_active_read_write_data;
	host->base.get_next_reset_verification_actions =
		host_processor_filtered_get_next_reset_verification_actions;
	host->base.needs_config_recovery = host_processor_filtered_needs_config_recovery;
	host->base.apply_recovery_image = host_processor_filtered_apply_recovery_image;
	host->base.bypass_mode = host_processor_single_bypass_mode;

	host->internal.enable_bypass_mode = host_processor_single_full_read_write_flash;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 *
 * @param host The host processor instance to initialize.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash device for the host processor.
 * @param state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init (struct host_processor_filtered *host, struct host_control *control,
	struct host_flash_manager_single *flash, struct host_state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	return host_processor_single_init_internal (host, control, flash, state, filter, pfm, recovery,
		0);
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * @param host The host processor instance to initialize.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash device for the host processor.
 * @param state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init_pulse_reset (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_single *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_single_init_internal (host, control, flash, state, filter, pfm, recovery,
		pulse_width);
}

/**
 * Release the resources used by the host processor interface.
 *
 * @param host The host processor instance to release.
 */
void host_processor_single_release (struct host_processor_filtered *host)
{
	host_processor_filtered_release (host);
}
