// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_processor_single.h"
#include "common/unused.h"


int host_processor_single_power_on_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	const struct host_processor_filtered *single = (const struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_power_on_reset (single, hash, rsa, true);
}

int host_processor_single_soft_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	const struct host_processor_filtered *single = (const struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (single, hash, rsa, true, true,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME, 0);
}

int host_processor_single_run_time_verification (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	const struct host_processor_filtered *single = (const struct host_processor_filtered*) host;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (single, hash, rsa, true, false,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET, HOST_PROCESSOR_NOTHING_TO_VERIFY);
}

int host_processor_single_flash_rollback (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool disable_bypass,
	bool no_reset)
{
	UNUSED (disable_bypass);
	UNUSED (no_reset);

	if ((host == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return HOST_PROCESSOR_NO_ROLLBACK;
}

int host_processor_single_recover_active_read_write_data (const struct host_processor *host)
{
	if (host == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return HOST_PROCESSOR_NO_ACTIVE_RW_DATA;
}

int host_processor_single_bypass_mode (const struct host_processor *host, bool swap_flash)
{
	const struct host_processor_filtered *single = (const struct host_processor_filtered*) host;

	UNUSED (swap_flash);

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&single->state->lock);

	if (!single->flash->has_two_flash_devices (single->flash)) {
		host_state_manager_save_read_only_flash_nv_config (single->host_state, SPI_FILTER_CS_0);
	}
	else if (swap_flash) {
		/* TODO:  This doesn't take any RO override into consideration. */
		if (host_state_manager_get_read_only_flash (single->host_state) == SPI_FILTER_CS_0) {
			host_state_manager_save_read_only_flash_nv_config (single->host_state, SPI_FILTER_CS_1);
		}
		else {
			host_state_manager_save_read_only_flash_nv_config (single->host_state, SPI_FILTER_CS_0);
		}
	}

	host_processor_filtered_config_bypass (single);
	host_processor_filtered_set_host_flash_access (single);

	platform_mutex_unlock (&single->state->lock);

	return 0;
}

int host_processor_single_get_flash_config (const struct host_processor *host,
	spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
	enum host_read_only_activation *apply_next_ro)
{
	const struct host_processor_filtered *single = (const struct host_processor_filtered*) host;
	int status = 0;

	if ((host == NULL) || (mode == NULL) || (current_ro == NULL) || (next_ro == NULL) ||
		(apply_next_ro == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	*current_ro = host_state_manager_get_read_only_flash (single->host_state);
	*next_ro = host_state_manager_get_read_only_flash_nv_config (single->host_state);
	*apply_next_ro = host_state_manager_get_read_only_activation_events (single->host_state);

	if (host_state_manager_is_bypass_mode (single->host_state)) {
		/* Use the host state rather than the filter state in bypass mode to cover both full and
		 * filtered bypass modes. */
		if (*current_ro == SPI_FILTER_CS_0) {
			*mode = SPI_FILTER_FLASH_BYPASS_CS0;
		}
		else {
			*mode = SPI_FILTER_FLASH_BYPASS_CS1;
		}
	}
	else {
		/* In this state, the filter should only be in single flash mode to the current RO device,
		 * but just return the raw configuration. */
		status = single->filter->get_filter_mode (single->filter, mode);
	}

	return status;
}

int host_processor_single_config_read_only_flash (const struct host_processor *host,
	const spi_filter_cs *current_ro, const spi_filter_cs *next_ro,
	const enum host_read_only_activation *apply_next_ro)
{
	const struct host_processor_filtered *single = (const struct host_processor_filtered*) host;
	spi_filter_cs ro;
	int status = 0;

	if (single == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if ((current_ro != NULL) && (*current_ro > SPI_FILTER_CS_1)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if ((next_ro != NULL) && (*next_ro > SPI_FILTER_CS_1)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if ((apply_next_ro != NULL) && (*apply_next_ro > HOST_READ_ONLY_ACTIVATE_ON_ALL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	/* Changing any flash configuration is only possible with two physical flash devices. */
	if (!single->flash->has_two_flash_devices (single->flash)) {
		return HOST_PROCESSOR_FLASH_CONFIG_UNSUPPORTED;
	}

	platform_mutex_lock (&single->state->lock);

	ro = host_state_manager_get_read_only_flash (single->host_state);

	if (current_ro != NULL) {
		if (ro != *current_ro) {
			host_state_manager_override_read_only_flash (single->host_state, *current_ro);

			status = single->flash->set_flash_for_rot_access (single->flash, single->control);

			if (status == 0) {
				host_processor_filtered_config_bypass (single);
			}

			host_processor_filtered_set_host_flash_access (single);
			if (status != 0) {
				goto exit;
			}
		}
	}

	if (next_ro != NULL) {
		if (ro != *next_ro) {
			if (!host_state_manager_has_read_only_flash_override (single->host_state)) {
				/* Before changing the non-volatile RO device, override the setting so the current
				 * RO doesn't change. */
				host_state_manager_override_read_only_flash (single->host_state, ro);
			}
		}

		host_state_manager_save_read_only_flash_nv_config (single->host_state, *next_ro);
	}

	if (apply_next_ro != NULL) {
		host_state_manager_save_read_only_activation_events (single->host_state, *apply_next_ro);
	}

exit:
	platform_mutex_unlock (&single->state->lock);

	return status;
}

/**
 * Configure the SPI filter to allow full read/write access to the host flash.  This is effectively
 * a bypass mode, but while blocking undesirable flash commands.
 *
 * @param host The host processor instance.
 *
 * @return 0 if the SPI filter was successfully configured or an error code.
 */
int host_processor_single_full_read_write_flash (const struct host_processor_filtered *host)
{
	struct flash_region rw;
	struct pfm_read_write_regions writable;
	int status;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_SINGLE_CS0;

	if (host->flash->has_two_flash_devices (host->flash)) {
		/* If there are two physical flash devices, use the current setting to determine which
		 * should be accessible. */
		if (host_state_manager_get_read_only_flash (host->host_state) == SPI_FILTER_CS_1) {
			mode = SPI_FILTER_FLASH_SINGLE_CS1;
		}
	}
	else {
		/* If there is only a single flash device, ensure the state represents a valid
		 * configuration. */
		host_state_manager_save_read_only_flash_nv_config (host->host_state, SPI_FILTER_CS_0);
		host_state_manager_clear_read_only_flash_override (host->host_state);
	}

	rw.start_addr = 0;
	rw.length = 0xffff0000;
	writable.regions = &rw;
	writable.count = 1;

	status = host_fw_config_spi_filter_read_write_regions (host->filter, &writable);
	if (status != 0) {
		return status;
	}

	return host->filter->set_filter_mode (host->filter, mode);
}

enum host_processor_filtered_dirty host_processor_single_prepare_verification (
	const struct host_processor_filtered *host, enum host_read_only_activation ro_ignore,
	const struct pfm *active_pfm, const struct pfm *pending_pfm)
{
	enum host_processor_filtered_dirty dirty_flash = HOST_PROCESSOR_FILTERED_DIRTY_NORMAL;
	spi_filter_cs ro = host_state_manager_get_read_only_flash (host->host_state);
	spi_filter_cs nv_ro = host_state_manager_get_read_only_flash_nv_config (host->host_state);
	enum host_read_only_activation ro_events =
		host_state_manager_get_read_only_activation_events (host->host_state);

	UNUSED (active_pfm);
	UNUSED (pending_pfm);

	if ((ro_events != HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY) && (ro_events != ro_ignore)) {
		/* Clear any override and apply the flash change. */
		if (ro != nv_ro) {
			host_state_manager_save_inactive_dirty (host->host_state, true);
			dirty_flash = HOST_PROCESSOR_FILTERED_DIRTY_FORCE;
		}

		host_state_manager_clear_read_only_flash_override (host->host_state);
	}

	return dirty_flash;
}

void host_processor_single_finalize_verification (const struct host_processor_filtered *host,
	int result)
{
	spi_filter_cs ro = host_state_manager_get_read_only_flash (host->host_state);
	spi_filter_cs nv_ro = host_state_manager_get_read_only_flash_nv_config (host->host_state);

	UNUSED (result);

	/* Clear any unnecessary RO override. */
	if (ro == nv_ro) {
		host_state_manager_clear_read_only_flash_override (host->host_state);
	}
}

/**
 * Internal function to initialize the core components for host processor actions using a single
 * flash.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param reset_pulse The length of the reset pulse to apply to the processor, in milliseconds.  Set
 * this to 0 to hold the processor instead of using a pulse.
 * @param reset_flash The flag to indicate that host flash should be reset based on every
 * host processor reset.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init_internal (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int reset_pulse, bool reset_flash)
{
	int status;

	if (flash == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = host_processor_filtered_init (host, state, control, &flash->base, host_state, filter,
		pfm, recovery, reset_pulse, reset_flash);
	if (status != 0) {
		return status;
	}

	host->base.power_on_reset = host_processor_single_power_on_reset;
	host->base.soft_reset = host_processor_single_soft_reset;
	host->base.run_time_verification = host_processor_single_run_time_verification;
	host->base.flash_rollback = host_processor_single_flash_rollback;
	host->base.recover_active_read_write_data =
		host_processor_single_recover_active_read_write_data;
	host->base.get_next_reset_verification_actions =
		host_processor_filtered_get_next_reset_verification_actions;
	host->base.needs_config_recovery = host_processor_filtered_needs_config_recovery;
	host->base.apply_recovery_image = host_processor_filtered_apply_recovery_image;
	host->base.bypass_mode = host_processor_single_bypass_mode;
	host->base.get_flash_config = host_processor_single_get_flash_config;
	host->base.config_read_only_flash = host_processor_single_config_read_only_flash;

	host->internal.enable_bypass_mode = host_processor_single_full_read_write_flash;
	host->internal.prepare_verification = host_processor_single_prepare_verification;
	host->internal.finalize_verification = host_processor_single_finalize_verification;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash device for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	return host_processor_single_init_internal (host, state, control, flash, host_state, filter,
		pfm, recovery, 0, false);
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash device for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init_pulse_reset (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_single_init_internal (host, state, control, flash, host_state, filter,
		pfm, recovery, pulse_width, false);
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 *
 * The host flash device will be reset when the host resets.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash device for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init_reset_flash (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	return host_processor_single_init_internal (host, state, control, flash, host_state, filter,
		pfm, recovery, 0, true);
}

/**
 * Initialize the interface for executing host processor actions using a single flash device.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * The host flash device will be reset on host resets.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash device for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_single_init_reset_flash_pulse_reset (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_single *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_single_init_internal (host, state, control, flash, host_state, filter,
		pfm, recovery, pulse_width, true);
}

/**
 * Release the resources used by the host processor interface.
 *
 * @param host The host processor instance to release.
 */
void host_processor_single_release (const struct host_processor_filtered *host)
{
	host_processor_filtered_release (host);
}
