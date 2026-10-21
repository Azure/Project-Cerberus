// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_fw_util.h"
#include "host_logging.h"
#include "host_processor_dual.h"
#include "host_state_manager.h"
#include "common/unused.h"
#include "flash/flash_util.h"
#include "recovery/recovery_image.h"



/**
 * Internal function to apply bypass mode.
 *
 * @param host The host to configure for bypass mode.
 * @param swap_flash Flag to swap flash roles before configuring bypass mode.
 */
static void host_processor_dual_force_bypass_mode (const struct host_processor_filtered *host,
	bool swap_flash)
{
	/* TODO:  This doesn't take any RO override into consideration. */
	if (swap_flash) {
		if (host_state_manager_get_read_only_flash (host->host_state) == SPI_FILTER_CS_0) {
			host_state_manager_save_read_only_flash_nv_config (host->host_state, SPI_FILTER_CS_1);
		}
		else {
			host_state_manager_save_read_only_flash_nv_config (host->host_state, SPI_FILTER_CS_0);
		}
	}

	host_processor_filtered_config_bypass (host);
}

int host_processor_dual_power_on_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_power_on_reset (dual, hash, rsa, false);
}

int host_processor_dual_soft_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (dual, hash, rsa, false, true,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME, 0);
}

int host_processor_dual_run_time_verification (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (dual, hash, rsa, false, false,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET, HOST_PROCESSOR_NOTHING_TO_VERIFY);
}

int host_processor_dual_flash_rollback (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool disable_bypass,
	bool no_reset)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;
	const struct pfm *active_pfm;
	struct host_flash_manager_rw_regions rw_list;
	const struct spi_flash *ro_flash;
	const struct spi_flash *rw_flash;
	uint32_t dev_size;
	int status = 0;

	if ((dual == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->state->lock);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_HOST_FW,
		HOST_LOGGING_ROLLBACK_STARTED, host_processor_get_port (&dual->base), 0);

	active_pfm = dual->pfm->get_active_pfm (dual->pfm);

	if (active_pfm && !host_state_manager_is_flash_supported (dual->host_state)) {
		status = HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
		goto exit;
	}

	if ((!active_pfm && !disable_bypass) ||
		(active_pfm && (!host_state_manager_is_inactive_dirty (dual->host_state) ||
		host_state_manager_is_bypass_mode (dual->host_state)))) {
		if (host_state_manager_is_bypass_mode (dual->host_state) && disable_bypass) {
			status = HOST_PROCESSOR_NO_ROLLBACK;
			goto exit;
		}

		if (!no_reset && !dual->reset_pulse) {
			dual->control->hold_processor_in_reset (dual->control, true);
		}

		status = dual->flash->set_flash_for_rot_access (dual->flash, dual->control);
		if (status != 0) {
			goto return_flash;
		}

		if (active_pfm) {
			if (!host_state_manager_is_bypass_mode (dual->host_state)) {
				/* Even though the dirty state hasn't been set, we still need to make sure the other
				 * flash contains a good image prior to activating it. */
				status = dual->flash->validate_read_write_flash (dual->flash, active_pfm, hash, rsa,
					&rw_list);
				if (status == 0) {
					host_processor_filtered_swap_flash (dual, &rw_list, NULL, true);
					dual->flash->free_read_write_regions (dual->flash, &rw_list);

					observable_notify_observers (&dual->base.state->observable,
						offsetof (struct host_processor_observer, on_active_mode));
				}
			}
			else {
				/* If we are in forced bypass mode, just switch flashes. */
				host_processor_dual_force_bypass_mode (dual, true);
			}
		}
		else {
			/* We are not in active mode yet, so just copy the contents from the second flash
			 * entirely into the boot flash. */
			ro_flash = dual->flash->get_read_only_flash (dual->flash);
			rw_flash = dual->flash->get_read_write_flash (dual->flash);
			spi_flash_get_device_size (ro_flash, &dev_size);

			status = spi_flash_chip_erase (ro_flash);
			if (status != 0) {
				goto return_flash;
			}

			status = flash_copy_ext_to_blank_and_verify (&ro_flash->base, 0, &rw_flash->base, 0,
				dev_size);
		}

return_flash:
		host_processor_filtered_set_host_flash_access (dual);

		if (!no_reset) {
			if (dual->reset_pulse) {
				dual->control->hold_processor_in_reset (dual->control, true);
				platform_msleep (dual->reset_pulse);
			}
			dual->control->hold_processor_in_reset (dual->control, false);
		}
	}
	else if (!active_pfm) {
		status = HOST_PROCESSOR_NO_ROLLBACK;
	}
	else {
		status = HOST_PROCESSOR_ROLLBACK_DIRTY;
	}

exit:
	if (active_pfm) {
		dual->pfm->free_pfm (dual->pfm, active_pfm);
	}

	if (status == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_ROLLBACK_COMPLETED, host_processor_get_port (&dual->base), 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_ROLLBACK_FAILED, status, host_processor_get_port (&dual->base));
	}

	platform_mutex_unlock (&dual->state->lock);

	return status;
}

int host_processor_dual_recover_active_read_write_data (const struct host_processor *host)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;
	const struct pfm *active_pfm;
	int status = HOST_PROCESSOR_NO_ACTIVE_RW_DATA;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if (!host_state_manager_is_bypass_mode (dual->host_state)) {
		active_pfm = dual->pfm->get_active_pfm (dual->pfm);
		if (active_pfm) {
			if (!dual->reset_pulse) {
				dual->control->hold_processor_in_reset (dual->control, true);
			}

			status = dual->flash->set_flash_for_rot_access (dual->flash, dual->control);
			if (status == 0) {
				status = host_processor_filtered_restore_read_write_data (dual, NULL, active_pfm);
			}

			dual->pfm->free_pfm (dual->pfm, active_pfm);

			host_processor_filtered_set_host_flash_access (dual);

			if (dual->reset_pulse) {
				dual->control->hold_processor_in_reset (dual->control, true);
				platform_msleep (dual->reset_pulse);
			}
			dual->control->hold_processor_in_reset (dual->control, false);
		}
	}

	return status;
}

int host_processor_dual_bypass_mode (const struct host_processor *host, bool swap_flash)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->state->lock);
	host_processor_dual_force_bypass_mode (dual, swap_flash);
	host_processor_filtered_set_host_flash_access (dual);
	platform_mutex_unlock (&dual->state->lock);

	return 0;
}

int host_processor_dual_get_flash_config (const struct host_processor *host,
	spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
	enum host_read_only_activation *apply_next_ro)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;
	bool bypass;
	bool dirty;
	spi_filter_cs nv_ro;
	int status;

	if ((dual == NULL) || (mode == NULL) || (current_ro == NULL) || (next_ro == NULL) ||
		(apply_next_ro == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	bypass = host_state_manager_is_bypass_mode (dual->host_state);
	dirty = host_state_manager_is_inactive_dirty (dual->host_state);
	nv_ro = host_state_manager_get_read_only_flash_nv_config (dual->host_state);

	*current_ro = host_state_manager_get_read_only_flash (dual->host_state);
	*apply_next_ro = host_state_manager_get_read_only_activation_events (dual->host_state);

	if (bypass) {
		/* Use the host state rather than the filter state in bypass mode to cover both full and
		 * filtered bypass modes. */
		if (*current_ro == SPI_FILTER_CS_0) {
			*mode = SPI_FILTER_FLASH_BYPASS_CS0;
		}
		else {
			*mode = SPI_FILTER_FLASH_BYPASS_CS1;
		}

		*next_ro = nv_ro;
	}
	else {
		/* In this state, the filter should always be in dual mode, but just report the raw filter
		 * configuration. */
		status = dual->filter->get_filter_mode (dual->filter, mode);
		if (status != 0) {
			return status;
		}

		if (dirty) {
			/* When the flash in dirty, the next host event will swap flash devices after running
			 * verification. */
			*next_ro = (nv_ro == SPI_FILTER_CS_0) ? SPI_FILTER_CS_1 : SPI_FILTER_CS_0;
		}
		else {
			*next_ro = nv_ro;
		}
	}

	return 0;
}

int host_processor_dual_config_read_only_flash (const struct host_processor *host,
	const spi_filter_cs *current_ro, const spi_filter_cs *next_ro,
	const enum host_read_only_activation *apply_next_ro)
{
	const struct host_processor_filtered *dual = (const struct host_processor_filtered*) host;
	bool bypass;
	spi_filter_cs ro;
	spi_filter_cs nv_ro;
	int status = 0;

	if (dual == NULL) {
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

	platform_mutex_lock (&dual->state->lock);

	bypass = host_state_manager_is_bypass_mode (dual->host_state);
	ro = host_state_manager_get_read_only_flash (dual->host_state);
	nv_ro = host_state_manager_get_read_only_flash_nv_config (dual->host_state);

	if (current_ro != NULL) {
		if (!bypass) {
			/* In active mode, the current RO flash device cannot be changed by this call.  The
			 * RO flash device needs to be swapped via some kind of verification. */
			status = HOST_PROCESSOR_FLASH_CONFIG_UNSUPPORTED;
			goto exit;
		}

		if (ro != *current_ro) {
			host_state_manager_override_read_only_flash (dual->host_state, *current_ro);

			status = dual->flash->set_flash_for_rot_access (dual->flash, dual->control);

			if (status == 0) {
				host_processor_filtered_config_bypass (dual);
			}

			host_processor_filtered_set_host_flash_access (dual);
			if (status != 0) {
				goto exit;
			}

			spi_filter_log_configuration (dual->filter);
		}
	}

	if (next_ro != NULL) {
		if (bypass) {
			if (ro != *next_ro) {
				if (!host_state_manager_has_read_only_flash_override (dual->host_state)) {
					/* Before changing the non-volatile RO device, override the setting so the
					 * current RO doesn't change. */
					host_state_manager_override_read_only_flash (dual->host_state, ro);
				}
			}

			host_state_manager_save_read_only_flash_nv_config (dual->host_state, *next_ro);
		}
		else {
			if (nv_ro != *next_ro) {
				host_state_manager_save_inactive_dirty (dual->host_state, true);

				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
					HOST_LOGGING_FORCE_DIRTY, host_processor_get_port (&dual->base), 0);
			}
			else {
				host_state_manager_save_inactive_dirty (dual->host_state, false);

				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
					HOST_LOGGING_FORCE_NOT_DIRTY, host_processor_get_port (&dual->base), 0);
			}
		}
	}

	if (apply_next_ro != NULL) {
		host_state_manager_save_read_only_activation_events (dual->host_state, *apply_next_ro);
	}

exit:
	platform_mutex_unlock (&dual->state->lock);

	return status;
}

enum host_processor_filtered_dirty host_processor_dual_prepare_verification (
	const struct host_processor_filtered *host, enum host_read_only_activation ro_ignore,
	const struct pfm *active_pfm, const struct pfm *pending_pfm)
{
	enum host_processor_filtered_dirty dirty_flash = HOST_PROCESSOR_FILTERED_DIRTY_NORMAL;
	bool bypass = host_state_manager_is_bypass_mode (host->host_state);
	spi_filter_cs ro = host_state_manager_get_read_only_flash (host->host_state);
	spi_filter_cs nv_ro = host_state_manager_get_read_only_flash_nv_config (host->host_state);
	enum host_read_only_activation ro_events =
		host_state_manager_get_read_only_activation_events (host->host_state);

	if ((ro_events == HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY) || (ro_events == ro_ignore)) {
		/* Ignore dirty flash if flash switching is not enabled during this verification. */
		dirty_flash = HOST_PROCESSOR_FILTERED_DIRTY_IGNORE;
	}
	else {
		/* Clear any override and apply the flash change. */
		if (ro != nv_ro) {
			if (!bypass && (active_pfm || pending_pfm)) {
				/* An override in active mode is not a valid configuration.  Update the non-volatile
				 * state to match override and set a dirty flash. */
				host_state_manager_save_read_only_flash_nv_config (host->host_state, ro);
			}

			host_state_manager_save_inactive_dirty (host->host_state, true);
			dirty_flash = HOST_PROCESSOR_FILTERED_DIRTY_FORCE;
		}

		host_state_manager_clear_read_only_flash_override (host->host_state);
	}

	return dirty_flash;
}

void host_processor_dual_finalize_verification (const struct host_processor_filtered *host,
	int result)
{
	spi_filter_cs ro = host_state_manager_get_read_only_flash (host->host_state);
	spi_filter_cs nv_ro = host_state_manager_get_read_only_flash_nv_config (host->host_state);

	UNUSED (result);

	if (host_state_manager_is_bypass_mode (host->host_state)) {
		/* Clear any unnecessary RO override. */
		if (ro == nv_ro) {
			host_state_manager_clear_read_only_flash_override (host->host_state);
		}
	}
	else if (host_state_manager_has_read_only_flash_override (host->host_state)) {
		/* When not in bypass mode, flash overrides are not valid.  Update the configuration to be
		 * valid. */
		host_state_manager_save_read_only_flash_nv_config (host->host_state, ro);
		host_state_manager_clear_read_only_flash_override (host->host_state);

		if (ro != nv_ro) {
			host_state_manager_save_inactive_dirty (host->host_state, true);
		}
		else {
			host_state_manager_save_inactive_dirty (host->host_state, false);
		}
	}
}

/**
 * Configure the SPI filter to allow full read/write access to the host flash.  This is effectively
 * a bypass mode, but while blocking undesirable flash commands.
 *
 * @param host The host processor instance.
 *
 * @return 0 if the SPI filter was successfully configured or an error code.
 */
int host_processor_dual_full_read_write_flash (const struct host_processor_filtered *host)
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

	return host->filter->set_ro_cs (host->filter,
		(host_state_manager_get_read_only_flash (host->host_state) == SPI_FILTER_CS_0) ?
			SPI_FILTER_CS_1 : SPI_FILTER_CS_0);
}

/**
 * Internal function to initialize the core components for host processor actions.
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
int host_processor_dual_init_internal (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_dual *flash, const struct host_state_manager *host_state,
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

	host->base.power_on_reset = host_processor_dual_power_on_reset;
	host->base.soft_reset = host_processor_dual_soft_reset;
	host->base.run_time_verification = host_processor_dual_run_time_verification;
	host->base.flash_rollback = host_processor_dual_flash_rollback;
	host->base.recover_active_read_write_data = host_processor_dual_recover_active_read_write_data;
	host->base.get_next_reset_verification_actions =
		host_processor_filtered_get_next_reset_verification_actions;
	host->base.needs_config_recovery = host_processor_filtered_needs_config_recovery;
	host->base.apply_recovery_image = host_processor_filtered_apply_recovery_image;
	host->base.bypass_mode = host_processor_dual_bypass_mode;
	host->base.get_flash_config = host_processor_dual_get_flash_config;
	host->base.config_read_only_flash = host_processor_dual_config_read_only_flash;

	host->internal.enable_bypass_mode = host_processor_dual_full_read_write_flash;
	host->internal.prepare_verification = host_processor_dual_prepare_verification;
	host->internal.finalize_verification = host_processor_dual_finalize_verification;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using two flash devices.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_dual *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	return host_processor_dual_init_internal (host, state, control, flash, host_state, filter, pfm,
		recovery, 0, false);
}

/**
 * Initialize the interface for executing host processor actions using two flash devices.
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
 * @param recovery The manager for recovery of the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init_pulse_reset (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_dual *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_dual_init_internal (host, state, control, flash, host_state, filter, pfm,
		recovery, pulse_width, false);
}

/**
 * Initialize the interface for executing host processor actions using two flash devices.
 *
 * The host flash devices will be reset on host resets.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init_reset_flash (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_dual *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	return host_processor_dual_init_internal (host, state, control, flash, host_state, filter, pfm,
		recovery, 0, true);
}

/**
 * Initialize the interface for executing host processor actions using two flash devices.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * The host flash devices will be reset on host resets.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init_reset_flash_pulse_reset (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager_dual *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_dual_init_internal (host, state, control, flash, host_state, filter, pfm,
		recovery, pulse_width, true);
}

/**
 * Release the resources used by the host processor interface.
 *
 * @param host The host processor instance to release.
 */
void host_processor_dual_release (const struct host_processor_filtered *host)
{
	host_processor_filtered_release (host);
}
