// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "host_processor_dual.h"
#include "host_fw_util.h"
#include "host_state_manager.h"
#include "host_logging.h"
#include "flash/flash_util.h"
#include "recovery/recovery_image.h"




/**
 * Internal function to apply bypass mode.
 *
 * @param host The host to configure for bypass mode.
 * @param swap_flash Flag to swap flash roles before configuring bypass mode.
 */
static void host_processor_dual_force_bypass_mode (struct host_processor_filtered *host,
	bool swap_flash)
{
	if (swap_flash) {
		if (host_state_manager_get_read_only_flash (host->state) == SPI_FILTER_CS_0) {
			host_state_manager_save_read_only_flash (host->state, SPI_FILTER_CS_1);
		}
		else {
			host_state_manager_save_read_only_flash (host->state, SPI_FILTER_CS_0);
		}
	}

	host_processor_filtered_config_bypass (host);
}

static int host_processor_dual_power_on_reset (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	struct host_processor_filtered *dual = (struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_power_on_reset (dual, hash, rsa, false);
}

static int host_processor_dual_soft_reset (struct host_processor *host, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	struct host_processor_filtered *dual = (struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (dual, hash, rsa, false, true, 0);
}

static int host_processor_dual_run_time_verification (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	struct host_processor_filtered *dual = (struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_filtered_update_verification (dual, hash, rsa, false, false,
		HOST_PROCESSOR_NOTHING_TO_VERIFY);
}

static int host_processor_dual_flash_rollback (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa, bool disable_bypass, bool no_reset)
{
	struct host_processor_filtered *dual = (struct host_processor_filtered*) host;
	struct pfm *active_pfm;
	struct host_flash_manager_rw_regions rw_list;
	struct spi_flash *ro_flash;
	struct spi_flash *rw_flash;
	uint32_t dev_size;
	int status = 0;

	if ((dual == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->lock);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_HOST_FW,
		HOST_LOGGING_ROLLBACK_STARTED, dual->base.port, 0);

	active_pfm = dual->pfm->get_active_pfm (dual->pfm);

	if (active_pfm && !host_state_manager_is_flash_supported (dual->state)) {
		status = HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
		goto exit;
	}

	if ((!active_pfm && !disable_bypass) ||
		(active_pfm && (!host_state_manager_is_inactive_dirty (dual->state) ||
			host_state_manager_is_bypass_mode (dual->state)))) {
		if (host_state_manager_is_bypass_mode (dual->state) && disable_bypass) {
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
			if (!host_state_manager_is_bypass_mode (dual->state)) {
				/* Even though the dirty state hasn't been set, we still need to make sure the other
				 * flash contains a good image prior to activating it. */
				status = dual->flash->validate_read_write_flash (dual->flash, active_pfm, hash, rsa,
					&rw_list);
				if (status == 0) {
					host_processor_filtered_swap_flash (dual, &rw_list, NULL, true);
					dual->flash->free_read_write_regions (dual->flash, &rw_list);

					observable_notify_observers (&dual->base.observable,
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
			HOST_LOGGING_ROLLBACK_COMPLETED, dual->base.port, 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_ROLLBACK_FAILED, status, dual->base.port);
	}

	platform_mutex_unlock (&dual->lock);
	return status;
}

static int host_processor_dual_recover_active_read_write_data (struct host_processor *host)
{
	struct host_processor_filtered *dual = (struct host_processor_filtered*) host;
	struct pfm *active_pfm;
	int status = HOST_PROCESSOR_NO_ACTIVE_RW_DATA;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if (!host_state_manager_is_bypass_mode (dual->state)) {
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

static int host_processor_dual_bypass_mode (struct host_processor *host, bool swap_flash)
{
	struct host_processor_filtered *dual = (struct host_processor_filtered*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->lock);
	host_processor_dual_force_bypass_mode (dual, swap_flash);
	host_processor_filtered_set_host_flash_access (dual);
	platform_mutex_unlock (&dual->lock);

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
static int host_processor_dual_full_read_write_flash (struct host_processor_filtered *host)
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
		(host_state_manager_get_read_only_flash (host->state) == SPI_FILTER_CS_0) ?
			SPI_FILTER_CS_1 : SPI_FILTER_CS_0);
}

/**
 * Internal function to initialize the core components for host processor actions.
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
int host_processor_dual_init_internal (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_dual *flash,
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

	host->internal.enable_bypass_mode = host_processor_dual_full_read_write_flash;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions using two flash devices.
 *
 * @param host The host processor instance to initialize.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init (struct host_processor_filtered *host, struct host_control *control,
	struct host_flash_manager_dual *flash, struct host_state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	return host_processor_dual_init_internal (host, control, flash, state, filter, pfm, recovery,
		0);
}

/**
 * Initialize the interface for executing host processor actions using two flash devices.
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
 * @param recovery The manager for recovery of the host processor.
 * @param pulse_width The width of the reset pulse, in milliseconds.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init_pulse_reset (struct host_processor_filtered *host,
	struct host_control *control, struct host_flash_manager_dual *flash,
	struct host_state_manager *state, struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int pulse_width)
{
	if (pulse_width <= 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return host_processor_dual_init_internal (host, control, flash, state, filter, pfm, recovery,
		pulse_width);
}

/**
 * Release the resources used by the host processor interface.
 *
 * @param host The host processor instance to release.
 */
void host_processor_dual_release (struct host_processor_filtered *host)
{
	host_processor_filtered_release (host);
}
