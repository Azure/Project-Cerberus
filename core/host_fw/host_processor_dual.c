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
 * Take the SPI flash from the host for the first time and configure the SPI filter for the devices.
 * This function will spin indefinitely until this operation is successful or a known error is
 * encountered indicating that it will never be successful.
 *
 * @param host The host processor instance.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int host_processor_dual_initial_rot_flash_access (struct host_processor_dual *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->set_flash_for_rot_access (host->flash, host->control);
		if ((status == SPI_FLASH_UNSUPPORTED_DEVICE) ||
			(status == SPI_FLASH_INCOMPATIBLE_SPI_MASTER) || (status == SPI_FLASH_NO_DEVICE) ||
			(status == SPI_FLASH_NO_4BYTE_CMDS) || (status == SPI_FLASH_SFDP_LARGE_DEVICE) ||
			(status == SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE) ||
			(status == SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN)) {
			host_state_manager_set_unsupported_flash (host->state, true);
			return status;
		}

		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_ROT_FLASH_ACCESS_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_ROT_FLASH_ACCESS_RETRIES, host->base.port, retries);
	}

	log_status = 0;
	retries = 0;
	do {
		retries++;
		status = host->flash->config_spi_filter_flash_type (host->flash);
		if ((status == MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR) ||
			(status == MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE) ||
			(status == HOST_FLASH_MGR_MISMATCH_VENDOR) ||
			(status == HOST_FLASH_MGR_MISMATCH_DEVICE) ||
			(status == HOST_FLASH_MGR_MISMATCH_SIZES)) {
			host_state_manager_set_unsupported_flash (host->state, true);
			return status;
		}

		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_FILTER_FLASH_TYPE_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_FILTER_FLASH_TYPE_RETRIES, host->base.port, retries);
	}

	host_state_manager_set_unsupported_flash (host->state, false);
	return 0;
}

/**
 * Give the SPI flash back to the host.  This function will spin indefinitely until this operation
 * is successful.  Until it succeeds, the host will never be able to boot.
 *
 * @param host The host processor instance.
 */
static void host_processor_dual_set_host_flash_access (struct host_processor_dual *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->set_flash_for_host_access (host->flash, host->control);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_HOST_FLASH_ACCESS_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_HOST_FLASH_ACCESS_RETRIES, host->base.port, retries);
	}
}

/**
 * Configure the filter for bypass mode.
 *
 * This will spin indefinitely until it is successful.  Setting bypass mode is only dependent on the
 * SPI filter, which should be highly reliable.  Plus, this mode is one that needs to work.  If  the
 * filter is being configured in bypass mode, that means that no other flow will successfully
 * execute.
 *
 * @param host The host processor instance being updated.
 */
static void host_processor_dual_config_bypass (struct host_processor_dual *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->internal.enable_bypass_mode (host);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_BYPASS_MODE_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_BYPASS_MODE_RETRIES, host->base.port, retries);
	}

	host_state_manager_set_bypass_mode (host->state, true);
	observable_notify_observers (&host->base.observable,
		offsetof (struct host_processor_observer, on_bypass_mode));
}

/**
 * Configure the flash and the filter to enable protection for the first time.
 *
 * This call will spin indefinitely until successful.  Failures in this sequence can leave the
 * filter and flash in an inconsistent state.  This must be completely successful before allowing
 * the host to access the flash.
 *
 * @param host The host processor instance being updated.
 * @param rw_list The list of read/write regions defined on the new flash.
 */
static void host_processor_dual_initialize_protection (struct host_processor_dual *host,
	struct pfm_read_write_regions *rw_list)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->initialize_flash_protection (host->flash, rw_list);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_INIT_PROTECTION_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_INIT_PROTECTION_RETRIES, host->base.port, retries);
	}

	host_state_manager_set_bypass_mode (host->state, false);
}

/**
 * Configure the read/write regions in the SPI filter.
 *
 * This call will spin indefinitely until successful.  Failures in this sequence can leave the
 * filter and flash in an inconsistent state.  This must be completely successful before allowing
 * the host to access the flash.
 *
 * @param host The host processor instance being updated.
 * @param rw_list The list of read/write regions defined on the new flash.
 */
static void host_processor_dual_config_rw (struct host_processor_dual *host,
	struct pfm_read_write_regions *rw_list)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host_fw_config_spi_filter_read_write_regions (host->filter, rw_list);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_FILTER_RW_REGIONS_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_FILTER_RW_REGIONS_RETRIES, host->base.port, retries);
	}
}

/**
 * Clear all read/write regions in the SPI filter.
 *
 * This call will spin indefinitely until successful.  Failures in this sequence can leave the
 * filter and flash in an inconsistent state.  This must be completely successful before allowing
 * the host to access the flash.
 *
 * @param host The host processor instance being updated.
 */
static void host_processor_dual_clear_rw (struct host_processor_dual *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->filter->clear_filter_rw_regions (host->filter);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_CLEAR_RW_REGIONS_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_CLEAR_RW_REGIONS_RETRIES, host->base.port, retries);
	}
}

/**
 * Update the filter to use the current read-only and read/write flash devices.
 *
 * This call will spin indefinitely until successful.  Failures in this sequence can leave the
 * filter and flash in an inconsistent state.  This must be completely successful before allowing
 * the host to access the flash.
 *
 * @param host The host processor instance being updated.
 */
static void host_processor_dual_config_flash (struct host_processor_dual *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->config_spi_filter_flash_devices (host->flash);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_CONFIG_FLASH_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_CONFIG_FLASH_RETRIES, host->base.port, retries);
	}
}

/**
 * Update the flash and the filter to switch the read-only and read/write flash devices.
 *
 * This call will spin indefinitely until successful.  Failures in this sequence can leave the
 * filter and flash in an inconsistent state.  This must be completely successful before allowing
 * the host to access the flash.
 *
 * @param host The host processor instance being updated.
 * @param rw_list The list of read/write regions defined on the new flash.
 * @param pfm Manager to use for PFM activation.
 * @param no_migrate Flag to indicate data migration should not happen.
 */
static void host_processor_dual_swap_flash (struct host_processor_dual *host,
	struct pfm_read_write_regions *rw_list, struct pfm_manager *pfm, bool no_migrate)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->swap_flash_devices (host->flash, (!no_migrate) ? rw_list : NULL, pfm);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_SWAP_FLASH_ERROR, host->base.port, status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_SWAP_FLASH_RETRIES, host->base.port, retries);
	}

	host_processor_dual_config_rw (host, rw_list);

	host_state_manager_set_run_time_validation (host->state, HOST_STATE_PREVALIDATED_NONE);
}

/**
 * Validate the flash against a single PFM.
 *
 * @param host The host processor instance to use for validation.
 * @param hash The hash engine to use for validation.
 * @param rsa The RSA engine to use for signature verification.
 * @param pfm The PFM that will be used to validate the flash.
 * @param active The current active PFM to use for read-only validation optimization.
 * @param is_pending Flag indicating if the validation PFM is pending activation.
 * @param is_bypass Flag indicating if the processor is running in bypass mode or only has a pending
 * PFM available.
 * @param skip_ro Flag indicating the read-only validation should be skipped.
 * @param skip_ro_confg Flag indicating the SPI filter configuration for read-only validation should
 * be skipped.
 * @param apply_filter_cfg Flag indicating if the SPI filter configuration should be applied upon
 * successful validation.
 * @param is_validated Flag indicating if the read/write flash has already been validated against
 * the PFM.
 * @param config_fail Output flag indicating the error was not during validation.
 *
 * @return 0 if the flash was successfully validated or an error code.
 */
static int host_processor_dual_validate_flash (struct host_processor_dual *host,
	struct hash_engine *hash, struct rsa_engine *rsa, struct pfm *pfm, struct pfm *active,
	bool is_pending, bool is_bypass, bool skip_ro, bool skip_ro_config, bool apply_filter_cfg,
	bool is_validated, bool *config_fail)
{
	struct pfm_read_write_regions rw_list;
	int status = HOST_PROCESSOR_RW_SKIPPED;
	int dirty_fail = 0;
	bool checked_rw = true;
	bool pfm_dirty = host_state_manager_is_pfm_dirty (host->state);

	if (!is_bypass && host_state_manager_is_inactive_dirty (host->state)) {
		if (!is_validated) {
			host_state_manager_set_run_time_validation (host->state, HOST_STATE_PREVALIDATED_NONE);
			status = host->flash->validate_read_write_flash (host->flash, pfm, hash, rsa, &rw_list);
		}
		else {
			status = host->flash->get_flash_read_write_regions (host->flash, pfm, true, &rw_list);
		}

		if (is_pending) {
			debug_log_create_entry (
				(status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
				DEBUG_LOG_COMPONENT_HOST_FW,
				(is_validated) ?
					HOST_LOGGING_PENDING_ACTIVATE_FW_UPDATE :
					HOST_LOGGING_PENDING_VERIFY_FW_UPDATE,
				host->base.port, status);
		}
		else {
			debug_log_create_entry (
				(status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
				DEBUG_LOG_COMPONENT_HOST_FW,
				(is_validated) ?
					HOST_LOGGING_ACTIVE_ACTIVATE_FW_UPDATE :
					HOST_LOGGING_ACTIVE_VERIFY_FW_UPDATE,
				host->base.port, status);
		}

		if (status == 0) {
			if (apply_filter_cfg) {
				if (is_pending) {
					host_processor_dual_swap_flash (host, &rw_list, host->pfm, false);
				}
				else {
					host_processor_dual_swap_flash (host, &rw_list, NULL, false);
				}

				observable_notify_observers (&host->base.observable,
					offsetof (struct host_processor_observer, on_active_mode));
			}
			else {
				status = host->filter->clear_flash_dirty_state (host->filter);
				if (status == 0) {
					if (is_pending) {
						host_state_manager_set_pfm_dirty (host->state, false);
						host_state_manager_set_run_time_validation (host->state,
							HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
					}
					else {
						host_state_manager_set_run_time_validation (host->state,
							HOST_STATE_PREVALIDATED_FLASH);
					}
				}
				else {
					*config_fail = true;
				}
			}

			pfm->free_read_write_regions (pfm, &rw_list);

			if (status != 0) {
				goto exit;
			}
		}
		else if (IS_VALIDATION_FAILURE (status)) {
			dirty_fail = status;

			host_state_manager_set_run_time_validation (host->state, HOST_STATE_PREVALIDATED_NONE);

			if (!is_pending || is_validated) {
				status = host->filter->clear_flash_dirty_state (host->filter);
				if (status == 0) {
					host_state_manager_save_inactive_dirty (host->state, false);
				}
			}

			status = dirty_fail;
		}
		else if (is_pending && !is_validated) {
			host_state_manager_set_pfm_dirty (host->state, true);
		}
	}
	else {
		checked_rw = false;
	}

	if (!skip_ro && (status != 0) && (!is_pending || is_bypass || pfm_dirty)) {
		status = host->flash->validate_read_only_flash (host->flash, pfm, active, hash, rsa,
			is_bypass, &rw_list);

		if (is_pending) {
			debug_log_create_entry (
				(status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
				DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_PENDING_VERIFY_CURRENT, host->base.port, status);
		}
		else {
			debug_log_create_entry (
				(status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
				DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_ACTIVE_VERIFY_CURRENT, host->base.port, status);
		}

		if (status == 0) {
			if (is_bypass) {
				host_processor_dual_initialize_protection (host, &rw_list);
			}

			if (is_pending) {
				host->pfm->base.activate_pending_manifest (&host->pfm->base);

				if (dirty_fail != 0) {
					status = host->filter->clear_flash_dirty_state (host->filter);
					if (status == 0) {
						host_state_manager_save_inactive_dirty (host->state, false);
					}

					status = 0;
				}
			}

			if (apply_filter_cfg) {
				if (!is_bypass && !skip_ro_config) {
					host_processor_dual_config_flash (host);
				}

				if (is_bypass || !skip_ro_config) {
					host_processor_dual_config_rw (host, &rw_list);
				}

				observable_notify_observers (&host->base.observable,
					offsetof (struct host_processor_observer, on_active_mode));
			}

			pfm->free_read_write_regions (pfm, &rw_list);
		}
		else if (is_pending && IS_VALIDATION_FAILURE (status) &&
			(!checked_rw || (checked_rw && (dirty_fail != 0)))) {
			/* If there was a validation failure on both flash devices with the pending PFM, clear
			 * the dirty PFM state. */
			host_state_manager_set_pfm_dirty (host->state, false);
		}
	}

exit:
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
static int host_processor_dual_full_read_write_flash (struct host_processor_dual *host)
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
 * Internal function to apply bypass mode.
 *
 * @param host The host to configure for bypass mode.
 * @param swap_flash Flag to swap flash roles before configuring bypass mode.
 */
static void host_processor_dual_force_bypass_mode (struct host_processor_dual *host,
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

	host_processor_dual_config_bypass (host);
}

static int host_processor_dual_power_on_reset (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	struct pfm *active_pfm = NULL;
	struct pfm *pending_pfm = NULL;
	int status;

	if ((dual == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->lock);

	host_state_manager_set_pfm_dirty (dual->state, true);
	host_state_manager_set_bypass_mode (dual->state, false);

	status = host_processor_dual_initial_rot_flash_access (dual);
	if (status != 0) {
		goto exit_host;
	}

	active_pfm = dual->pfm->get_active_pfm (dual->pfm);
	pending_pfm = dual->pfm->get_pending_pfm (dual->pfm);

	if (active_pfm) {
		/* If there is at least an active PFM, use it for validation and don't allow bypass mode.
		 * If there is a pending PFM, run the initial validation using the pending PFM to see if it
		 * can be activated.  If validation fails, try validation again with the active PFM to see
		 * if the flash is bad or if the new PFM just doesn't work with it.
		 *
		 * A pending PFM requires a successful flash validation to be run against it before it is
		 * activated.  This prevents a scenario where the system is not allowed to boot because
		 * the flash and the PFM don't match. */
		if (pending_pfm) {
			status = host_processor_dual_validate_flash (dual, hash, rsa, pending_pfm, NULL, true,
				false, false, false, true, false, NULL);
		}
		else {
			host_state_manager_set_pfm_dirty (dual->state, false);
		}

		if (!pending_pfm || (status != 0)) {
			status = host_processor_dual_validate_flash (dual, hash, rsa, active_pfm, NULL, false,
				false, false, false, true, false, NULL);
			if (status != 0) {
				goto exit;
			}
		}
	}
	else if (pending_pfm) {
		/* Even when there is no active PFM, the pending PFM needs a successful validation to be run
		 * before it becomes the active PFM.  If validation fails with no active PFM available,
		 * revert to bypass mode.  Without an active PFM, dirty flash is meaningless. */
		status = host_processor_dual_validate_flash (dual, hash, rsa, pending_pfm, NULL, true, true,
			false, false, true, false, NULL);
		if (status != 0) {
			if (!IS_VALIDATION_FAILURE (status)) {
				goto exit;
			}
			else {
				host_processor_dual_config_bypass (dual);
				status = 0;
			}
		}
	}
	else {
		/* When there is no PFM available, run the system in bypass mode.  Dirty flash is
		 * meaningless without a PFM. */
		dual->filter->clear_flash_dirty_state (dual->filter);
		host_state_manager_save_inactive_dirty (dual->state, false);
		host_state_manager_set_pfm_dirty (dual->state, false);

		host_processor_dual_config_bypass (dual);
	}

exit:
	if (active_pfm) {
		dual->pfm->free_pfm (dual->pfm, active_pfm);
	}
	if (pending_pfm) {
		dual->pfm->free_pfm (dual->pfm, pending_pfm);
	}
	if (status != 0) {
		platform_mutex_unlock (&dual->lock);
		return status;
	}

exit_host:
	host_processor_dual_set_host_flash_access (dual);

	platform_mutex_unlock (&dual->lock);
	return status;
}

static int host_processor_dual_soft_reset (struct host_processor *host, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	struct pfm *active_pfm;
	struct pfm *pending_pfm;
	int status = 0;
	enum host_state_prevalidated flash_checked;
	bool prevalidated;
	bool bypass;
	bool only_validated = false;
	bool notified = false;

	if ((dual == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if (!host_state_manager_is_flash_supported (dual->state)) {
		return HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
	}

	platform_mutex_lock (&dual->lock);

	active_pfm = dual->pfm->get_active_pfm (dual->pfm);
	pending_pfm = dual->pfm->get_pending_pfm (dual->pfm);

	bypass = host_state_manager_is_bypass_mode (dual->state);

	if (pending_pfm ||
		(active_pfm && (host_state_manager_is_inactive_dirty (dual->state) || bypass))) {
		if (active_pfm && !host_state_manager_is_inactive_dirty (dual->state) &&
			!host_state_manager_is_pfm_dirty (dual->state) && !bypass) {
			goto exit;
		}

		if (!dual->reset_pulse) {
			dual->control->hold_processor_in_reset (dual->control, true);
		}

		status = dual->flash->set_flash_for_rot_access (dual->flash, dual->control);
		if (status != 0) {
			goto return_flash;
		}

		if (bypass) {
			host_state_manager_set_run_time_validation (dual->state, HOST_STATE_PREVALIDATED_NONE);
		}
		flash_checked = host_state_manager_get_run_time_validation (dual->state);

		if (pending_pfm) {
			if (bypass) {
				prevalidated = false;
			}
			else {
				switch (flash_checked) {
					case HOST_STATE_PREVALIDATED_FLASH_AND_PFM:
						prevalidated = !host_state_manager_is_pfm_dirty (dual->state);
						break;

					case HOST_STATE_PREVALIDATED_FLASH:
						if (!host_state_manager_is_pfm_dirty (dual->state)) {
							status = HOST_PROCESSOR_NOTHING_TO_VERIFY;
						}
						/* no break */

					default:
						prevalidated = false;
						break;
				}
			}

			if (status == 0) {
				only_validated = prevalidated;
				status = host_processor_dual_validate_flash (dual, hash, rsa, pending_pfm,
					bypass ? NULL : active_pfm, true, !active_pfm || bypass, only_validated, true,
					true, prevalidated, NULL);
			}
		}
		else {
			host_state_manager_set_pfm_dirty (dual->state, false);
		}

		if (!pending_pfm || (active_pfm && (status != 0) && !only_validated &&
			(host_state_manager_is_inactive_dirty (dual->state) || bypass))) {
			if (flash_checked == HOST_STATE_PREVALIDATED_FLASH) {
				prevalidated = true;
				host_state_manager_set_run_time_validation (dual->state,
					HOST_STATE_PREVALIDATED_FLASH);
			}
			else {
				prevalidated = false;
			}

			status = host_processor_dual_validate_flash (dual, hash, rsa, active_pfm, NULL, false,
				bypass, !bypass, true, true, prevalidated, NULL);
		}

return_flash:
		observable_notify_observers (&dual->base.observable,
			offsetof (struct host_processor_observer, on_soft_reset));
		notified = true;

		host_processor_dual_set_host_flash_access (dual);

		if (dual->reset_pulse) {
			dual->control->hold_processor_in_reset (dual->control, true);
			platform_msleep (dual->reset_pulse);
		}
	}
	else {
		host_state_manager_set_pfm_dirty (dual->state, false);
		if (!active_pfm && !pending_pfm) {
			dual->filter->clear_flash_dirty_state (dual->filter);
			host_state_manager_save_inactive_dirty (dual->state, false);
		}
	}

exit:
	if (!notified) {
		observable_notify_observers (&dual->base.observable,
			offsetof (struct host_processor_observer, on_soft_reset));
	}

	if (active_pfm) {
		dual->pfm->free_pfm (dual->pfm, active_pfm);
	}
	if (pending_pfm) {
		dual->pfm->free_pfm (dual->pfm, pending_pfm);
	}

	/* Some implementations will set the processor reset independently of this flow, so we need
	 * to be sure the reset is always released after soft reset processing.  Releasing the reset
	 * in cases where the reset is never set is not an issue. */
	dual->control->hold_processor_in_reset (dual->control, false);

	platform_mutex_unlock (&dual->lock);
	return status;
}

static int host_processor_dual_run_time_verification (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	struct pfm *active_pfm;
	struct pfm *pending_pfm;
	int status;
	bool config_fail = false;
	int validation_status = HOST_PROCESSOR_NOTHING_TO_VERIFY;
	enum host_state_prevalidated validated;
	bool bypass;

	if ((dual == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if (!host_state_manager_is_flash_supported (dual->state)) {
		return HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
	}

	platform_mutex_lock (&dual->lock);

	active_pfm = dual->pfm->get_active_pfm (dual->pfm);
	pending_pfm = dual->pfm->get_pending_pfm (dual->pfm);

	bypass = host_state_manager_is_bypass_mode (dual->state);

	status = dual->flash->set_flash_for_rot_access (dual->flash, dual->control);
	if (status != 0) {
		validation_status = status;
		goto exit;
	}

	if (pending_pfm ||
		(active_pfm && (host_state_manager_is_inactive_dirty (dual->state) || bypass))) {
		if (active_pfm && !host_state_manager_is_inactive_dirty (dual->state) &&
			!host_state_manager_is_pfm_dirty (dual->state) && !bypass) {
			goto exit;
		}

		if (bypass) {
			host_state_manager_set_run_time_validation (dual->state, HOST_STATE_PREVALIDATED_NONE);
		}
		validated = host_state_manager_get_run_time_validation (dual->state);

		if (pending_pfm) {
			if (host_state_manager_is_pfm_dirty (dual->state) ||
				(validated == HOST_STATE_PREVALIDATED_NONE)) {
				validation_status = host_processor_dual_validate_flash (dual, hash, rsa,
					pending_pfm, bypass ? NULL : active_pfm, true, !active_pfm || bypass, false,
					true, !active_pfm || bypass, false, &config_fail);
				if (config_fail) {
					goto exit;
				}
			}
		}

		if (!pending_pfm || (active_pfm && (validation_status != 0) &&
			(bypass || (validation_status != HOST_PROCESSOR_NOTHING_TO_VERIFY)))) {
			if (!pending_pfm) {
				host_state_manager_set_pfm_dirty (dual->state, false);
			}

			if (active_pfm && (host_state_manager_is_inactive_dirty (dual->state) || bypass)) {
				if (validated != HOST_STATE_PREVALIDATED_FLASH) {
					validation_status = host_processor_dual_validate_flash (dual, hash, rsa,
						active_pfm, NULL, false, bypass, !bypass, true, bypass, false,
						&config_fail);
				}
				else {
					host_state_manager_set_run_time_validation (dual->state, validated);
				}
			}
		}
	}
	else {
		host_state_manager_set_pfm_dirty (dual->state, false);
		if (!active_pfm && !pending_pfm) {
			dual->filter->clear_flash_dirty_state (dual->filter);
			host_state_manager_save_inactive_dirty (dual->state, false);
		}
	}

exit:
	status = dual->flash->set_flash_for_host_access (dual->flash, dual->control);
	if (status != 0) {
		validation_status = status;
	}

	if (active_pfm) {
		dual->pfm->free_pfm (dual->pfm, active_pfm);
	}
	if (pending_pfm) {
		dual->pfm->free_pfm (dual->pfm, pending_pfm);
	}

	platform_mutex_unlock (&dual->lock);
	return validation_status;
}

static int host_processor_dual_flash_rollback (struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa, bool disable_bypass, bool no_reset)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	struct pfm *active_pfm;
	struct pfm_read_write_regions rw_list;
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
				status = dual->flash->validate_read_write_flash (dual->flash, active_pfm, hash,
					rsa, &rw_list);
				if (status == 0) {
					host_processor_dual_swap_flash (dual, &rw_list, NULL, true);
					active_pfm->free_read_write_regions (active_pfm, &rw_list);

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
		host_processor_dual_set_host_flash_access (dual);

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

static int host_processor_dual_get_next_reset_verification_actions (struct host_processor *host)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	struct pfm *active_pfm;
	struct pfm *pending_pfm;
	int action = HOST_PROCESSOR_ACTION_NONE;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	active_pfm = dual->pfm->get_active_pfm (dual->pfm);
	pending_pfm = dual->pfm->get_pending_pfm (dual->pfm);

	if (pending_pfm) {
		if (host_state_manager_is_bypass_mode (dual->state) || !active_pfm) {
			action = HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH;
		}
		else {
			if (!host_state_manager_is_pfm_dirty (dual->state)) {
				switch (host_state_manager_get_run_time_validation (dual->state)) {
					case HOST_STATE_PREVALIDATED_FLASH_AND_PFM:
						action = HOST_PROCESSOR_ACTION_ACTIVATE_PFM_AND_UPDATE;
						break;

					case HOST_STATE_PREVALIDATED_FLASH:
							action = HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE;
						break;

					case HOST_STATE_PREVALIDATED_NONE:
						if (host_state_manager_is_inactive_dirty (dual->state)) {
							action = HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE;
						}
						break;
				}
			}
			else if (host_state_manager_is_inactive_dirty (dual->state)) {
				action = HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE;
			}
			else {
				action = HOST_PROCESSOR_ACTION_VERIFY_PFM;
			}
		}
	}
	else if (active_pfm) {
		if (host_state_manager_is_bypass_mode (dual->state)) {
			action = HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH;
		}
		else if (host_state_manager_is_inactive_dirty (dual->state)) {
			if (host_state_manager_get_run_time_validation (dual->state) ==
				HOST_STATE_PREVALIDATED_FLASH) {
				action = HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE;
			}
			else {
				action = HOST_PROCESSOR_ACTION_VERIFY_UPDATE;
			}
		}
	}

	if (active_pfm) {
		dual->pfm->free_pfm (dual->pfm, active_pfm);
	}
	if (pending_pfm) {
		dual->pfm->free_pfm (dual->pfm, pending_pfm);
	}
	return action;
}

static int host_processor_dual_needs_config_recovery (struct host_processor *host)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	int status;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = dual->flash->host_has_flash_access (dual->flash, dual->control);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	return !status;
}

static int host_processor_dual_apply_recovery_image (struct host_processor *host, bool no_reset)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;
	struct recovery_image *active_image;
	struct spi_flash *ro_flash;
	int status = 0;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->lock);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
		HOST_LOGGING_RECOVERY_STARTED, dual->base.port, 0);

	if (!host_state_manager_is_bypass_mode (dual->state) &&
		!host_state_manager_is_flash_supported (dual->state)) {
		status = HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
		goto free_lock;
	}

	if (!dual->recovery) {
		status = HOST_PROCESSOR_RECOVERY_UNSUPPORTED;
		goto free_lock;
	}

	active_image = dual->recovery->get_active_recovery_image (dual->recovery);
	if (active_image == NULL) {
		status = HOST_PROCESSOR_NO_RECOVERY_IMAGE;
		goto free_lock;
	}

	if (!no_reset && !dual->reset_pulse) {
		dual->control->hold_processor_in_reset (dual->control, true);
	}

	status = dual->flash->set_flash_for_rot_access (dual->flash, dual->control);
	if (status != 0) {
		goto return_flash;
	}

	ro_flash = dual->flash->get_read_only_flash (dual->flash);

	/* Trigger the notification as soon as the flash is modified for the recovery image. */
	observable_notify_observers (&dual->base.observable,
		offsetof (struct host_processor_observer, on_recovery));

	status = spi_flash_chip_erase (ro_flash);
	if (status != 0) {
		goto return_flash;
	}

	status = active_image->apply_to_flash (active_image, ro_flash);
	if (status != 0) {
		goto return_flash;
	}

	if (!host_state_manager_is_bypass_mode (dual->state)) {
		host_processor_dual_clear_rw (dual);
		host_processor_dual_config_flash (dual);
	}

return_flash:
	host_processor_dual_set_host_flash_access (dual);

	if (!no_reset) {
		if (dual->reset_pulse) {
			dual->control->hold_processor_in_reset (dual->control, true);
			platform_msleep (dual->reset_pulse);
		}
		dual->control->hold_processor_in_reset (dual->control, false);
	}

	if (active_image) {
		dual->recovery->free_recovery_image (dual->recovery, active_image);
	}

free_lock:
	if (status == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_COMPLETED, dual->base.port, 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_FAILED, status, dual->base.port);
	}

	platform_mutex_unlock (&dual->lock);
	return status;
}

static int host_processor_dual_bypass_mode (struct host_processor *host, bool swap_flash)
{
	struct host_processor_dual *dual = (struct host_processor_dual*) host;

	if (dual == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&dual->lock);
	host_processor_dual_force_bypass_mode (dual, swap_flash);
	host_processor_dual_set_host_flash_access (dual);
	platform_mutex_unlock (&dual->lock);

	return 0;
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
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_dual_init_internal (struct host_processor_dual *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status;

	if ((host == NULL) || (control == NULL) || (flash == NULL) || (state == NULL) ||
		(filter == NULL) || (pfm == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (host, 0, sizeof (struct host_processor_dual));

	status = host_processor_init (&host->base);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&host->lock);
	if (status != 0) {
		return status;
	}

	host->base.power_on_reset = host_processor_dual_power_on_reset;
	host->base.soft_reset = host_processor_dual_soft_reset;
	host->base.run_time_verification = host_processor_dual_run_time_verification;
	host->base.flash_rollback = host_processor_dual_flash_rollback;
	host->base.get_next_reset_verification_actions =
		host_processor_dual_get_next_reset_verification_actions;
	host->base.needs_config_recovery = host_processor_dual_needs_config_recovery;
	host->base.apply_recovery_image = host_processor_dual_apply_recovery_image;
	host->base.bypass_mode = host_processor_dual_bypass_mode;

	host->control = control;
	host->flash = flash;
	host->state = state;
	host->filter = filter;
	host->pfm = pfm;
	host->recovery = recovery;

	return 0;
}

/**
 * Internal function to initialize the core components for host processor actions.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed for 100ms.
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
int host_processor_dual_init_pulse_reset_internal (struct host_processor_dual *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status = host_processor_dual_init_internal (host, control, flash, state, filter, pfm,
		recovery);
	if (status != 0) {
		return status;
	}

	host->reset_pulse = 100;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions.
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
int host_processor_dual_init (struct host_processor_dual *host, struct host_control *control,
	struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status = host_processor_dual_init_internal (host, control, flash, state, filter, pfm,
		recovery);
	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_dual_full_read_write_flash;

	return 0;
}

/**
 * Initialize the interface for executing host processor actions.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed for 100ms.
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
int host_processor_dual_init_pulse_reset (struct host_processor_dual *host,
	struct host_control *control, struct host_flash_manager *flash, struct state_manager *state,
	struct spi_filter_interface *filter, struct pfm_manager *pfm,
	struct recovery_image_manager *recovery)
{
	int status = host_processor_dual_init_pulse_reset_internal (host, control, flash, state, filter,
		pfm, recovery);
	if (status != 0) {
		return status;
	}

	host->internal.enable_bypass_mode = host_processor_dual_full_read_write_flash;

	return 0;
}

/**
 * Release the resources used by the host processor interface.
 *
 * @param host The host processor instance to release.
 */
void host_processor_dual_release (struct host_processor_dual *host)
{
	if (host) {
		platform_mutex_free (&host->lock);
		host_processor_release (&host->base);
	}
}
