// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_logging.h"
#include "host_processor.h"
#include "host_processor_filtered.h"


/**
 * Initialize the common components for host processor actions using a SPI filter.
 *
 * @param host The host processor instance to initialize.
 * @param state Variable context for host processor handling.  This must be uninitialized.
 * @param control The interface for controlling the host processor.
 * @param flash The manager for the flash devices for the host processor.
 * @param host_state The state information for the host.
 * @param filter The SPI filter controlling flash access for the host processor.
 * @param pfm The manager for PFMs for the host processor.
 * @param recovery The manager for recovery of the host processor.
 * @param reset_pulse Length of the reset pulse to use after authentication has completed, in
 * milliseconds.  If 0, the processor is held in reset during authentication.
 * @param reset_flash The flag to indicate that host flash should be reset based on every
 * host processor reset.
 *
 * @return 0 if the host processor interface was successfully initialized or an error code.
 */
int host_processor_filtered_init (struct host_processor_filtered *host,
	struct host_processor_filtered_state *state, const struct host_control *control,
	const struct host_flash_manager *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct pfm_manager *pfm,
	struct recovery_image_manager *recovery, int reset_pulse, bool reset_flash)
{
	int status;

	if ((host == NULL) || (state == NULL) || (control == NULL) || (flash == NULL) ||
		(host_state == NULL) || (filter == NULL) || (pfm == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (host, 0, sizeof (*host));
	memset (state, 0, sizeof (*state));

	status = host_processor_init (&host->base, &state->base);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&state->lock);
	if (status != 0) {
		host_processor_release (&host->base);

		return status;
	}

	host->state = state;
	host->control = control;
	host->flash = flash;
	host->host_state = host_state;
	host->filter = filter;
	host->pfm = pfm;
	host->recovery = recovery;
	host->reset_pulse = reset_pulse;
	host->reset_flash = reset_flash;

	return 0;
}

/**
 * Initialize only the variable state for common host processor actions using a SPI filter.  The
 * rest of the instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param host The host processor that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int host_processor_filtered_init_state (const struct host_processor_filtered *host)
{
	int status;

	if ((host == NULL) || (host->state == NULL) || (host->control == NULL) ||
		(host->flash == NULL) || (host->host_state == NULL) || (host->filter == NULL) ||
		(host->pfm == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if (host->reset_pulse < 0) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (host->state, 0, sizeof (*host->state));

	status = host_processor_init_state (&host->base);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&host->state->lock);
	if (status != 0) {
		host_processor_release (&host->base);

		return status;
	}

	return 0;
}

/**
 * Release the resources used for common host processor handling.
 *
 * @param host The common components to release.
 */
void host_processor_filtered_release (const struct host_processor_filtered *host)
{
	if (host) {
		platform_mutex_free (&host->state->lock);
		host_processor_release (&host->base);
	}
}

/**
 * Take the SPI flash from the host for the first time and configure the SPI filter for the devices.
 * If the flash cannot be successfully initialized after several retries, this function will mark
 * the flash an unsupported and return an error.  Marking the flash as unsupported will prevent
 * other workflows that use host flash to fail.
 *
 * @param host The host processor instance.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int host_processor_filtered_initial_rot_flash_access (
	const struct host_processor_filtered *host)
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
			host_state_manager_set_unsupported_flash (host->host_state, true);

			return status;
		}

		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_ROT_FLASH_ACCESS_ERROR, host_processor_get_port (&host->base), status);
			log_status = status;
		}
	} while ((status != 0) && (retries < 5));

	if (status != 0) {
		/* The flash could not be initialized.  Treat it as unsupported. */
		host_state_manager_set_unsupported_flash (host->host_state, true);

		return status;
	}
	else if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_ROT_FLASH_ACCESS_RETRIES, host_processor_get_port (&host->base), retries);
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
			(status == HOST_FLASH_MGR_MISMATCH_SIZES) ||
			(status == HOST_FLASH_MGR_MISMATCH_ADDR_MODE)) {
			host_state_manager_set_unsupported_flash (host->host_state, true);

			return status;
		}

		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_FILTER_FLASH_TYPE_ERROR, host_processor_get_port (&host->base),
				status);
			log_status = status;
		}
	} while ((status != 0) && (retries < 5));

	if (status != 0) {
		/* The filter could not be configured.  Treat the flash as unsupported. */
		host_state_manager_set_unsupported_flash (host->host_state, true);

		return status;
	}
	else if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_FILTER_FLASH_TYPE_RETRIES, host_processor_get_port (&host->base), retries);
	}

	host_state_manager_set_unsupported_flash (host->host_state, false);

	return 0;
}

/**
 * Give the SPI flash back to the host.  This function will spin indefinitely until this operation
 * is successful.  Until it succeeds, the host will never be able to boot.
 *
 * @param host The host processor instance.
 */
void host_processor_filtered_set_host_flash_access (const struct host_processor_filtered *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->set_flash_for_host_access (host->flash, host->control);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_HOST_FLASH_ACCESS_ERROR, host_processor_get_port (&host->base),
				status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_HOST_FLASH_ACCESS_RETRIES, host_processor_get_port (&host->base), retries);
	}
}

/**
 * Configure the filter for bypass mode.
 *
 * This will spin indefinitely until it is successful.  Setting bypass mode is only dependent on the
 * SPI filter, which should be highly reliable.  Plus, this mode is one that needs to work.  If the
 * filter is being configured in bypass mode, that means that no other flow will successfully
 * execute.
 *
 * @param host The host processor instance being updated.
 */
void host_processor_filtered_config_bypass (const struct host_processor_filtered *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->internal.enable_bypass_mode (host);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_BYPASS_MODE_ERROR, host_processor_get_port (&host->base), status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_BYPASS_MODE_RETRIES, host_processor_get_port (&host->base), retries);
	}

	host_state_manager_set_bypass_mode (host->host_state, true);
	observable_notify_observers (&host->base.state->observable,
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
static void host_processor_filtered_initialize_protection (
	const struct host_processor_filtered *host, const struct host_flash_manager_rw_regions *rw_list)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->initialize_flash_protection (host->flash, rw_list);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_INIT_PROTECTION_ERROR, host_processor_get_port (&host->base), status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_INIT_PROTECTION_RETRIES, host_processor_get_port (&host->base), retries);
	}

	host_state_manager_set_bypass_mode (host->host_state, false);
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
static void host_processor_filtered_config_rw (const struct host_processor_filtered *host,
	const struct host_flash_manager_rw_regions *rw_list)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host_fw_config_spi_filter_read_write_regions_multiple_fw (host->filter,
			rw_list->writable, rw_list->count);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_FILTER_RW_REGIONS_ERROR, host_processor_get_port (&host->base),
				status);
			log_status = status;

			if (status == SPI_FILTER_UNSUPPORTED_RW_REGION) {
				/* The current R/W configuration is not supported by the filter.  By this point,
				 * everything is expecting to run the new FW, so just log this error and move on.
				 * Without correct R/W filtering, the host FW may not operate correctly, but this
				 * should not be a production scenario with validated FW. */
				return;
			}
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_FILTER_RW_REGIONS_RETRIES, host_processor_get_port (&host->base), retries);
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
static void host_processor_filtered_config_flash (const struct host_processor_filtered *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->config_spi_filter_flash_devices (host->flash);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_CONFIG_FLASH_ERROR, host_processor_get_port (&host->base), status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_CONFIG_FLASH_RETRIES, host_processor_get_port (&host->base), retries);
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
void host_processor_filtered_swap_flash (const struct host_processor_filtered *host,
	const struct host_flash_manager_rw_regions *rw_list, const struct pfm_manager *pfm,
	bool no_migrate)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->flash->swap_flash_devices (host->flash, (!no_migrate) ? rw_list : NULL, pfm);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_SWAP_FLASH_ERROR, host_processor_get_port (&host->base), status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_SWAP_FLASH_RETRIES, host_processor_get_port (&host->base), retries);
	}

	host_processor_filtered_config_rw (host, rw_list);

	host_state_manager_set_run_time_validation (host->host_state, HOST_STATE_PREVALIDATED_NONE);
}

/**
 * Restore read/write data for the current read only image.
 *
 * Failures in this flow will cause retries, but will not retry indefinitely.  If the read/write
 * regions cannot be restored, system boot will be allowed to proceed and the host firmware must be
 * able to handle the possible data corruption or have some other recovery flow.
 *
 * @param host The host processor instance to execute.
 * @param rw_list The list of read/write regions defined for the current image.  This can be null if
 * the list is not already known.
 * @param pfm The PFM to use to determine the read/write regions.  Set to null to use a
 * predetermined list.
 *
 * @return 0 if the data was successfully restored or an error code.
 */
int host_processor_filtered_restore_read_write_data (const struct host_processor_filtered *host,
	struct host_flash_manager_rw_regions *rw_list, const struct pfm *pfm)
{
	struct host_flash_manager_rw_regions restore;
	int status;
	int retries = 3;

	if (pfm != NULL) {
		if (rw_list == NULL) {
			rw_list = &restore;
		}

		status = host->flash->get_flash_read_write_regions (host->flash, pfm, false, rw_list);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_RW_RESTORE_START, host_processor_get_port (&host->base), status);

			return status;
		}
	}

	do {
		/* Restoring the R/W data could corrupt prevalidated images on flash, so clear any
		 * prevalidated state. */
		host_state_manager_set_run_time_validation (host->host_state, HOST_STATE_PREVALIDATED_NONE);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RW_RESTORE_START, host_processor_get_port (&host->base), 0);

		status = host->flash->restore_flash_read_write_regions (host->flash, rw_list);

		debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
			DEBUG_LOG_COMPONENT_HOST_FW, HOST_LOGGING_RW_RESTORE_FINISH,
			host_processor_get_port (&host->base), status);
	} while ((status != 0) && (--retries > 0));

	if (pfm != NULL) {
		host->flash->free_read_write_regions (host->flash, rw_list);
	}

	return status;
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
 * @param single Flag indicating if only a single validation should be run against the PFM, or if
 * both flashes should be checked.
 * @param config_fail Output flag indicating the error was not during validation.
 *
 * @return 0 if the flash was successfully validated or an error code.
 */
static int host_processor_filtered_validate_flash (const struct host_processor_filtered *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, const struct pfm *pfm,
	const struct pfm *active, bool is_pending, bool is_bypass, bool skip_ro, bool skip_ro_config,
	bool apply_filter_cfg, bool is_validated, bool single, bool *config_fail)
{
	struct host_flash_manager_rw_regions rw_list;
	int status = HOST_PROCESSOR_RW_SKIPPED;
	int dirty_fail = 0;
	bool checked_rw = true;
	bool failed_rw = false;
	bool pfm_dirty = host_state_manager_is_pfm_dirty (host->host_state);

	if (!is_bypass && host_state_manager_is_inactive_dirty (host->host_state)) {
		if (!is_validated) {
			host_state_manager_set_run_time_validation (host->host_state,
				HOST_STATE_PREVALIDATED_NONE);
			status = host->flash->validate_read_write_flash (host->flash, pfm, hash, rsa, &rw_list);
		}
		else {
			status = host->flash->get_flash_read_write_regions (host->flash, pfm, true, &rw_list);
		}
		if (status != 0) {
			failed_rw = true;
		}

		if (is_pending) {
			debug_log_create_entry ((status ==
				0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
				DEBUG_LOG_COMPONENT_HOST_FW, (is_validated) ?
					HOST_LOGGING_PENDING_ACTIVATE_FW_UPDATE :
					HOST_LOGGING_PENDING_VERIFY_FW_UPDATE, host_processor_get_port (&host->base),
				status);
		}
		else {
			debug_log_create_entry ((status ==
				0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
				DEBUG_LOG_COMPONENT_HOST_FW, (is_validated) ?
					HOST_LOGGING_ACTIVE_ACTIVATE_FW_UPDATE :
					HOST_LOGGING_ACTIVE_VERIFY_FW_UPDATE, host_processor_get_port (&host->base),
				status);
		}

		if (status == 0) {
			if (apply_filter_cfg) {
				if (is_pending) {
					host_processor_filtered_swap_flash (host, &rw_list, host->pfm, false);
				}
				else {
					host_processor_filtered_swap_flash (host, &rw_list, NULL, false);
				}

				observable_notify_observers (&host->base.state->observable,
					offsetof (struct host_processor_observer, on_active_mode));
			}
			else {
				status = host->filter->clear_flash_dirty_state (host->filter);
				if (status == 0) {
					if (is_pending) {
						host_state_manager_set_pfm_dirty (host->host_state, false);
						host_state_manager_set_run_time_validation (host->host_state,
							HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
					}
					else {
						host_state_manager_set_run_time_validation (host->host_state,
							HOST_STATE_PREVALIDATED_FLASH);
					}
				}
				else {
					*config_fail = true;
				}
			}

			host->flash->free_read_write_regions (host->flash, &rw_list);

			if (status != 0) {
				goto exit;
			}
		}
		else {
			if (!single && ((skip_ro && !is_pending) || is_validated) && apply_filter_cfg) {
				/* R/W verification failed with no RO verification going to take place.  We need to
				 * restore R/W regions here using the active PFM. */
				host_processor_filtered_restore_read_write_data (host, NULL,
					(is_pending) ? active : pfm);
			}

			if (IS_VALIDATION_FAILURE (status)) {
				dirty_fail = status;

				if (single && is_pending) {
					/* Validation is only run against one flash, so clear the PFM dirty state. */
					host_state_manager_set_pfm_dirty (host->host_state, false);
				}
			}
			else if (is_pending && !is_validated) {
				host_state_manager_set_pfm_dirty (host->host_state, true);
			}
		}
	}
	else {
		checked_rw = false;
	}

	if (!skip_ro && (status != 0) && (!is_pending || is_bypass || pfm_dirty) &&
		(!single || !checked_rw)) {
		status = host->flash->validate_read_only_flash (host->flash, pfm, active, hash, rsa,
			is_bypass, &rw_list);

		if (is_pending) {
			debug_log_create_entry ((status ==
				0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
				DEBUG_LOG_COMPONENT_HOST_FW, HOST_LOGGING_PENDING_VERIFY_CURRENT,
				host_processor_get_port (&host->base), status);
		}
		else {
			debug_log_create_entry ((status ==
				0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
				DEBUG_LOG_COMPONENT_HOST_FW, HOST_LOGGING_ACTIVE_VERIFY_CURRENT,
				host_processor_get_port (&host->base), status);
		}

		if (status == 0) {
			if (is_bypass) {
				host_processor_filtered_initialize_protection (host, &rw_list);
			}
			else if (apply_filter_cfg && failed_rw) {
				host_processor_filtered_restore_read_write_data (host, &rw_list, NULL);
			}

			if (is_pending) {
				host->pfm->base.activate_pending_manifest (&host->pfm->base);
			}

			if (apply_filter_cfg) {
				if (!is_bypass && !skip_ro_config) {
					host_processor_filtered_config_flash (host);
				}

				host_processor_filtered_config_rw (host, &rw_list);

				observable_notify_observers (&host->base.state->observable,
					offsetof (struct host_processor_observer, on_active_mode));
			}

			host->flash->free_read_write_regions (host->flash, &rw_list);
		}
		else if (is_pending && IS_VALIDATION_FAILURE (status) &&
			(!checked_rw || (checked_rw && (dirty_fail != 0)))) {
			/* If there was a validation failure on both flash devices with the pending PFM, clear
			 * the dirty PFM state. */
			host_state_manager_set_pfm_dirty (host->host_state, false);
		}
	}

	/* Handle situations where the flash dirty state needs to be cleared.  Do this last to ensure
	 * all other operations fully complete before we wipe the indication that flash had been
	 * modified and needed authentication. */
	if ((dirty_fail != 0) &&
		(!single && checked_rw &&
		(!is_pending || is_validated || (status == 0) ||
		(is_pending && !active && skip_ro_config)))) {
		dirty_fail = host->filter->clear_flash_dirty_state (host->filter);
		if (dirty_fail == 0) {
			host_state_manager_save_inactive_dirty (host->host_state, false);
		}
	}

exit:

	return status;
}

/**
 * Check if the pending PFM is empty.  If so, clear the PFMs to force the filter into bypass mode.
 *
 * @param host The host instance to check.
 * @param active_pfm The active PFM for the host.
 * @param pending_pfm The pending PFM for the host.
 * @param empty_status Output for the status of the empty PFM check.
 *
 * @return 0 if the check was successful or an error code.
 */
static int host_processor_filtered_check_force_bypass_mode (
	const struct host_processor_filtered *host, const struct pfm **active_pfm,
	const struct pfm **pending_pfm, int *empty_status)
{
	int status;

	status = (*pending_pfm)->base.is_empty (&(*pending_pfm)->base);
	if (status == 1) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_CLEAR_PFMS, host_processor_get_port (&host->base), 0);

		if (*active_pfm) {
			host->pfm->free_pfm (host->pfm, *active_pfm);
			*active_pfm = NULL;
		}

		host->pfm->free_pfm (host->pfm, *pending_pfm);
		*pending_pfm = NULL;

		status = host->pfm->base.clear_all_manifests (&host->pfm->base);
		if (status != 0) {
			return status;
		}
	}
	else if (status != 0) {
		/* We could not determine the state of the pending PFM.  Remove it from being considered for
		 * validation flows. */
		host->pfm->free_pfm (host->pfm, *pending_pfm);
		*pending_pfm = NULL;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_CHECK_PENDING_FAILED, host_processor_get_port (&host->base), status);
	}

	*empty_status = status;

	return 0;
}

/**
 * Common handler for power-on reset events.
 *
 * @param host The host instance generating the event.
 * @param hash Hash engine for firmware validation.
 * @param rsa RSA engine for firmware signature verification.
 * @param single True to enable only a single validation against flash per PFM.
 *
 * @return 0 if the event was handled successfully or an error code.
 */
int host_processor_filtered_power_on_reset (const struct host_processor_filtered *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool single)
{
	const struct pfm *active_pfm = NULL;
	const struct pfm *pending_pfm = NULL;
	int status;

	if ((hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&host->state->lock);

	host_state_manager_set_pfm_dirty (host->host_state, true);
	host_state_manager_set_bypass_mode (host->host_state, false);

	status = host_processor_filtered_initial_rot_flash_access (host);
	if (status != 0) {
		goto exit_host;
	}

	active_pfm = host->pfm->get_active_pfm (host->pfm);
	pending_pfm = host->pfm->get_pending_pfm (host->pfm);

	if (pending_pfm) {
		int empty_status;

		status = host_processor_filtered_check_force_bypass_mode (host, &active_pfm, &pending_pfm,
			&empty_status);
		if (status != 0) {
			goto exit_host;
		}

		status = empty_status;
	}

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
			status = host_processor_filtered_validate_flash (host, hash, rsa, pending_pfm, NULL,
				true, false, false, false, true, false, single, NULL);
		}
		else if (status == 0) {
			host_state_manager_set_pfm_dirty (host->host_state, false);
		}

		if (!pending_pfm || (status != 0)) {
			status = host_processor_filtered_validate_flash (host, hash, rsa, active_pfm, NULL,
				false, false, false, false, true, false, single, NULL);
			if (status != 0) {
				goto exit;
			}
		}
	}
	else if (pending_pfm) {
		/* Even when there is no active PFM, the pending PFM needs a successful validation to be run
		 * before it becomes the active PFM.  If validation fails with no active PFM available,
		 * revert to bypass mode.  Without an active PFM, dirty flash is meaningless. */
		status = host_processor_filtered_validate_flash (host, hash, rsa, pending_pfm, NULL, true,
			true, false, false, true, false, single, NULL);
		if (status != 0) {
			if (!IS_VALIDATION_FAILURE (status)) {
				goto exit;
			}
			else {
				host_processor_filtered_config_bypass (host);
				status = 0;
			}
		}
	}
	else {
		/* When there is no PFM available, run the system in bypass mode.  Dirty flash is
		 * meaningless without a PFM. */
		host->filter->clear_flash_dirty_state (host->filter);
		host_state_manager_save_inactive_dirty (host->host_state, false);
		host_state_manager_set_pfm_dirty (host->host_state, false);

		host_processor_filtered_config_bypass (host);
		status = 0;
	}

exit:
	if (active_pfm) {
		host->pfm->free_pfm (host->pfm, active_pfm);
	}
	if (pending_pfm) {
		host->pfm->free_pfm (host->pfm, pending_pfm);
	}
	if (status != 0) {
		platform_mutex_unlock (&host->state->lock);

		return status;
	}

exit_host:
	host_processor_filtered_set_host_flash_access (host);

	platform_mutex_unlock (&host->state->lock);

	return status;
}

/**
 * Reset the host flash. The flash reset will retry a fixed number of times on failures unless the
 * reset command is unsupported.
 *
 * @param host The host processor instance.
 */
static void host_processor_filtered_reset_host_flash (const struct host_processor_filtered *host)
{
	int status = 0;
	int retries = 3;

	do {
		if (status != 0) {
			platform_msleep (100);
		}

		status = host->flash->reset_flash (host->flash);

		debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
			DEBUG_LOG_COMPONENT_HOST_FW, HOST_LOGGING_FLASH_RESET,
			host_processor_get_port (&host->base), status);
	} while (((status != 0) && (--retries > 0) && (status != SPI_FLASH_RESET_NOT_SUPPORTED)));
}

/**
 * Clear the PFM and host flash dirty states.
 *
 * @param host The host processor instance.
 * @param no_pfm Flag indicating if there is no active or pending PFM.
 */
static void host_processor_filtered_clear_host_dirty_state (
	const struct host_processor_filtered *host, bool no_pfm)
{
	host_state_manager_set_pfm_dirty (host->host_state, false);
	if (no_pfm) {
		host->filter->clear_flash_dirty_state (host->filter);
		host_state_manager_save_inactive_dirty (host->host_state, false);
	}
}

/**
 * Common handler for verification events that occur after the host has been initialized.
 *
 * @param host The host instance generating the event.
 * @param hash Hash engine for firmware validation.
 * @param rsa RSA engine for firmware signature verification.
 * @param single True to enable only a single validation against flash per PFM.
 * @param reset Flag indicating if the verification is being run in reset context.
 * @param bypass_status Status code to return when there are no PFMs available, which means no
 * validation is executed.
 *
 * @return 0 if the event was handled successfully or an error code.
 */
int host_processor_filtered_update_verification (const struct host_processor_filtered *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool single, bool reset,
	int bypass_status)
{
	const struct pfm *active_pfm;
	const struct pfm *pending_pfm;
	int status = 0;
	enum host_state_prevalidated flash_checked = HOST_STATE_PREVALIDATED_NONE;
	bool prevalidated;
	bool bypass;
	bool dirty;
	bool only_validated = false;
	bool notified = !reset;
	bool validate_flash;
	bool reset_flash = host->reset_flash && reset;
	bool no_pfm;
	bool no_state_change;

	if ((hash == NULL) || (rsa == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	if (!host_state_manager_is_flash_supported (host->host_state)) {
		return HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
	}

	platform_mutex_lock (&host->state->lock);

	active_pfm = host->pfm->get_active_pfm (host->pfm);
	pending_pfm = host->pfm->get_pending_pfm (host->pfm);
	if (!active_pfm && !pending_pfm) {
		status = bypass_status;
	}

	bypass = host_state_manager_is_bypass_mode (host->host_state);
	dirty = host_state_manager_is_inactive_dirty (host->host_state);

	no_pfm = !active_pfm && !pending_pfm;
	validate_flash = pending_pfm || (no_pfm && !bypass) || (active_pfm && (dirty || bypass));
	no_state_change = !dirty && !bypass && !host_state_manager_is_pfm_dirty (host->host_state) &&
		(active_pfm || (pending_pfm && !active_pfm));

	if (validate_flash || reset_flash) {
		/* If nothing has changed since the last validation, just exit. */
		if (!reset_flash && no_state_change) {
			goto exit;
		}

		if (reset && !host->reset_pulse) {
			host->control->hold_processor_in_reset (host->control, true);
		}

		status = host->flash->set_flash_for_rot_access (host->flash, host->control);
		if (reset_flash && (status == 0)) {
			host_processor_filtered_reset_host_flash (host);
		}

		if ((status != 0) || !validate_flash || no_state_change) {
			if (!validate_flash) {
				host_processor_filtered_clear_host_dirty_state (host, no_pfm);
			}

			goto return_flash;
		}

		if (pending_pfm) {
			int empty_status;

			status = host_processor_filtered_check_force_bypass_mode (host, &active_pfm,
				&pending_pfm, &empty_status);
			if (status != 0) {
				goto return_flash;
			}

			status = empty_status;
			if ((status != 0) && (!active_pfm || (active_pfm && !dirty))) {
				goto return_flash;
			}
		}

		if (!bypass) {
			flash_checked = host_state_manager_get_run_time_validation (host->host_state);
		}
		host_state_manager_set_run_time_validation (host->host_state, HOST_STATE_PREVALIDATED_NONE);

		if (pending_pfm) {
			if (bypass || !active_pfm) {
				prevalidated = false;
			}
			else {
				switch (flash_checked) {
					case HOST_STATE_PREVALIDATED_FLASH_AND_PFM:
						prevalidated = !host_state_manager_is_pfm_dirty (host->host_state);
						break;

					case HOST_STATE_PREVALIDATED_FLASH:
						if (!host_state_manager_is_pfm_dirty (host->host_state)) {
							status = HOST_PROCESSOR_NOTHING_TO_VERIFY;
						}
					/* fall through */ /* no break */

					default:
						prevalidated = false;
						break;
				}
			}

			if (status == 0) {
				only_validated = prevalidated;
				status = host_processor_filtered_validate_flash (host, hash, rsa, pending_pfm,
					bypass ? NULL : active_pfm, true, bypass, only_validated, true, true,
					prevalidated, single, NULL);
			}
		}
		else if (status == 0) {
			host_state_manager_set_pfm_dirty (host->host_state, false);
		}

		if ((!pending_pfm && active_pfm) ||
			(active_pfm && (status != 0) && !only_validated && (dirty || bypass))) {
			if (flash_checked == HOST_STATE_PREVALIDATED_FLASH) {
				prevalidated = true;
			}
			else {
				prevalidated = false;
			}

			status = host_processor_filtered_validate_flash (host, hash, rsa, active_pfm, NULL,
				false, bypass, !bypass, true, true, prevalidated, single, NULL);
		}
		else if (!pending_pfm && !active_pfm) {
			/* When there is no PFM available, ensure the system is running in bypass mode.  PFMs
			 * that were present at POR could have been cleared, so apply bypass configuration. */
			host->filter->clear_flash_dirty_state (host->filter);
			host_state_manager_save_inactive_dirty (host->host_state, false);
			host_state_manager_set_pfm_dirty (host->host_state, false);

			if (!bypass) {
				host_processor_filtered_config_bypass (host);
			}
		}

return_flash:
		if (!notified) {
			observable_notify_observers (&host->base.state->observable,
				offsetof (struct host_processor_observer, on_soft_reset));
			notified = true;
		}

		host_processor_filtered_set_host_flash_access (host);

		if (reset && host->reset_pulse) {
			host->control->hold_processor_in_reset (host->control, true);
			platform_msleep (host->reset_pulse);
		}
	}
	else {
		host_processor_filtered_clear_host_dirty_state (host, no_pfm);
	}

exit:
	if (!notified) {
		observable_notify_observers (&host->base.state->observable,
			offsetof (struct host_processor_observer, on_soft_reset));
	}

	if (active_pfm) {
		host->pfm->free_pfm (host->pfm, active_pfm);
	}
	if (pending_pfm) {
		host->pfm->free_pfm (host->pfm, pending_pfm);
	}

	if (reset) {
		/* Some implementations will set the processor reset independently of this flow, so we need
		 * to be sure the reset is always released after soft reset processing.  Releasing the reset
		 * in cases where the reset is never set is not an issue. */
		host->control->hold_processor_in_reset (host->control, false);
	}

	platform_mutex_unlock (&host->state->lock);

	return status;
}

int host_processor_filtered_get_next_reset_verification_actions (const struct host_processor *host)
{
	const struct host_processor_filtered *filtered = (const struct host_processor_filtered*) host;
	const struct pfm *active_pfm;
	const struct pfm *pending_pfm;
	enum host_processor_reset_actions action = HOST_PROCESSOR_ACTION_NONE;

	if (filtered == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	active_pfm = filtered->pfm->get_active_pfm (filtered->pfm);
	pending_pfm = filtered->pfm->get_pending_pfm (filtered->pfm);

	if (pending_pfm) {
		if (host_state_manager_is_bypass_mode (filtered->host_state) || !active_pfm) {
			action = HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH;
		}
		else {
			if (!host_state_manager_is_pfm_dirty (filtered->host_state)) {
				switch (host_state_manager_get_run_time_validation (filtered->host_state)) {
					case HOST_STATE_PREVALIDATED_FLASH_AND_PFM:
						action = HOST_PROCESSOR_ACTION_ACTIVATE_PFM_AND_UPDATE;
						break;

					case HOST_STATE_PREVALIDATED_FLASH:
						action = HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE;
						break;

					case HOST_STATE_PREVALIDATED_NONE:
						if (host_state_manager_is_inactive_dirty (filtered->host_state)) {
							action = HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE;
						}
						break;
				}
			}
			else if (host_state_manager_is_inactive_dirty (filtered->host_state)) {
				action = HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE;
			}
			else {
				action = HOST_PROCESSOR_ACTION_VERIFY_PFM;
			}
		}
	}
	else if (active_pfm) {
		if (host_state_manager_is_bypass_mode (filtered->host_state)) {
			action = HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH;
		}
		else if (host_state_manager_is_inactive_dirty (filtered->host_state)) {
			if (host_state_manager_get_run_time_validation (filtered->host_state) ==
				HOST_STATE_PREVALIDATED_FLASH) {
				action = HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE;
			}
			else {
				action = HOST_PROCESSOR_ACTION_VERIFY_UPDATE;
			}
		}
	}

	if (active_pfm) {
		filtered->pfm->free_pfm (filtered->pfm, active_pfm);
	}
	if (pending_pfm) {
		filtered->pfm->free_pfm (filtered->pfm, pending_pfm);
	}

	return action;
}

int host_processor_filtered_needs_config_recovery (const struct host_processor *host)
{
	const struct host_processor_filtered *filtered = (const struct host_processor_filtered*) host;
	int status;

	if (filtered == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = filtered->flash->host_has_flash_access (filtered->flash, filtered->control);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	return !status;
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
static void host_processor_filtered_clear_rw (const struct host_processor_filtered *host)
{
	int status;
	int log_status = 0;
	uint32_t retries = 0;

	do {
		retries++;
		status = host->filter->clear_filter_rw_regions (host->filter);
		if (status != log_status) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_CLEAR_RW_REGIONS_ERROR, host_processor_get_port (&host->base), status);
			log_status = status;
		}
	} while (status != 0);

	if (log_status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_CLEAR_RW_REGIONS_RETRIES, host_processor_get_port (&host->base), retries);
	}
}

int host_processor_filtered_apply_recovery_image (const struct host_processor *host, bool no_reset)
{
	const struct host_processor_filtered *filtered = (const struct host_processor_filtered*) host;
	struct recovery_image *active_image;
	const struct spi_flash *ro_flash;
	int status = 0;

	if (filtered == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&filtered->state->lock);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
		HOST_LOGGING_RECOVERY_STARTED, host_processor_get_port (&filtered->base), 0);

	if (!host_state_manager_is_bypass_mode (filtered->host_state) &&
		!host_state_manager_is_flash_supported (filtered->host_state)) {
		status = HOST_PROCESSOR_FLASH_NOT_SUPPORTED;
		goto free_lock;
	}

	if (!filtered->recovery) {
		status = HOST_PROCESSOR_RECOVERY_UNSUPPORTED;
		goto free_lock;
	}

	active_image = filtered->recovery->get_active_recovery_image (filtered->recovery);
	if (active_image == NULL) {
		status = HOST_PROCESSOR_NO_RECOVERY_IMAGE;
		goto free_lock;
	}

	if (!no_reset && !filtered->reset_pulse) {
		filtered->control->hold_processor_in_reset (filtered->control, true);
	}

	status = filtered->flash->set_flash_for_rot_access (filtered->flash, filtered->control);
	if (status != 0) {
		goto return_flash;
	}

	ro_flash = filtered->flash->get_read_only_flash (filtered->flash);

	/* Trigger the notification as soon as the flash is modified for the recovery image. */
	observable_notify_observers (&filtered->base.state->observable,
		offsetof (struct host_processor_observer, on_recovery));

	status = spi_flash_chip_erase (ro_flash);
	if (status != 0) {
		goto return_flash;
	}

	status = active_image->apply_to_flash (active_image, ro_flash);
	if (status != 0) {
		goto return_flash;
	}

	if (!host_state_manager_is_bypass_mode (filtered->host_state)) {
		host_processor_filtered_clear_rw (filtered);
		host_processor_filtered_config_flash (filtered);
	}

return_flash:
	host_processor_filtered_set_host_flash_access (filtered);

	if (!no_reset) {
		if (filtered->reset_pulse) {
			filtered->control->hold_processor_in_reset (filtered->control, true);
			platform_msleep (filtered->reset_pulse);
		}

		filtered->control->hold_processor_in_reset (filtered->control, false);
	}

	if (active_image) {
		filtered->recovery->free_recovery_image (filtered->recovery, active_image);
	}

free_lock:
	if (status == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_COMPLETED, host_processor_get_port (&filtered->base), 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_FAILED, status, host_processor_get_port (&filtered->base));
	}

	platform_mutex_unlock (&filtered->state->lock);

	return status;
}
