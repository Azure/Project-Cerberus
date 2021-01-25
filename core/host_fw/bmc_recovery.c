// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "bmc_recovery.h"
#include "host_logging.h"


/**
 * Transition the recovery state machine to the running state.
 *
 * @param recovery The recovery state machine to update.
 */
static void bmc_recovery_enter_running_state (struct bmc_recovery *recovery)
{
	int status = recovery->irq->enable_chip_selects (recovery->irq, false);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_IRQ, status, false);
	}

	recovery->state = BMC_RECOVERY_STATE_RUNNING;
}

/**
 * Transition the recovery state machine to the in reset state.
 *
 * @param recovery The recovery state machine to update.
 */
static void bmc_recovery_enter_in_reset_state (struct bmc_recovery *recovery)
{
	int status = recovery->irq->enable_chip_selects (recovery->irq, true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_IRQ, status, true);
	}

	recovery->state = BMC_RECOVERY_STATE_IN_RESET;
}

static void bmc_recovery_on_host_reset (struct bmc_recovery *recovery)
{
	if (recovery == NULL) {
		return;
	}

	switch (recovery->state) {
		case BMC_RECOVERY_STATE_RUNNING:
		case BMC_RECOVERY_STATE_EXIT_RESET:
			bmc_recovery_enter_in_reset_state (recovery);
			break;
	}
}

static void bmc_recovery_on_host_out_of_reset (struct bmc_recovery *recovery)
{
	if (recovery == NULL) {
		return;
	}

	switch (recovery->state) {
		case BMC_RECOVERY_STATE_IN_RESET:
		case BMC_RECOVERY_STATE_ROLLBACK_DONE:
			recovery->state = BMC_RECOVERY_STATE_EXIT_RESET;
			break;
	}
}

static void bmc_recovery_on_host_cs0 (struct bmc_recovery *recovery)
{
	if (recovery == NULL) {
		return;
	}

	switch (recovery->state) {
		case BMC_RECOVERY_STATE_RUNNING:
		case BMC_RECOVERY_STATE_EXIT_RESET:
			bmc_recovery_enter_running_state (recovery);
			break;

		case BMC_RECOVERY_STATE_ROLLBACK_DONE:
			recovery->state = BMC_RECOVERY_STATE_IN_RESET;
			break;
	}
}

static int bmc_recovery_on_host_cs1 (struct bmc_recovery *recovery, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	int status = 0;
	int time_status = 0;

	if (recovery == NULL) {
		return 0;
	}

	switch (recovery->state) {
		case BMC_RECOVERY_STATE_RUNNING:
			bmc_recovery_enter_running_state (recovery);
			break;

		case BMC_RECOVERY_STATE_IN_RESET:
		case BMC_RECOVERY_STATE_EXIT_RESET:
			if (platform_has_timeout_expired (&recovery->timeout) == 1) {
				recovery->num_wdt = 0;
				recovery->skip_recovery = false;
			}

			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_BMC_RECOVERY_DETECTED, host_processor_get_port (recovery->host),
				recovery->num_wdt);

			if (recovery->num_wdt < recovery->rec_ctrl.min_wdt) {
				recovery->control->hold_processor_in_reset (recovery->control, true);
				platform_msleep (100);
				recovery->control->hold_processor_in_reset (recovery->control, false);
				recovery->state = BMC_RECOVERY_STATE_ROLLBACK_DONE;
			}
			else {
				if (recovery->num_wdt == recovery->rec_ctrl.min_wdt) {
					status = recovery->host->recover_active_read_write_data (recovery->host);
					if ((status == HOST_PROCESSOR_NO_ACTIVE_RW_DATA) ||
						(status == HOST_PROCESSOR_RW_RECOVERY_UNSUPPORTED)) {
						recovery->num_wdt++;
					}
				}

				if (recovery->skip_recovery ||
					(recovery->num_wdt == (recovery->rec_ctrl.min_wdt + 1))) {
					status = recovery->host->flash_rollback (recovery->host, hash, rsa, false,
						false);
					if (IS_VALIDATION_FAILURE (status) || (status == HOST_PROCESSOR_NO_ROLLBACK) ||
						(status == HOST_PROCESSOR_ROLLBACK_DIRTY)) {
						recovery->num_wdt++;
					}
				}

				if (!recovery->skip_recovery &&
					(recovery->num_wdt >= (recovery->rec_ctrl.min_wdt + 2))) {
					status = recovery->host->apply_recovery_image (recovery->host, false);
					if ((status == HOST_PROCESSOR_RECOVERY_UNSUPPORTED) ||
						(status == HOST_PROCESSOR_NO_RECOVERY_IMAGE)) {
						recovery->skip_recovery = true;
					}
				}

				recovery->state = BMC_RECOVERY_STATE_ROLLBACK_DONE;
				if (status != 0) {
					recovery->control->hold_processor_in_reset (recovery->control, true);
					platform_msleep (100);
					recovery->control->hold_processor_in_reset (recovery->control, false);
				}
			}

			recovery->num_wdt++;
			time_status = platform_init_timeout (recovery->rec_ctrl.msec, &recovery->timeout);

			break;
	}

	return (status != 0) ? status : time_status;
}

/**
 * Initialize the recovery manager for BMC watchdog resets.
 *
 * @param recovery The recovery manager to initialize.
 * @param irq The IRQ control interface.
 * @param host The BMC host for recovery operations.
 * @param control The interface for controlling the host processor.
 * @param rec_ctrl Optional input control parameters for host recovery.
 *
 * @return 0 if the BMC recovery manager was initialized successfully or an error code.
 */
int bmc_recovery_init (struct bmc_recovery *recovery, struct host_irq_control *irq,
	struct host_processor *host, struct host_control *control,
	struct bmc_recovery_control *rec_ctrl)
{
	int status;

	if ((recovery == NULL) || (irq == NULL) || (host == NULL) || (control == NULL) ||
		(rec_ctrl == NULL)) {
		return BMC_RECOVERY_INVALID_ARGUMENT;
	}

	memset (recovery, 0, sizeof (struct bmc_recovery));

	status = irq->enable_exit_reset (irq, true);
	if (status != 0) {
		return status;
	}

	memcpy (&recovery->rec_ctrl, rec_ctrl, sizeof (struct bmc_recovery_control));
	status = platform_init_current_tick (&recovery->timeout);
	if (status != 0) {
		return status;
	}

	recovery->on_host_reset = bmc_recovery_on_host_reset;
	recovery->on_host_out_of_reset = bmc_recovery_on_host_out_of_reset;
	recovery->on_host_cs0 = bmc_recovery_on_host_cs0;
	recovery->on_host_cs1 = bmc_recovery_on_host_cs1;

	recovery->irq = irq;
	recovery->host = host;
	recovery->control = control;

	return 0;
}

/**
 * Release the resources used by the BMC watchdog recovery manager.
 *
 * @param recovery The recovery manager to release.
 */
void bmc_recovery_release (struct bmc_recovery *recovery)
{
	if (recovery && recovery->irq) {
		recovery->irq->enable_exit_reset (recovery->irq, false);
		recovery->irq->enable_chip_selects (recovery->irq, false);
	}
}

/**
 * Initialize the state of the recovery manager.  This should be called only once, just before
 * host interrupts are enabled.
 *
 * @param recovery The recovery manager to update.
 * @param in_reset Flag indicating if the host processor is currently in reset.
 *
 * @return 0 if the initial state was successful set or an error code.
 */
int bmc_recovery_set_initial_state (struct bmc_recovery *recovery, bool in_reset)
{
	if (recovery == NULL) {
		return BMC_RECOVERY_INVALID_ARGUMENT;
	}

	if (in_reset) {
		bmc_recovery_enter_in_reset_state (recovery);
	}

	return 0;
}
