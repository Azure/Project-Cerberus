// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_irq_handler.h"
#include "host_logging.h"


int host_irq_handler_power_on (const struct host_irq_handler *handler, bool allow_unsecure,
	const struct hash_engine *hash)
{
	int status;
	int retries;
	bool flash_switched = false;

	if (handler == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	if (hash == NULL) {
		hash = handler->hash;
	}

	retries = 1;
	do {
		status = handler->host->power_on_reset (handler->host, hash, handler->rsa);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_POWER_ON_RESET, host_processor_get_port (handler->host), status);
		}
	} while ((status != 0) && (retries--));

	retries = 2;
	while ((status != 0) && (status != HOST_PROCESSOR_NO_ROLLBACK) &&
		(status != HOST_PROCESSOR_ROLLBACK_DIRTY) && (retries--)) {
		status = handler->host->flash_rollback (handler->host, hash, handler->rsa, true, true);
		/* Errors logged in the handler. */
	}

	retries = 2;
	while ((status != 0) && (status != HOST_PROCESSOR_RECOVERY_UNSUPPORTED) &&
		(status != HOST_PROCESSOR_NO_RECOVERY_IMAGE) &&
		(status != HOST_PROCESSOR_FLASH_NOT_SUPPORTED) && (retries--)) {
		status = handler->host->apply_recovery_image (handler->host, true);
		/* Errors logged in the handler. */
	}

	retries = 2;
	while (allow_unsecure && (status != 0) && (retries--)) {
		if (!flash_switched && (status != HOST_PROCESSOR_RECOVERY_UNSUPPORTED) &&
			(status != HOST_PROCESSOR_NO_RECOVERY_IMAGE) &&
			(status != HOST_PROCESSOR_FLASH_NOT_SUPPORTED)) {
			/* Since we attempted to put on the recovery image but failed, the RO flash is assumed
			 * to be trashed.  If we have any chance of booting, it will be with the RW flash.  Only
			 * switch the flash once. */
			status = handler->host->bypass_mode (handler->host, true);
			flash_switched = true;
		}
		else {
			status = handler->host->bypass_mode (handler->host, false);
		}

		debug_log_create_entry ((status ==
			0) ? DEBUG_LOG_SEVERITY_WARNING : DEBUG_LOG_SEVERITY_ERROR,	DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_BYPASS_MODE, host_processor_get_port (handler->host), status);
	}

	return status;
}

int host_irq_handler_enter_reset (const struct host_irq_handler *handler)
{
	int status;

	if (handler == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	if (handler->recovery) {
		handler->recovery->on_host_reset (handler->recovery);
	}

	status = handler->host->soft_reset (handler->host, handler->hash, handler->rsa);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_SOFT_RESET, host_processor_get_port (handler->host), status);
	}

	return status;
}

void host_irq_handler_exit_reset (const struct host_irq_handler *handler)
{
	if (handler && handler->recovery) {
		handler->recovery->on_host_out_of_reset (handler->recovery);
	}
}

void host_irq_handler_assert_cs0 (const struct host_irq_handler *handler)
{
	if (handler && handler->recovery) {
		handler->recovery->on_host_cs0 (handler->recovery);
	}
}

int host_irq_handler_assert_cs1 (const struct host_irq_handler *handler)
{
	int status = 0;

	if (handler && handler->recovery) {
		status = handler->recovery->on_host_cs1 (handler->recovery, handler->hash, handler->rsa);
	}

	return status;
}

int host_irq_handler_force_recovery (const struct host_irq_handler *handler)
{
	int status;
	uint32_t retries = 0;

	if (handler == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	do {
		retries++;
		status = handler->host->apply_recovery_image (handler->host, true);
		if ((status == HOST_PROCESSOR_RECOVERY_UNSUPPORTED) ||
			(status == HOST_PROCESSOR_NO_RECOVERY_IMAGE)) {
			return status;
		}
		/* Retry indefinitely on an unknown error since if the first attempt fails to write to flash
		 * it's possible Cerberus would have erased flash and partially written the recovery image
		 * to flash and so the system couldn't boot until the recovery attempt succeeds. */
	} while (status != 0);

	if (retries > 1) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_RECOVERY_RETRIES, host_processor_get_port (handler->host), retries);
	}

	return status;
}

/**
 * Internal function to initialize the common components of a host interrupt handler.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 * @param control An interface for enabling host interrupts.
 * @param notify_exit_reset Flag indicating to enable host reset exit interrupts.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
static int host_irq_handler_init_internal (struct host_irq_handler *handler,
	const struct host_processor *host, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control, bool notify_exit_reset)
{
	if ((handler == NULL) || (host == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct host_irq_handler));

	handler->power_on = host_irq_handler_power_on;
	handler->enter_reset = host_irq_handler_enter_reset;
	handler->exit_reset = host_irq_handler_exit_reset;
	handler->assert_cs0 = host_irq_handler_assert_cs0;
	handler->assert_cs1 = host_irq_handler_assert_cs1;
	handler->force_recovery = host_irq_handler_force_recovery;

	handler->host = host;
	handler->hash = hash;
	handler->rsa = rsa;
	handler->recovery = recovery;
	handler->control = control;
	handler->notify_exit_reset = notify_exit_reset;

	return 0;
}

/**
 * Initialize a handler for host interrupts.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
int host_irq_handler_init (struct host_irq_handler *handler, const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, struct bmc_recovery *recovery)
{
	return host_irq_handler_init_internal (handler, host, hash, rsa, recovery, NULL, false);
}

/**
 * Initialize a handler for host interrupts. The handler will initialize the interface for enabling
 * host interrupts to a non-null value.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 * @param control An interface for enabling host interrupts.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
int host_irq_handler_init_with_irq_ctrl (struct host_irq_handler *handler,
	const struct host_processor *host, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control)
{
	if (control == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	return host_irq_handler_init_internal (handler, host, hash, rsa, recovery, control, false);
}

/**
 * Initialize a handler for host interrupts. The handler will enable host reset exit
 * notifications.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 * @param control An interface for enabling host interrupts.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
int host_irq_handler_init_enable_exit_reset (struct host_irq_handler *handler,
	const struct host_processor *host, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control)
{
	int status;

	if (control == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	status = host_irq_handler_init_internal (handler, host, hash, rsa, recovery, control, true);
	if (status != 0) {
		return status;
	}

	return handler->control->enable_exit_reset (control, true);
}

/**
 * Configure host interrupts.
 *
 * @param handler The handler instance to initialize.
 *
 * @return 0 if the host interrupts ware successfully configured or an error code.
 */
int host_irq_handler_config_interrupts (const struct host_irq_handler *handler)
{
	if ((handler == NULL) || (handler->host == NULL) || (handler->hash == NULL) ||
		(handler->rsa == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	if (!handler->notify_exit_reset) {
		return 0;
	}

	if (handler->control == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	return handler->control->enable_exit_reset (handler->control, true);
}

/**
 * Release the resources used by a host IRQ handler.
 *
 * @param handler The handler instance to release.
 */
void host_irq_handler_release (const struct host_irq_handler *handler)
{
	if (handler) {
		if (handler->control && handler->notify_exit_reset) {
			handler->control->enable_exit_reset (handler->control, false);
		}
	}
}

/**
 * Update the manager for the host generating interrupts.
 *
 * @param handler The handler instance to update.
 * @param host The new instance for the host generating interrupts.
 *
 * @return 0 if the handler was updated successfully or an error code.
 */
int host_irq_handler_set_host (struct host_irq_handler *handler, const struct host_processor *host)
{
	if ((handler == NULL) || (host == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	handler->host = host;

	return 0;
}
