// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_irq_handler.h"
#include "host_logging.h"


int host_irq_handler_power_on (struct host_irq_handler *handler, bool allow_unsecure,
	struct hash_engine *hash)
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
		(status != HOST_PROCESSOR_NO_RECOVERY_IMAGE) && (retries--)) {
		status = handler->host->apply_recovery_image (handler->host, true);
		/* Errors logged in the handler. */
	}

	retries = 2;
	while (allow_unsecure && (status != 0) && (retries--)) {
		if (!flash_switched && (status != HOST_PROCESSOR_RECOVERY_UNSUPPORTED) &&
			(status != HOST_PROCESSOR_NO_RECOVERY_IMAGE)) {
			/* Since we attempted to put on the recovery image but failed, the RO flash is assumed
			 * to be trashed.  If we have any chance of booting, it will be with the RW flash.  Only
			 * switch the flash once.*/
			status = handler->host->bypass_mode (handler->host, true);
			flash_switched = true;
		}
		else {
			status = handler->host->bypass_mode (handler->host, false);
		}

		debug_log_create_entry (
			(status == 0) ? DEBUG_LOG_SEVERITY_WARNING : DEBUG_LOG_SEVERITY_ERROR,
			DEBUG_LOG_COMPONENT_HOST_FW, HOST_LOGGING_BYPASS_MODE,
			host_processor_get_port (handler->host), status);
	}

	return status;
}

int host_irq_handler_enter_reset (struct host_irq_handler *handler)
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

void host_irq_handler_exit_reset (struct host_irq_handler *handler)
{
	if (handler && handler->recovery) {
		handler->recovery->on_host_out_of_reset (handler->recovery);
	}
}

void host_irq_handler_assert_cs0 (struct host_irq_handler *handler)
{
	if (handler && handler->recovery) {
		handler->recovery->on_host_cs0 (handler->recovery);
	}
}

int host_irq_handler_assert_cs1 (struct host_irq_handler *handler)
{
	int status = 0;

	if (handler && handler->recovery) {
		status = handler->recovery->on_host_cs1 (handler->recovery, handler->hash, handler->rsa);
	}

	return status;
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
int host_irq_handler_init (struct host_irq_handler *handler, struct host_processor *host,
	struct hash_engine *hash, struct rsa_engine *rsa, struct bmc_recovery *recovery)
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

	handler->host = host;
	handler->hash = hash;
	handler->rsa = rsa;
	handler->recovery = recovery;

	return 0;
}

/**
 * Release the resources used by a host IRQ handler.
 *
 * @param handler The handler instance to release.
 */
void host_irq_handler_release (struct host_irq_handler *handler)
{

}

/**
 * Update the manager for the host generating interrupts.
 *
 * @param handler The handler instance to update.
 * @param host The new instance for the host generating interrupts.
 *
 * @return 0 if the handler was updated successfully or an error code.
 */
int host_irq_handler_set_host (struct host_irq_handler *handler, struct host_processor *host)
{
	if ((handler == NULL) || (host == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	handler->host = host;
	return 0;
}
