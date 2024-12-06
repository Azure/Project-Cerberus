// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_irq_handler_auth_check.h"


void host_irq_handler_auth_check_exit_reset (const struct host_irq_handler *handler)
{
	const struct host_irq_handler_auth_check *check =
		(const struct host_irq_handler_auth_check*) handler;
	int auth_action;

	if (check) {
		host_irq_handler_exit_reset (handler);

		auth_action = check->base.host->get_next_reset_verification_actions (check->base.host);
		if (auth_action != HOST_PROCESSOR_ACTION_NONE) {
			check->control->hold_processor_in_reset (check->control, true);
		}
	}
}

/**
 * Initialize a handler for host interrupts.  The host reset control signal will be asserted on
 * reset exit if firmware authentication is required on the next host reset.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 * @param control The interface for host control signals.
 * @param irq Interface to enable host interrupts.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
int host_irq_handler_auth_check_init (struct host_irq_handler_auth_check *handler,
	struct host_processor *host, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_control *control,
	const struct host_irq_control *irq)
{
	int status;

	if ((handler == NULL) || (control == NULL) || (irq == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct host_irq_handler_auth_check));

	status = host_irq_handler_init_enable_exit_reset (&handler->base, host, hash, rsa, recovery,
		irq);
	if (status != 0) {
		return status;
	}

	handler->base.exit_reset = host_irq_handler_auth_check_exit_reset;

	handler->control = control;

	return 0;
}

/**
 * Configure host interrupts.
 *
 * @param handler The handler instance to initialize.
 * @param control The host control instance.
 *
 * @return 0 if the host interrupts ware successfully configured or an error code.
 */
int host_irq_handler_auth_check_config_interrupts (const struct host_irq_handler *handler,
	const struct host_control *control)
{
	if (control == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	return host_irq_handler_config_interrupts (handler);
}

/**
 * Release the resource used by an IRQ handler that checks for PFMs.
 *
 * @param handler The IRQ handler to release.
 */
void host_irq_handler_auth_check_release (const struct host_irq_handler_auth_check *handler)
{
	if (handler) {
		host_irq_handler_release (&handler->base);
	}
}
