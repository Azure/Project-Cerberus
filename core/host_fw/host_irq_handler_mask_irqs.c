// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_irq_handler_mask_irqs.h"


int host_irq_handler_mask_irqs_enter_reset (const struct host_irq_handler *handler)
{
	const struct host_irq_handler_mask_irqs *irq =
		(const struct host_irq_handler_mask_irqs*) handler;
	int status;

	if (irq == NULL) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	irq->base.control->enable_notifications (irq->base.control, false);
	status = host_irq_handler_enter_reset (handler);
	irq->base.control->enable_notifications (irq->base.control, true);

	return status;
}

int host_irq_handler_mask_irqs_assert_cs1 (const struct host_irq_handler *handler)
{
	const struct host_irq_handler_mask_irqs *irq =
		(const struct host_irq_handler_mask_irqs*) handler;
	int status = 0;

	if (irq) {
		irq->base.control->enable_notifications (irq->base.control, false);
		status = host_irq_handler_assert_cs1 (handler);
		irq->base.control->enable_notifications (irq->base.control, true);
	}

	return status;
}

/**
 * Initialize a handler for host interrupts.  The handler will mask generation of new interrupt
 * notifications while handling an IRQ.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 * @param control The control interface for IRQ notifications.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
int host_irq_handler_mask_irqs_init (struct host_irq_handler_mask_irqs *handler,
	struct host_processor *host, struct hash_engine *hash, struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control)
{
	int status;

	if ((handler == NULL) || (control == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct host_irq_handler_mask_irqs));

	status = host_irq_handler_init_with_irq_ctrl (&handler->base, host, hash, rsa, recovery,
		control);
	if (status != 0) {
		return status;
	}

	handler->base.enter_reset = host_irq_handler_mask_irqs_enter_reset;
	handler->base.assert_cs1 = host_irq_handler_mask_irqs_assert_cs1;

	return 0;
}

/**
 * Initialize a handler for host interrupts.  The handler will mask generation of new interrupt
 * notifications while handling an IRQ and will enable host reset exit notifications.
 *
 * @param handler The handler instance to initialize.
 * @param host The host generating the interrupts.
 * @param hash The hash engine to use for reset validation.
 * @param rsa The RSA engine to use for reset signature verification.
 * @param recovery An optional recovery manager for detecting BMC watchdog recovery boots.
 * @param control The control interface for IRQ notifications.
 *
 * @return 0 if the IRQ handler was successfully initialized or an error code.
 */
int host_irq_handler_mask_irqs_init_enable_exit_reset (struct host_irq_handler_mask_irqs *handler,
	struct host_processor *host, struct hash_engine *hash, struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control)
{
	int status;

	if ((handler == NULL) || (control == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct host_irq_handler_mask_irqs));

	status = host_irq_handler_init_enable_exit_reset (&handler->base, host, hash, rsa, recovery,
		control);
	if (status != 0) {
		return status;
	}

	handler->base.enter_reset = host_irq_handler_mask_irqs_enter_reset;
	handler->base.assert_cs1 = host_irq_handler_mask_irqs_assert_cs1;

	return 0;
}

/**
 * Configure host interrupts.
 *
 * @param handler The handler instance to initialize.
 *
 * @return 0 if the host interrupts ware successfully configured or an error code.
 */
int host_irq_handler_mask_irqs_config_interrupts (const struct host_irq_handler *handler)
{
	if ((handler == NULL) || (handler->control == NULL)) {
		return HOST_IRQ_HANDLER_INVALID_ARGUMENT;
	}

	return host_irq_handler_config_interrupts (handler);
}

/**
 * Release the resources used by a host IRQ handler.
 *
 * @param handler The handler instance to release.
 */
void host_irq_handler_mask_irqs_release (const struct host_irq_handler_mask_irqs *handler)
{
	if (handler) {
		host_irq_handler_release (&handler->base);
	}
}
