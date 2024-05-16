// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_AUTH_CHECK_STATIC_H_
#define HOST_IRQ_HANDLER_AUTH_CHECK_STATIC_H_

#include "host_irq_handler_auth_check.h"


/* Internal functions declared to allow for static initialization. */
void host_irq_handler_auth_check_exit_reset (const struct host_irq_handler *handler);

/**
 * Static initializer for the authentication check irqs internal customization hooks.
 */
#define	HOST_IRQ_HANDLER_AUTH_CHECK_INTERNAL_API_INIT  { \
		.power_on = host_irq_handler_power_on, \
		.enter_reset = host_irq_handler_enter_reset, \
		.exit_reset = host_irq_handler_auth_check_exit_reset, \
		.assert_cs0 = host_irq_handler_assert_cs0, \
		.assert_cs1 = host_irq_handler_assert_cs1, \
		.force_recovery = host_irq_handler_force_recovery \
	}

/**
 * Static initializer for the authentication check IRQ handler instance with IRQ control.
 *
 * There is no validation done on the arguments.
 *
 * @param host_ptr The host generating the IRQs.
 * @param hash_ptr Hash engine to use for reset validation.
 * @param rsa_ptr RSA engine to use for reset validation.
 * @param recovery_ptr The recovery manager for BMC watchdog failover.
 * @param host_control_ptr The interface for host control signals.
 * @param irq_control_ptr Interface for enabling host interrupts.
 */
#define	host_irq_handler_auth_check_static_init(host_ptr, hash_ptr, rsa_ptr, recovery_ptr, \
	host_control_ptr, irq_control_ptr)	{ \
		.base = HOST_IRQ_HANDLER_AUTH_CHECK_INTERNAL_API_INIT, \
		.base.host = host_ptr, \
		.base.hash = hash_ptr, \
		.base.rsa = rsa_ptr, \
		.base.recovery = recovery_ptr, \
		.base.control = irq_control_ptr, \
		.base.notify_exit_reset = true, \
		.control = host_control_ptr \
	}


#endif	/* HOST_IRQ_HANDLER_AUTH_CHECK_STATIC_H_ */
