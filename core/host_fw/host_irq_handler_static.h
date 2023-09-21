// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_STATIC_H_
#define HOST_IRQ_HANDLER_STATIC_H_

#include "host_irq_handler.h"


/**
 * Static initializer for the host irqs internal customization hooks.
 */
#define	HOST_IRQ_HANDLER_INTERNAL_API_INIT   \
		.power_on = host_irq_handler_power_on, \
		.enter_reset = host_irq_handler_enter_reset, \
		.exit_reset = host_irq_handler_exit_reset, \
		.assert_cs0 = host_irq_handler_assert_cs0, \
		.assert_cs1 = host_irq_handler_assert_cs1, \
		.force_recovery = host_irq_handler_force_recovery 

/**
 * Static initializer for the IRQ handler instance.
 *
 * There is no validation done on the arguments.
 *
 * @param host_ptr The host generating the IRQs.
 * @param hash_ptr Hash engine to use for reset validation.
 * @param rsa_ptr RSA engine to use for reset validation.
 * @param recovery_ptr The recovery manager for BMC watchdog failover.
 */
#define	host_irq_handler_static_init(host_ptr, hash_ptr, rsa_ptr, recovery_ptr)	{ \
		HOST_IRQ_HANDLER_INTERNAL_API_INIT, \
		.host = host_ptr, \
		.hash = hash_ptr, \
		.rsa = rsa_ptr, \
		.recovery = recovery_ptr, \
		.control = NULL, \
		.notify_exit_reset = false \
	}

/**
 * Static initializer for the IRQ handler instance with IRQ control.
 *
 * There is no validation done on the arguments.
 *
 * @param host_ptr The host generating the IRQs.
 * @param hash_ptr Hash engine to use for reset validation.
 * @param rsa_ptr RSA engine to use for reset validation.
 * @param recovery_ptr The recovery manager for BMC watchdog failover.
 * @param control_ptr Interface for enabling host interrupts.
 */
#define	host_irq_handler_static_init_irq_ctrl(host_ptr, hash_ptr, rsa_ptr, recovery_ptr, \
	control_ptr)	{ \
		HOST_IRQ_HANDLER_INTERNAL_API_INIT, \
		.host = host_ptr, \
		.hash = hash_ptr, \
		.rsa = rsa_ptr, \
		.recovery = recovery_ptr, \
		.control = control_ptr, \
		.notify_exit_reset = false \
	}

/**
 * Static initializer for the IRQ handler instance with IRQ control and notify exit reset.
 *
 * There is no validation done on the arguments.
 *
 * @param host_ptr The host generating the IRQs.
 * @param hash_ptr Hash engine to use for reset validation.
 * @param rsa_ptr RSA engine to use for reset validation.
 * @param recovery_ptr The recovery manager for BMC watchdog failover.
 * @param control_ptr Interface for enabling host interrupts.
 */
#define	host_irq_handler_static_init_enable_exit_reset(host_ptr, hash_ptr, rsa_ptr, recovery_ptr, \
	control_ptr)	{ \
		HOST_IRQ_HANDLER_INTERNAL_API_INIT, \
		.host = host_ptr, \
		.hash = hash_ptr, \
		.rsa = rsa_ptr, \
		.recovery = recovery_ptr, \
		.control = control_ptr, \
		.notify_exit_reset = true \
	}


#endif /* HOST_IRQ_HANDLER_STATIC_H_ */
