// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_AUTH_CHECK_H_
#define HOST_IRQ_HANDLER_AUTH_CHECK_H_

#include "host_irq_handler.h"
#include "host_control.h"
#include "host_irq_control.h"


/**
 * A host IRQ handler that will assert the host reset control signal on reset exit if firmware
 * authentication is required on the next host reset.
 */
struct host_irq_handler_auth_check {
	struct host_irq_handler base;			/**< The base IRQ handler. */
	const struct host_control *control;		/**< The interface for host control signals. */
};


int host_irq_handler_auth_check_init (struct host_irq_handler_auth_check *handler,
	struct host_processor *host, struct hash_engine *hash, struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_control *control,
	const struct host_irq_control *irq);
void host_irq_handler_auth_check_release (const struct host_irq_handler_auth_check *handler);


#endif /* HOST_IRQ_HANDLER_AUTH_CHECK_H_ */
