// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_PFM_CHECK_H_
#define HOST_IRQ_HANDLER_PFM_CHECK_H_

#include "host_irq_handler.h"
#include "host_control.h"
#include "host_irq_control.h"
#include "manifest/pfm/pfm_manager.h"


/**
 * A host IRQ handler that will assert the host reset control signal if there a pending PFM on reset
 * exit.
 */
struct host_irq_handler_pfm_check {
	struct host_irq_handler base;		/**< The base IRQ handler. */
	struct host_control *control;		/**< The interface for host control signals. */
	struct host_irq_control *irq;		/**< Interface for enabling host interrupts. */
	struct pfm_manager *pfm;			/**< The PFM manager for the host. */
};


int host_irq_handler_pfm_check_init (struct host_irq_handler_pfm_check *handler,
	struct host_processor *host, struct hash_engine *hash, struct rsa_engine *rsa,
	struct bmc_recovery *recovery, struct host_control *control, struct host_irq_control *irq,
	struct pfm_manager *pfm);
void host_irq_handler_pfm_check_release (struct host_irq_handler_pfm_check *handler);


#endif /* HOST_IRQ_HANDLER_PFM_CHECK_H_ */
