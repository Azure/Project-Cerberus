// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_MASK_IRQS_H_
#define HOST_IRQ_HANDLER_MASK_IRQS_H_

#include "host_irq_handler.h"
#include "host_irq_control.h"


/**
 * A host IRQ handler that will mask additional notifications while processing the current IRQ.
 */
struct host_irq_handler_mask_irqs {
	struct host_irq_handler base;			/**< The base IRQ handler. */
	struct host_irq_control *control;		/**< Control interface for IRQ notifications. */
};


int host_irq_handler_mask_irqs_init (struct host_irq_handler_mask_irqs *handler,
	struct host_processor *host, struct hash_engine *hash, struct rsa_engine *rsa,
	struct bmc_recovery *recovery, struct host_irq_control *control);
void host_irq_handler_mask_irqs_release (struct host_irq_handler_mask_irqs *handler);


#endif /* HOST_IRQ_HANDLER_MASK_IRQS_H_ */
