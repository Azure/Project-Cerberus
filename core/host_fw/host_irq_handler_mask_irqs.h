// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_MASK_IRQS_H_
#define HOST_IRQ_HANDLER_MASK_IRQS_H_

#include "host_irq_control.h"
#include "host_irq_handler.h"


/**
 * A host IRQ handler that will mask additional notifications while processing the current IRQ.
 */
struct host_irq_handler_mask_irqs {
	struct host_irq_handler base;	/**< The base IRQ handler. */
};


int host_irq_handler_mask_irqs_init (struct host_irq_handler_mask_irqs *handler,
	const struct host_processor *host, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control);
int host_irq_handler_mask_irqs_init_enable_exit_reset (struct host_irq_handler_mask_irqs *handler,
	const struct host_processor *host, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct bmc_recovery *recovery, const struct host_irq_control *control);
int host_irq_handler_mask_irqs_config_interrupts (const struct host_irq_handler_mask_irqs *handler);
void host_irq_handler_mask_irqs_release (const struct host_irq_handler_mask_irqs *handler);


#endif	/* HOST_IRQ_HANDLER_MASK_IRQS_H_ */
