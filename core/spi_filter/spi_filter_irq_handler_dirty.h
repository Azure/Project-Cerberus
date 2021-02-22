// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_IRQ_HANDLER_DIRTY_H_
#define SPI_FILTER_IRQ_HANDLER_DIRTY_H_

#include "spi_filter_irq_handler.h"
#include "host_fw/host_control.h"


/**
 * Handler for SPI filter IRQs that will set the reset control signal to the host processor when
 * dirty flash is detected.
 */
struct spi_filter_irq_handler_dirty {
	struct spi_filter_irq_handler base;		/**< The base handler instance. */
	struct host_control *control;			/**< The control interface for host resets. */
};


int spi_filter_irq_handler_dirty_init (struct spi_filter_irq_handler_dirty *handler,
	struct host_state_manager *host_state, struct host_control *control);
void spi_filter_irq_handler_dirty_release (struct spi_filter_irq_handler_dirty *handler);


#endif /* SPI_FILTER_IRQ_HANDLER_DIRTY_H_ */
