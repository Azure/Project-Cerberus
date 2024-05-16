// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_IRQ_HANDLER_DIRTY_STATIC_H_
#define SPI_FILTER_IRQ_HANDLER_DIRTY_STATIC_H_

#include "spi_filter_irq_handler_dirty.h"


/* Internal functions declared to allow for static initialization. */
void spi_filter_irq_handler_dirty_ro_flash_dirty (const struct spi_filter_irq_handler *handler);


/**
 * Initialize a static IRQ handler for a SPI filter.
 *
 * There is no validation done on the arguments.
 *
 * @param host_state_ptr State for the host connected to the SPI filter.
 * @param control_ptr Interface for host control signals.
 */
#define	spi_filter_irq_handler_dirty_static_init(host_state_ptr, control_ptr)	{ \
		.base = { \
			.ro_flash_dirty = spi_filter_irq_handler_dirty_ro_flash_dirty, \
			.host_state = host_state_ptr, \
		}, \
		.control = control_ptr, \
	}


#endif	/* SPI_FILTER_IRQ_HANDLER_DIRTY_STATIC_H_ */
