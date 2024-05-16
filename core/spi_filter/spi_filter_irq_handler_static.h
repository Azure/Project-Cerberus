// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_IRQ_HANDLER_STATIC_H_
#define SPI_FILTER_IRQ_HANDLER_STATIC_H_

#include "spi_filter_irq_handler.h"


/* Internal functions declared to allow for static initialization. */


/**
 * Constant initializer for the task API.
 */
#define	SPI_FILTER_IRQ_HANDLER_API_INIT \
	.ro_flash_dirty = spi_filter_irq_handler_ro_flash_dirty,


/**
 * Initialize a static IRQ handler for a SPI filter.
 *
 * There is no validation done on the arguments.
 *
 * @param host_state_ptr State for the host connected to the SPI filter.
 */
#define	spi_filter_irq_handler_static_init(host_state_ptr)	{ \
		SPI_FILTER_IRQ_HANDLER_API_INIT \
		.host_state = host_state_ptr \
	}


#endif	/* SPI_FILTER_IRQ_HANDLER_STATIC_H_ */
