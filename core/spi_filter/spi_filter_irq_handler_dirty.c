// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "spi_filter_irq_handler_dirty.h"


static void spi_filter_irq_handler_dirty_ro_flash_dirty (struct spi_filter_irq_handler *handler)
{
	struct spi_filter_irq_handler_dirty *dirty = (struct spi_filter_irq_handler_dirty*) handler;

	if (dirty) {
		dirty->control->hold_processor_in_reset (dirty->control, true);
		spi_filter_irq_handler_ro_flash_dirty (handler);
	}
}


/**
 * Initialize the SPI filter IRQ handler.  This handler will assert the host reset control signal
 * when a dirty flash interrupt occurs.
 *
 * @param handler The IRQ handler to initialize.
 * @param host_state State for the host connected to the SPI filter.
 * @param control Interface for host control signals.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int spi_filter_irq_handler_dirty_init (struct spi_filter_irq_handler_dirty *handler,
	struct host_state_manager *host_state, struct host_control *control)
{
	int status;

	if ((handler == NULL) || (control == NULL)) {
		return SPI_FILTER_IRQ_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct spi_filter_irq_handler_dirty));

	status = spi_filter_irq_handler_init (&handler->base, host_state);
	if (status != 0) {
		return status;
	}

	handler->base.ro_flash_dirty = spi_filter_irq_handler_dirty_ro_flash_dirty;

	handler->control = control;

	return 0;
}

/**
 * Release the resources used for SPI filter IRQ handling.
 *
 * @param handler The handler to release.
 */
void spi_filter_irq_handler_dirty_release (struct spi_filter_irq_handler_dirty *handler)
{
	if (handler) {
		spi_filter_irq_handler_release (&handler->base);
	}
}
