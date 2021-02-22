// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "spi_filter_irq_handler.h"
#include "host_fw/host_state_manager.h"


void spi_filter_irq_handler_ro_flash_dirty (struct spi_filter_irq_handler *handler)
{
	if (handler) {
		host_state_manager_save_inactive_dirty (handler->host_state, true);
	}
}

/**
 * Initialize the IRQ handler for a SPI filter.
 *
 * @param handler The handler to initialize.
 * @param host_state State for the host connected to the SPI filter.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int spi_filter_irq_handler_init (struct spi_filter_irq_handler *handler,
	struct host_state_manager *host_state)
{
	if ((handler == NULL) || (host_state == NULL)) {
		return SPI_FILTER_IRQ_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct spi_filter_irq_handler));

	handler->ro_flash_dirty = spi_filter_irq_handler_ro_flash_dirty;

	handler->host_state = host_state;

	return 0;
}

/**
 * Release the resources for a SPI filter IRQ handler.
 *
 * @param handler The handler to release.
 */
void spi_filter_irq_handler_release (struct spi_filter_irq_handler *handler)
{

}
