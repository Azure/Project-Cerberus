// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_IRQ_HANDLER_MOCK_H_
#define SPI_FILTER_IRQ_HANDLER_MOCK_H_

#include "spi_filter/spi_filter_irq_handler.h"
#include "mock.h"


struct spi_filter_irq_handler_mock {
	struct spi_filter_irq_handler base;		/**< The base IRQ handler. */
	struct mock mock;						/**< The bas mock interface. */
};


int spi_filter_irq_handler_mock_init (struct spi_filter_irq_handler_mock *mock);
void spi_filter_irq_handler_mock_release (struct spi_filter_irq_handler_mock *mock);

int spi_filter_irq_handler_mock_validate_and_release (struct spi_filter_irq_handler_mock *mock);


#endif /* SPI_FILTER_IRQ_HANDLER_MOCK_H_ */
