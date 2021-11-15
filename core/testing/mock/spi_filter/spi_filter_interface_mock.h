// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_INTERFACE_MOCK_H_
#define SPI_FILTER_INTERFACE_MOCK_H_

#include "spi_filter/spi_filter_interface.h"
#include "mock.h"


/**
 * Mock for a SPI filter.
 */
struct spi_filter_interface_mock {
	struct spi_filter_interface base;		/**< The base SPI filter instance. */
	struct mock mock;						/**< The base mock interface. */
};


int spi_filter_interface_mock_init (struct spi_filter_interface_mock *mock);
void spi_filter_interface_mock_release (struct spi_filter_interface_mock *mock);

int spi_filter_interface_mock_validate_and_release (struct spi_filter_interface_mock *mock);


#endif /* SPI_FILTER_INTERFACE_MOCK_H_ */
