// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_LOGGING_H_
#define SPI_FILTER_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for the SPI filter.
 */
enum {
	SPI_FILTER_LOGGING_BLOCKED_COMMAND,			/**< A SPI command was blocked by the filter. */
	SPI_FILTER_LOGGING_READ_BLOCKED_FAIL,		/**< Failed to read a blocked SPI command code. */
	SPI_FILTER_LOGGING_IRQ_STATUS,				/**< The cause of SPI filter interrupts. */
	SPI_FILTER_LOGGING_FILTER_CONFIG,			/**< SPI filter configuration. */
	SPI_FILTER_LOGGING_ADDRESS_MODE,			/**< The address mode of the filter has changed. */
	SPI_FILTER_LOGGING_FILTER_REGION,			/**< A R/W address region for the filter. */
	SPI_FILTER_LOGGING_DEVICE_SIZE,				/**< The device size configuration. */
};


#endif /* SPI_FILTER_LOGGING_H_ */
