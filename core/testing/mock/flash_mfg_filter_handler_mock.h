// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_MFG_FILTER_HANDLER_MOCK_H_
#define FLASH_MFG_FILTER_HANDLER_MOCK_H_

#include "spi_filter/flash_mfg_filter_handler.h"
#include "mock.h"


/**
 * A mock for the SPI filter API to handle device manufacturer information.
 */
struct flash_mfg_filter_handler_mock {
	struct flash_mfg_filter_handler base;	/**< The base handler instance. */
	struct mock mock;						/**< The base mock interface. */
};


int flash_mfg_filter_handler_mock_init (struct flash_mfg_filter_handler_mock *mock);
void flash_mfg_filter_handler_mock_release (struct flash_mfg_filter_handler_mock *mock);

int flash_mfg_filter_handler_mock_validate_and_release (struct flash_mfg_filter_handler_mock *mock);


#endif /* FLASH_MFG_FILTER_HANDLER_MOCK_H_ */
