// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IDE_DRIVER_INTERFACE_MOCK_H_
#define IDE_DRIVER_INTERFACE_MOCK_H_

#include "mock.h"
#include "pcisig/ide/ide_driver.h"


/**
 * IDE driver interface mock
 */
struct ide_driver_mock {
	struct ide_driver base;	/**< The IDE driver interface. */
	struct mock mock;		/**< The mock interface. */
};


int ide_driver_mock_init (struct ide_driver_mock *mock);

int ide_driver_mock_validate_and_release (struct ide_driver_mock *mock);


#endif	/* IDE_DRIVER_INTERFACE_MOCK_H_ */
