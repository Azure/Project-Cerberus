// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IDE_DRIVER_OBSERVER_MOCK_H_
#define IDE_DRIVER_OBSERVER_MOCK_H_

#include "mock.h"
#include "pcisig/ide/ide_driver_observer.h"


/**
 * A mock for IDE driver notifications.
 */
struct ide_driver_observer_mock {
	struct ide_driver_observer base;	/**< The base observer instance. */
	struct mock mock;					/**< The base mock interface. */
};


int ide_driver_observer_mock_init (struct ide_driver_observer_mock *mock);
void ide_driver_observer_mock_release (struct ide_driver_observer_mock *mock);

int ide_driver_observer_mock_validate_and_release (
	struct ide_driver_observer_mock *mock);


#endif	/* IDE_DRIVER_OBSERVER_MOCK_H_ */
