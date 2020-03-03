// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_OBSERVER_MOCK_H_
#define FIRMWARE_UPDATE_OBSERVER_MOCK_H_

#include "firmware/firmware_update_observer.h"
#include "mock.h"


/**
 * A mock for firmware update notifications.
 */
struct firmware_update_observer_mock {
	struct firmware_update_observer base;	/**< The base observer instance. */
	struct mock mock;						/**< The base mock interface. */
};


int firmware_update_observer_mock_init (struct firmware_update_observer_mock *mock);
void firmware_update_observer_mock_release (struct firmware_update_observer_mock *mock);

int firmware_update_observer_mock_validate_and_release (struct firmware_update_observer_mock *mock);


#endif /* FIRMWARE_UPDATE_OBSERVER_MOCK_H_ */
