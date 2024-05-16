// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEVICE_MANAGER_OBSERVER_MOCK_H_
#define DEVICE_MANAGER_OBSERVER_MOCK_H_

#include "mock.h"
#include "cmd_interface/device_manager_observer.h"


/**
 * A mock for handling device manager observer.
 */
struct device_manager_observer_mock {
	struct device_manager_observer base;	/**< The base authorization handler. */
	struct mock mock;						/**< The base mock interface. */
};


int device_manager_observer_mock_init (struct device_manager_observer_mock *mock);
void device_manager_observer_mock_release (struct device_manager_observer_mock *mock);

int device_manager_observer_mock_validate_and_release (struct device_manager_observer_mock *mock);


#endif	/* DEVICE_MANAGER_OBSERVER_MOCK_H_ */
