// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_OBSERVER_MOCK_H_
#define SYSTEM_OBSERVER_MOCK_H_

#include "system/system_observer.h"
#include "mock.h"


/**
 * A mock for system notifications.
 */
struct system_observer_mock {
	struct system_observer base;	/**< The base observer instance. */
	struct mock mock;				/**< The base mock interface. */
};


int system_observer_mock_init (struct system_observer_mock *mock);
void system_observer_mock_release (struct system_observer_mock *mock);

int system_observer_mock_validate_and_release (struct system_observer_mock *mock);


#endif /* SYSTEM_OBSERVER_MOCK_H_ */
