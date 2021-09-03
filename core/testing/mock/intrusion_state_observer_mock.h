// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_STATE_OBSERVER_MOCK_H_
#define INTRUSION_STATE_OBSERVER_MOCK_H_

#include "intrusion/intrusion_state_observer.h"
#include "mock.h"


/**
 * A mock for intrusion state events.
 */
struct intrusion_state_observer_mock {
	struct intrusion_state_observer base;		/**< The base observer instance. */
	struct mock mock;							/**< The base mock interface. */
};


int intrusion_state_observer_mock_init (struct intrusion_state_observer_mock *mock);
void intrusion_state_observer_mock_release (struct intrusion_state_observer_mock *mock);

int intrusion_state_observer_mock_validate_and_release (struct intrusion_state_observer_mock *mock);


#endif /* INTRUSION_STATE_OBSERVER_MOCK_H_ */
