// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_OBSERVER_MOCK_H_
#define HOST_STATE_OBSERVER_MOCK_H_

#include "host_fw/host_state_observer.h"
#include "mock.h"


/**
 * A mock for host state events.
 */
struct host_state_observer_mock {
	struct host_state_observer base;			/**< The base observer instance. */
	struct mock mock;							/**< The base mock interface. */
};


int host_state_observer_mock_init (struct host_state_observer_mock *mock);
void host_state_observer_mock_release (struct host_state_observer_mock *mock);

int host_state_observer_mock_validate_and_release (struct host_state_observer_mock *mock);


#endif /* HOST_STATE_OBSERVER_MOCK_H_ */
