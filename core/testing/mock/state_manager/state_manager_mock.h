// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef STATE_MANAGER_MOCK_H_
#define STATE_MANAGER_MOCK_H_

#include "state_manager/state_manager.h"
#include "mock.h"


/**
 * Mock for base state manager functions.
 */
struct state_manager_mock {
	struct state_manager base;			/**< The base state manager instance. */
	struct mock mock;					/**< The base mock interface. */
};


int state_manager_mock_init (struct state_manager_mock *mock);
void state_manager_mock_release (struct state_manager_mock *mock);

int state_manager_mock_validate_and_release (struct state_manager_mock *mock);


#endif /* STATE_MANAGER_MOCK_H_ */
