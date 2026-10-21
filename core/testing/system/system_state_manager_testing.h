// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_STATE_MANAGER_TESTING_H_
#define SYSTEM_STATE_MANAGER_TESTING_H_

#include "testing.h"
#include "state_manager/state_manager.h"
#include "testing/mock/flash/flash_mock.h"


void system_state_manager_testing_init_system_state (CuTest *test, struct state_manager *manager,
	struct state_manager_state *state, struct flash_mock *flash, bool init_flash);


#endif	/* SYSTEM_STATE_MANAGER_TESTING_H_ */
