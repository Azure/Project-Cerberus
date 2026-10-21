// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_MANAGER_TESTING_H_
#define HOST_STATE_MANAGER_TESTING_H_

#include "testing.h"
#include "host_fw/host_state_manager.h"
#include "testing/mock/flash/flash_mock.h"


void host_state_manager_testing_init_host_state (CuTest *test, struct host_state_manager *manager,
	struct host_state_manager_state *state, struct flash_mock *flash, bool init_flash);


#endif	/* HOST_STATE_MANAGER_TESTING_H_ */
