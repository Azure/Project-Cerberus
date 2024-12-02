// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MANAGER_MOCK_H_
#define CFM_MANAGER_MOCK_H_

#include "mock.h"
#include "manifest/cfm/cfm_manager.h"
#include "testing/engines/hash_testing_engine.h"


/**
 * A mock for the CFM management API.
 */
struct cfm_manager_mock {
	struct cfm_manager base;	/**< The base manager instance. */
	struct mock mock;			/**< The base mock interface. */
	HASH_TESTING_ENGINE (hash);	/**< Manager hash instance. */
};


int cfm_manager_mock_init (struct cfm_manager_mock *mock);
void cfm_manager_mock_release (struct cfm_manager_mock *mock);

int cfm_manager_mock_validate_and_release (struct cfm_manager_mock *mock);


#endif	/* CFM_MANAGER_MOCK_H_ */
