// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_MANAGER_MOCK_H_
#define INTRUSION_MANAGER_MOCK_H_

#include "intrusion/intrusion_manager.h"
#include "mock.h"


/**
 * A mock for generic intrusion management.
 */
struct intrusion_manager_mock {
	struct intrusion_manager base;	/**< The base manager instance. */
	struct mock mock;				/**< The base mock interface. */
};


int intrusion_manager_mock_init (struct intrusion_manager_mock *mock);
void intrusion_manager_mock_release (struct intrusion_manager_mock *mock);

int intrusion_manager_mock_validate_and_release (struct intrusion_manager_mock *mock);


#endif /* INTRUSION_MANAGER_MOCK_H_ */
