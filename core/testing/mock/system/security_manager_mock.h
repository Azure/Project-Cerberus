// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURITY_MANAGER_MOCK_H_
#define SECURITY_MANAGER_MOCK_H_

#include "mock.h"
#include "system/security_manager.h"


/**
 * A mock for a security manager.
 */
struct security_manager_mock {
	struct security_manager base;	/**< The base manager instance. */
	struct mock mock;				/**< The base mock interface. */
};


int security_manager_mock_init (struct security_manager_mock *mock);
void security_manager_mock_release (struct security_manager_mock *mock);

int security_manager_mock_validate_and_release (struct security_manager_mock *mock);


#endif	/* SECURITY_MANAGER_MOCK_H_ */
