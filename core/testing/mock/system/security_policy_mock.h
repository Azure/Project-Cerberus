// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURITY_POLICY_MOCK_H_
#define SECURITY_POLICY_MOCK_H_

#include "mock.h"
#include "system/security_policy.h"


/**
 * A mock for the device security policy.
 */
struct security_policy_mock {
	struct security_policy base;	/**< The base policy instance. */
	struct mock mock;				/**< The base mock interface. */
};


int security_policy_mock_init (struct security_policy_mock *mock);
void security_policy_mock_release (struct security_policy_mock *mock);

int security_policy_mock_validate_and_release (struct security_policy_mock *mock);


#endif	/* SECURITY_POLICY_MOCK_H_ */
