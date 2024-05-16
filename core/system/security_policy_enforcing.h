// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURITY_POLICY_ENFORCING_H_
#define SECURITY_POLICY_ENFORCING_H_

#include "security_policy.h"


/**
 * A security policy that will always report an enforcing state.
 */
struct security_policy_enforcing {
	struct security_policy base;	/**< The base policy API. */
};


int security_policy_enforcing_init (struct security_policy_enforcing *policy);
void security_policy_enforcing_release (const struct security_policy_enforcing *policy);


#endif	/* SECURITY_POLICY_ENFORCING_H_ */
