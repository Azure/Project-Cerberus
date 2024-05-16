// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURITY_POLICY_ENFORCING_STATIC_H_
#define SECURITY_POLICY_ENFORCING_STATIC_H_

#include "security_policy_enforcing.h"


/* Internal functions declared to allow for static initialization. */
int security_policy_enforcing_is_persistent (const struct security_policy *policy);
int security_policy_enforcing_enforce_firmware_signing (const struct security_policy *policy);
int security_policy_enforcing_enforce_anti_rollback (const struct security_policy *policy);
int security_policy_enforcing_check_unlock_persistence (const struct security_policy *policy,
	const uint8_t *unlock, size_t length);
int security_policy_enforcing_parse_unlock_policy (const struct security_policy *policy,
	const uint8_t *unlock, size_t length);


/**
 * Constant initializer for the security policy API.
 */
#define	SECURITY_POLICY_ENFORCING_API_INIT	{ \
		.is_persistent = security_policy_enforcing_is_persistent, \
		.enforce_firmware_signing = security_policy_enforcing_enforce_firmware_signing, \
		.enforce_anti_rollback = security_policy_enforcing_enforce_anti_rollback, \
		.check_unlock_persistence = security_policy_enforcing_check_unlock_persistence, \
		.parse_unlock_policy = security_policy_enforcing_parse_unlock_policy, \
	}


/**
 * Initialize a static instance of a security policy that always enforces security checks.  This can
 * be a constant instance.
 */
#define	security_policy_enforcing_static_init	{ \
		.base = SECURITY_POLICY_ENFORCING_API_INIT, \
	}


#endif	/* SECURITY_POLICY_ENFORCING_STATIC_H_ */
