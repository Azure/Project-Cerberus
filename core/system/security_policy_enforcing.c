// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "security_policy_enforcing.h"
#include "common/unused.h"


int security_policy_enforcing_is_persistent (const struct security_policy *policy)
{
	if (policy == NULL) {
		return SECURITY_POLICY_INVALID_ARGUMENT;
	}

	/* While this certainly may be persistent, it could be used in different scenarios with
	 * different properties.  Assume that it may not be persistent and that this fact doesn't have
	 * an impact on other workflows.  This value can be parameterized later, if necessary. */
	return 0;
}

int security_policy_enforcing_enforce_firmware_signing (const struct security_policy *policy)
{
	if (policy == NULL) {
		return SECURITY_POLICY_INVALID_ARGUMENT;
	}

	return 1;
}

int security_policy_enforcing_enforce_anti_rollback (const struct security_policy *policy)
{
	if (policy == NULL) {
		return SECURITY_POLICY_INVALID_ARGUMENT;
	}

	return 1;
}

int security_policy_enforcing_check_unlock_persistence (const struct security_policy *policy,
	const uint8_t *unlock, size_t length)
{
	if ((policy == NULL) || (unlock == NULL)) {
		return SECURITY_POLICY_INVALID_ARGUMENT;
	}

	/* Always return the same value as the is_persistent check. */
	return 0;
}

int security_policy_enforcing_parse_unlock_policy (const struct security_policy *policy,
	const uint8_t *unlock, size_t length)
{
	if ((policy == NULL) || (unlock == NULL)) {
		return SECURITY_POLICY_INVALID_ARGUMENT;
	}

	/* It's not possible to load a different policy. */
	return SECURITY_POLICY_IMMUTABLE;
}

/**
 * Initialize a security policy that always enforces security checks.
 *
 * @param policy The policy to initialize.
 *
 * @return 0 if the policy was initialized successfully or an error code.
 */
int security_policy_enforcing_init (struct security_policy_enforcing *policy)
{
	if (policy == NULL) {
		return SECURITY_POLICY_INVALID_ARGUMENT;
	}

	memset (policy, 0, sizeof (struct security_policy_enforcing));

	policy->base.is_persistent = security_policy_enforcing_is_persistent;
	policy->base.enforce_firmware_signing = security_policy_enforcing_enforce_firmware_signing;
	policy->base.enforce_anti_rollback = security_policy_enforcing_enforce_anti_rollback;
	policy->base.check_unlock_persistence = security_policy_enforcing_check_unlock_persistence;
	policy->base.parse_unlock_policy = security_policy_enforcing_parse_unlock_policy;

	return 0;
}

/**
 * Release the resources used by an enforcing security policy.
 *
 * @param policy The policy to release.
 */
void security_policy_enforcing_release (const struct security_policy_enforcing *policy)
{
	UNUSED (policy);
}
