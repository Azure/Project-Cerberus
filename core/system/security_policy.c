// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include "security_policy.h"
#include "system_logging.h"


/**
 * Determine if a security policy requires signature enforcement for firmware images.
 *
 * This is a wrapper call around security_policy.enforce_firmware_signing, but this call can never
 * fail.  Any errors are logged and will fail into the more restrictive policy of signature
 * enforcement.
 *
 * @param policy The security policy to query.
 *
 * @return true if signature enforcement is required or false if not.
 */
bool security_policy_enforce_firmware_signing (const struct security_policy *policy)
{
	int enforce;

	if (policy == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_POLICY_CHECK_FAIL, SYSTEM_LOGGING_POLICY_FW_SIGNING,
			SECURITY_POLICY_INVALID_ARGUMENT);

		return true;
	}

	enforce = policy->enforce_firmware_signing (policy);
	if (ROT_IS_ERROR (enforce)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_POLICY_CHECK_FAIL, SYSTEM_LOGGING_POLICY_FW_SIGNING, enforce);

		enforce = 1;
	}

	return (enforce != 0);
}

/**
 * Determine if a security policy requires anti-rollback checks to be enforced for firmware
 * components.
 *
 * This is a wrapper call around security_policy.enforce_anti_rollback, but this call can never
 * fail.  Any errors are logged and will fail into the more restrictive policy of anti-rollback
 * enforcement.
 *
 * @param policy The security policy to query.
 *
 * @return true if anti-rollback checks are required or false if not.
 */
bool security_policy_enforce_anti_rollback (const struct security_policy *policy)
{
	int enforce;

	if (policy == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_POLICY_CHECK_FAIL, SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK,
			SECURITY_POLICY_INVALID_ARGUMENT);

		return true;
	}

	enforce = policy->enforce_anti_rollback (policy);
	if (ROT_IS_ERROR (enforce)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_POLICY_CHECK_FAIL, SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK, enforce);

		enforce = 1;
	}

	return (enforce != 0);
}
