// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include "security_manager.h"
#include "system_logging.h"
#include "common/unused.h"


/**
 * Every platform must define a default security policy that can be used when no other policy is
 * available.  This needs to be a global and unbound from any specific security manager instance to
 * ensure this is available even in null manager cases.
 *
 * This must NOT be initialized to a null pointer.
 */
extern const struct security_policy *const default_policy;


/**
 * Get the current security policy applied to the device.
 *
 * @param manager The security manager to query.
 *
 * @return The current security policy.  This will always be a valid instance.  It will never be
 * null.
 */
const struct security_policy* security_manager_get_security_policy (
	const struct security_manager *manager)
{
	const struct security_policy *active_policy;
	int status;

	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_GET_POLICY_FAIL, SECURITY_MANAGER_INVALID_ARGUMENT, 0);

		return default_policy;
	}

	status = manager->internal.get_security_policy (manager, &active_policy);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_GET_POLICY_FAIL, status, 0);

		active_policy = NULL;
	}

	if (active_policy != NULL) {
		return active_policy;
	}
	else {
		return default_policy;
	}
}
