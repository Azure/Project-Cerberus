// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_LOGGING_H_
#define SYSTEM_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for system management.
 */
enum {
	SYSTEM_LOGGING_RESET_NOT_EXECUTED,		/**< Failed to schedule a device reset. */
	SYSTEM_LOGGING_RESET_FAIL,				/**< Failed to reset the device. */
	SYSTEM_LOGGING_PERIODIC_FAILED,			/**< A periodic task failed to execute a handler. */
	SYSTEM_LOGGING_POLICY_CHECK_FAIL,		/**< Failed to query the device security policy. */
	SYSTEM_LOGGING_GET_POLICY_FAIL,			/**< Failed to query for the active security policy. */
	SYSTEM_LOGGING_UNDETERMINED_UNLOCK,		/**< An error prevented detection or application of any possible unlock policy. */
};

/**
 * Identifiers for security policy parameters.
 */
enum {
	SYSTEM_LOGGING_POLICY_FW_SIGNING,		/**< Security policy check for firmware signing. */
	SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK,	/**< Security policy check for anti-rollback. */
};


#endif /* SYSTEM_LOGGING_H_ */
