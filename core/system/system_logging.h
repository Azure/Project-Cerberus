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
	SYSTEM_LOGGING_DEVICE_UNLOCKED,			/**< An unlock policy has been applied to the device. */
	SYSTEM_LOGGING_LOCK_STATE_FAIL,			/**< An error occurred attempting to make the lock state consistent. */
	SYSTEM_LOGGING_TOKEN_INVALIDATE_FAIL,	/**< Failed to invalidate a consumed unlock token. */
	SYSTEM_LOGGING_REFRESH_WATCHDOG_FAIL,	/**< Failed to refresh the hardware watchdog timer. */
	SYSTEM_LOGGING_START_WATCHDOG_FAIL,		/**< Failed to start the hardware watchdog timer. */
};

/**
 * Identifiers for security policy parameters.
 */
enum {
	SYSTEM_LOGGING_POLICY_FW_SIGNING,		/**< Security policy check for firmware signing. */
	SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK,	/**< Security policy check for anti-rollback. */
};

/**
 * Identifiers for types of unlock policies that can be applied.
 */
enum {
	SYSTEM_LOGGING_UNLOCK_PERSISTENT,	/**< Identifier for a persistent unlock policy. */
	SYSTEM_LOGGING_UNLOCK_ONE_TIME,		/**< Identifier for a one-time unlock policy. */
};


#endif	/* SYSTEM_LOGGING_H_ */
