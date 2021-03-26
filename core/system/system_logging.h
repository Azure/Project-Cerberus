// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_LOGGING_H_
#define SYSTEM_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for system management.
 */
enum {
	SYSTEM_LOGGING_RESET_NOT_EXECUTED,	/**< Failed to schedule a device reset. */
	SYSTEM_LOGGING_RESET_FAIL,			/**< Failed to reset the device. */
};


#endif /* SYSTEM_LOGGING_H_ */
