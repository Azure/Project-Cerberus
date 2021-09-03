// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_LOGGING_H_
#define INTRUSION_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for chassis intrusion management.
 */
enum {
	INTRUSION_LOGGING_INTRUSION_DETECTED,			/**< Chassis intrusion detected. */
	INTRUSION_LOGGING_HANDLE_FAILED,				/**< Intrusion handling failed. */
	INTRUSION_LOGGING_CHECK_FAILED,					/**< Intrusion state check failed. */
	INTRUSION_LOGGING_INTRUSION_NOTIFICATION,		/**< Processed an intrusion notification. */
	INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION,	/**< Processed a no intrusion notification. */
	INTRUSION_LOGGING_ERROR_NOTIFICATION,			/**< Processed a intrusion error notification. */
};


#endif /* INTRUSION_LOGGING_H_ */
