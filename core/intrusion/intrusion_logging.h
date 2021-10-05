// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_LOGGING_H_
#define INTRUSION_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for chassis intrusion management.
 */
enum {
	INTRUSION_LOGGING_INTRUSION_DETECTED,				/**< Chassis intrusion detected. */
	INTRUSION_LOGGING_HANDLE_FAILED,					/**< Intrusion handling failed. */
	INTRUSION_LOGGING_CHECK_FAILED,						/**< Intrusion state check failed. */
	INTRUSION_LOGGING_INTRUSION_NOTIFICATION,			/**< Processed an intrusion notification. */
	INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION,		/**< Processed a no intrusion notification. */
	INTRUSION_LOGGING_ERROR_NOTIFICATION,				/**< Processed a intrusion error notification. */
	INTRUSION_LOGGING_STORE_DATA_FAIL,					/**< Received a store data failure response. */
	INTRUSION_LOGGING_CHALLENGE_DATA_FAIL,				/**< Received a challenge data failure response. */
	INTRUSION_LOGGING_CHALLENGE_DATA_INVALID_HASH_LEN,	/**< Received a challenge data response with an incorrect hash len. */
};


#endif /* INTRUSION_LOGGING_H_ */
