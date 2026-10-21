// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_LOGGING_H_
#define RIOT_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for RIoT operations.
 */
enum {
	RIOT_LOGGING_DEVID_AUTH_STATUS,			/**< Authentication status for a signed Device ID. */
	RIOT_LOGGING_DME_REVOKED,				/**< The current DME key has been revoked. */
	RIOT_LOGGING_DME_REVOCATION_FAILED,		/**< Failed to revoke the current DME key. */
	RIOT_LOGGING_DICE_REVOKED,				/**< The current DICE identity has been revoked. */
	RIOT_LOGGING_DICE_REVOCATION_FAILED,	/**< Failed to revoke the current DICE identity. */
};


#endif	/* RIOT_LOGGING_H_ */
