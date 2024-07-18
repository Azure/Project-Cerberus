// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_LOGGING_H_
#define KEYSTORE_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for keystore operations.
 */
enum {
	KEYSTORE_LOGGING_KEY_GENERATION_FAIL,	/**< Failed to generate a cached ephemeral key */
	KEYSTORE_LOGGING_ADD_KEY_FAIL,			/**< Failed to cache a generated ephemeral key */
};


#endif	/* KEYSTORE_LOGGING_H_ */
