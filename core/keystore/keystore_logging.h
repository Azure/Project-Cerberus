// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_LOGGING_H_
#define KEYSTORE_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for keystore operations.
 */
enum {
	KEYSTORE_LOGGING_EPHEMERAL_KEY_GENERATION_FAIL,	/**< Failed to generate a cached ephemeral key */
	KEYSTORE_LOGGING_EPHEMERAL_KEY_ADD_FAIL,		/**< Failed to cache a generated ephemeral key */
	KEYSTORE_LOGGING_CACHE_INIT_FAIL,				/**< Failed to initialize the key cache */
	KEYSTORE_LOGGING_CACHE_READ_AND_VALIDATE_FAIL,	/**< Failed to read and validate the key cache */
	KEYSTORE_LOGGING_CACHE_BLOCK_CORRUPTED,			/**< Key cache block is corrupted */
	KEYSTORE_LOGGING_CACHE_INVALID_QUEUE_INDEX,		/**< Invalid queue index */
	KEYSTORE_LOGGING_CACHE_UNAVAILABLE_STORAGE,		/**< Not enough storage available for key cache */
};


#endif	/* KEYSTORE_LOGGING_H_ */
