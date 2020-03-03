// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef STATE_LOGGING_H_
#define STATE_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for state management.
 */
enum {
	STATE_LOGGING_PERSIST_FAIL,			/**< Failed to persist non-volatile state. */
	STATE_LOGGING_ERASE_FAIL,			/**< Failed to erase unused state region. */
};


#endif /* STATE_LOGGING_H_ */
