// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RMA_LOGGING_H_
#define RMA_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for RMA operations.
 */
enum {
	RMA_LOGGING_RMA_TRANSITION_DONE,	/**< The device has been transitioned to the RMA state. */
	RMA_LOGGING_RMA_TRANSITION_FAILED,	/**< The RMA state transition has not been completed. */
};


#endif	/* RMA_LOGGING_H_ */
