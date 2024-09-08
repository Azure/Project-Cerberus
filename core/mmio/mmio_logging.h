// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MMIO_LOGGING_H_
#define MMIO_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for MMIO stack.
 */
enum {
	MMIO_LOGGING_ALREADY_MAPPED,	/**< Unexpected map() call while block is already mapped */
	MMIO_LOGGING_NOT_MAPPED,		/**< Unexpected unmap() call while block is not mapped */
};


#endif	/* MMIO_LOGGING_H_ */
