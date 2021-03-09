// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_LOGGING_H_
#define FLASH_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for flash.
 */
enum {
	FLASH_LOGGING_INCOMPLETE_WRITE,				/**< A write was only partially completed. */
	FLASH_LOGGING_ECC_ERROR,					/**< An ECC error was detected on flash. */
	FLASH_LOGGING_ECC_REFRESH,					/**< Flash data refresh due to ECC error. */
};


#endif /* FLASH_LOGGING_H_ */
