// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_CLOCK_FREERTOS_H_
#define PLATFORM_CLOCK_FREERTOS_H_

#include "FreeRTOS.h"


/**
 * Container for FreeRTOS tick counts to track timeouts.
 */
typedef struct {
	TickType_t start;
	TickType_t end;
} platform_clock;

/* The clock resolution depends on the tick configuration. */
#define	PLATFORM_CLOCK_RESOLUTION	portTICK_PERIOD_MS


#endif /* PLATFORM_CLOCK_FREERTOS_H_ */
