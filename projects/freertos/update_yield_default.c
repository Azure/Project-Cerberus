// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "FreeRTOS.h"
#include "platform_api.h"


/* Unoptimized implementation of an inlined context switch as indicated by the ISR API.  This file
 * can be used when no special handling of the flag has been implemented. */
void freertos_isr_update_yield (BaseType_t yield)
{
	if (yield == pdTRUE) {
		vTaskSwitchContext ();
	}
}

