// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "FreeRTOS.h"
#include "common/unused.h"


/* Dummy implementation for handling ISR platform calls.  This file can be used when no other 
 * processing for this request is necessary for the platform. */
void freertos_isr_update_yield (BaseType_t yield)
{
	UNUSED (yield);
}
