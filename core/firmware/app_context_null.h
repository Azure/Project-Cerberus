// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef APP_CONTEXT_NULL_H_
#define APP_CONTEXT_NULL_H_

#include "firmware/app_context.h"


/**
 * Null handler for application context, for scenarios where no context saving is needed.
 */
struct app_context_null {
	struct app_context base;		/**< Base application context API. */
};


int app_context_null_init (struct app_context_null *context);
void app_context_null_release (const struct app_context_null *context);


#endif /* APP_CONTEXT_NULL_H_ */
