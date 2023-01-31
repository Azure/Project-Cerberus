// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "app_context_null.h"
#include "common/unused.h"


int app_context_null_save (const struct app_context *context)
{
	if (context == NULL) {
		return APP_CONTEXT_INVALID_ARGUMENT;
	}

	/* Nothing to save. */

	return 0;
}

/**
 * Initialize a handler for platforms that have no application context to save or restore.
 *
 * @param context The context handler to initialize.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int app_context_null_init (struct app_context_null *context)
{
	if (context == NULL) {
		return APP_CONTEXT_INVALID_ARGUMENT;
	}

	memset (context, 0, sizeof (struct app_context_null));

	context->base.save = app_context_null_save;

	return 0;
}

/**
 * Release a null application context handler.
 *
 * @param context The context handler to release.
 */
void app_context_null_release (const struct app_context_null *context)
{
	UNUSED (context);
}
