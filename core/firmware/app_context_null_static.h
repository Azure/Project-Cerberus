// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef APP_CONTEXT_NULL_STATIC_H_
#define APP_CONTEXT_NULL_STATIC_H_

#include "firmware/app_context_null.h"


/* Internal functions declared to allow for static initialization. */
int app_context_null_save (const struct app_context *context);


/**
 * Constant initializer for the application context API.
 */
#define	APP_CONTEXT_NULL_API_INIT  { \
		.save = app_context_null_save \
	}


/**
 * Initialize a static instance of an application context handler for platforms that have no
 * application context to save or restore.
 *
 * There is no validation done on the arguments.
 */
#define	app_context_null_static_init	{ \
		.base = APP_CONTEXT_NULL_API_INIT, \
	}


#endif	/* APP_CONTEXT_NULL_STATIC_H_ */
