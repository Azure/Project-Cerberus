// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef APP_CONTEXT_H_
#define APP_CONTEXT_H_

#include "status/rot_status.h"


/**
 * A platform-independent API for storing the running context that will be restored on reboot.
 */
struct app_context {
	/**
	 * Save the current context for the running application.  A reboot after this context has been
	 * saved will restore it and skip normal boot-time initializations and checks.
	 *
	 * @param context The application context instance.
	 *
	 * @return 0 if the application context has been saved or an error code.
	 */
	int (*save) (const struct app_context *context);
};


#define	APP_CONTEXT_ERROR(code)		ROT_ERROR (ROT_MODULE_APP_CONTEXT, code)

/**
 * Error codes that can be generated by the application context.
 */
enum {
	APP_CONTEXT_INVALID_ARGUMENT = APP_CONTEXT_ERROR (0x00),	/**< Input parameter is null or not valid. */
	APP_CONTEXT_NO_MEMORY = APP_CONTEXT_ERROR (0x01),			/**< Memory allocation failed. */
	APP_CONTEXT_SAVE_FAILED = APP_CONTEXT_ERROR (0x02),			/**< The running context has not been saved. */
	APP_CONTEXT_NO_CONTEXT = APP_CONTEXT_ERROR (0x03),			/**< No context is available. */
	APP_CONTEXT_NO_DATA = APP_CONTEXT_ERROR (0x04),				/**< No data is available. */
};


#endif	/* APP_CONTEXT_H_ */
