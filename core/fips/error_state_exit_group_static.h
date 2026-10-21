// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ERROR_STATE_EXIT_GROUP_STATIC_H_
#define ERROR_STATE_EXIT_GROUP_STATIC_H_

#include "error_state_exit_group.h"


/* Internal functions declared to allow for static initialization. */
int error_state_exit_group_exit_error_state (const struct error_state_exit_interface *exit);


/**
 * Constant initializer for the error state API.
 */
#define	ERROR_STATE_EXIT_GROUP_API_INIT  { \
		.exit_error_state  = error_state_exit_group_exit_error_state, \
	}


/**
 * Initialize a static instance for a group of handlers that should be executed to exit the FIPS
 * error state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param handlers_ptr List of individual error state handlers that will be executed when exiting
 * the error state.
 * @param count_arg The number of handlers in the list.
 */
#define	error_state_exit_group_static_init(handlers_ptr, count_arg)	{ \
		.base = ERROR_STATE_EXIT_GROUP_API_INIT, \
		.handlers = handlers_ptr, \
		.count = count_arg, \
	}


#endif	/* ERROR_STATE_EXIT_GROUP_STATIC_H_ */
