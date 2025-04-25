// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ERROR_STATE_ENTRY_GROUP_STATIC_H_
#define ERROR_STATE_ENTRY_GROUP_STATIC_H_

#include "error_state_entry_group.h"


/* Internal functions declared to allow for static initialization. */
void error_state_entry_group_enter_error_state (const struct error_state_entry_interface *entry,
	const struct debug_log_entry_info *error_log);


/**
 * Constant initializer for the error state API.
 */
#define	ERROR_STATE_ENTRY_GROUP_API_INIT  { \
		.enter_error_state  = error_state_entry_group_enter_error_state, \
	}


/**
 * Initialize a static instance for a group of handlers that should be executed to enter the FIPS
 * error state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param handlers_ptr List of individual error state handlers that will be executed when entering
 * the error state.
 * @param count_arg The number of handlers in the list.
 */
#define	error_state_entry_group_static_init(handlers_ptr, count_arg)	{ \
		.base = ERROR_STATE_ENTRY_GROUP_API_INIT, \
		.handlers = handlers_ptr, \
		.count = count_arg, \
	}


#endif	/* ERROR_STATE_ENTRY_GROUP_STATIC_H_ */
