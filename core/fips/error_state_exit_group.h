// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ERROR_STATE_EXIT_GROUP_H_
#define ERROR_STATE_EXIT_GROUP_H_

#include <stddef.h>
#include "error_state_exit_interface.h"


/**
 * A handler to exit the FIPS error state that provides the ability to aggregate multiple
 * independent steps that need to be executed when exiting the error state.
 */
struct error_state_exit_group {
	struct error_state_exit_interface base;						/**< The base error state API. */
	const struct error_state_exit_interface *const *handlers;	/**< List of error state handlers to execute. */
	size_t count;												/**< Number of handlers in the list. */
};


int error_state_exit_group_init (struct error_state_exit_group *group,
	const struct error_state_exit_interface *const *handlers, size_t count);
void error_state_exit_group_release (const struct error_state_exit_group *group);


#endif	/* ERROR_STATE_EXIT_GROUP_H_ */
