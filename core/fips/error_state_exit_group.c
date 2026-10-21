// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "error_state_exit_group.h"
#include "common/unused.h"


int error_state_exit_group_exit_error_state (const struct error_state_exit_interface *exit)
{
	const struct error_state_exit_group *group = (const struct error_state_exit_group*) exit;
	size_t i;
	int status;

	if (exit == NULL) {
		return ERROR_STATE_EXIT_INVALID_ARGUMENT;
	}

	for (i = 0; i < group->count; i++) {
		status = group->handlers[i]->exit_error_state (group->handlers[i]);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Initialize a group of handlers that should be executed to exit the FIPS error state.
 *
 * Individual handlers will be executed in the order they are populated in the list.
 *
 * @param group The error state handler group to initialize.
 * @param handlers List of individual error state handlers that will be executed when exiting the
 * error state.
 * @param count The number of handlers in the list.
 *
 * @return 0 if the handler group was initialized successfully or an error code.
 */
int error_state_exit_group_init (struct error_state_exit_group *group,
	const struct error_state_exit_interface *const *handlers, size_t count)
{
	if ((group == NULL) || (handlers == NULL) || (count == 0)) {
		return ERROR_STATE_EXIT_INVALID_ARGUMENT;
	}

	memset (group, 0, sizeof (*group));

	group->base.exit_error_state = error_state_exit_group_exit_error_state;

	group->handlers = handlers;
	group->count = count;

	return 0;
}

/**
 * Release the resources used for a group of error state exit handlers.
 *
 * @param group The error state handler group to release.
 */
void error_state_exit_group_release (const struct error_state_exit_group *group)
{
	UNUSED (group);
}
