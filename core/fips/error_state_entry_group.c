// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "error_state_entry_group.h"
#include "common/unused.h"


void error_state_entry_group_enter_error_state (const struct error_state_entry_interface *entry,
	const struct debug_log_entry_info *error_log)
{
	const struct error_state_entry_group *group = (const struct error_state_entry_group*) entry;
	size_t i;

	if (entry == NULL) {
		return;
	}

	for (i = 0; i < group->count; i++) {
		group->handlers[i]->enter_error_state (group->handlers[i], error_log);
	}
}

/**
 * Initialize a group of handlers that should be executed to enter the FIPS error state.
 *
 * Individual handlers will be executed in the order they are populated in the list.
 *
 * @param group The error state handler group to initialize.
 * @param handlers List of individual error state handlers that will be executed when entering the
 * error state.
 * @param count The number of handlers in the list.
 *
 * @return 0 if the handler group was initialized successfully or an error code.
 */
int error_state_entry_group_init (struct error_state_entry_group *group,
	const struct error_state_entry_interface *const *handlers, size_t count)
{
	if ((group == NULL) || (handlers == NULL) || (count == 0)) {
		return ERROR_STATE_ENTRY_INVALID_ARGUMENT;
	}

	memset (group, 0, sizeof (*group));

	group->base.enter_error_state = error_state_entry_group_enter_error_state;

	group->handlers = handlers;
	group->count = count;

	return 0;
}

/**
 * Release the resources used for a group of error state entry handlers.
 *
 * @param group The error state handler group to release.
 */
void error_state_entry_group_release (const struct error_state_entry_group *group)
{
	UNUSED (group);
}
