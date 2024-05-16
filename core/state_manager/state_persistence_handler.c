// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "state_logging.h"
#include "state_persistence_handler.h"
#include "common/unused.h"


void state_persistence_handler_prepare (const struct periodic_task_handler *handler)
{
	const struct state_persistence_handler *persist =
		(const struct state_persistence_handler*) handler;

	if (platform_init_timeout (persist->period, &persist->state->next) == 0) {
		persist->state->next_valid = true;
	}
	else {
		persist->state->next_valid = false;
	}
}

const platform_clock* state_persistence_handler_get_next_execution (
	const struct periodic_task_handler *handler)
{
	const struct state_persistence_handler *persist =
		(const struct state_persistence_handler*) handler;

	if (persist->state->next_valid) {
		return &persist->state->next;
	}
	else {
		/* If the next timeout is not valid, just indicate immediate execution. */
		return NULL;
	}
}

void state_persistence_handler_execute (const struct periodic_task_handler *handler)
{
	const struct state_persistence_handler *persist =
		(const struct state_persistence_handler*) handler;
	size_t i;
	int status;

	for (i = 0; i < persist->manager_count; i++) {
		status = state_manager_store_non_volatile_state (persist->managers[i]);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_STATE_MGR,
				STATE_LOGGING_PERSIST_FAIL, i, status);
		}
	}

	state_persistence_handler_prepare (handler);
}

/**
 * Initialize a handler to persist current state to flash.
 *
 * @param handler The state handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param managers The list of states that should be stored.
 * @param manager_count The number of state managers in the list.
 * @param period_ms The amount of time between state storage requests, in milliseconds.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int state_persistence_handler_init (struct state_persistence_handler *handler,
	struct state_persistence_handler_state *state, struct state_manager **managers,
	size_t manager_count, uint32_t period_ms)
{
	if ((handler == NULL) || (state == NULL) || (managers == NULL) || (manager_count == 0)) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct state_persistence_handler));

	handler->base.prepare = state_persistence_handler_prepare;
	handler->base.get_next_execution = state_persistence_handler_get_next_execution;
	handler->base.execute = state_persistence_handler_execute;

	handler->state = state;
	handler->managers = managers;
	handler->manager_count = manager_count;
	handler->period = period_ms;

	return state_persistence_handler_init_state (handler);
}

/**
 * Initialize only the variable state for a state persistence handler.  The rest of the handler is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The persistence handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int state_persistence_handler_init_state (const struct state_persistence_handler *handler)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->managers == NULL) ||
		(handler->manager_count == 0)) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (struct state_persistence_handler_state));

	return 0;
}

/**
 * Release the resources used by a state persistence handler.
 *
 * @param handler The persistence handler to release.
 */
void state_persistence_handler_release (const struct state_persistence_handler *handler)
{
	UNUSED (handler);
}
