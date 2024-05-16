// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "periodic_task.h"
#include "system_logging.h"


/**
 * Prepare a list of handlers for execution.
 *
 * @param handlers The list of handlers to prepare.  Each entry in the list is a pointer to a
 * handler to prepare.
 * @param count The number of handlers in the list.
 */
void periodic_task_prepare_handlers (const struct periodic_task_handler **handlers, size_t count)
{
	if (handlers) {
		size_t i;

		for (i = 0; i < count; i++) {
			if (handlers[i] && handlers[i]->prepare) {
				handlers[i]->prepare (handlers[i]);
			}
		}
	}
}

/**
 * Determine the next handler that will be ready for execution.  If the handler is ready
 * immediately, execute it.  If the handler will be ready at some point in the future, wait until
 * that time, then execute the handler.
 *
 * This is a simple search and does not guarantee fair opportunity for each handler to run.  It is
 * expected that handlers will be constructed to not starve each other.
 *
 * @param handlers The list of handlers to search.  Each entry in the list is a pointer to a
 * handler that could be executed.
 * @param count The number of handlers in the list.
 *
 * @return 0 if the next handler was executed or an error code.  This does not report status of the
 * handler, just whether a handler was executed or not.
 */
int periodic_task_execute_next_handler (const struct periodic_task_handler **handlers, size_t count)
{
	size_t i;
	const struct periodic_task_handler *next = NULL;
	uint32_t wait_time = 0xffffffff;
	int status;

	if ((handlers == NULL) || (count == 0)) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	for (i = 0; i < count; i++) {
		if (handlers[i] != NULL) {
			const platform_clock *next_time = handlers[i]->get_next_execution (handlers[i]);
			uint32_t next_wait;

			if (next_time != NULL) {
				status = platform_get_timeout_remaining (next_time, &next_wait);
				if (status != 0) {
					return status;
				}

				if (next_wait < wait_time) {
					wait_time = next_wait;
					next = handlers[i];
				}
			}
			else if (wait_time != 0) {
				wait_time = 0;
				next = handlers[i];
			}
		}
	}

	if (next == NULL) {
		return PERIODIC_TASK_NO_HANDLERS;
	}

	if (wait_time != 0) {
		platform_msleep (wait_time);
	}

	next->execute (next);

	return 0;
}
