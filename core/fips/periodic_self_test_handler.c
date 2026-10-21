// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "periodic_self_test_handler.h"
#include "common/unused.h"


/**
 * Update the time for the text periodic self-test execution.
 *
 * @param self_test Self-test handler to update.
 */
static void periodic_self_test_handler_update_execution_time (
	const struct periodic_self_test_handler *self_test)
{
	int status;

	status = platform_init_timeout (self_test->interval_ms, &self_test->state->next);
	self_test->state->next_valid = (status == 0);
}

void periodic_self_test_handler_prepare (const struct periodic_task_handler *handler)
{
	const struct periodic_self_test_handler *self_test =
		(const struct periodic_self_test_handler*) handler;

	periodic_self_test_handler_update_execution_time (self_test);
}

const platform_clock* periodic_self_test_handler_get_next_execution (
	const struct periodic_task_handler *handler)
{
	const struct periodic_self_test_handler *self_test =
		(const struct periodic_self_test_handler*) handler;

	if (self_test->state->next_valid) {
		return &self_test->state->next;
	}
	else {
		return NULL;
	}
}

void periodic_self_test_handler_execute (const struct periodic_task_handler *handler)
{
	const struct periodic_self_test_handler *self_test =
		(const struct periodic_self_test_handler*) handler;
	struct debug_log_entry_info error_log;
	size_t i;
	int status;

	for (i = 0; i < self_test->count; i++) {
		memset (&error_log, 0, sizeof (error_log));

		status = self_test->tests[i]->run_self_test (self_test->tests[i], &error_log);
		if (status != 0) {
			/* There was a self-test failure, so enter the error state and stop running any more
			 * tests. */
			self_test->error->enter_error_state (self_test->error,
				(error_log.format != 0) ? &error_log : NULL);
			break;
		}
		else if ((status == 0) && (error_log.format != 0)) {
			/* Log an entry provided by the successful self-test. */
			debug_log_create_entry (error_log.severity, error_log.component, error_log.msg_index,
				error_log.arg1, error_log.arg2);
		}
	}

	periodic_self_test_handler_update_execution_time (self_test);
}

/**
 * Initialize a handler to execute periodic self-tests for a FIPS module.
 *
 * @param handler The self-test execution handler to initialize.
 * @param state Variable context for the self-test handler.  This must be uninitialized.
 * @param self_tests A list of self-tests that should be executed.
 * @param self_test_count The number of self-tests in the list.
 * @param self_test_interval The amount of time to wait between self-test execution, in
 * milliseconds.  At each execution interval, all registered self-tests will be executed.
 * @param error_state Handler to put the module into the error state.
 *
 * @return 0 if the self-test handler was initialized successfully or an error code.
 */
int periodic_self_test_handler_init (struct periodic_self_test_handler *handler,
	struct periodic_self_test_handler_state *state,
	const struct self_test_interface *const *self_tests, size_t self_test_count,
	uint32_t self_test_interval_ms, const struct error_state_entry_interface *error_state)
{
	if ((handler == NULL) || (state == NULL) || (self_tests == NULL) || (self_test_count == 0) ||
		(error_state == NULL)) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (*handler));

	handler->base.prepare = periodic_self_test_handler_prepare;
	handler->base.get_next_execution = periodic_self_test_handler_get_next_execution;
	handler->base.execute = periodic_self_test_handler_execute;

	handler->state = state;
	handler->tests = self_tests;
	handler->count = self_test_count;
	handler->interval_ms = self_test_interval_ms;
	handler->error = error_state;

	return 0;
}

/**
 * Release the resources used for executing periodic self-tests.
 *
 * @param handler The self-test execution handler to release.
 */
void periodic_self_test_handler_release (const struct periodic_self_test_handler *handler)
{
	UNUSED (handler);
}
