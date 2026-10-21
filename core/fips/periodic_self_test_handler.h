// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_SELF_TEST_HANDLER_H_
#define PERIODIC_SELF_TEST_HANDLER_H_

#include <stdbool.h>
#include <stddef.h>
#include "error_state_entry_interface.h"
#include "platform_api.h"
#include "self_test_interface.h"
#include "system/periodic_task.h"


/**
 * Variable context for periodic self-test execution.
 */
struct periodic_self_test_handler_state {
	platform_clock next;	/**< Time for the next self-test execution. */
	bool next_valid;		/**< Flag indicating the timeout was set correctly. */
};

/**
 * Handler to execute periodic self-tests on the module.
 */
struct periodic_self_test_handler {
	struct periodic_task_handler base;					/**< Base API for integration with periodic task. */
	struct periodic_self_test_handler_state *state;		/**< Variable context for self-test execution. */
	const struct self_test_interface *const *tests;		/**< List of self-tests to execute. */
	size_t count;										/**< The number of self-tests in the list. */
	uint32_t interval_ms;								/**< Time between self-test executions. */
	const struct error_state_entry_interface *error;	/**< Error state handler for self-test failures. */
};


int periodic_self_test_handler_init (struct periodic_self_test_handler *handler,
	struct periodic_self_test_handler_state *state,
	const struct self_test_interface *const *self_test, size_t self_test_count,
	uint32_t self_test_interval_ms, const struct error_state_entry_interface *error_state);
void periodic_self_test_handler_release (const struct periodic_self_test_handler *handler);


#endif	/* PERIODIC_SELF_TEST_HANDLER_H_ */
