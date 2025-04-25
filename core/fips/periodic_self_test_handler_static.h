// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_SELF_TEST_HANDLER_STATIC_H_
#define PERIODIC_SELF_TEST_HANDLER_STATIC_H_

#include "periodic_self_test_handler.h"


/* Internal functions declared to allow for static initialization. */
void periodic_self_test_handler_prepare (const struct periodic_task_handler *handler);
const platform_clock* periodic_self_test_handler_get_next_execution (
	const struct periodic_task_handler *handler);
void periodic_self_test_handler_execute (const struct periodic_task_handler *handler);


/**
 * Constant initializer for the task handler API.
 */
#define	PERIODIC_SELF_TEST_HANDLER_API_INIT  { \
		.prepare = periodic_self_test_handler_prepare, \
		.get_next_execution = periodic_self_test_handler_get_next_execution, \
		.execute = periodic_self_test_handler_execute \
	}


/**
 * Initialize a static instance of a handler to execute periodic self-tests for a FIPS module.  This
 * can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the self-test handler.
 * @param self_tests_ptr A list of self-tests that should be executed.
 * @param self_test_count_arg The number of self-tests in the list.
 * @param self_test_interval_ms_arg The amount of time to wait between self-test execution, in
 * milliseconds.  At each execution interval, all registered self-tests will be executed.
 * @param error_state_ptr Handler to put the module into the error state.
 */
#define	periodic_self_test_handler_static_init(state_ptr, self_tests_ptr, self_test_count_arg, \
	self_test_interval_ms_arg, error_state_ptr)	{ \
		.base = PERIODIC_SELF_TEST_HANDLER_API_INIT, \
		.state = state_ptr, \
		.tests = self_tests_ptr, \
		.count = self_test_count_arg, \
		.interval_ms = self_test_interval_ms_arg, \
		.error = error_state_ptr, \
	}


#endif	/* PERIODIC_SELF_TEST_HANDLER_STATIC_H_ */
