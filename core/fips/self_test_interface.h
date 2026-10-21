// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SELF_TEST_INTERFACE_H_
#define SELF_TEST_INTERFACE_H_

#include <stdint.h>
#include "logging/debug_log.h"


/**
 * Interface to manage execution of module self-tests.
 */
struct self_test_interface {
	/**
	 * Execute the module self-test.  Self-test failures will be reported without yielding task
	 * execution.
	 *
	 * Errors during self-test execution must not be logged by self-test instance unless it can be
	 * guaranteed by the specific implementation that creating a log entry will never yield
	 * processing to other operations.
	 *
	 * @param self_test The self-test to execute.
	 * @param error_info Output for self-test details that should be logged, generally in the case
	 * of a self-test error.  The format marker in the log structure will be used as a flag to
	 * indicate when the log contents are valid.  A non-zero format indicates valid log contents.
	 *
	 * @return 0 if the self-test ran successfully or an error code.
	 */
	int (*run_self_test) (const struct self_test_interface *self_test,
		struct debug_log_entry_info *error_info);
};


/* This type does not define any error codes.  The expectation is that specific self-test instances
 * will use error codes relevant for the specific self-test being executed. */


#endif	/* SELF_TEST_INTERFACE_H_ */
