// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/host_fw/host_processor_single_testing.h"


TEST_SUITE_LABEL ("host_processor_single");


/*******************
 * Test cases
 *******************/

static void host_processor_single_test_flash_rollback_not_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_not_dirty_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_not_dirty_checked (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_not_dirty_checked_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_dirty_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_dirty_checked (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_dirty_checked_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base,
		false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ROLLBACK, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_flash_rollback_null (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host.test.base.flash_rollback (NULL, &host.hash.base, &host.rsa.base, false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.flash_rollback (&host.test.base, NULL, &host.rsa.base, false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, NULL, false, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}


TEST_SUITE_START (host_processor_single_flash_rollback);

TEST (host_processor_single_test_flash_rollback_not_dirty);
TEST (host_processor_single_test_flash_rollback_not_dirty_bypass);
TEST (host_processor_single_test_flash_rollback_not_dirty_checked);
TEST (host_processor_single_test_flash_rollback_not_dirty_checked_bypass);
TEST (host_processor_single_test_flash_rollback_dirty);
TEST (host_processor_single_test_flash_rollback_dirty_bypass);
TEST (host_processor_single_test_flash_rollback_dirty_checked);
TEST (host_processor_single_test_flash_rollback_dirty_checked_bypass);
TEST (host_processor_single_test_flash_rollback_null);

TEST_SUITE_END;
