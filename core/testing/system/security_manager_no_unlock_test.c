// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/security_manager_no_unlock.h"
#include "system/security_manager_no_unlock_static.h"


TEST_SUITE_LABEL ("security_manager_no_unlock");


/*******************
 * Test cases
 *******************/

static void security_manager_no_unlock_test_init (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.base.lock_device);
	CuAssertPtrNotNull (test, manager.base.unlock_device);
	CuAssertPtrNotNull (test, manager.base.get_unlock_counter);
	CuAssertPtrNotNull (test, manager.base.has_unlock_policy);
	CuAssertPtrNotNull (test, manager.base.load_security_policy);
	CuAssertPtrNotNull (test, manager.base.apply_device_config);

	CuAssertPtrNotNull (test, manager.base.internal.get_security_policy);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (NULL);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);
}

static void security_manager_no_unlock_test_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, manager.base.lock_device);
	CuAssertPtrNotNull (test, manager.base.unlock_device);
	CuAssertPtrNotNull (test, manager.base.get_unlock_counter);
	CuAssertPtrNotNull (test, manager.base.has_unlock_policy);
	CuAssertPtrNotNull (test, manager.base.load_security_policy);
	CuAssertPtrNotNull (test, manager.base.apply_device_config);

	CuAssertPtrNotNull (test, manager.base.internal.get_security_policy);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_release_null (CuTest *test)
{
	TEST_START;

	security_manager_no_unlock_release (NULL);
}

static void security_manager_no_unlock_test_lock_device (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.lock_device (&manager.base);
	CuAssertIntEquals (test, 0, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_lock_device_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	int status;

	TEST_START;

	status = manager.base.lock_device (&manager.base);
	CuAssertIntEquals (test, 0, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_lock_device_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.lock_device (NULL);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_unlock_device (CuTest *test)
{
	struct security_manager_no_unlock manager;
	uint8_t policy[2];
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.unlock_device (&manager.base, policy, sizeof (policy));
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_unlock_device_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	uint8_t policy[2];
	int status;

	TEST_START;

	status = manager.base.unlock_device (&manager.base, policy, sizeof (policy));
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_unlock_device_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	uint8_t policy[2];
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.unlock_device (NULL, policy, sizeof (policy));
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	status = manager.base.unlock_device (&manager.base, NULL, sizeof (policy));
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	status = manager.base.unlock_device (&manager.base, policy, 0);
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_unlock_counter (CuTest *test)
{
	struct security_manager_no_unlock manager;
	uint8_t counter = 5;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.get_unlock_counter (&manager.base, &counter, 1);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 0, counter);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_unlock_counter_large_buffer (CuTest *test)
{
	struct security_manager_no_unlock manager;
	uint8_t counter[2] = {5, 9};
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.get_unlock_counter (&manager.base, counter, 2);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 0, counter[0]);
	CuAssertIntEquals (test, 9, counter[1]);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_unlock_counter_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	uint8_t counter = 0xa;
	int status;

	TEST_START;

	status = manager.base.get_unlock_counter (&manager.base, &counter, 1);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 0, counter);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_unlock_counter_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	uint8_t counter = 5;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.get_unlock_counter (NULL, &counter, 1);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	status = manager.base.get_unlock_counter (&manager.base, NULL, 1);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_unlock_counter_small_buffer (CuTest *test)
{
	struct security_manager_no_unlock manager;
	uint8_t counter = 5;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.get_unlock_counter (&manager.base, &counter, 0);
	CuAssertIntEquals (test, SECURITY_MANAGER_SMALL_COUNTER_BUFFER, status);
	CuAssertIntEquals (test, 5, counter);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_has_unlock_policy (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.has_unlock_policy (&manager.base);
	CuAssertIntEquals (test, 0, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_has_unlock_policy_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	int status;

	TEST_START;

	status = manager.base.has_unlock_policy (&manager.base);
	CuAssertIntEquals (test, 0, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_has_unlock_policy_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.has_unlock_policy (NULL);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_load_security_policy (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.load_security_policy (&manager.base);
	CuAssertIntEquals (test, 0, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_load_security_policy_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	int status;

	TEST_START;

	status = manager.base.load_security_policy (&manager.base);
	CuAssertIntEquals (test, 0, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_load_security_policy_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.load_security_policy (NULL);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_apply_device_config (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.apply_device_config (&manager.base);
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_apply_device_config_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	int status;

	TEST_START;

	status = manager.base.apply_device_config (&manager.base);
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_apply_device_config_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.apply_device_config (NULL);
	CuAssertIntEquals (test, SECURITY_MANAGER_UNSUPPORTED, status);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_security_policy (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;
	const struct security_policy *policy = (const struct security_policy*) &status;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.internal.get_security_policy (&manager.base, &policy);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, (void*) policy);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_security_policy_static_init (CuTest *test)
{
	struct security_manager_no_unlock manager = security_manager_no_unlock_static_init;
	int status;
	const struct security_policy *policy = (const struct security_policy*) &status;

	TEST_START;

	status = manager.base.internal.get_security_policy (&manager.base, &policy);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, (void*) policy);

	security_manager_no_unlock_release (&manager);
}

static void security_manager_no_unlock_test_get_security_policy_null (CuTest *test)
{
	struct security_manager_no_unlock manager;
	int status;
	const struct security_policy *policy;

	TEST_START;

	status = security_manager_no_unlock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.internal.get_security_policy (NULL, &policy);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	status = manager.base.internal.get_security_policy (&manager.base, NULL);
	CuAssertIntEquals (test, SECURITY_MANAGER_INVALID_ARGUMENT, status);

	security_manager_no_unlock_release (&manager);
}


// *INDENT-OFF*
TEST_SUITE_START (security_manager_no_unlock);

TEST (security_manager_no_unlock_test_init);
TEST (security_manager_no_unlock_test_init_null);
TEST (security_manager_no_unlock_test_static_init);
TEST (security_manager_no_unlock_test_release_null);
TEST (security_manager_no_unlock_test_lock_device);
TEST (security_manager_no_unlock_test_lock_device_static_init);
TEST (security_manager_no_unlock_test_lock_device_null);
TEST (security_manager_no_unlock_test_unlock_device);
TEST (security_manager_no_unlock_test_unlock_device_static_init);
TEST (security_manager_no_unlock_test_unlock_device_null);
TEST (security_manager_no_unlock_test_get_unlock_counter);
TEST (security_manager_no_unlock_test_get_unlock_counter_large_buffer);
TEST (security_manager_no_unlock_test_get_unlock_counter_static_init);
TEST (security_manager_no_unlock_test_get_unlock_counter_null);
TEST (security_manager_no_unlock_test_get_unlock_counter_small_buffer);
TEST (security_manager_no_unlock_test_has_unlock_policy);
TEST (security_manager_no_unlock_test_has_unlock_policy_static_init);
TEST (security_manager_no_unlock_test_has_unlock_policy_null);
TEST (security_manager_no_unlock_test_load_security_policy);
TEST (security_manager_no_unlock_test_load_security_policy_static_init);
TEST (security_manager_no_unlock_test_load_security_policy_null);
TEST (security_manager_no_unlock_test_apply_device_config);
TEST (security_manager_no_unlock_test_apply_device_config_static_init);
TEST (security_manager_no_unlock_test_apply_device_config_null);
TEST (security_manager_no_unlock_test_get_security_policy);
TEST (security_manager_no_unlock_test_get_security_policy_static_init);
TEST (security_manager_no_unlock_test_get_security_policy_null);

TEST_SUITE_END;
// *INDENT-ON*
