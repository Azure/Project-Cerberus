// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/security_policy_enforcing.h"
#include "system/security_policy_enforcing_static.h"


TEST_SUITE_LABEL ("security_policy_enforcing");


/*******************
 * Test cases
 *******************/

static void security_policy_enforcing_test_init (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, policy.base.is_persistent);
	CuAssertPtrNotNull (test, policy.base.enforce_firmware_signing);
	CuAssertPtrNotNull (test, policy.base.enforce_anti_rollback);
	CuAssertPtrNotNull (test, policy.base.check_unlock_persistence);
	CuAssertPtrNotNull (test, policy.base.parse_unlock_policy);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = security_policy_enforcing_init (NULL);
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);
}

static void security_policy_enforcing_test_static_init (CuTest *test)
{
	struct security_policy_enforcing policy = security_policy_enforcing_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, policy.base.is_persistent);
	CuAssertPtrNotNull (test, policy.base.enforce_firmware_signing);
	CuAssertPtrNotNull (test, policy.base.enforce_anti_rollback);
	CuAssertPtrNotNull (test, policy.base.check_unlock_persistence);
	CuAssertPtrNotNull (test, policy.base.parse_unlock_policy);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_release_null (CuTest *test)
{
	TEST_START;

	security_policy_enforcing_release (NULL);
}

static void security_policy_enforcing_test_is_persistent (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.is_persistent (&policy.base);
	CuAssertIntEquals (test, 0, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_is_persistent_static_init (CuTest *test)
{
	struct security_policy_enforcing policy = security_policy_enforcing_static_init;
	int status;

	TEST_START;

	status = policy.base.is_persistent (&policy.base);
	CuAssertIntEquals (test, 0, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_is_persistent_null (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.is_persistent (NULL);
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_enforce_firmware_signing (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.enforce_firmware_signing (&policy.base);
	CuAssertIntEquals (test, 1, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_enforce_firmware_signing_static_init (CuTest *test)
{
	struct security_policy_enforcing policy = security_policy_enforcing_static_init;
	int status;

	TEST_START;

	status = policy.base.enforce_firmware_signing (&policy.base);
	CuAssertIntEquals (test, 1, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_enforce_firmware_signing_null (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.enforce_firmware_signing (NULL);
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_enforce_anti_rollback (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.enforce_anti_rollback (&policy.base);
	CuAssertIntEquals (test, 1, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_enforce_anti_rollback_static_init (CuTest *test)
{
	struct security_policy_enforcing policy = security_policy_enforcing_static_init;
	int status;

	TEST_START;

	status = policy.base.enforce_anti_rollback (&policy.base);
	CuAssertIntEquals (test, 1, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_enforce_anti_rollback_null (CuTest *test)
{
	struct security_policy_enforcing policy;
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.enforce_anti_rollback (NULL);
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_parse_unlock_policy (CuTest *test)
{
	struct security_policy_enforcing policy;
	uint8_t unlock[4];
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.parse_unlock_policy (&policy.base, unlock, sizeof (unlock));
	CuAssertIntEquals (test, SECURITY_POLICY_IMMUTABLE, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_parse_unlock_policy_static_init (CuTest *test)
{
	struct security_policy_enforcing policy = security_policy_enforcing_static_init;
	uint8_t unlock[4];
	int status;

	TEST_START;

	status = policy.base.parse_unlock_policy (&policy.base, unlock, sizeof (unlock));
	CuAssertIntEquals (test, SECURITY_POLICY_IMMUTABLE, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_parse_unlock_policy_null (CuTest *test)
{
	struct security_policy_enforcing policy;
	uint8_t unlock[4];
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.parse_unlock_policy (NULL, unlock, sizeof (unlock));
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	status = policy.base.parse_unlock_policy (&policy.base, NULL, sizeof (unlock));
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_check_unlock_persistence (CuTest *test)
{
	struct security_policy_enforcing policy;
	uint8_t unlock[4];
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.check_unlock_persistence (&policy.base, unlock, sizeof (unlock));
	CuAssertIntEquals (test, 0, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_check_unlock_persistence_static_init (CuTest *test)
{
	struct security_policy_enforcing policy = security_policy_enforcing_static_init;
	uint8_t unlock[4];
	int status;

	TEST_START;

	status = policy.base.check_unlock_persistence (&policy.base, unlock, sizeof (unlock));
	CuAssertIntEquals (test, 0, status);

	security_policy_enforcing_release (&policy);
}

static void security_policy_enforcing_test_check_unlock_persistence_null (CuTest *test)
{
	struct security_policy_enforcing policy;
	uint8_t unlock[4];
	int status;

	TEST_START;

	status = security_policy_enforcing_init (&policy);
	CuAssertIntEquals (test, 0, status);

	status = policy.base.check_unlock_persistence (NULL, unlock, sizeof (unlock));
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	status = policy.base.check_unlock_persistence (&policy.base, NULL, sizeof (unlock));
	CuAssertIntEquals (test, SECURITY_POLICY_INVALID_ARGUMENT, status);

	security_policy_enforcing_release (&policy);
}


// *INDENT-OFF*
TEST_SUITE_START (security_policy_enforcing);

TEST (security_policy_enforcing_test_init);
TEST (security_policy_enforcing_test_init_null);
TEST (security_policy_enforcing_test_static_init);
TEST (security_policy_enforcing_test_release_null);
TEST (security_policy_enforcing_test_is_persistent);
TEST (security_policy_enforcing_test_is_persistent_static_init);
TEST (security_policy_enforcing_test_is_persistent_null);
TEST (security_policy_enforcing_test_enforce_firmware_signing);
TEST (security_policy_enforcing_test_enforce_firmware_signing_static_init);
TEST (security_policy_enforcing_test_enforce_firmware_signing_null);
TEST (security_policy_enforcing_test_enforce_anti_rollback);
TEST (security_policy_enforcing_test_enforce_anti_rollback_static_init);
TEST (security_policy_enforcing_test_enforce_anti_rollback_null);
TEST (security_policy_enforcing_test_parse_unlock_policy);
TEST (security_policy_enforcing_test_parse_unlock_policy_static_init);
TEST (security_policy_enforcing_test_parse_unlock_policy_null);
TEST (security_policy_enforcing_test_check_unlock_persistence);
TEST (security_policy_enforcing_test_check_unlock_persistence_static_init);
TEST (security_policy_enforcing_test_check_unlock_persistence_null);

TEST_SUITE_END;
// *INDENT-ON*
