// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "manifest/manifest_manager_null.h"
#include "manifest/manifest_manager_null_static.h"


TEST_SUITE_LABEL ("manifest_manager_null");


/*******************
 * Test cases
 *******************/

static void manifest_manager_null_test_init (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.clear_all_manifests);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = manifest_manager_null_init (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);
}

static void manifest_manager_null_test_static_init (CuTest *test)
{
	struct manifest_manager_null manager = manifest_manager_null_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, manager.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.clear_all_manifests);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_manager_null_release (NULL);
}

static void manifest_manager_null_test_activate_pending_manifest (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.activate_pending_manifest (&manager.base);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_activate_pending_manifest_static_init (CuTest *test)
{
	struct manifest_manager_null manager = manifest_manager_null_static_init;
	int status;

	TEST_START;

	status = manager.base.activate_pending_manifest (&manager.base);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_activate_pending_manifest_null (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.activate_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_clear_pending_region (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.clear_pending_region (&manager.base, 1000);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_clear_pending_region_static_init (CuTest *test)
{
	struct manifest_manager_null manager = manifest_manager_null_static_init;
	int status;

	TEST_START;

	status = manager.base.clear_pending_region (&manager.base, 1000);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_clear_pending_region_null (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.clear_pending_region (NULL, 1000);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_write_pending_data (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.write_pending_data (&manager.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_write_pending_data_static_init (CuTest *test)
{
	struct manifest_manager_null manager = manifest_manager_null_static_init;
	int status;

	TEST_START;

	status = manager.base.write_pending_data (&manager.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_write_pending_data_null (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.write_pending_data (NULL, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_verify_pending_manifest (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.verify_pending_manifest (&manager.base);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_verify_pending_manifest_static_init (CuTest *test)
{
	struct manifest_manager_null manager = manifest_manager_null_static_init;
	int status;

	TEST_START;

	status = manager.base.verify_pending_manifest (&manager.base);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_verify_pending_manifest_null (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.verify_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_clear_all_manifests (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.clear_all_manifests (&manager.base);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_clear_all_manifests_static_init (CuTest *test)
{
	struct manifest_manager_null manager = manifest_manager_null_static_init;
	int status;

	TEST_START;

	status = manager.base.clear_all_manifests (&manager.base);
	CuAssertIntEquals (test, 0, status);

	manifest_manager_null_release (&manager);
}

static void manifest_manager_null_test_clear_all_manifests_null (CuTest *test)
{
	struct manifest_manager_null manager;
	int status;

	TEST_START;

	status = manifest_manager_null_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.clear_all_manifests (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_manager_null_release (&manager);
}


// *INDENT-OFF*
TEST_SUITE_START (manifest_manager_null);

TEST (manifest_manager_null_test_init);
TEST (manifest_manager_null_test_init_null);
TEST (manifest_manager_null_test_static_init);
TEST (manifest_manager_null_test_release_null);
TEST (manifest_manager_null_test_activate_pending_manifest);
TEST (manifest_manager_null_test_activate_pending_manifest_static_init);
TEST (manifest_manager_null_test_activate_pending_manifest_null);
TEST (manifest_manager_null_test_clear_pending_region);
TEST (manifest_manager_null_test_clear_pending_region_static_init);
TEST (manifest_manager_null_test_clear_pending_region_null);
TEST (manifest_manager_null_test_write_pending_data);
TEST (manifest_manager_null_test_write_pending_data_static_init);
TEST (manifest_manager_null_test_write_pending_data_null);
TEST (manifest_manager_null_test_verify_pending_manifest);
TEST (manifest_manager_null_test_verify_pending_manifest_static_init);
TEST (manifest_manager_null_test_verify_pending_manifest_null);
TEST (manifest_manager_null_test_clear_all_manifests);
TEST (manifest_manager_null_test_clear_all_manifests_static_init);
TEST (manifest_manager_null_test_clear_all_manifests_null);

TEST_SUITE_END;
// *INDENT-ON*
