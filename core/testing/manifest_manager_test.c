// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_manager.h"


static const char *SUITE = "manifest_manager";


/*******************
 * Test cases
 *******************/

static void manifest_manager_test_set_port (CuTest *test)
{
	struct manifest_manager manager;

	TEST_START;

	manifest_manager_set_port (&manager, 1);
	CuAssertIntEquals (test, 1, manifest_manager_get_port (&manager));
}

static void manifest_manager_test_set_port_null (CuTest *test)
{
	TEST_START;

	manifest_manager_set_port (NULL, 1);
}

static void manifest_manager_test_get_port_null (CuTest *test)
{
	int status;

	TEST_START;

	status = manifest_manager_get_port (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);
}


CuSuite* get_manifest_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, manifest_manager_test_set_port);
	SUITE_ADD_TEST (suite, manifest_manager_test_set_port_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_port_null);

	return suite;
}
