// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "mock/host_processor_mock.h"


static const char *SUITE = "host_processor";


static void host_processor_test_set_port (CuTest *test)
{
	struct host_processor_mock host;
	int status;

	TEST_START;

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	host_processor_set_port (&host.base, 1);
	CuAssertIntEquals (test, 1, host_processor_get_port (&host.base));

	host_processor_mock_release (&host);
}

static void host_processor_test_set_port_null (CuTest *test)
{
	TEST_START;

	host_processor_set_port (NULL, 1);
}

static void host_processor_test_get_port_null (CuTest *test)
{
	struct host_processor_mock host;
	int status;

	TEST_START;

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	host_processor_set_port (&host.base, 1);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, host_processor_get_port (NULL));

	host_processor_mock_release (&host);
}


CuSuite* get_host_processor_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, host_processor_test_set_port);
	SUITE_ADD_TEST (suite, host_processor_test_set_port_null);
	SUITE_ADD_TEST (suite, host_processor_test_get_port_null);

	return suite;
}
