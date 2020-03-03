// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_observer_pending_reset.h"
#include "mock/host_control_mock.h"
#include "mock/pfm_mock.h"


static const char *SUITE = "pfm_observer_pending_reset";


/*******************
 * Test cases
 *******************/

static void pfm_observer_pending_reset_test_init (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, observer.base.on_pfm_verified);
	CuAssertPtrEquals (test, NULL, observer.base.on_pfm_activated);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}

static void pfm_observer_pending_reset_test_init_null (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (NULL, &control.base);
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	status = pfm_observer_pending_reset_init (&observer, NULL);
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_observer_pending_reset_test_release_null (CuTest *test)
{
	TEST_START;

	pfm_observer_pending_reset_release (NULL);
}

static void pfm_observer_pending_reset_test_on_pfm_verified (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	int status;
	struct pfm_mock pfm;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_verified (&observer.base, &pfm.base);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}

static void pfm_observer_pending_reset_test_on_pfm_verified_control_error (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	int status;
	struct pfm_mock pfm;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control,
		HOST_CONTROL_HOLD_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_verified (&observer.base, &pfm.base);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}


CuSuite* get_pfm_observer_pending_reset_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pfm_observer_pending_reset_test_init);
	SUITE_ADD_TEST (suite, pfm_observer_pending_reset_test_init_null);
	SUITE_ADD_TEST (suite, pfm_observer_pending_reset_test_release_null);
	SUITE_ADD_TEST (suite, pfm_observer_pending_reset_test_on_pfm_verified);
	SUITE_ADD_TEST (suite, pfm_observer_pending_reset_test_on_pfm_verified_control_error);

	return suite;
}
