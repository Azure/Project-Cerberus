// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_manager.h"
#include "mock/pfm_mock.h"
#include "mock/pfm_manager_mock.h"
#include "mock/pfm_observer_mock.h"


static const char *SUITE = "pfm_manager";


/*******************
 * Test cases
 *******************/

static void pfm_manager_test_on_pfm_verified_no_observers (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_verified (&manager.base);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_verified_one_observer (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&observer.mock, observer.base.on_pfm_verified, &observer, 0,
		MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_verified (&manager.base);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_verified_no_event_handler (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_verified = NULL;

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_verified (&manager.base);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_verified_no_pending_pfm (CuTest *test)
{
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_pfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_verified (&manager.base);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_verified_null (CuTest *test)
{
	TEST_START;

	pfm_manager_on_pfm_verified (NULL);
}

static void pfm_manager_test_on_pfm_activated_no_observers (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_activated (&manager.base);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_activated_one_observer (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&observer.mock, observer.base.on_pfm_activated, &observer, 0,
		MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_activated (&manager.base);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_activated_no_event_handler (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated = NULL;

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_activated (&manager.base);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_activated_no_active_pfm (CuTest *test)
{
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_pfm_activated (&manager.base);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_pfm_activated_null (CuTest *test)
{
	TEST_START;

	pfm_manager_on_pfm_activated (NULL);
}

static void pfm_manager_test_add_observer_null (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (NULL, &observer.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_add_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_remove_observer_null (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_remove_observer (NULL, &observer.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_remove_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}


CuSuite* get_pfm_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_verified_no_observers);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_verified_one_observer);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_verified_no_event_handler);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_verified_no_pending_pfm);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_verified_null);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_activated_no_observers);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_activated_one_observer);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_activated_no_event_handler);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_activated_no_active_pfm);
	SUITE_ADD_TEST (suite, pfm_manager_test_on_pfm_activated_null);
	SUITE_ADD_TEST (suite, pfm_manager_test_add_observer_null);
	SUITE_ADD_TEST (suite, pfm_manager_test_remove_observer_null);

	return suite;
}
