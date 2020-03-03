// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_manager.h"
#include "mock/pcd_mock.h"
#include "mock/pcd_manager_mock.h"
#include "mock/pcd_observer_mock.h"


static const char *SUITE = "pcd_manager";


/*******************
 * Test cases
 *******************/

static void pcd_manager_test_on_pcd_verified_no_observers (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_verified (&manager.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_verified_one_observer (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_verified (&manager.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_verified_no_event_handler (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_verified = NULL;

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_verified (&manager.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_verified_null (CuTest *test)
{
	TEST_START;

	pcd_manager_on_pcd_verified (NULL);
}

static void pcd_manager_test_on_pcd_activated_no_observers (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) &pcd);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));

	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_activated (&manager.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_activated_one_observer (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) &pcd);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));

	status |= mock_expect (&observer.mock, observer.base.on_pcd_activated, &observer, 0,
		MOCK_ARG (&pcd));

	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_activated (&manager.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_activated_no_event_handler (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated = NULL;

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) &pcd);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));

	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_activated (&manager.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_activated_no_active_pcd (CuTest *test)
{
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_activated (&manager.base);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_activated_null (CuTest *test)
{
	TEST_START;

	pcd_manager_on_pcd_activated (NULL);
}

static void pcd_manager_test_add_observer_null (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (NULL, &observer.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_add_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_remove_observer_null (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_remove_observer (NULL, &observer.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_remove_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}


CuSuite* get_pcd_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_verified_no_observers);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_verified_one_observer);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_verified_no_event_handler);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_verified_null);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_activated_no_observers);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_activated_one_observer);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_activated_no_event_handler);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_activated_no_active_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_test_on_pcd_activated_null);
	SUITE_ADD_TEST (suite, pcd_manager_test_add_observer_null);
	SUITE_ADD_TEST (suite, pcd_manager_test_remove_observer_null);

	return suite;
}
