// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/cfm/cfm_manager.h"
#include "mock/cfm_mock.h"
#include "mock/cfm_manager_mock.h"
#include "mock/cfm_observer_mock.h"


static const char *SUITE = "cfm_manager";


/*******************
 * Test cases
 *******************/

static void cfm_manager_test_on_cfm_verified_no_observers (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_verified (&manager.base);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_verified_one_observer (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&observer.mock, observer.base.on_cfm_verified, &observer, 0,
		MOCK_ARG (&cfm));

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_verified (&manager.base);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_verified_no_event_handler (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_verified = NULL;

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_verified (&manager.base);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_verified_no_pending_cfm (CuTest *test)
{
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_pending_cfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_verified (&manager.base);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_verified_null (CuTest *test)
{
	TEST_START;

	cfm_manager_on_cfm_verified (NULL);
}

static void cfm_manager_test_on_cfm_activated_no_observers (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_activated (&manager.base);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_activated_one_observer (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&observer.mock, observer.base.on_cfm_activated, &observer, 0,
		MOCK_ARG (&cfm));

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_activated (&manager.base);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_activated_no_event_handler (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated = NULL;

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_activated (&manager.base);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_activated_no_active_cfm (CuTest *test)
{
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_cfm_activated (&manager.base);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_cfm_activated_null (CuTest *test)
{
	TEST_START;

	cfm_manager_on_cfm_activated (NULL);
}

static void cfm_manager_test_add_observer_null (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_add_observer (NULL, &observer.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = cfm_manager_add_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_remove_observer_null (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_remove_observer (NULL, &observer.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = cfm_manager_remove_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}


CuSuite* get_cfm_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_verified_no_observers);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_verified_one_observer);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_verified_no_event_handler);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_verified_no_pending_cfm);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_verified_null);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_activated_no_observers);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_activated_one_observer);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_activated_no_event_handler);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_activated_no_active_cfm);
	SUITE_ADD_TEST (suite, cfm_manager_test_on_cfm_activated_null);
	SUITE_ADD_TEST (suite, cfm_manager_test_add_observer_null);
	SUITE_ADD_TEST (suite, cfm_manager_test_remove_observer_null);

	return suite;
}
