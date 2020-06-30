// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "pcd_testing.h"
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

static void pcd_manager_test_get_id_measured_data (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (id), status);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_id_measured_data_offset (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 2, buffer, length);
	CuAssertIntEquals (test, sizeof (id) - 2, status);

	status = testing_validate_array (id + 2, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_id_measured_data_small_buffer (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 0, buffer, length);
	CuAssertIntEquals (test, 4, status);

	status = testing_validate_array (id, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_id_measured_data_no_active_pcd (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[5] = {0};
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (id), status);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_id_measured_data_null (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (NULL, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 0, NULL, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_id_measured_data_fail (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 2, buffer, length);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[PCD_PLATFORM_ID_LEN + 1];
	size_t length = sizeof (buffer);
	size_t id_length = PCD_PLATFORM_ID_LEN + 1;
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (id_length);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, PCD_PLATFORM_ID);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length);
	CuAssertIntEquals (test, id_length, status);

	status = testing_validate_array ((uint8_t*) PCD_PLATFORM_ID, buffer, id_length);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_offset (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[PCD_PLATFORM_ID_LEN + 1];
	size_t length = sizeof (buffer);
	size_t id_length = PCD_PLATFORM_ID_LEN + 1;
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (id_length);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, PCD_PLATFORM_ID);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 2, buffer, length);
	CuAssertIntEquals (test, id_length - 2, status);

	status = testing_validate_array ((uint8_t*) PCD_PLATFORM_ID + 2, buffer, id_length - 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_small_buffer (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (PCD_PLATFORM_ID_LEN + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, PCD_PLATFORM_ID);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) PCD_PLATFORM_ID, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_no_active_pcd (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer;
	char id = '\0';
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, &buffer, 1);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array ((uint8_t*) &id, &buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_null (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[PCD_PLATFORM_ID_LEN];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (NULL, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, NULL, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_fail (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
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
	SUITE_ADD_TEST (suite, pcd_manager_test_get_id_measured_data);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_id_measured_data_offset);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_id_measured_data_small_buffer);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_id_measured_data_no_active_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_id_measured_data_null);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_id_measured_data_fail);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_platform_id_measured_data);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_platform_id_measured_data_offset);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_platform_id_measured_data_small_buffer);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_platform_id_measured_data_no_active_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_platform_id_measured_data_null);
	SUITE_ADD_TEST (suite, pcd_manager_test_get_platform_id_measured_data_fail);

	return suite;
}
