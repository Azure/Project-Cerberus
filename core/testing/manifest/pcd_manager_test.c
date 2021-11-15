// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_manager.h"
#include "testing/mock/manifest/pcd_mock.h"
#include "testing/mock/manifest/pcd_manager_mock.h"
#include "testing/mock/manifest/pcd_observer_mock.h"
#include "testing/manifest/pcd_testing.h"


TEST_SUITE_LABEL ("pcd_manager");


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

	status = mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_verified (&manager.base, &pcd.base);

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

	status = mock_expect (&observer.mock, observer.base.on_pcd_verified, &observer, 0,
		MOCK_ARG (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));

	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_verified (&manager.base, &pcd.base);

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

	status = mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_pcd_verified (&manager.base, &pcd.base);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_verified_no_pending_pcd (CuTest *test)
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

	pcd_manager_on_pcd_verified (&manager.base, NULL);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_pcd_verified_null (CuTest *test)
{
	struct pcd_mock pcd;

	TEST_START;

	pcd_manager_on_pcd_verified (NULL, &pcd.base);
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

static void pcd_manager_test_on_clear_active_no_observers (CuTest *test)
{
	struct pcd_manager_mock manager;
	int status;

	TEST_START;

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_clear_active (&manager.base);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_clear_active_one_observer (CuTest *test)
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

	status = mock_expect (&observer.mock, observer.base.on_clear_active, &observer, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_clear_active (&manager.base);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_clear_active_no_event_handler (CuTest *test)
{
	struct pcd_manager_mock manager;
	struct pcd_observer_mock observer;
	int status;

	TEST_START;

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_clear_active = NULL;

	status = pcd_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_on_clear_active (&manager.base);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_on_clear_active_null (CuTest *test)
{
	TEST_START;

	pcd_manager_on_clear_active (NULL);
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
	uint32_t total_len;
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

	status = pcd_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

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
	uint32_t total_len;
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

	status = pcd_manager_get_id_measured_data (&manager.base, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 2, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

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
	uint32_t total_len;
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

	status = pcd_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

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
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_id_measured_data_0_bytes_read (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[5];
	uint8_t id[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
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

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, sizeof (id), buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

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
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_id_measured_data (&manager.base, 0, NULL, length, &total_len);
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
	uint32_t total_len;
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

	status = pcd_manager_get_id_measured_data (&manager.base, 2, buffer, length, &total_len);
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
	uint8_t buffer[PCD_TESTING.manifest.plat_id_str_len + 1];
	size_t length = sizeof (buffer);
	size_t id_length = PCD_TESTING.manifest.plat_id_str_len + 1;
	const char *id = PCD_TESTING.manifest.plat_id_str;
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) PCD_TESTING.manifest.plat_id_str, buffer,
		id_length);
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
	uint8_t buffer[PCD_TESTING.manifest.plat_id_str_len + 1];
	size_t length = sizeof (buffer);
	size_t id_length = PCD_TESTING.manifest.plat_id_str_len + 1;
	const char *id = PCD_TESTING.manifest.plat_id_str;
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 2, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length - 2, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) PCD_TESTING.manifest.plat_id_str + 2, buffer,
		id_length - 2);
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
	const char *id = PCD_TESTING.manifest.plat_id_str;
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, PCD_TESTING.manifest.plat_id_str_len + 1, total_len);

	status = testing_validate_array ((uint8_t*) PCD_TESTING.manifest.plat_id_str, buffer, length);
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
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, &buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1, total_len);

	status = testing_validate_array ((uint8_t*) &id, &buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_0_bytes_read (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[PCD_TESTING.manifest.plat_id_str_len + 1];
	size_t length = sizeof (buffer);
	size_t id_length = PCD_TESTING.manifest.plat_id_str_len + 1;
	const char *id = PCD_TESTING.manifest.plat_id_str;
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, id_length, buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_platform_id_measured_data_null (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[PCD_TESTING.manifest.plat_id_str_len];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, NULL, length, &total_len);
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
	uint32_t total_len;
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
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len, status);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len, total_len);

	status = testing_validate_array (PCD_TESTING.manifest.hash, buffer,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_sha384 (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	uint8_t hash[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	memset (hash, 0x55, sizeof (hash));

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, sizeof (hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, hash, sizeof (hash), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (hash), status);
	CuAssertIntEquals (test, sizeof (hash), total_len);

	status = testing_validate_array (hash, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_sha512 (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	uint8_t hash[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	memset (hash, 0x55, sizeof (hash));

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, sizeof (hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, hash, sizeof (hash), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (hash), status);
	CuAssertIntEquals (test, sizeof (hash), total_len);

	status = testing_validate_array (hash, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_offset (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len - offset, status);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len, total_len);

	status = testing_validate_array (PCD_TESTING.manifest.hash + 2, buffer,
		PCD_TESTING.manifest.hash_len - 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_small_buffer (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, 0, buffer,
		SHA256_HASH_LENGTH - 2, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 2, status);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len, total_len);

	status = testing_validate_array (PCD_TESTING.manifest.hash, buffer,
		PCD_TESTING.manifest.hash_len - 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_no_active_pcd (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_0_bytes_read (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		(intptr_t) &pcd.base);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager,
		0, MOCK_ARG (&pcd.base));

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, PCD_TESTING.manifest.hash_len,
		buffer, length,	&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCD_TESTING.manifest.hash_len, total_len);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pcd_manager_test_get_pcd_measured_data_null (CuTest *test)
{
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pcd_manager_get_pcd_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);
}

static void pcd_manager_test_get_pcd_measured_data_fail (CuTest *test)
{
	struct pcd_mock pcd;
	struct pcd_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
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

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_get_pcd_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_GET_HASH_FAILED, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (pcd_manager);

TEST (pcd_manager_test_on_pcd_verified_no_observers);
TEST (pcd_manager_test_on_pcd_verified_one_observer);
TEST (pcd_manager_test_on_pcd_verified_no_event_handler);
TEST (pcd_manager_test_on_pcd_verified_no_pending_pcd);
TEST (pcd_manager_test_on_pcd_verified_null);
TEST (pcd_manager_test_on_pcd_activated_no_observers);
TEST (pcd_manager_test_on_pcd_activated_one_observer);
TEST (pcd_manager_test_on_pcd_activated_no_event_handler);
TEST (pcd_manager_test_on_pcd_activated_no_active_pcd);
TEST (pcd_manager_test_on_pcd_activated_null);
TEST (pcd_manager_test_on_clear_active_no_observers);
TEST (pcd_manager_test_on_clear_active_one_observer);
TEST (pcd_manager_test_on_clear_active_no_event_handler);
TEST (pcd_manager_test_on_clear_active_null);
TEST (pcd_manager_test_add_observer_null);
TEST (pcd_manager_test_remove_observer_null);
TEST (pcd_manager_test_get_id_measured_data);
TEST (pcd_manager_test_get_id_measured_data_offset);
TEST (pcd_manager_test_get_id_measured_data_small_buffer);
TEST (pcd_manager_test_get_id_measured_data_no_active_pcd);
TEST (pcd_manager_test_get_id_measured_data_0_bytes_read);
TEST (pcd_manager_test_get_id_measured_data_null);
TEST (pcd_manager_test_get_id_measured_data_fail);
TEST (pcd_manager_test_get_platform_id_measured_data);
TEST (pcd_manager_test_get_platform_id_measured_data_offset);
TEST (pcd_manager_test_get_platform_id_measured_data_small_buffer);
TEST (pcd_manager_test_get_platform_id_measured_data_no_active_pcd);
TEST (pcd_manager_test_get_platform_id_measured_data_0_bytes_read);
TEST (pcd_manager_test_get_platform_id_measured_data_null);
TEST (pcd_manager_test_get_platform_id_measured_data_fail);
TEST (pcd_manager_test_get_pcd_measured_data);
TEST (pcd_manager_test_get_pcd_measured_data_sha384);
TEST (pcd_manager_test_get_pcd_measured_data_sha512);
TEST (pcd_manager_test_get_pcd_measured_data_offset);
TEST (pcd_manager_test_get_pcd_measured_data_small_buffer);
TEST (pcd_manager_test_get_pcd_measured_data_no_active_pcd);
TEST (pcd_manager_test_get_pcd_measured_data_0_bytes_read);
TEST (pcd_manager_test_get_pcd_measured_data_null);
TEST (pcd_manager_test_get_pcd_measured_data_fail);

TEST_SUITE_END;
