// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_manager.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/mock/manifest/pfm_observer_mock.h"
#include "testing/manifest/pfm_testing.h"


TEST_SUITE_LABEL ("pfm_manager");


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

static void pfm_manager_test_on_clear_active_no_observers (CuTest *test)
{
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_clear_active (&manager.base);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_clear_active_one_observer (CuTest *test)
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

	status = mock_expect (&observer.mock, observer.base.on_clear_active, &observer, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_clear_active (&manager.base);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_clear_active_no_event_handler (CuTest *test)
{
	struct pfm_manager_mock manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_clear_active = NULL;

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_on_clear_active (&manager.base);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_on_clear_active_null (CuTest *test)
{
	TEST_START;

	pfm_manager_on_clear_active (NULL);
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

static void pfm_manager_test_get_id_measured_data (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_id_measured_data_offset (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 2, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id + 2, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_id_measured_data_small_buffer (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[3];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_id_measured_data_no_active_pfm (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint8_t id[5] = {0};
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_id_measured_data_0_bytes_read (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	uint8_t id[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, sizeof (id), buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_id_measured_data_null (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, 0, NULL, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_id_measured_data_fail (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_id_measured_data (&manager.base, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	const char *id = PFM_PLATFORM_ID;
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) PFM_PLATFORM_ID, buffer, id_length);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data_offset (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	const char *id = PFM_PLATFORM_ID;
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, 2, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length - 2, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) PFM_PLATFORM_ID + 2, buffer, id_length - 2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data_small_buffer (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	const char *id = PFM_PLATFORM_ID;
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) PFM_PLATFORM_ID, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data_no_active_pfm (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer;
	char id = '\0';
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, 0, &buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1, total_len);

	status = testing_validate_array ((uint8_t*) &id, &buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data_0_bytes_read (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	const char *id = PFM_PLATFORM_ID;
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, id_length, buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data_null (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, 0, NULL, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_platform_id_measured_data_fail (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PFM_HASH_LEN, status);
	CuAssertIntEquals (test, PFM_HASH_LEN, total_len);

	status = testing_validate_array (PFM_HASH, buffer, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_sha384 (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	uint8_t hash[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	memset (hash, 0x55, sizeof (hash));

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, sizeof (hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, hash, sizeof (hash), 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (hash), status);
	CuAssertIntEquals (test, sizeof (hash), total_len);

	status = testing_validate_array (hash, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_sha512 (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	uint8_t hash[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	memset (hash, 0x55, sizeof (hash));

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, sizeof (hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, hash, sizeof (hash), 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (hash), status);
	CuAssertIntEquals (test, sizeof (hash), total_len);

	status = testing_validate_array (hash, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_offset (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, PFM_HASH_LEN - offset, status);
	CuAssertIntEquals (test, PFM_HASH_LEN, total_len);

	status = testing_validate_array (PFM_HASH + 2, buffer, PFM_HASH_LEN - 2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_small_buffer (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, 0, buffer,
		SHA256_HASH_LENGTH - 2, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 2, status);
	CuAssertIntEquals (test, PFM_HASH_LEN, total_len);

	status = testing_validate_array (PFM_HASH, buffer, PFM_HASH_LEN - 2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_no_active_pfm (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PFM_HASH_LEN, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_0_bytes_read (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, PFM_HASH_LEN, buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_HASH_LEN, total_len);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_manager_test_get_pfm_measured_data_null (CuTest *test)
{
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_manager_get_pfm_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);
}

static void pfm_manager_test_get_pfm_measured_data_fail (CuTest *test)
{
	struct pfm_mock pfm;
	struct pfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager,
		(intptr_t) &pfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager,
		0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_get_pfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_GET_HASH_FAILED, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (pfm_manager);

TEST (pfm_manager_test_on_pfm_verified_no_observers);
TEST (pfm_manager_test_on_pfm_verified_one_observer);
TEST (pfm_manager_test_on_pfm_verified_no_event_handler);
TEST (pfm_manager_test_on_pfm_verified_no_pending_pfm);
TEST (pfm_manager_test_on_pfm_verified_null);
TEST (pfm_manager_test_on_pfm_activated_no_observers);
TEST (pfm_manager_test_on_pfm_activated_one_observer);
TEST (pfm_manager_test_on_pfm_activated_no_event_handler);
TEST (pfm_manager_test_on_pfm_activated_no_active_pfm);
TEST (pfm_manager_test_on_pfm_activated_null);
TEST (pfm_manager_test_on_clear_active_no_observers);
TEST (pfm_manager_test_on_clear_active_one_observer);
TEST (pfm_manager_test_on_clear_active_no_event_handler);
TEST (pfm_manager_test_on_clear_active_null);
TEST (pfm_manager_test_add_observer_null);
TEST (pfm_manager_test_remove_observer_null);
TEST (pfm_manager_test_get_id_measured_data);
TEST (pfm_manager_test_get_id_measured_data_offset);
TEST (pfm_manager_test_get_id_measured_data_small_buffer);
TEST (pfm_manager_test_get_id_measured_data_no_active_pfm);
TEST (pfm_manager_test_get_id_measured_data_0_bytes_read);
TEST (pfm_manager_test_get_id_measured_data_null);
TEST (pfm_manager_test_get_id_measured_data_fail);
TEST (pfm_manager_test_get_platform_id_measured_data);
TEST (pfm_manager_test_get_platform_id_measured_data_offset);
TEST (pfm_manager_test_get_platform_id_measured_data_small_buffer);
TEST (pfm_manager_test_get_platform_id_measured_data_no_active_pfm);
TEST (pfm_manager_test_get_platform_id_measured_data_0_bytes_read);
TEST (pfm_manager_test_get_platform_id_measured_data_null);
TEST (pfm_manager_test_get_platform_id_measured_data_fail);
TEST (pfm_manager_test_get_pfm_measured_data);
TEST (pfm_manager_test_get_pfm_measured_data_sha384);
TEST (pfm_manager_test_get_pfm_measured_data_sha512);
TEST (pfm_manager_test_get_pfm_measured_data_offset);
TEST (pfm_manager_test_get_pfm_measured_data_small_buffer);
TEST (pfm_manager_test_get_pfm_measured_data_no_active_pfm);
TEST (pfm_manager_test_get_pfm_measured_data_0_bytes_read);
TEST (pfm_manager_test_get_pfm_measured_data_null);
TEST (pfm_manager_test_get_pfm_measured_data_fail);

TEST_SUITE_END;
