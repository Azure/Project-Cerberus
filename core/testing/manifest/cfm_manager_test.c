// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/cfm/cfm_manager.h"
#include "testing/mock/manifest/cfm_mock.h"
#include "testing/mock/manifest/cfm_manager_mock.h"
#include "testing/mock/manifest/cfm_observer_mock.h"
#include "testing/manifest/cfm_testing.h"


TEST_SUITE_LABEL ("cfm_manager");


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

static void cfm_manager_test_on_clear_active_no_observers (CuTest *test)
{
	struct cfm_manager_mock manager;
	int status;

	TEST_START;

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_clear_active (&manager.base);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_clear_active_one_observer (CuTest *test)
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

	status = mock_expect (&observer.mock, observer.base.on_clear_active, &observer, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_clear_active (&manager.base);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_clear_active_no_event_handler (CuTest *test)
{
	struct cfm_manager_mock manager;
	struct cfm_observer_mock observer;
	int status;

	TEST_START;

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_clear_active = NULL;

	status = cfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	cfm_manager_on_clear_active (&manager.base);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_on_clear_active_null (CuTest *test)
{
	TEST_START;

	cfm_manager_on_clear_active (NULL);
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

static void cfm_manager_test_get_id_measured_data (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_id_measured_data_offset (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 2, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id + 2, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_id_measured_data_small_buffer (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_id_measured_data_no_active_cfm (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[5] = {0};
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (buffer), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_id_measured_data_0_bytes_read (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint8_t id[5];
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, sizeof (id), buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_id_measured_data_null (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, 0, NULL, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_id_measured_data_fail (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_id_measured_data (&manager.base, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	char *id = "CFM Test1";
	size_t id_length = strlen (id) + 1;
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) id, buffer, id_length);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data_offset (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	char *id = "CFM Test1";
	size_t id_length = strlen (id) + 1;
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, 2, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length - 2, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = testing_validate_array ((uint8_t*) id + 2, buffer, id_length - 2);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data_small_buffer (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[9];
	size_t length = sizeof (buffer);
	char *id = "CFM Test1";
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, strlen (id) + 1, total_len);

	status = testing_validate_array ((uint8_t*) id, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data_no_active_cfm (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer;
	char id = '\0';
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, 0, &buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1, total_len);

	status = testing_validate_array ((uint8_t*) &id, &buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data_0_bytes_read (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	char *id = "CFM Test1";
	size_t id_length = strlen (id) + 1;
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0, MOCK_ARG (id));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, id_length, buffer, length,
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, id_length, total_len);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data_null (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, 0, NULL, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_platform_id_measured_data_fail (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_platform_id_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash, 
		CFM_TESTING.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, CFM_TESTING.manifest.hash_len, status);
	CuAssertIntEquals (test, CFM_TESTING.manifest.hash_len, total_len);

	status = testing_validate_array (CFM_TESTING.manifest.hash, buffer, 
		CFM_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_sha384 (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	uint8_t hash[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	memset (hash, 0x55, sizeof (hash));

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, sizeof (hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, hash, sizeof (hash), 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (hash), status);
	CuAssertIntEquals (test, sizeof (hash), total_len);

	status = testing_validate_array (hash, buffer, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_sha512 (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	uint8_t hash[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	memset (hash, 0xaa, sizeof (hash));

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, sizeof (hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, hash, sizeof (hash), 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (hash), status);
	CuAssertIntEquals (test, sizeof (hash), total_len);

	status = testing_validate_array (hash, buffer, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_offset (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash, 
		CFM_TESTING.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, CFM_TESTING.manifest.hash_len - offset, status);
	CuAssertIntEquals (test, CFM_TESTING.manifest.hash_len, total_len);

	status = testing_validate_array (CFM_TESTING.manifest.hash + 2, buffer, 
		CFM_TESTING.manifest.hash_len - 2);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_small_buffer (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash, 
		CFM_TESTING.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, 0, buffer,
		SHA256_HASH_LENGTH - 2, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 2, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (CFM_TESTING.manifest.hash, buffer, 
		CFM_TESTING.manifest.hash_len - 2);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_no_active_cfm (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_0_bytes_read (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash, 
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, CFM_TESTING.manifest.hash_len, 
		buffer, length,	&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_TESTING.manifest.hash_len, total_len);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}

static void cfm_manager_test_get_cfm_measured_data_null (CuTest *test)
{
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_manager_get_cfm_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);
}

static void cfm_manager_test_get_cfm_measured_data_fail (CuTest *test)
{
	struct cfm_mock cfm;
	struct cfm_manager_mock manager;
	uint8_t buffer[4224];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager,
		(intptr_t) &cfm.base);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager,
		0, MOCK_ARG (&cfm.base));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_get_cfm_measured_data (&manager.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_GET_HASH_FAILED, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (cfm_manager);

TEST (cfm_manager_test_on_cfm_verified_no_observers);
TEST (cfm_manager_test_on_cfm_verified_one_observer);
TEST (cfm_manager_test_on_cfm_verified_no_event_handler);
TEST (cfm_manager_test_on_cfm_verified_no_pending_cfm);
TEST (cfm_manager_test_on_cfm_verified_null);
TEST (cfm_manager_test_on_cfm_activated_no_observers);
TEST (cfm_manager_test_on_cfm_activated_one_observer);
TEST (cfm_manager_test_on_cfm_activated_no_event_handler);
TEST (cfm_manager_test_on_cfm_activated_no_active_cfm);
TEST (cfm_manager_test_on_cfm_activated_null);
TEST (cfm_manager_test_on_clear_active_no_observers);
TEST (cfm_manager_test_on_clear_active_one_observer);
TEST (cfm_manager_test_on_clear_active_no_event_handler);
TEST (cfm_manager_test_on_clear_active_null);
TEST (cfm_manager_test_add_observer_null);
TEST (cfm_manager_test_remove_observer_null);
TEST (cfm_manager_test_get_id_measured_data);
TEST (cfm_manager_test_get_id_measured_data_offset);
TEST (cfm_manager_test_get_id_measured_data_small_buffer);
TEST (cfm_manager_test_get_id_measured_data_no_active_cfm);
TEST (cfm_manager_test_get_id_measured_data_0_bytes_read);
TEST (cfm_manager_test_get_id_measured_data_null);
TEST (cfm_manager_test_get_id_measured_data_fail);
TEST (cfm_manager_test_get_platform_id_measured_data);
TEST (cfm_manager_test_get_platform_id_measured_data_offset);
TEST (cfm_manager_test_get_platform_id_measured_data_small_buffer);
TEST (cfm_manager_test_get_platform_id_measured_data_no_active_cfm);
TEST (cfm_manager_test_get_platform_id_measured_data_0_bytes_read);
TEST (cfm_manager_test_get_platform_id_measured_data_null);
TEST (cfm_manager_test_get_platform_id_measured_data_fail);
TEST (cfm_manager_test_get_cfm_measured_data);
TEST (cfm_manager_test_get_cfm_measured_data_sha384);
TEST (cfm_manager_test_get_cfm_measured_data_sha512);
TEST (cfm_manager_test_get_cfm_measured_data_offset);
TEST (cfm_manager_test_get_cfm_measured_data_small_buffer);
TEST (cfm_manager_test_get_cfm_measured_data_no_active_cfm);
TEST (cfm_manager_test_get_cfm_measured_data_0_bytes_read);
TEST (cfm_manager_test_get_cfm_measured_data_null);
TEST (cfm_manager_test_get_cfm_measured_data_fail);

TEST_SUITE_END;
