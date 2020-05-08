// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_manager.h"
#include "mock/manifest_mock.h"


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

static void manifest_manager_test_get_manifest_id_measured_data (CuTest *test)
{
	struct manifest_mock manifest;
	uint32_t id = 0x1234;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id, sizeof (id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (id), status);

	status = testing_validate_array ((uint8_t*) &id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_with_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint32_t id = 0x1234;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id, sizeof (id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 2, buffer, length);
	CuAssertIntEquals (test, sizeof (id) - 2, status);

	status = testing_validate_array ((uint8_t*) &id + 2, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_small_buffer (CuTest *test)
{
	struct manifest_mock manifest;
	uint32_t id = 0x1234;
	uint8_t buffer[3];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id, sizeof (id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (id) - 1, status);

	status = testing_validate_array ((uint8_t*) &id, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_small_buffer_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint32_t id = 0x1234;
	uint8_t buffer[3];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id, sizeof (id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 1, buffer, length);
	CuAssertIntEquals (test, sizeof (id) - 1, status);

	status = testing_validate_array ((uint8_t*) &id + 1, buffer, sizeof (id) - 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_invalid_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 4, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_null (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (NULL, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, NULL, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_fail (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data (CuTest *test)
{
	struct manifest_mock manifest;
	char *id = "Manifest Test";
	uint8_t buffer[14];
	size_t length = sizeof (buffer);
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length);
	CuAssertIntEquals (test, strlen (id) + 1, status);

	status = testing_validate_array ((uint8_t*) id, buffer, strlen (id) + 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_offset (CuTest *test)
{
	struct manifest_mock manifest;
	char *id = "Manifest Test";
	uint8_t buffer[14];
	size_t length = sizeof (buffer);
	size_t id_length = strlen (id) + 1;
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 2, buffer, length);
	CuAssertIntEquals (test, id_length - 2, status);

	status = testing_validate_array ((uint8_t*) id + 2, buffer, id_length - 2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_small_buffer (
	CuTest *test)
{
	struct manifest_mock manifest;
	char *id = "Manifest Test";
	uint8_t buffer[13];
	size_t length = sizeof (buffer);
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) id, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_small_buffer_offset (
	CuTest *test)
{
	struct manifest_mock manifest;
	char *id = "Manifest Test";
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 2, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) id + 2, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_invalid_offset (
	CuTest *test)
{
	struct manifest_mock manifest;
	char *id = "Manifest Test";
	uint8_t buffer[14];
	size_t length = sizeof (buffer);
	size_t id_length = strlen (id) + 1;
	char *platform_id;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, id_length, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_null (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (NULL, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, NULL, length);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_fail (
	CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}


CuSuite* get_manifest_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, manifest_manager_test_set_port);
	SUITE_ADD_TEST (suite, manifest_manager_test_set_port_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_port_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_with_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_id_measured_data_small_buffer_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_invalid_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_fail);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_offset);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_small_buffer_offset);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_invalid_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_fail);

	return suite;
}
