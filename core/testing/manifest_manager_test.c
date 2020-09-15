// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_manager.h"
#include "mock/manifest_mock.h"
#include "mock/hash_mock.h"
#include "engines/hash_testing_engine.h"
#include "pfm_testing.h"
#include "hash_testing.h"


static const char *SUITE = "manifest_manager";


/*******************
 * Test cases
 *******************/

static void manifest_manager_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (NULL, &hash.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_init (&manager, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

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

static void manifest_manager_test_get_manifest_measured_data (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_hash, &manifest, 0,
		MOCK_ARG (&hash.base), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manifest.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base, 0, buffer,
		length, &total_len);
	CuAssertIntEquals (test, PFM_HASH_LEN, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (PFM_HASH, buffer, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_with_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_hash, &manifest, 0,
		MOCK_ARG (&hash.base), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manifest.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base, offset, buffer,
		length, &total_len);
	CuAssertIntEquals (test, PFM_HASH_LEN - offset, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (PFM_HASH + offset, buffer, PFM_HASH_LEN - offset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH] = {0};
	uint8_t zero[2] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_hash, &manifest, 0,
		MOCK_ARG (&hash.base), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manifest.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base, 0, buffer,
		length - 2, &total_len);
	CuAssertIntEquals (test, PFM_HASH_LEN - 2, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (PFM_HASH, buffer, PFM_HASH_LEN - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + PFM_HASH_LEN - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_small_buffer_with_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH] = {0};
	uint8_t zero[4] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_hash, &manifest, 0,
		MOCK_ARG (&hash.base), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manifest.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base, offset, buffer,
		length - 4, &total_len);
	CuAssertIntEquals (test, PFM_HASH_LEN - 4, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (PFM_HASH + offset, buffer, PFM_HASH_LEN - 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + PFM_HASH_LEN - 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_no_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, NULL, 0, buffer, length, 
		&total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_no_active_with_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, NULL, offset, buffer, length, 
		&total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - offset, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH - offset);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_no_active_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, NULL, 0, buffer, length - 2, 
		&total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 2, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH - 2);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_no_active_small_buffer_with_offset (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, NULL, offset, buffer,
		length - 4, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 4, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_0_bytes_read (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base, PFM_HASH_LEN, 
		buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_invalid_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base,
		SHA256_HASH_LENGTH, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_no_active_invalid_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, NULL, SHA256_HASH_LENGTH,
		buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, total_len);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (NULL, &manifest.base, SHA256_HASH_LENGTH,
		buffer, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base,
		SHA256_HASH_LENGTH, NULL, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base,
		SHA256_HASH_LENGTH, buffer, length, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_measured_data_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct manifest_manager manager;
	struct manifest_mock manifest;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_init (&manager, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_hash, &manifest,
		MANIFEST_GET_HASH_FAILED, MOCK_ARG (&hash.base), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_manifest_measured_data (&manager, &manifest.base, 0, buffer,
		length, &total_len);
	CuAssertIntEquals (test, MANIFEST_GET_HASH_FAILED, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void manifest_manager_test_get_manifest_id_measured_data (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {1, 2, 3, 4, 5};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_with_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {1, 2, 3, 4, 5};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 2, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id + 2, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_small_buffer (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 1, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id) - 2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_small_buffer_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[] = {1, 2, 3, 4, 5};
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &id[1], sizeof (id) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 1, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 1, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id + 1, buffer, sizeof (id) - 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_no_active (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {0};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id));
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_no_active_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {0};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (NULL, 1, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (id) - 1, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (id) - 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_no_active_small_buffer (
	CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {0};
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (buffer), status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_no_active_small_buffer_offset (
	CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {0};
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (NULL, 4, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = testing_validate_array (id, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_0_bytes_read (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {1, 2, 3, 4, 5};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, sizeof (id), buffer, length, 
		&total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_no_active_invalid_offset (
	CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {1, 2, 3, 4, 5};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (NULL, 5, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_invalid_offset (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t id[5] = {1, 2, 3, 4, 5};
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 5, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (id), total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_null (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, NULL, length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_id_measured_data_fail (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_id, &manifest, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_id_measured_data (&manifest.base, 0, buffer, length, &total_len);
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
	uint32_t total_len;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length, 
		&total_len);
	CuAssertIntEquals (test, strlen (id) + 1, status);
	CuAssertIntEquals (test, strlen (id) + 1, total_len);

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
	uint32_t total_len;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 2, buffer, length,
		&total_len);
	CuAssertIntEquals (test, id_length - 2, status);
	CuAssertIntEquals (test, id_length, total_len);

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
	uint32_t total_len;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, strlen (id) + 1, total_len);

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
	uint32_t total_len;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 2, buffer, length, 
		&total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, strlen (id) + 1, total_len);

	status = testing_validate_array ((uint8_t*) id + 2, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_no_active (CuTest *test)
{
	struct manifest_mock manifest;
	char id = '\0';
	uint8_t buffer;
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (NULL, 0, &buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1, total_len);

	status = testing_validate_array ((uint8_t*) &id, &buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_0_bytes_read (CuTest *test)
{
	struct manifest_mock manifest;
	char *id = "Manifest Test";
	uint8_t buffer[14];
	size_t length = sizeof (buffer);
	char *platform_id;
	uint32_t total_len;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, strlen (id) + 1, 
		buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (id) + 1, total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_no_active_invalid_offset (
	CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (NULL, 1, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, total_len);

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
	uint32_t total_len;
	int status;

	TEST_START;

	platform_id = platform_malloc (strlen (id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, id);

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, id_length, buffer,
		length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (id) + 1, total_len);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}

static void manifest_manager_test_get_manifest_platform_id_measured_data_null (CuTest *test)
{
	struct manifest_mock manifest;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, NULL, length, 
		&total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length, 
		NULL);
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
	uint32_t total_len;
	int status;

	TEST_START;

	status = manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.get_platform_id, &manifest,
		MANIFEST_GET_ID_FAILED, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_platform_id_measured_data (&manifest.base, 0, buffer, length, 
		&total_len);
	CuAssertIntEquals (test, MANIFEST_GET_ID_FAILED, status);

	status = manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);
}


CuSuite* get_manifest_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, manifest_manager_test_init);
	SUITE_ADD_TEST (suite, manifest_manager_test_init_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_set_port);
	SUITE_ADD_TEST (suite, manifest_manager_test_set_port_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_port_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_with_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_measured_data_small_buffer_with_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_no_active);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_no_active_with_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_no_active_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_measured_data_no_active_small_buffer_with_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_0_bytes_read);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_invalid_offset);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_measured_data_no_active_invalid_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_measured_data_fail);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_with_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_id_measured_data_small_buffer_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_no_active);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_no_active_offset);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_id_measured_data_no_active_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_id_measured_data_no_active_small_buffer_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_0_bytes_read);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_id_measured_data_no_active_invalid_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_invalid_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_id_measured_data_fail);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_offset);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_small_buffer);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_small_buffer_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_no_active);
	SUITE_ADD_TEST (suite, 
		manifest_manager_test_get_manifest_platform_id_measured_data_0_bytes_read);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_no_active_invalid_offset);
	SUITE_ADD_TEST (suite,
		manifest_manager_test_get_manifest_platform_id_measured_data_invalid_offset);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_null);
	SUITE_ADD_TEST (suite, manifest_manager_test_get_manifest_platform_id_measured_data_fail);

	return suite;
}
