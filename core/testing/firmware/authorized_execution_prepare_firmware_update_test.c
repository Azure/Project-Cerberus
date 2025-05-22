// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/config_reset.h"
#include "firmware/authorized_execution_prepare_firmware_update.h"
#include "firmware/authorized_execution_prepare_firmware_update_static.h"
#include "firmware/firmware_logging.h"
#include "testing/crypto/hash_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/firmware/firmware_update_control_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("authorized_execution_prepare_firmware_update");


/**
 * Dependencies for testing.
 */
struct authorized_execution_prepare_firmware_update_testing {
	struct firmware_update_control_mock fw_update;				/**< Mock for firmware update handling. */
	struct logging_mock log;									/**< Mock for debug logging. */
	struct authorized_execution_prepare_firmware_update test;	/**< Authorized execution under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_prepare_firmware_update_testing_init_dependencies (CuTest *test,
	struct authorized_execution_prepare_firmware_update_testing *execution)
{
	int status;

	debug_log = NULL;

	status = firmware_update_control_mock_init (&execution->fw_update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&execution->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &execution->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing dependencies to release.
 */
static void authorized_execution_prepare_firmware_update_testing_release_dependencies (CuTest *test,
	struct authorized_execution_prepare_firmware_update_testing *execution)
{
	int status;

	debug_log = NULL;

	status = firmware_update_control_mock_validate_and_release (&execution->fw_update);
	status |= logging_mock_validate_and_release (&execution->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a prepare firmware update execution context for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 * @param timeout The timeout to use for the operation.
 */
static void authorized_execution_prepare_firmware_update_testing_init (CuTest *test,
	struct authorized_execution_prepare_firmware_update_testing *execution, uint32_t timeout)
{
	int status;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, execution);

	status = authorized_execution_prepare_firmware_update_init (&execution->test,
		&execution->fw_update.base, timeout);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing components to release.
 */
static void authorized_execution_prepare_firmware_update_testing_release (CuTest *test,
	struct authorized_execution_prepare_firmware_update_testing *execution)
{
	authorized_execution_prepare_firmware_update_release (&execution->test);

	authorized_execution_prepare_firmware_update_testing_release_dependencies (test, execution);
}

/**
 * Maximum length of the prepare firmware update data.
 */
#define	AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA	(9 + SHA512_HASH_LENGTH)

/**
 * Construct the payload used to execute firmware update preparation.
 *
 * @param img_length Length of the image to specify.
 * @param digest Digest of the image.
 * @param digest_length Length of the digest data.
 * @param hash_type Hash algorithm to specify.
 * @param data Output for the execution data payload.  This must be large enough for the expected
 * data, which is 9 bytes plus the digest length.
 * @param length Output for the length of the data payload.
 */
static void authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (
	uint32_t img_length, const uint8_t *digest, size_t digest_length, enum hash_type hash_type,
	uint8_t *data, size_t *length)
{
	uint8_t *pos = data;

	*((uint32_t*) pos) = 0x46575550;	// Magic number
	pos += 4;

	*((uint32_t*) pos) = img_length;
	pos += 4;

	*pos = (int) hash_type - 1;
	pos++;

	memcpy (pos, digest, digest_length);
	pos += digest_length;

	*length = pos - data;
}


/*******************
 * Test cases
 *******************/

static void authorized_execution_prepare_firmware_update_test_init (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	status = authorized_execution_prepare_firmware_update_init (&execution.test,
		&execution.fw_update.base, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.validate_data);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_init_null (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	status = authorized_execution_prepare_firmware_update_init (NULL, &execution.fw_update.base, 0);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_prepare_firmware_update_init (&execution.test, NULL, 0);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_prepare_firmware_update_testing_release_dependencies (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_static_init (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution = {
		.test = authorized_execution_prepare_firmware_update_static_init (&execution.fw_update.base,
			0)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.validate_data);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_execution_prepare_firmware_update_release (NULL);
}

static void authorized_execution_prepare_firmware_update_test_execute_sha256 (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_sha384 (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x654321;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA384_FULL_BLOCK_2048_HASH, SHA384_HASH_LENGTH, HASH_TYPE_SHA384, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (SHA384_FULL_BLOCK_2048_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_sha512 (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x112233;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA512_FULL_BLOCK_1024_HASH, SHA512_HASH_LENGTH, HASH_TYPE_SHA512, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (SHA512_FULL_BLOCK_1024_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_no_reset_req (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, NULL);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_multiple_status_poll (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void
authorized_execution_prepare_firmware_update_test_execute_multiple_status_poll_status_starting (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STARTING);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_with_timeout (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 500);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_static_init (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution = {
		.test = authorized_execution_prepare_firmware_update_static_init (&execution.fw_update.base,
			0)
	};
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_static_init_with_timeout (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution = {
		.test = authorized_execution_prepare_firmware_update_static_init (&execution.fw_update.base,
			500)
	};
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, 0, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_null (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.execute (NULL, data, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, reset_req);

	status = execution.test.base.execute (&execution.test.base, NULL, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_short_payload (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	/* The minimum payload length is 41 bytes, but the minimum fixed data length is 9 bytes. */
	status = execution.test.base.execute (&execution.test.base, data, 8, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_bad_payload_marker (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	data[1] ^= 0x55;	// Corrupt the marker.

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_unknown_hash_algorithm (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	data[8] = 3;	// Change the hash type.

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_short_digest (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.execute (&execution.test.base, data, length - 1, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_long_digest (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.execute (&execution.test.base, data, length + 1, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_prepare_staging_error (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL,
		.arg1 = FIRMWARE_UPDATE_TASK_BUSY,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, FIRMWARE_UPDATE_TASK_BUSY, MOCK_ARG (img_length));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_TASK_BUSY, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_execute_prepare_staging_execution_fail
	(CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP_FAIL);

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_EXECUTE_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void
authorized_execution_prepare_firmware_update_test_execute_prepare_staging_execution_timeout	(
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL,
		.arg1 = AUTHORIZED_EXECUTION_EXECUTE_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 110);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STARTING);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_EXECUTE_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	/* Don't use release helper so that mock validation can be skipped to avoid timing-based
	 * failures. */
	authorized_execution_prepare_firmware_update_release (&execution.test);
	firmware_update_control_mock_release (&execution.fw_update);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&execution.log);
	CuAssertIntEquals (test, 0, status);
}

static void
authorized_execution_prepare_firmware_update_test_execute_prepare_staging_execution_timeout_static_init
	(CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution = {
		.test = authorized_execution_prepare_firmware_update_static_init (&execution.fw_update.base,
			110)
	};
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL,
		.arg1 = AUTHORIZED_EXECUTION_EXECUTE_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STARTING);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);
	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_STAGING_PREP);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_EXECUTE_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	/* Don't use release helper so that mock validation can be skipped to avoid timing-based
	 * failures. */
	authorized_execution_prepare_firmware_update_release (&execution.test);
	firmware_update_control_mock_release (&execution.fw_update);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&execution.log);
	CuAssertIntEquals (test, 0, status);
}

static void authorized_execution_prepare_firmware_update_test_execute_set_digest_error (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	bool reset_req = false;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL,
		.arg1 = FIRMWARE_UPDATE_UNSUPPORTED_HASH,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = mock_expect (&execution.fw_update.mock, execution.fw_update.base.prepare_staging,
		&execution.fw_update, 0, MOCK_ARG (img_length));

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.get_status,
		&execution.fw_update, UPDATE_STATUS_SUCCESS);

	status |= mock_expect (&execution.fw_update.mock, execution.fw_update.base.set_image_digest,
		&execution.fw_update, FIRMWARE_UPDATE_UNSUPPORTED_HASH, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, data, length, &reset_req);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_UNSUPPORTED_HASH, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_sha256 (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.validate_data (&execution.test.base, data, length);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_sha384 (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x654321;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA384_FULL_BLOCK_2048_HASH, SHA384_HASH_LENGTH, HASH_TYPE_SHA384, data, &length);

	status = execution.test.base.validate_data (&execution.test.base, data, length);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_sha512 (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x112233;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA512_FULL_BLOCK_1024_HASH, SHA512_HASH_LENGTH, HASH_TYPE_SHA512, data, &length);

	status = execution.test.base.validate_data (&execution.test.base, data, length);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_static_init (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution = {
		.test = authorized_execution_prepare_firmware_update_static_init (&execution.fw_update.base,
			0)
	};
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.validate_data (&execution.test.base, data, length);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_null (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.validate_data (NULL, data, length);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = execution.test.base.validate_data (&execution.test.base, NULL, length);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_short_payload (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	/* The minimum payload length is 41 bytes, but the minimum fixed data length is 9 bytes. */
	status = execution.test.base.validate_data (&execution.test.base, data, 8);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_bad_payload_marker (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	data[1] ^= 0x55;	// Corrupt the marker.

	status = execution.test.base.validate_data (&execution.test.base, data, length);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_unknown_hash_algorithm (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	data[8] = 3;	// Change the hash type.

	status = execution.test.base.validate_data (&execution.test.base, data, length);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_short_digest (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.validate_data (&execution.test.base, data, length - 1);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_validate_data_long_digest (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	int status;
	uint32_t img_length = 0x12345;
	uint8_t data[AUTHORIZED_EXECUTION_PREPARE_FIRMARE_UPDATE_TESTING_MAX_DATA];
	size_t length;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	authorized_exeuction_prepare_firmware_update_testing_generate_operation_data (img_length,
		SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH, HASH_TYPE_SHA256, data, &length);

	status = execution.test.base.validate_data (&execution.test.base, data, length + 1);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_DATA_NOT_VALID, status);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_get_status_identifiers (CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_get_status_identifiers_static_init (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution = {
		.test = authorized_execution_prepare_firmware_update_static_init (&execution.fw_update.base,
			0)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}

static void authorized_execution_prepare_firmware_update_test_get_status_identifiers_null (
	CuTest *test)
{
	struct authorized_execution_prepare_firmware_update_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_prepare_firmware_update_testing_init (test, &execution, 0);

	execution.test.base.get_status_identifiers (NULL, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	start = 0;
	error = 0;

	execution.test.base.get_status_identifiers (&execution.test.base, NULL, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, NULL);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);

	authorized_execution_prepare_firmware_update_testing_release (test, &execution);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_execution_prepare_firmware_update);

TEST (authorized_execution_prepare_firmware_update_test_init);
TEST (authorized_execution_prepare_firmware_update_test_init_null);
TEST (authorized_execution_prepare_firmware_update_test_static_init);
TEST (authorized_execution_prepare_firmware_update_test_release_null);
TEST (authorized_execution_prepare_firmware_update_test_execute_sha256);
TEST (authorized_execution_prepare_firmware_update_test_execute_sha384);
TEST (authorized_execution_prepare_firmware_update_test_execute_sha512);
TEST (authorized_execution_prepare_firmware_update_test_execute_no_reset_req);
TEST (authorized_execution_prepare_firmware_update_test_execute_multiple_status_poll);
TEST (authorized_execution_prepare_firmware_update_test_execute_multiple_status_poll_status_starting);
TEST (authorized_execution_prepare_firmware_update_test_execute_with_timeout);
TEST (authorized_execution_prepare_firmware_update_test_execute_static_init);
TEST (authorized_execution_prepare_firmware_update_test_execute_static_init_with_timeout);
TEST (authorized_execution_prepare_firmware_update_test_execute_null);
TEST (authorized_execution_prepare_firmware_update_test_execute_short_payload);
TEST (authorized_execution_prepare_firmware_update_test_execute_bad_payload_marker);
TEST (authorized_execution_prepare_firmware_update_test_execute_unknown_hash_algorithm);
TEST (authorized_execution_prepare_firmware_update_test_execute_short_digest);
TEST (authorized_execution_prepare_firmware_update_test_execute_long_digest);
TEST (authorized_execution_prepare_firmware_update_test_execute_prepare_staging_error);
TEST (authorized_execution_prepare_firmware_update_test_execute_prepare_staging_execution_fail);
TEST (authorized_execution_prepare_firmware_update_test_execute_prepare_staging_execution_timeout);
TEST (authorized_execution_prepare_firmware_update_test_execute_prepare_staging_execution_timeout_static_init);
TEST (authorized_execution_prepare_firmware_update_test_execute_set_digest_error);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_sha256);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_sha384);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_sha512);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_static_init);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_null);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_short_payload);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_bad_payload_marker);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_unknown_hash_algorithm);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_short_digest);
TEST (authorized_execution_prepare_firmware_update_test_validate_data_long_digest);
TEST (authorized_execution_prepare_firmware_update_test_get_status_identifiers);
TEST (authorized_execution_prepare_firmware_update_test_get_status_identifiers_static_init);
TEST (authorized_execution_prepare_firmware_update_test_get_status_identifiers_null);

TEST_SUITE_END;
// *INDENT-ON*
