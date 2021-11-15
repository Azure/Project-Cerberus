// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "intrusion/intrusion_manager.h"
#include "attestation/pcr_store.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/intrusion/intrusion_state_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/intrusion/intrusion_manager_testing.h"


TEST_SUITE_LABEL ("intrusion_manager");


/**
 * Test measurement without a detected intrusion;
 */
const uint8_t INTRUSION_MANAGER_TESTING_NO_INTRUSION[] = {
	0x61,0xc8,0xcc,0xdf,0x40,0x25,0x38,0x96,0x3e,0x88,0x1d,0x08,0x77,0xff,0xc4,0x71,
	0xac,0x99,0x1c,0x68,0x46,0xab,0xd8,0xa0,0xfb,0x1c,0x85,0xd5,0xc7,0xc2,0xb3,0x48
};

/**
 * Test measurement for an intrusion.
 */
const uint8_t INTRUSION_MANAGER_TESTING_INTRUSION[] = {
	0x50,0x29,0x0a,0x4d,0xe7,0x13,0x7d,0xbb,0x61,0x5a,0xee,0xeb,0x8a,0xb2,0x57,0xfe,
	0x79,0x0d,0xde,0x2b,0x50,0x22,0x24,0xe3,0x0d,0xf0,0x33,0x84,0x5a,0x85,0x59,0x92
};

/**
 * Test measurement for an unknown intrusion state.
 */
const uint8_t INTRUSION_MANAGER_TESTING_UNKNOWN[] = {
	0x57,0xd7,0x46,0x26,0x40,0x83,0x6f,0xe0,0x58,0xe7,0xd9,0x3d,0x9a,0xe4,0xf8,0xcf,
	0x9e,0xea,0x3f,0x50,0x30,0x19,0x31,0x03,0x2f,0x17,0xb8,0x1d,0x6e,0xcb,0xf2,0x2a
};

/**
 * Dependencies for testing.
 */
struct intrusion_manager_testing {
	struct intrusion_state_mock state;		/**< Mock for intrusion state. */
	struct pcr_store store;					/**< PCR manager for testing. */
	HASH_TESTING_ENGINE hash;				/**< Hash engine for PCR testing. */
	struct hash_engine_mock hash_mock;		/**< Mock for the hash engine. */
	uint16_t pcr_id;						/**< The measurement ID used for testing. */
	struct intrusion_manager test;			/**< Intrusion manager being tested. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param manager Testing dependencies to initailize.
 * @param pcr_measurement The measurement ID to use.
 */
static void intrusion_manager_testing_init_dependencies (CuTest *test,
	struct intrusion_manager_testing *manager, uint16_t pcr_measurement)
{
	uint8_t num_measurements[1] = {2};
	int status;

	status = intrusion_state_mock_init (&manager->state);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&manager->store, num_measurements, sizeof (num_measurements));
	CuAssertIntEquals (test, 0, status);

	manager->pcr_id = pcr_measurement;
	status = pcr_store_update_event_type (&manager->store, manager->pcr_id,
		INTRUSION_MANAGER_TESTING_EVENT_ID);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&manager->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&manager->hash_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate all mocks.
 *
 * @param test The test framework.
 * @param manager Testing dependencies to validate.
 */
static void intrusion_manager_testing_validate_dependencies (CuTest *test,
	struct intrusion_manager_testing *manager)
{
	int status;

	status = mock_validate (&manager->state.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param manager Testing dependencies to release.
 */
static void intrusion_manager_testing_release_dependencies (CuTest *test,
	struct intrusion_manager_testing *manager)
{
	int status;

	status = intrusion_state_mock_validate_and_release (&manager->state);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&manager->hash_mock);
	CuAssertIntEquals (test, 0, status);

	pcr_store_release (&manager->store);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
}

/**
 * Initialize an intrusion manager for testing.
 *
 * @param test The test framework.
 * @param manager Testing components to initialize.
 * @param pcr_measurement The measurement ID to use.
 */
static void intrusion_manager_testing_init (CuTest *test, struct intrusion_manager_testing *manager,
	uint16_t pcr_measurement)
{
	int status;

	intrusion_manager_testing_init_dependencies (test, manager, pcr_measurement);

	status = intrusion_manager_init (&manager->test, &manager->state.base, &manager->hash.base,
		&manager->store, manager->pcr_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an intrusion manager for testing using a mock hash engine.
 *
 * @param test The test framework.
 * @param manager Testing components to initialize.
 * @param pcr_measurement The measurement ID to use.
 */
static void intrusion_manager_testing_init_with_hash_mock (CuTest *test,
	struct intrusion_manager_testing *manager, uint16_t pcr_measurement)
{
	uint32_t event = INTRUSION_MANAGER_TESTING_EVENT_ID;
	uint8_t version = INTRUSION_MANAGER_TESTING_EVENT_VERSION;
	uint8_t value = 2;
	int status;

	intrusion_manager_testing_init_dependencies (test, manager, pcr_measurement);

	status = mock_expect (&manager->hash_mock.mock, manager->hash_mock.base.start_sha256,
		&manager->hash_mock, 0);

	status |= mock_expect (&manager->hash_mock.mock, manager->hash_mock.base.update,
		&manager->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP (&event, sizeof (event)),
		MOCK_ARG (sizeof (event)));
	status |= mock_expect (&manager->hash_mock.mock, manager->hash_mock.base.update,
		&manager->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP (&version, sizeof (version)),
		MOCK_ARG (sizeof (version)));
	status |= mock_expect (&manager->hash_mock.mock, manager->hash_mock.base.update,
		&manager->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP (&value, sizeof (value)),
		MOCK_ARG (sizeof (value)));

	status |= mock_expect (&manager->hash_mock.mock, manager->hash_mock.base.finish,
		&manager->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manager->hash_mock.mock, 0, INTRUSION_MANAGER_TESTING_UNKNOWN,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_init (&manager->test, &manager->state.base, &manager->hash_mock.base,
		&manager->store, manager->pcr_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release intrusion manager testing components and validate mocks.
 *
 * @param test The test framework.
 * @param manager Testing components to release.
 */
static void intrusion_manager_testing_validate_and_release (CuTest *test,
	struct intrusion_manager_testing *manager)
{
	intrusion_manager_testing_release_dependencies (test, manager);
	intrusion_manager_release (&manager->test);
}

/**
 * Release intrusion manager testing components without validating mocks.
 *
 * @param test The test framework.
 * @param manager Testing components to release.
 */
static void intrusion_manager_testing_release (CuTest *test,
	struct intrusion_manager_testing *manager)
{
	intrusion_manager_release (&manager->test);
	intrusion_state_mock_release (&manager->state);
	hash_mock_release (&manager->hash_mock);
	pcr_store_release (&manager->store);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
}


/*******************
 * Test cases
 *******************/

static void intrusion_manager_test_init (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = intrusion_manager_init (&manager.test, &manager.state.base, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.handle_intrusion);
	CuAssertPtrNotNull (test, manager.test.reset_intrusion);
	CuAssertPtrNotNull (test, manager.test.check_state);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_and_release (test, &manager);
}

static void intrusion_manager_test_init_second_measurement (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 1));

	status = intrusion_manager_init (&manager.test, &manager.state.base, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.handle_intrusion);
	CuAssertPtrNotNull (test, manager.test.reset_intrusion);
	CuAssertPtrNotNull (test, manager.test.check_state);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_and_release (test, &manager);
}

static void intrusion_manager_test_init_null (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint8_t zero[INTRUSION_MANAGER_TESTING_DIGEST_LEN] = {0};

	TEST_START;

	intrusion_manager_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = intrusion_manager_init (NULL, &manager.state.base, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = intrusion_manager_init (&manager.test, NULL, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = intrusion_manager_init (&manager.test, &manager.state.base, NULL,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = intrusion_manager_init (&manager.test, &manager.state.base, &manager.hash.base,
		NULL, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertPtrEquals (test, NULL, measurement.measured_data);

	status = testing_validate_array (zero, measurement.digest, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_release_dependencies (test, &manager);
}

static void intrusion_manager_test_init_invalid_measurement (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint8_t zero[INTRUSION_MANAGER_TESTING_DIGEST_LEN] = {0};

	TEST_START;

	intrusion_manager_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = intrusion_manager_init (&manager.test, &manager.state.base, &manager.hash.base,
		&manager.store, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertPtrEquals (test, NULL, measurement.measured_data);

	status = testing_validate_array (zero, measurement.digest, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_release_dependencies (test, &manager);
}

static void intrusion_manager_test_init_hash_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint8_t zero[INTRUSION_MANAGER_TESTING_DIGEST_LEN] = {0};

	TEST_START;

	intrusion_manager_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_init (&manager.test, &manager.state.base, &manager.hash_mock.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertPtrEquals (test, NULL, measurement.measured_data);

	status = testing_validate_array (zero, measurement.digest, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_release_dependencies (test, &manager);
}

static void intrusion_manager_test_release_null (CuTest *test)
{
	TEST_START;

	intrusion_manager_release (NULL);
}

static void intrusion_manager_test_handle_intrusion (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.set, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.handle_intrusion (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_handle_intrusion_null (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = manager.test.handle_intrusion (NULL);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_handle_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 1));

	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&manager.state.mock, manager.state.base.set, &manager.state, 0);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.handle_intrusion (&manager.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_handle_intrusion_state_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.set, &manager.state,
		INTRUSION_STATE_SET_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.handle_intrusion (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_SET_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_handle_intrusion_hash_error_and_state_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&manager.state.mock, manager.state.base.set, &manager.state,
		INTRUSION_STATE_SET_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.handle_intrusion (&manager.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_reset_intrusion (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.reset_intrusion (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 0, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_NO_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_reset_intrusion_null (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = manager.test.reset_intrusion (NULL);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_reset_intrusion_state_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 1));

	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state,
		INTRUSION_STATE_CLEAR_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.reset_intrusion (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_CLEAR_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_reset_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state, 0);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.reset_intrusion (&manager.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_no_intrusion (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 0, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_NO_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_intrusion (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_check_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state,
		INTRUSION_STATE_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_CHECK_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_check_error_from_intrusion (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.set, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.handle_intrusion (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Error checking the state. */
	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state,
		INTRUSION_STATE_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_CHECK_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_check_error_from_no_intrusion (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the no intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.reset_intrusion (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 0, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_NO_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Error checking the state. */
	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state,
		INTRUSION_STATE_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_CHECK_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_deferred (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.reset_intrusion (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 0, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_NO_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Error checking the state. */
	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state,
		INTRUSION_STATE_CHECK_DEFERRED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_CHECK_DEFERRED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_null (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = manager.test.check_state (NULL);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_no_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 0);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 1);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_UNKNOWN, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}

static void intrusion_manager_test_check_state_check_error_and_hash_error (CuTest *test)
{
	struct intrusion_manager_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = INTRUSION_MANAGER_TESTING_EVENT_ID;
	uint8_t version = INTRUSION_MANAGER_TESTING_EVENT_VERSION;
	uint8_t value = 1;

	TEST_START;

	intrusion_manager_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.set, &manager.state, 0);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, 0);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.update,
		&manager.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)),
		MOCK_ARG (sizeof (event)));
	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.update,
		&manager.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)),
		MOCK_ARG (sizeof (version)));
	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.update,
		&manager.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&value, sizeof (value)),
		MOCK_ARG (sizeof (value)));

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.finish,
		&manager.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manager.hash_mock.mock, 0, INTRUSION_MANAGER_TESTING_INTRUSION,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.handle_intrusion (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 1, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Error checking the state. */
	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state,
		INTRUSION_STATE_CHECK_FAILED);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.check_state (&manager.test);
	CuAssertIntEquals (test, INTRUSION_STATE_CHECK_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_VERSION, measurement.version);
	CuAssertPtrNotNull (test, measurement.measured_data);
	CuAssertIntEquals (test, PCR_DATA_TYPE_1BYTE, measurement.measured_data->type);
	CuAssertIntEquals (test, 2, measurement.measured_data->data.value_1byte);

	status = testing_validate_array (INTRUSION_MANAGER_TESTING_INTRUSION, measurement.digest,
		INTRUSION_MANAGER_TESTING_DIGEST_LEN);
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.handle_intrusion (&manager.test);

	intrusion_manager_testing_release (test, &manager);
}


TEST_SUITE_START (intrusion_manager);

TEST (intrusion_manager_test_init);
TEST (intrusion_manager_test_init_second_measurement);
TEST (intrusion_manager_test_init_null);
TEST (intrusion_manager_test_init_invalid_measurement);
TEST (intrusion_manager_test_init_hash_error);
TEST (intrusion_manager_test_release_null);
TEST (intrusion_manager_test_handle_intrusion);
TEST (intrusion_manager_test_handle_intrusion_null);
TEST (intrusion_manager_test_handle_intrusion_hash_error);
TEST (intrusion_manager_test_handle_intrusion_state_error);
TEST (intrusion_manager_test_handle_intrusion_hash_error_and_state_error);
TEST (intrusion_manager_test_reset_intrusion);
TEST (intrusion_manager_test_reset_intrusion_null);
TEST (intrusion_manager_test_reset_intrusion_state_error);
TEST (intrusion_manager_test_reset_intrusion_hash_error);
TEST (intrusion_manager_test_check_state_no_intrusion);
TEST (intrusion_manager_test_check_state_intrusion);
TEST (intrusion_manager_test_check_state_check_error);
TEST (intrusion_manager_test_check_state_check_error_from_intrusion);
TEST (intrusion_manager_test_check_state_check_error_from_no_intrusion);
TEST (intrusion_manager_test_check_state_deferred);
TEST (intrusion_manager_test_check_state_null);
TEST (intrusion_manager_test_check_state_no_intrusion_hash_error);
TEST (intrusion_manager_test_check_state_intrusion_hash_error);
TEST (intrusion_manager_test_check_state_check_error_and_hash_error);

TEST_SUITE_END;
