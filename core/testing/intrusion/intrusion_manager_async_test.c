// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "intrusion/intrusion_manager_async.h"
#include "intrusion/intrusion_logging.h"
#include "attestation/pcr_store.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/intrusion/intrusion_state_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/intrusion/intrusion_manager_testing.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("intrusion_manager_async");


/**
 * Dependencies for testing.
 */
struct intrusion_manager_async_testing {
	struct intrusion_state_mock state;		/**< Mock for intrusion state. */
	struct pcr_store store;					/**< PCR manager for testing. */
	HASH_TESTING_ENGINE hash;				/**< Hash engine for PCR testing. */
	struct hash_engine_mock hash_mock;		/**< Mock for the hash engine. */
	uint16_t pcr_id;						/**< The measurement ID used for testing. */
	struct logging_mock log;				/**< Mock for the debug log. */
	struct intrusion_manager_async test;	/**< Intrusion manager being tested. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param manager Testing dependencies to initailize.
 * @param pcr_measurement The measurement ID to use.
 */
static void intrusion_manager_async_testing_init_dependencies (CuTest *test,
	struct intrusion_manager_async_testing *manager, uint16_t pcr_measurement)
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

	status = logging_mock_init (&manager->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate all mocks.
 *
 * @param test The test framework.
 * @param manager Testing dependencies to validate.
 */
static void intrusion_manager_async_testing_validate_dependencies (CuTest *test,
	struct intrusion_manager_async_testing *manager)
{
	int status;

	status = mock_validate (&manager->state.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->log.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param manager Testing dependencies to release.
 */
static void intrusion_manager_async_testing_release_dependencies (CuTest *test,
	struct intrusion_manager_async_testing *manager)
{
	int status;

	status = intrusion_state_mock_validate_and_release (&manager->state);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&manager->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&manager->log);
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
static void intrusion_manager_async_testing_init (CuTest *test,
	struct intrusion_manager_async_testing *manager, uint16_t pcr_measurement)
{
	int status;

	intrusion_manager_async_testing_init_dependencies (test, manager, pcr_measurement);

	status = intrusion_manager_async_init (&manager->test, &manager->state.base,
		&manager->hash.base, &manager->store, manager->pcr_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an intrusion manager for testing using a mock hash engine.
 *
 * @param test The test framework.
 * @param manager Testing components to initialize.
 * @param pcr_measurement The measurement ID to use.
 */
static void intrusion_manager_async_testing_init_with_hash_mock (CuTest *test,
	struct intrusion_manager_async_testing *manager, uint16_t pcr_measurement)
{
	uint32_t event = INTRUSION_MANAGER_TESTING_EVENT_ID;
	uint8_t version = INTRUSION_MANAGER_TESTING_EVENT_VERSION;
	uint8_t value = 2;
	int status;

	intrusion_manager_async_testing_init_dependencies (test, manager, pcr_measurement);

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

	status = intrusion_manager_async_init (&manager->test, &manager->state.base,
		&manager->hash_mock.base, &manager->store, manager->pcr_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release intrusion manager testing components and validate mocks.
 *
 * @param test The test framework.
 * @param manager Testing components to release.
 */
static void intrusion_manager_async_testing_validate_and_release (CuTest *test,
	struct intrusion_manager_async_testing *manager)
{
	intrusion_manager_async_testing_release_dependencies (test, manager);
	intrusion_manager_async_release (&manager->test);
}

/**
 * Release intrusion manager testing components without validating mocks.
 *
 * @param test The test framework.
 * @param manager Testing components to release.
 */
static void intrusion_manager_async_testing_release (CuTest *test,
	struct intrusion_manager_async_testing *manager)
{
	intrusion_manager_async_release (&manager->test);
	intrusion_state_mock_release (&manager->state);
	hash_mock_release (&manager->hash_mock);
	logging_mock_release (&manager->log);
	pcr_store_release (&manager->store);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
}


/*******************
 * Test cases
 *******************/

static void intrusion_manager_async_test_init (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = intrusion_manager_async_init (&manager.test, &manager.state.base, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.base.handle_intrusion);
	CuAssertPtrNotNull (test, manager.test.base.reset_intrusion);
	CuAssertPtrNotNull (test, manager.test.base.check_state);

	CuAssertPtrNotNull (test, manager.test.base_observer.on_intrusion);
	CuAssertPtrNotNull (test, manager.test.base_observer.on_no_intrusion);
	CuAssertPtrNotNull (test, manager.test.base_observer.on_error);

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

	intrusion_manager_async_testing_validate_and_release (test, &manager);
}

static void intrusion_manager_async_test_init_second_measurement (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 1));

	status = intrusion_manager_async_init (&manager.test, &manager.state.base, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.base.handle_intrusion);
	CuAssertPtrNotNull (test, manager.test.base.reset_intrusion);
	CuAssertPtrNotNull (test, manager.test.base.check_state);

	CuAssertPtrNotNull (test, manager.test.base_observer.on_intrusion);
	CuAssertPtrNotNull (test, manager.test.base_observer.on_no_intrusion);
	CuAssertPtrNotNull (test, manager.test.base_observer.on_error);

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

	intrusion_manager_async_testing_validate_and_release (test, &manager);
}

static void intrusion_manager_async_test_init_null (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint8_t zero[INTRUSION_MANAGER_TESTING_DIGEST_LEN] = {0};

	TEST_START;

	intrusion_manager_async_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = intrusion_manager_async_init (NULL, &manager.state.base, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = intrusion_manager_async_init (&manager.test, NULL, &manager.hash.base,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = intrusion_manager_async_init (&manager.test, &manager.state.base, NULL,
		&manager.store, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = intrusion_manager_async_init (&manager.test, &manager.state.base, &manager.hash.base,
		NULL, manager.pcr_id);
	CuAssertIntEquals (test, INTRUSION_MANAGER_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertPtrEquals (test, NULL, measurement.measured_data);

	status = testing_validate_array (zero, measurement.digest, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_async_testing_release_dependencies (test, &manager);
}

static void intrusion_manager_async_test_init_invalid_measurement (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint8_t zero[INTRUSION_MANAGER_TESTING_DIGEST_LEN] = {0};

	TEST_START;

	intrusion_manager_async_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = intrusion_manager_async_init (&manager.test, &manager.state.base, &manager.hash.base,
		&manager.store, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertPtrEquals (test, NULL, measurement.measured_data);

	status = testing_validate_array (zero, measurement.digest, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_async_testing_release_dependencies (test, &manager);
}

static void intrusion_manager_async_test_init_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint8_t zero[INTRUSION_MANAGER_TESTING_DIGEST_LEN] = {0};

	TEST_START;

	intrusion_manager_async_testing_init_dependencies (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_async_init (&manager.test, &manager.state.base,
		&manager.hash_mock.base, &manager.store, manager.pcr_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&manager.store, manager.pcr_id, &measurement);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, INTRUSION_MANAGER_TESTING_EVENT_ID, measurement.event_type);
	CuAssertPtrEquals (test, NULL, measurement.measured_data);

	status = testing_validate_array (zero, measurement.digest, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	intrusion_manager_async_testing_release_dependencies (test, &manager);
}

static void intrusion_manager_async_test_release_null (CuTest *test)
{
	TEST_START;

	intrusion_manager_async_release (NULL);
}

static void intrusion_manager_async_test_check_state_no_intrusion (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_intrusion (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_check_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state,
		INTRUSION_STATE_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_check_error_from_intrusion (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.set, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.handle_intrusion (&manager.test.base);
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

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_check_error_from_no_intrusion (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the no intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.reset_intrusion (&manager.test.base);
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

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_deferred (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.clear, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.reset_intrusion (&manager.test.base);
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

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_null (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = manager.test.base.check_state (NULL);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_no_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 0);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	intrusion_manager_async_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.state.mock, manager.state.base.check, &manager.state, 1);

	status |= mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_check_state_check_error_and_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = INTRUSION_MANAGER_TESTING_EVENT_ID;
	uint8_t version = INTRUSION_MANAGER_TESTING_EVENT_VERSION;
	uint8_t value = 1;

	TEST_START;

	intrusion_manager_async_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

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

	status = manager.test.base.handle_intrusion (&manager.test.base);
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

	status = manager.test.base.check_state (&manager.test.base);
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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_on_intrusion (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_INTRUSION,
		.msg_index = INTRUSION_LOGGING_INTRUSION_NOTIFICATION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;
	manager.test.base_observer.on_intrusion (&manager.test.base_observer);
	debug_log = NULL;

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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_on_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_INTRUSION,
		.msg_index = INTRUSION_LOGGING_INTRUSION_NOTIFICATION,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};

	TEST_START;

	intrusion_manager_async_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;
	manager.test.base_observer.on_intrusion (&manager.test.base_observer);
	debug_log = NULL;

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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_on_no_intrusion (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_INTRUSION,
		.msg_index = INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;
	manager.test.base_observer.on_no_intrusion (&manager.test.base_observer);
	debug_log = NULL;

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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_on_no_intrusion_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_INTRUSION,
		.msg_index = INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};

	TEST_START;

	intrusion_manager_async_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;
	manager.test.base_observer.on_no_intrusion (&manager.test.base_observer);
	debug_log = NULL;

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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_on_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_INTRUSION,
		.msg_index = INTRUSION_LOGGING_ERROR_NOTIFICATION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	intrusion_manager_async_testing_init (test, &manager, PCR_MEASUREMENT (0, 0));

	/* Set the intrusion state. */
	status = mock_expect (&manager.state.mock, manager.state.base.set, &manager.state, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.handle_intrusion (&manager.test.base);
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

	/* Trigger the error condition. */
	status = mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;
	manager.test.base_observer.on_error (&manager.test.base_observer);
	debug_log = NULL;

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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}

static void intrusion_manager_async_test_on_error_hash_error (CuTest *test)
{
	struct intrusion_manager_async_testing manager;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = INTRUSION_MANAGER_TESTING_EVENT_ID;
	uint8_t version = INTRUSION_MANAGER_TESTING_EVENT_VERSION;
	uint8_t value = 1;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_INTRUSION,
		.msg_index = INTRUSION_LOGGING_ERROR_NOTIFICATION,
		.arg1 = HASH_ENGINE_START_SHA256_FAILED,
		.arg2 = 0
	};

	TEST_START;

	intrusion_manager_async_testing_init_with_hash_mock (test, &manager, PCR_MEASUREMENT (0, 0));

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

	status = manager.test.base.handle_intrusion (&manager.test.base);
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

	/* Trigger the error condition. */
	status = mock_expect (&manager.hash_mock.mock, manager.hash_mock.base.start_sha256,
		&manager.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;
	manager.test.base_observer.on_error (&manager.test.base_observer);
	debug_log = NULL;

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

	intrusion_manager_async_testing_validate_dependencies (test, &manager);

	/* Check for proper unlocking */
	manager.test.base.handle_intrusion (&manager.test.base);

	intrusion_manager_async_testing_release (test, &manager);
}


TEST_SUITE_START (intrusion_manager_async);

TEST (intrusion_manager_async_test_init);
TEST (intrusion_manager_async_test_init_second_measurement);
TEST (intrusion_manager_async_test_init_null);
TEST (intrusion_manager_async_test_init_invalid_measurement);
TEST (intrusion_manager_async_test_init_hash_error);
TEST (intrusion_manager_async_test_release_null);
/* Base implementations are used for handle_intrusion and reset_intrusion. */
TEST (intrusion_manager_async_test_check_state_no_intrusion);
TEST (intrusion_manager_async_test_check_state_intrusion);
TEST (intrusion_manager_async_test_check_state_check_error);
TEST (intrusion_manager_async_test_check_state_check_error_from_intrusion);
TEST (intrusion_manager_async_test_check_state_check_error_from_no_intrusion);
TEST (intrusion_manager_async_test_check_state_deferred);
TEST (intrusion_manager_async_test_check_state_null);
TEST (intrusion_manager_async_test_check_state_no_intrusion_hash_error);
TEST (intrusion_manager_async_test_check_state_intrusion_hash_error);
TEST (intrusion_manager_async_test_check_state_check_error_and_hash_error);
TEST (intrusion_manager_async_test_on_intrusion);
TEST (intrusion_manager_async_test_on_intrusion_hash_error);
TEST (intrusion_manager_async_test_on_no_intrusion);
TEST (intrusion_manager_async_test_on_no_intrusion_hash_error);
TEST (intrusion_manager_async_test_on_error);
TEST (intrusion_manager_async_test_on_error_hash_error);

TEST_SUITE_END;
