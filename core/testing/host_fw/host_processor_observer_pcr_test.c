// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "attestation/pcr_store.h"
#include "common/array_size.h"
#include "host_fw/host_logging.h"
#include "host_fw/host_processor_observer_pcr.h"
#include "host_fw/host_processor_observer_pcr_static.h"
#include "host_fw/host_state_manager.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/host_fw/host_state_manager_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("host_processor_observer_pcr");

/**
 * Digest of the number 0 with event type 0xaabbccdd and version 0x0.  This indicates valid FW in
 * active mode.
 */
static const uint8_t DIGEST_ACTIVE[] = {
	0x91, 0xc2, 0x06, 0x73, 0x18, 0x55, 0x21, 0x12, 0xdf, 0xc2, 0x77, 0x4c, 0xc2, 0xa7, 0xb4, 0xc2,
	0x3b, 0xd5, 0xe8, 0x1c, 0xe8, 0x15, 0x57, 0x53, 0xf7, 0xb8, 0x01, 0xf4, 0x5d, 0x6a, 0x34, 0x84
};

/**
 * Digest of the state indicating bypass mode with event type 0xaabbccdd and version 0x0.
 */
static const uint8_t DIGEST_BYPASS[] = {
	0xa2, 0xe2, 0x43, 0x21, 0x71, 0x34, 0x36, 0xa7, 0xa8, 0xa2, 0xb0, 0x06, 0x0f, 0x18, 0xb8, 0x1a,
	0xb2, 0xb1, 0x8f, 0xa5, 0x4d, 0x19, 0x76, 0xea, 0xa7, 0xfe, 0x45, 0xda, 0x02, 0x00, 0x4e, 0xe6
};

/**
 * Digest of the state indicating recovery mode with event type 0xaabbccdd and version 0x0.
 */
static const uint8_t DIGEST_RECOVERY[] = {
	0xe7, 0xf4, 0x3e, 0x01, 0xe6, 0x52, 0x1b, 0xcc, 0x6a, 0x7d, 0x4a, 0xa0, 0x7d, 0x6a, 0x02, 0xdb,
	0x8f, 0x39, 0x12, 0x06, 0x44, 0xc3, 0x07, 0x84, 0xf4, 0xd0, 0x13, 0x2f, 0x8b, 0x1d, 0xfb, 0xc6
};

/**
 * Digest of the state indicating unvalidated flash with event type 0xaabbccdd and version 0x0.
 */
static const uint8_t DIGEST_NOT_VALIDATED[] = {
	0x2d, 0x89, 0xc3, 0x8b, 0xe5, 0x2a, 0x9b, 0xf8, 0xec, 0xfd, 0xb7, 0xe4, 0x73, 0x5b, 0xec, 0xbb,
	0x81, 0x77, 0xb1, 0xfb, 0x63, 0xf4, 0x02, 0x27, 0x9f, 0xce, 0xb6, 0x42, 0x25, 0xf7, 0xb1, 0xa1
};

/**
 * Digest of the initial state with event type 0xaabbccdd and version 0x0 for testing.
 */
static const uint8_t DIGEST_INIT[] = {
	0x74, 0x47, 0xfb, 0x73, 0xef, 0xb5, 0x87, 0xea, 0x5f, 0xb1, 0x69, 0xc3, 0xae, 0xa0, 0xcc, 0xd1,
	0x69, 0x8a, 0xe2, 0x28, 0x52, 0x4d, 0xe9, 0xd2, 0xb7, 0x4c, 0xc0, 0x55, 0xa0, 0x17, 0x76, 0x48
};


/**
 * Dependencies for testing.
 */
struct host_processor_observer_pcr_testing {
	HASH_TESTING_ENGINE (hash);						/**< Hash engine for PCR calculation. */
	struct hash_engine_mock hash_mock;				/**< Mock for hash operations. */
	struct pcr_store store;							/**< PCR management. */
	struct flash_mock flash;						/**< Mock for the state flash. */
	struct logging_mock logger;						/**< Mock for debug logging. */
	struct host_state_manager_state host_state_ctx;	/**< Variable context for host state. */
	struct host_state_manager host_state;			/**< Manager for host state. */
	uint32_t state;									/**< Verification state storage. */
	struct host_processor_observer_pcr test;		/**< Host observer being tested. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param observer The testing components to initialize.
 * @param init_state Initial value to assign to the verification state.
 */
static void host_processor_observer_pcr_testing_init_dependencies (CuTest *test,
	struct host_processor_observer_pcr_testing *observer, uint32_t init_state)
{
	const struct pcr_config pcr_config[2] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	status = HASH_TESTING_ENGINE_INIT (&observer->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&observer->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&observer->store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&observer->flash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&observer->logger);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &observer->host_state,
		&observer->host_state_ctx, &observer->flash, false);

	observer->state = init_state;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param observer The testing components to release.
 */
static void host_processor_observer_pcr_testing_release_dependencies (CuTest *test,
	struct host_processor_observer_pcr_testing *observer)
{
	int status;

	debug_log = NULL;

	status = hash_mock_validate_and_release (&observer->hash_mock);
	status |= flash_mock_validate_and_release (&observer->flash);
	status |= logging_mock_validate_and_release (&observer->logger);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&observer->host_state);
	pcr_store_release (&observer->store);
	HASH_TESTING_ENGINE_RELEASE (&observer->hash);
}

/**
 * Initialize a host processor observer for testing.
 *
 * @param test The test framework.
 * @param observer Testing components to initialize.
 * @param measurement_id ID for the measurement to use for PCR updates.
 * @param event_id Event ID to assign to the measurement.
 * @param init_state Initial value to assign to the verification state.
 */
static void host_processor_observer_pcr_testing_init (CuTest *test,
	struct host_processor_observer_pcr_testing *observer, uint16_t measurement_id,
	uint32_t event_id, uint32_t init_state)
{
	int status;

	host_processor_observer_pcr_testing_init_dependencies (test, observer, init_state);

	status = pcr_store_set_tcg_event_type (&observer->store, measurement_id, event_id);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer->test, &observer->hash.base,
		&observer->store, measurement_id, &observer->state);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor observer for testing using a hash mock.
 *
 * @param test The test framework.
 * @param observer Testing components to initialize.
 * @param measurement_id ID for the measurement to use for PCR updates.
 * @param event_id Event ID to assign to the measurement.
 * @param init_state Initial value to assign to the verification state.
 */
static void host_processor_observer_pcr_testing_init_with_mock (CuTest *test,
	struct host_processor_observer_pcr_testing *observer, uint16_t measurement_id,
	uint32_t event_id, uint32_t init_state)
{
	uint8_t version = 0;
	int status;

	host_processor_observer_pcr_testing_init_dependencies (test, observer, init_state);

	status = pcr_store_set_tcg_event_type (&observer->store, measurement_id, event_id);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer->hash_mock.mock, observer->hash_mock.base.start_sha256,
		&observer->hash_mock, 0);
	status |= mock_expect (&observer->hash_mock.mock, observer->hash_mock.base.update,
		&observer->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP (&event_id, sizeof (event_id)),
		MOCK_ARG (sizeof (event_id)));
	status |= mock_expect (&observer->hash_mock.mock, observer->hash_mock.base.update,
		&observer->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP (&version, sizeof (version)),
		MOCK_ARG (sizeof (version)));
	status |= mock_expect (&observer->hash_mock.mock, observer->hash_mock.base.update,
		&observer->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&observer->hash_mock.mock, observer->hash_mock.base.finish,
		&observer->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer->test, &observer->hash_mock.base,
		&observer->store, measurement_id, &observer->state);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&observer->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param observer Testing components to release.
 */
static void host_processor_observer_pcr_testing_release (CuTest *test,
	struct host_processor_observer_pcr_testing *observer)
{
	host_processor_observer_pcr_release (&observer->test);
	host_processor_observer_pcr_testing_release_dependencies (test, observer);
}

/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void host_processor_observer_pcr_testing_suite_tear_down (CuTest *test)
{
	debug_log = NULL;
}


/*******************
 * Test cases
 *******************/

static void host_processor_observer_pcr_test_init (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer.test, &observer.hash.base, &observer.store,
		PCR_MEASUREMENT (0, 0), &observer.state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.test.base.on_soft_reset);
	CuAssertPtrNotNull (test, observer.test.base.on_bypass_mode);
	CuAssertPtrNotNull (test, observer.test.base.on_active_mode);
	CuAssertPtrNotNull (test, observer.test.base.on_recovery);

	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_active_pfm);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_read_only_flash);
	CuAssertPtrNotNull (test, observer.test.base_state.on_inactive_dirty);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_active_recovery_image);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_pfm_dirty);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_run_time_validation);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_unsupported_flash);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_INIT, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_init_valid (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer, 0);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer.test, &observer.hash.base, &observer.store,
		PCR_MEASUREMENT (0, 2), &observer.state);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 2), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_ACTIVE, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_init_null (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = host_processor_observer_pcr_init (NULL, &observer.hash.base, &observer.store,
		PCR_MEASUREMENT (0, 0), &observer.state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init (&observer.test, NULL, &observer.store,
		PCR_MEASUREMENT (0, 0), &observer.state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init (&observer.test, &observer.hash.base, NULL,
		PCR_MEASUREMENT (0, 0), &observer.state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init (&observer.test, &observer.hash.base, &observer.store,
		PCR_MEASUREMENT (0, 0), NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	host_processor_observer_pcr_testing_release_dependencies (test, &observer);
}

static void host_processor_observer_pcr_test_init_invalid_measurement (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = host_processor_observer_pcr_init (&observer.test, &observer.hash.base, &observer.store,
		PCR_MEASUREMENT (7, 0), &observer.state);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	host_processor_observer_pcr_testing_release_dependencies (test, &observer);
}

static void host_processor_observer_pcr_test_static_init (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (0, 0), &observer.state)
	};
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	CuAssertPtrEquals (test, NULL, observer.test.base.on_soft_reset);
	CuAssertPtrNotNull (test, observer.test.base.on_bypass_mode);
	CuAssertPtrNotNull (test, observer.test.base.on_active_mode);
	CuAssertPtrNotNull (test, observer.test.base.on_recovery);

	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_active_pfm);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_read_only_flash);
	CuAssertPtrNotNull (test, observer.test.base_state.on_inactive_dirty);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_active_recovery_image);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_pfm_dirty);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_run_time_validation);
	CuAssertPtrEquals (test, NULL, observer.test.base_state.on_unsupported_flash);

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_INIT, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_static_init_valid (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (0, 2), &observer.state)
	};
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer, 0);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 2), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_ACTIVE, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_static_init_null (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	struct host_processor_observer_pcr null_hash = host_processor_observer_pcr_static_init (NULL,
		&observer.store, PCR_MEASUREMENT (0, 0), &observer.state);
	struct host_processor_observer_pcr null_store =
		host_processor_observer_pcr_static_init (&observer.hash.base, NULL, PCR_MEASUREMENT (0, 0),
		&observer.state);
	struct host_processor_observer_pcr null_state =
		host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
		PCR_MEASUREMENT (0, 0), NULL);
	int status;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = host_processor_observer_pcr_init_state (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init_state (&null_hash);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init_state (&null_store);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init_state (&null_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	host_processor_observer_pcr_testing_release_dependencies (test, &observer);
}

static void host_processor_observer_pcr_test_static_init_invalid_measurement (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (7, 0), &observer.state)
	};
	int status;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	host_processor_observer_pcr_testing_release_dependencies (test, &observer);
}

static void host_processor_observer_pcr_test_on_bypass_mode (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init (test, &observer, PCR_MEASUREMENT (0, 0), event,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	observer.test.base.on_bypass_mode (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_BYPASS, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_BYPASS, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_bypass_mode_error (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_PCR_UPDATE_ERROR,
		.arg1 = PCR_MEASUREMENT (0, 0),
		.arg2 = HASH_ENGINE_UPDATE_FAILED
	};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_with_mock (test, &observer, PCR_MEASUREMENT (0, 0),
		event, HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.start_sha256,
		&observer.hash_mock, 0);
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.update,
		&observer.hash_mock, HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.cancel,
		&observer.hash_mock, 0);

	status |= mock_expect (&observer.logger.mock, observer.logger.base.create_entry,
		&observer.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &observer.logger.base;

	observer.test.base.on_bypass_mode (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_BYPASS, observer.state);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_bypass_mode_static_init (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (0, 0), &observer.state)
	};
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_bypass_mode (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_BYPASS, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_BYPASS, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_active_mode (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init (test, &observer, PCR_MEASUREMENT (0, 0), event,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	observer.test.base.on_active_mode (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_VALID, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_ACTIVE, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_active_mode_error (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_PCR_UPDATE_ERROR,
		.arg1 = PCR_MEASUREMENT (0, 0),
		.arg2 = HASH_ENGINE_UPDATE_FAILED
	};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_with_mock (test, &observer, PCR_MEASUREMENT (0, 0),
		event, HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.start_sha256,
		&observer.hash_mock, 0);
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.update,
		&observer.hash_mock, HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.cancel,
		&observer.hash_mock, 0);

	status |= mock_expect (&observer.logger.mock, observer.logger.base.create_entry,
		&observer.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &observer.logger.base;

	observer.test.base.on_active_mode (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_VALID, observer.state);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_active_mode_static_init (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (0, 0), &observer.state)
	};
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_active_mode (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_VALID, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_ACTIVE, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_recovery (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init (test, &observer, PCR_MEASUREMENT (0, 0), event,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	observer.test.base.on_recovery (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_RECOVERY, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_RECOVERY, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_recovery_error (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_PCR_UPDATE_ERROR,
		.arg1 = PCR_MEASUREMENT (0, 0),
		.arg2 = HASH_ENGINE_UPDATE_FAILED
	};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_with_mock (test, &observer, PCR_MEASUREMENT (0, 0),
		event, HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.start_sha256,
		&observer.hash_mock, 0);
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.update,
		&observer.hash_mock, HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.cancel,
		&observer.hash_mock, 0);

	status |= mock_expect (&observer.logger.mock, observer.logger.base.create_entry,
		&observer.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &observer.logger.base;

	observer.test.base.on_recovery (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_RECOVERY, observer.state);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_recovery_static_init (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (0, 0), &observer.state)
	};
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, 0, status);

	observer.test.base.on_recovery (&observer.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_RECOVERY, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_RECOVERY, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_dirty (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init (test, &observer, PCR_MEASUREMENT (0, 0), event,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	host_state_manager_save_inactive_dirty (&observer.host_state, true);

	observer.test.base_state.on_inactive_dirty (&observer.test.base_state, &observer.host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_NOT_VALIDATED, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_not_dirty (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init (test, &observer, PCR_MEASUREMENT (0, 0), event,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	host_state_manager_save_inactive_dirty (&observer.host_state, false);

	observer.test.base_state.on_inactive_dirty (&observer.test.base_state, &observer.host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_INIT, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_INIT, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_error (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_PCR_UPDATE_ERROR,
		.arg1 = PCR_MEASUREMENT (0, 0),
		.arg2 = HASH_ENGINE_UPDATE_FAILED
	};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_with_mock (test, &observer, PCR_MEASUREMENT (0, 0),
		event, HOST_PROCESSOR_OBSERVER_PCR_INIT);

	host_state_manager_save_inactive_dirty (&observer.host_state, true);

	status = mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.start_sha256,
		&observer.hash_mock, 0);
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.update,
		&observer.hash_mock, HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&observer.hash_mock.mock, observer.hash_mock.base.cancel,
		&observer.hash_mock, 0);

	status |= mock_expect (&observer.logger.mock, observer.logger.base.create_entry,
		&observer.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &observer.logger.base;

	observer.test.base_state.on_inactive_dirty (&observer.test.base_state, &observer.host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED, observer.state);

	host_processor_observer_pcr_testing_release (test, &observer);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_static_init (CuTest *test)
{
	struct host_processor_observer_pcr_testing observer = {
		.test = host_processor_observer_pcr_static_init (&observer.hash.base, &observer.store,
			PCR_MEASUREMENT (0, 0), &observer.state)
	};
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	host_processor_observer_pcr_testing_init_dependencies (test, &observer,
		HOST_PROCESSOR_OBSERVER_PCR_INIT);

	status = pcr_store_set_tcg_event_type (&observer.store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init_state (&observer.test);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_save_inactive_dirty (&observer.host_state, true);

	observer.test.base_state.on_inactive_dirty (&observer.test.base_state, &observer.host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED, observer.state);

	status = pcr_store_get_measurement (&observer.store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (DIGEST_NOT_VALIDATED, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_release (test, &observer);
}


// *INDENT-OFF*
TEST_SUITE_START (host_processor_observer_pcr);

TEST (host_processor_observer_pcr_test_init);
TEST (host_processor_observer_pcr_test_init_valid);
TEST (host_processor_observer_pcr_test_init_null);
TEST (host_processor_observer_pcr_test_init_invalid_measurement);
TEST (host_processor_observer_pcr_test_static_init);
TEST (host_processor_observer_pcr_test_static_init_valid);
TEST (host_processor_observer_pcr_test_static_init_null);
TEST (host_processor_observer_pcr_test_static_init_invalid_measurement);
TEST (host_processor_observer_pcr_test_on_bypass_mode);
TEST (host_processor_observer_pcr_test_on_bypass_mode_error);
TEST (host_processor_observer_pcr_test_on_bypass_mode_static_init);
TEST (host_processor_observer_pcr_test_on_active_mode);
TEST (host_processor_observer_pcr_test_on_active_mode_error);
TEST (host_processor_observer_pcr_test_on_active_mode_static_init);
TEST (host_processor_observer_pcr_test_on_recovery);
TEST (host_processor_observer_pcr_test_on_recovery_error);
TEST (host_processor_observer_pcr_test_on_recovery_static_init);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_dirty);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_not_dirty);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_error);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_static_init);

/* Tear down after the tests in this suite have run. */
TEST (host_processor_observer_pcr_testing_suite_tear_down);

TEST_SUITE_END;
// *INDENT-ON*
