// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_processor_observer_pcr.h"
#include "host_fw/host_logging.h"
#include "host_fw/host_state_manager.h"
#include "attestation/pcr_store.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("host_processor_observer_pcr");

/**
 * Digest of the number 0 with event type 0xaabbccdd and version 0x0.  This indicates valid FW in
 * active mode.
 */
static const uint8_t DIGEST_ACTIVE[] = {
	0x91,0xc2,0x06,0x73,0x18,0x55,0x21,0x12,0xdf,0xc2,0x77,0x4c,0xc2,0xa7,0xb4,0xc2,
	0x3b,0xd5,0xe8,0x1c,0xe8,0x15,0x57,0x53,0xf7,0xb8,0x01,0xf4,0x5d,0x6a,0x34,0x84
};

/**
 * Digest of the state indicating bypass mode with event type 0xaabbccdd and version 0x0.
 */
static const uint8_t DIGEST_BYPASS[] = {
	0xa2,0xe2,0x43,0x21,0x71,0x34,0x36,0xa7,0xa8,0xa2,0xb0,0x06,0x0f,0x18,0xb8,0x1a,
	0xb2,0xb1,0x8f,0xa5,0x4d,0x19,0x76,0xea,0xa7,0xfe,0x45,0xda,0x02,0x00,0x4e,0xe6
};

/**
 * Digest of the state indicating recovery mode with event type 0xaabbccdd and version 0x0.
 */
static const uint8_t DIGEST_RECOVERY[] = {
	0xe7,0xf4,0x3e,0x01,0xe6,0x52,0x1b,0xcc,0x6a,0x7d,0x4a,0xa0,0x7d,0x6a,0x02,0xdb,
	0x8f,0x39,0x12,0x06,0x44,0xc3,0x07,0x84,0xf4,0xd0,0x13,0x2f,0x8b,0x1d,0xfb,0xc6
};

/**
 * Digest of the state indicating unvalidated flash with event type 0xaabbccdd and version 0x0.
 */
static const uint8_t DIGEST_NOT_VALIDATED[] = {
	0x2d,0x89,0xc3,0x8b,0xe5,0x2a,0x9b,0xf8,0xec,0xfd,0xb7,0xe4,0x73,0x5b,0xec,0xbb,
	0x81,0x77,0xb1,0xfb,0x63,0xf4,0x02,0x27,0x9f,0xce,0xb6,0x42,0x25,0xf7,0xb1,0xa1
};

/**
 * Digest of the initial state with event type 0xaabbccdd and version 0x0 for testing.
 */
static const uint8_t DIGEST_INIT[] = {
	0x74,0x47,0xfb,0x73,0xef,0xb5,0x87,0xea,0x5f,0xb1,0x69,0xc3,0xae,0xa0,0xcc,0xd1,
	0x69,0x8a,0xe2,0x28,0x52,0x4d,0xe9,0xd2,0xb7,0x4c,0xc0,0x55,0xa0,0x17,0x76,0x48
};


/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash The flash device to initialize for state.
 */
void host_processor_observer_pcr_testing_init_host_state (CuTest *test,
	struct host_state_manager *state, struct flash_mock *flash)
{
	int status;
	uint32_t sector_size = 0x1000;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_mock_init (flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash->mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
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
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_soft_reset);
	CuAssertPtrNotNull (test, observer.base.on_bypass_mode);
	CuAssertPtrNotNull (test, observer.base.on_active_mode);
	CuAssertPtrNotNull (test, observer.base.on_recovery);

	CuAssertPtrEquals (test, NULL, observer.base_state.on_active_pfm);
	CuAssertPtrEquals (test, NULL, observer.base_state.on_read_only_flash);
	CuAssertPtrNotNull (test, observer.base_state.on_inactive_dirty);
	CuAssertPtrEquals (test, NULL, observer.base_state.on_active_recovery_image);
	CuAssertPtrEquals (test, NULL, observer.base_state.on_pfm_dirty);
	CuAssertPtrEquals (test, NULL, observer.base_state.on_run_time_validation);
	CuAssertPtrEquals (test, NULL, observer.base_state.on_unsupported_flash);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_INIT, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_init_valid (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = 0;
	struct host_processor_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 2), &state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_soft_reset);
	CuAssertPtrNotNull (test, observer.base.on_bypass_mode);
	CuAssertPtrNotNull (test, observer.base.on_active_mode);
	CuAssertPtrNotNull (test, observer.base.on_recovery);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_ACTIVE, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (NULL, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init (&observer, NULL, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, NULL,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_init_invalid_measurement (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (7, 0), &state);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_on_bypass_mode (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_bypass_mode (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_BYPASS, state);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_BYPASS, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_on_bypass_mode_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct logging_mock logger;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
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
	uint8_t version = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base.on_bypass_mode (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_BYPASS, state);

	debug_log = NULL;

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
}

static void host_processor_observer_pcr_test_on_active_mode (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_active_mode (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_VALID, state);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_ACTIVE, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_on_active_mode_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct logging_mock logger;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
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
	uint8_t version = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base.on_active_mode (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_VALID, state);

	debug_log = NULL;

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
}

static void host_processor_observer_pcr_test_on_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_RECOVERY, state);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_RECOVERY, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_on_recovery_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct logging_mock logger;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
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
	uint8_t version = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base.on_recovery (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_RECOVERY, state);

	debug_log = NULL;

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_dirty (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct flash_mock flash;
	struct host_state_manager host_state;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_init_host_state (test, &host_state, &flash);

	host_state_manager_save_inactive_dirty (&host_state, true);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	observer.base_state.on_inactive_dirty (&observer.base_state, &host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED, state);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_NOT_VALIDATED, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_not_dirty (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct flash_mock flash;
	struct host_state_manager host_state;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_init_host_state (test, &host_state, &flash);

	host_state_manager_save_inactive_dirty (&host_state, false);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	observer.base_state.on_inactive_dirty (&observer.base_state, &host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_INIT, state);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (DIGEST_INIT, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void host_processor_observer_pcr_test_on_inactive_dirty_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct logging_mock logger;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	uint32_t state = HOST_PROCESSOR_OBSERVER_PCR_INIT;
	struct host_processor_observer_pcr observer;
	int status;
	struct flash_mock flash;
	struct host_state_manager host_state;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_PCR_UPDATE_ERROR,
		.arg1 = PCR_MEASUREMENT (0, 0),
		.arg2 = HASH_ENGINE_UPDATE_FAILED
	};
	uint32_t event = 0xaabbccdd;
	uint8_t version = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_testing_init_host_state (test, &host_state, &flash);

	host_state_manager_save_inactive_dirty (&host_state, true);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0), &state);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (uint32_t)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base_state.on_inactive_dirty (&observer.base_state, &host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_NOT_VALIDATED, state);

	debug_log = NULL;

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
}


TEST_SUITE_START (host_processor_observer_pcr);

TEST (host_processor_observer_pcr_test_init);
TEST (host_processor_observer_pcr_test_init_valid);
TEST (host_processor_observer_pcr_test_init_null);
TEST (host_processor_observer_pcr_test_init_invalid_measurement);
TEST (host_processor_observer_pcr_test_on_bypass_mode);
TEST (host_processor_observer_pcr_test_on_bypass_mode_error);
TEST (host_processor_observer_pcr_test_on_active_mode);
TEST (host_processor_observer_pcr_test_on_active_mode_error);
TEST (host_processor_observer_pcr_test_on_recovery);
TEST (host_processor_observer_pcr_test_on_recovery_error);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_dirty);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_not_dirty);
TEST (host_processor_observer_pcr_test_on_inactive_dirty_error);

/* Tear down after the tests in this suite have run. */
TEST (host_processor_observer_pcr_testing_suite_tear_down);

TEST_SUITE_END;
