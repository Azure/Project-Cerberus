// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_processor_observer_pcr.h"
#include "host_fw/host_logging.h"
#include "attestation/pcr_store.h"
#include "mock/hash_mock.h"
#include "mock/logging_mock.h"
#include "engines/hash_testing_engine.h"


static const char *SUITE = "host_processor_observer_pcr";

/**
 * Digest of the number 0.  This indicates valid FW in active mode.
 */
static const uint8_t DIGEST_ZERO[] = {
	0x47,0x40,0x56,0x46,0xe6,0x3c,0x9f,0x11,0xb4,0xc9,0xc5,0x80,0x03,0x82,0x7f,0xdb,
	0x51,0x14,0xfa,0x50,0x1e,0xab,0x92,0xe5,0xf0,0xc1,0xc4,0xb5,0x0b,0xc0,0x2d,0x8b
};

/**
 * Digest of the state indicating bypass mode.
 */
static const uint8_t DIGEST_BYPASS[] = {
	0xb1,0xde,0x2f,0x62,0x8f,0xb6,0x8c,0x28,0xc1,0x2b,0x1f,0xee,0xad,0x61,0xe6,0x0c,
	0x5a,0x4b,0x0b,0x20,0x49,0xa9,0x12,0x34,0x82,0x72,0x62,0xf2,0x12,0x3c,0xa4,0xb0
};

/**
 * Digest of the state indicating recovery mode.
 */
static const uint8_t DIGEST_RECOVERY[] = {
	0xfa,0xb6,0x6f,0x51,0x96,0x05,0x96,0x9a,0x1a,0xa0,0xd2,0x87,0x00,0xee,0x25,0x84,
	0x8a,0x27,0x39,0x80,0xe2,0xcc,0x45,0xda,0x53,0x2d,0xb3,0xad,0xc8,0xc0,0xf7,0x37
};

/**
 * Digest of the initial state.
 */
static const uint8_t DIGEST_INIT[] = {
	0x8f,0xce,0x49,0xc6,0x07,0xe3,0xf4,0xad,0x60,0x9f,0x37,0xb3,0xc8,0x7f,0x31,0xd9,
	0x53,0x25,0xc4,0xe5,0xb7,0x6d,0x49,0x9e,0x9a,0x4a,0x95,0x5b,0x51,0x64,0x3f,0x30
};


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

	status = testing_validate_array (DIGEST_ZERO, measurement.digest, SHA256_HASH_LENGTH);
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
	struct pcr_measurement measurement;
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
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, sizeof (entry)), MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base.on_bypass_mode (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_BYPASS, state);

	debug_log = NULL;

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

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

	status = testing_validate_array (DIGEST_ZERO, measurement.digest, SHA256_HASH_LENGTH);
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
	struct pcr_measurement measurement;
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
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, sizeof (entry)), MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base.on_active_mode (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_VALID, state);

	debug_log = NULL;

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

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
	struct pcr_measurement measurement;
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
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, sizeof (entry)), MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	observer.base.on_recovery (&observer.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_OBSERVER_PCR_RECOVERY, state);

	debug_log = NULL;

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	host_processor_observer_pcr_release (&observer);

	pcr_store_release (&store);
}


CuSuite* get_host_processor_observer_pcr_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_init);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_init_valid);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_init_null);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_init_invalid_measurement);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_on_bypass_mode);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_on_bypass_mode_error);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_on_active_mode);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_on_active_mode_error);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_on_recovery);
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_test_on_recovery_error);

	/* Tear down after the tests in this suite have run. */
	SUITE_ADD_TEST (suite, host_processor_observer_pcr_testing_suite_tear_down);
	return suite;
}
