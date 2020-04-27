// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/cfm/cfm_observer_pcr.h"
#include "attestation/pcr_store.h"
#include "mock/cfm_mock.h"
#include "mock/cfm_manager_mock.h"
#include "engines/hash_testing_engine.h"
#include "cfm_testing.h"


static const char *SUITE = "cfm_observer_pcr";

/**
 * CFM_ID hash for testing.
 */
static const uint8_t CFM_ID_HASH[] = {
	0x67,0xab,0xdd,0x72,0x10,0x24,0xf0,0xff,0x4e,0x0b,0x3f,0x4c,0x2f,0xc1,0x3b,0xc5,
	0xba,0xd4,0x2d,0x0b,0x78,0x51,0xd4,0x56,0xd8,0x8d,0x20,0x3d,0x15,0xaa,0xa4,0x50
};

/**
 * Length of the test CFM ID hash.
 */
static const uint32_t CFM_ID_HASH_LEN = sizeof (CFM_ID_HASH);

/**
 * CFM_PLATFORM_ID hash for testing.
 */
static const uint8_t CFM_PLATFORM_ID_HASH[] = {
	0x3d,0xf8,0x0a,0x45,0x67,0xbc,0x96,0x19,0xa6,0x36,0x92,0xef,0x51,0x6b,0x29,0x82,
	0x0f,0xd7,0x84,0x2c,0xa8,0x96,0x47,0x6b,0x74,0x4a,0x2a,0x66,0xbe,0xad,0x7e,0x24
};

/**
 * Length of the test CFM Platform ID hash.
 */
static const uint32_t CFM_PLATFORM_ID_HASH_LEN = sizeof (CFM_PLATFORM_ID_HASH);


/*******************
 * Test cases
 *******************/

static void cfm_observer_pcr_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_cfm_verified);
	CuAssertPtrNotNull (test, observer.base.on_cfm_activated);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (NULL, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, CFM_OBSERVER_INVALID_ARGUMENT, status);

	status = cfm_observer_pcr_init (&observer, NULL, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, CFM_OBSERVER_INVALID_ARGUMENT, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, NULL, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, CFM_OBSERVER_INVALID_ARGUMENT, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_init_bad_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 6),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 6), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_init_same_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, CFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 2), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, CFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, CFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, CFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_release_null (CuTest *test)
{
	TEST_START;

	cfm_observer_pcr_release (NULL);
}

static void cfm_observer_pcr_test_on_cfm_activated (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	char *cfm_platform_id = "CFM Test1";
	char *platform_id;

	TEST_START;

	platform_id = platform_malloc (strlen (cfm_platform_id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, cfm_platform_id);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, CFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_ID_HASH, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		CFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_on_cfm_activated_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_on_cfm_activated_get_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_on_cfm_activated_get_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 1;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, CFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_ID_HASH, id_measurement.digest, CFM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_record_measurement (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	char *cfm_platform_id = "CFM Test1";
	char *platform_id;

	TEST_START;

	platform_id = platform_malloc (strlen (cfm_platform_id) + 1);
	CuAssertPtrNotNull (test, platform_id);

	strcpy (platform_id, cfm_platform_id);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, CFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_ID_HASH, id_measurement.digest, CFM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		CFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_record_measurement_no_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_record_measurement_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (NULL, &manager.base);

	cfm_observer_pcr_record_measurement (&observer, NULL);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_record_measurement_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_record_measurement_get_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_record_measurement_get_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct cfm_mock cfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 1;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_ID_HASH, id_measurement.digest, CFM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


CuSuite* get_cfm_observer_pcr_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_init);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_init_null);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_init_bad_measurement_type);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_init_same_measurement_type);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_release_null);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_on_cfm_activated);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_on_cfm_activated_hash_error);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_on_cfm_activated_get_id_error);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_on_cfm_activated_get_platform_id_error);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_no_active);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_null);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_hash_error);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_get_id_error);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_get_platform_id_error);

	return suite;
}
