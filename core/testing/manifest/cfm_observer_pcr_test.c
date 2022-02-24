// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/cfm/cfm_observer_pcr.h"
#include "attestation/pcr_store.h"
#include "testing/mock/manifest/cfm_mock.h"
#include "testing/mock/manifest/cfm_manager_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/cfm_testing.h"
#include "testing/manifest/manifest_observer_pcr_testing.h"


TEST_SUITE_LABEL ("cfm_observer_pcr");


/**
 * Hash for CFM platform ID "CFM Test1", event type 0xaabbccdd, and version 0x0 for testing.
 */
static const uint8_t CFM_PLATFORM_ID_HASH[] = {
	0xe8,0xe0,0xf5,0x96,0x6a,0x87,0x44,0xf0,0x74,0x24,0xaa,0xec,0x0d,0xcb,0xac,0xc6,
	0x32,0xce,0x3f,0xe3,0x6b,0x55,0xe8,0xd7,0x19,0x6f,0x15,0xb3,0x69,0x53,0x87,0xbb
};

/**
 * Length of the test CFM Platform ID hash.
 */
static const uint32_t CFM_PLATFORM_ID_HASH_LEN = sizeof (CFM_PLATFORM_ID_HASH);

/**
 * CFM_DATA hash digest for testing.
 */
const uint8_t CFM_HASH_DIGEST[] = {
	0x8a,0xfd,0xac,0x0f,0x82,0x6a,0x88,0x25,0x30,0x92,0x98,0xbd,0xc1,0x40,0xda,0xad,
	0xa1,0x96,0x8e,0x56,0xc0,0x9a,0x3d,0x02,0x7f,0xf6,0xe7,0xbc,0xc0,0xfe,0xd3,0x5a
};


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
	CuAssertPtrNotNull (test, observer.base.on_clear_active);

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
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash,
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &cfm_platform_id, sizeof (cfm_platform_id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0,
		MOCK_ARG (cfm_platform_id));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH_DIGEST, measurement.digest,
		CFM_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
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

static void cfm_observer_pcr_test_on_cfm_activated_sha384 (CuTest *test)
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
	uint8_t hash_out[5 + SHA384_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	char *cfm_platform_id = "CFM Test1";
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA384_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, SHA384_HASH_LENGTH,
		MOCK_ARG (&hash),  MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, &hash_out[5], SHA384_HASH_LENGTH, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &cfm_platform_id, sizeof (cfm_platform_id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0,
		MOCK_ARG (cfm_platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
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

static void cfm_observer_pcr_test_on_cfm_activated_sha512 (CuTest *test)
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
	uint8_t hash_out[5 + SHA512_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	char *cfm_platform_id = "CFM Test1";
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA512_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, SHA512_HASH_LENGTH,
		MOCK_ARG (&hash),  MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, &hash_out[5], SHA512_HASH_LENGTH, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &cfm_platform_id, sizeof (cfm_platform_id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0,
		MOCK_ARG (cfm_platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
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
	uint32_t event = 0xaabbccdd;

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

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash,
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH_DIGEST, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
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
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash,
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH_DIGEST, measurement.digest,
		CFM_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
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
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash,
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &cfm_platform_id, sizeof (cfm_platform_id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0,
		MOCK_ARG (cfm_platform_id));

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH_DIGEST, measurement.digest,
		CFM_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
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

static void cfm_observer_pcr_test_record_measurement_sha384 (CuTest *test)
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
	uint8_t hash_out[5 + SHA384_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	char *cfm_platform_id = "CFM Test1";
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA384_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, SHA384_HASH_LENGTH,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, &hash_out[5], SHA384_HASH_LENGTH, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &cfm_platform_id, sizeof (cfm_platform_id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0,
		MOCK_ARG (cfm_platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
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

static void cfm_observer_pcr_test_record_measurement_sha512 (CuTest *test)
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
	uint8_t hash_out[5 + SHA512_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	char *cfm_platform_id = "CFM Test1";
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA512_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, SHA512_HASH_LENGTH,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, &hash_out[5], SHA512_HASH_LENGTH, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&cfm.mock, 0, &cfm_platform_id, sizeof (cfm_platform_id), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.free_platform_id, &cfm, 0,
		MOCK_ARG (cfm_platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
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
	struct pcr_measurement component_id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &component_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, component_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (NO_MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &component_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (EMPTY_STRING_HASH, component_id_measurement.digest,
		SHA256_HASH_LENGTH);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (NULL, &manager.base);

	cfm_observer_pcr_record_measurement (&observer, NULL);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
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
	uint32_t event = 0xaabbccdd;

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

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash,
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH_DIGEST, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
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
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, CFM_TESTING.manifest.hash_len,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_TESTING.manifest.hash,
		CFM_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_id, &cfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm.mock, 0, &id, sizeof (uint32_t), -1);

	status |= mock_expect (&cfm.mock, cfm.base.base.get_platform_id, &cfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH_DIGEST, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void cfm_observer_pcr_test_on_clear_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct cfm_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement component_id_measurement;
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 2, event);
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

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &component_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, component_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_clear_active (&observer.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (NO_MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &component_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (EMPTY_STRING_HASH, component_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


TEST_SUITE_START (cfm_observer_pcr);

TEST (cfm_observer_pcr_test_init);
TEST (cfm_observer_pcr_test_init_null);
TEST (cfm_observer_pcr_test_init_bad_measurement_type);
TEST (cfm_observer_pcr_test_init_same_measurement_type);
TEST (cfm_observer_pcr_test_release_null);
TEST (cfm_observer_pcr_test_on_cfm_activated);
TEST (cfm_observer_pcr_test_on_cfm_activated_sha384);
TEST (cfm_observer_pcr_test_on_cfm_activated_sha512);
TEST (cfm_observer_pcr_test_on_cfm_activated_hash_error);
TEST (cfm_observer_pcr_test_on_cfm_activated_get_id_error);
TEST (cfm_observer_pcr_test_on_cfm_activated_get_platform_id_error);
TEST (cfm_observer_pcr_test_record_measurement);
TEST (cfm_observer_pcr_test_record_measurement_sha384);
TEST (cfm_observer_pcr_test_record_measurement_sha512);
TEST (cfm_observer_pcr_test_record_measurement_no_active);
TEST (cfm_observer_pcr_test_record_measurement_null);
TEST (cfm_observer_pcr_test_record_measurement_hash_error);
TEST (cfm_observer_pcr_test_record_measurement_get_id_error);
TEST (cfm_observer_pcr_test_record_measurement_get_platform_id_error);
TEST (cfm_observer_pcr_test_on_clear_active);

TEST_SUITE_END;
