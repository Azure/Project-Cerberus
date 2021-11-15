// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_observer_pcr.h"
#include "attestation/pcr_store.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/pfm_testing.h"
#include "testing/manifest/manifest_observer_pcr_testing.h"


TEST_SUITE_LABEL ("pfm_observer_pcr");


/**
 * Hash for PFM platform ID PFM_PLATFORM_ID, event type 0xaabbccdd, and version 0x0 for testing.
 */
static const uint8_t PFM_PLATFORM_ID_HASH[] = {
	0x5e,0x29,0x9f,0x2e,0x68,0x12,0x44,0x62,0x8c,0x51,0x7c,0x9a,0x21,0x0e,0x26,0x93,
	0x69,0x2b,0x08,0x64,0x5b,0xbb,0x84,0x5c,0x00,0x94,0x65,0x54,0xca,0xb8,0x14,0xdc
};

/**
 * Length of the test PFM Platform ID hash.
 */
static const uint32_t PFM_PLATFORM_ID_HASH_LEN = sizeof (PFM_PLATFORM_ID_HASH);


/*******************
 * Test cases
 *******************/

static void pfm_observer_pcr_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_pfm_verified);
	CuAssertPtrNotNull (test, observer.base.on_pfm_activated);
	CuAssertPtrNotNull (test, observer.base.on_clear_active);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (NULL, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	status = pfm_observer_pcr_init (&observer, NULL, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, NULL, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_init_bad_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 6),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (1, 7), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 2), PCR_MEASUREMENT (0, 7));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_init_same_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (1, 0), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, PFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 2), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, PFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, PFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_release_null (CuTest *test)
{
	TEST_START;

	pfm_observer_pcr_release (NULL);
}

static void pfm_observer_pcr_test_on_pfm_activated (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement manifest_measurement;
	struct pcr_measurement manifest_id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_manifest_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	const char *platform_id = PFM_PLATFORM_ID;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &manifest_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, manifest_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &manifest_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, manifest_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated (&observer.base, &pfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &manifest_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH_DIGEST, manifest_measurement.digest, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &manifest_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, manifest_id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_on_pfm_activated_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement manifest_measurement;
	struct pcr_measurement manifest_id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_manifest_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA384_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const char *platform_id = PFM_PLATFORM_ID;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &manifest_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, manifest_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &manifest_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, manifest_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SHA384_HASH_LENGTH,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, &hash_out[5], SHA384_HASH_LENGTH, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated (&observer.base, &pfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &manifest_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_measurement, manifest_measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &manifest_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, manifest_id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_on_pfm_activated_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement manifest_measurement;
	struct pcr_measurement manifest_id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_manifest_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA512_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const char *platform_id = PFM_PLATFORM_ID;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &manifest_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, manifest_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &manifest_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, manifest_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_manifest_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SHA512_HASH_LENGTH,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, &hash_out[5], SHA512_HASH_LENGTH, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated (&observer.base, &pfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &manifest_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_measurement, manifest_measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &manifest_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, manifest_id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_on_pfm_activated_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated (&observer.base, &pfm.base);

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

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_on_pfm_activated_get_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated (&observer.base, &pfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH_DIGEST, measurement.digest, PFM_HASH_LEN);
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

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_on_pfm_activated_get_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pfm_activated (&observer.base, &pfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH_DIGEST, measurement.digest, PFM_HASH_LEN);
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

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	const char *platform_id = PFM_PLATFORM_ID;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH_DIGEST, measurement.digest, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest,
		MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA384_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const char *platform_id = PFM_PLATFORM_ID;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SHA384_HASH_LENGTH,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, &hash_out[5], SHA384_HASH_LENGTH, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

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

	status = testing_validate_array (PFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA512_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const char *platform_id = PFM_PLATFORM_ID;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, SHA512_HASH_LENGTH,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, &hash_out[5], SHA512_HASH_LENGTH, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

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

	status = testing_validate_array (PFM_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PFM_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_no_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
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

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (NO_MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (EMPTY_STRING_HASH, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	pfm_observer_pcr_record_measurement (NULL, &manager.base);

	pfm_observer_pcr_record_measurement (&observer, NULL);

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

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

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

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_get_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH_DIGEST, measurement.digest, PFM_HASH_LEN);
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

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_record_measurement_get_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pfm_mock pfm;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
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

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);
	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_hash, &pfm, PFM_HASH_LEN, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.mock, 1, PFM_HASH, PFM_HASH_LEN, 2);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_HASH_DIGEST, measurement.digest, PFM_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_observer_pcr_test_on_clear_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pfm_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pfm_manager_mock manager;
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

	status = pfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
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

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (EMPTY_STRING_HASH, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


TEST_SUITE_START (pfm_observer_pcr);

TEST (pfm_observer_pcr_test_init);
TEST (pfm_observer_pcr_test_init_null);
TEST (pfm_observer_pcr_test_init_bad_measurement_type);
TEST (pfm_observer_pcr_test_init_same_measurement_type);
TEST (pfm_observer_pcr_test_release_null);
TEST (pfm_observer_pcr_test_on_pfm_activated);
TEST (pfm_observer_pcr_test_on_pfm_activated_sha384);
TEST (pfm_observer_pcr_test_on_pfm_activated_sha512);
TEST (pfm_observer_pcr_test_on_pfm_activated_hash_error);
TEST (pfm_observer_pcr_test_on_pfm_activated_get_id_error);
TEST (pfm_observer_pcr_test_on_pfm_activated_get_platform_id_error);
TEST (pfm_observer_pcr_test_record_measurement);
TEST (pfm_observer_pcr_test_record_measurement_sha384);
TEST (pfm_observer_pcr_test_record_measurement_sha512);
TEST (pfm_observer_pcr_test_record_measurement_no_active);
TEST (pfm_observer_pcr_test_record_measurement_null);
TEST (pfm_observer_pcr_test_record_measurement_hash_error);
TEST (pfm_observer_pcr_test_record_measurement_get_id_error);
TEST (pfm_observer_pcr_test_record_measurement_get_platform_id_error);
TEST (pfm_observer_pcr_test_on_clear_active);

TEST_SUITE_END;
