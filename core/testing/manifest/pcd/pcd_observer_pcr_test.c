// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "attestation/pcr_store.h"
#include "common/array_size.h"
#include "manifest/pcd/pcd_observer_pcr.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/manifest_observer_pcr_testing.h"
#include "testing/manifest/pcd/pcd_testing.h"
#include "testing/mock/manifest/pcd/pcd_manager_mock.h"
#include "testing/mock/manifest/pcd/pcd_mock.h"


TEST_SUITE_LABEL ("pcd_observer_pcr");


/**
 * Hash for PCD_PLATFORM_ID, event type 0xaabbccdd, and version 0x0 for testing.
 */
static const uint8_t PCD_PLATFORM_ID_HASH[] = {
	0x7a, 0x79, 0xd3, 0x58, 0x6e, 0xe7, 0x63, 0xca, 0x9b, 0x43, 0xa1, 0x0f, 0xff, 0xbe, 0xa0, 0xc3,
	0x78, 0xe2, 0x42, 0x5c, 0x58, 0x13, 0x40, 0xe6, 0x7c, 0x5c, 0x61, 0x35, 0x3c, 0xf4, 0x26, 0x5f
};

/**
 * Length of the test PCD Platform ID hash.
 */
static const uint32_t PCD_PLATFORM_ID_HASH_LEN = sizeof (PCD_PLATFORM_ID_HASH);

/**
 * PCD_DATA hash digest using event type 0xaabbccdd and version 0x0 for testing.
 *
 * (printf "\xdd\xcc\xbb\xaa\x00"; cat pcd_hash.bin) | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_HASH_DIGEST[] = {
	0x53, 0xbf, 0x7a, 0x9d, 0xa9, 0x77, 0xf7, 0xb0, 0xed, 0x9c, 0x14, 0x38, 0xe8, 0xf9, 0xf5, 0x2b,
	0x33, 0xf4, 0xb4, 0xa1, 0x02, 0x30, 0x78, 0x83, 0x77, 0xdb, 0x4b, 0xa9, 0x84, 0x78, 0xdf, 0xf2
};


/*******************
 * Test cases
 *******************/

static void pcd_observer_pcr_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_pcd_verified);
	CuAssertPtrNotNull (test, observer.base.on_pcd_activated);
	CuAssertPtrNotNull (test, observer.base.on_clear_active);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (NULL, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCD_OBSERVER_INVALID_ARGUMENT, status);

	status = pcd_observer_pcr_init (&observer, NULL, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCD_OBSERVER_INVALID_ARGUMENT, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, NULL, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCD_OBSERVER_INVALID_ARGUMENT, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_init_bad_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 6),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 6), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_init_same_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCD_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 2), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, PCD_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, PCD_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 1),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 1));
	CuAssertIntEquals (test, PCD_OBSERVER_MEASUREMENTS_NOT_UNIQUE, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_release_null (CuTest *test)
{
	TEST_START;

	pcd_observer_pcr_release (NULL);
}

static void pcd_observer_pcr_test_on_pcd_activated (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	const uint8_t *platform_id = PCD_TESTING.manifest.plat_id;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0,
		MOCK_ARG_PTR (platform_id));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH_DIGEST, measurement.digest,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PCD_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_on_pcd_activated_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA384_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const uint8_t *platform_id = PCD_TESTING.manifest.plat_id;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA384_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, SHA384_HASH_LENGTH,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, &hash_out[5], SHA384_HASH_LENGTH, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0,
		MOCK_ARG_PTR (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PCD_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_on_pcd_activated_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA512_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const uint8_t *platform_id = PCD_TESTING.manifest.plat_id;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA512_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, SHA512_HASH_LENGTH,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, &hash_out[5], SHA512_HASH_LENGTH, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0,
		MOCK_ARG_PTR (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PCD_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_on_pcd_activated_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_on_pcd_activated_get_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH_DIGEST, measurement.digest,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_on_pcd_activated_get_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH_DIGEST, measurement.digest,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	const uint8_t *platform_id = PCD_TESTING.manifest.plat_id;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG_PTR (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0,
		MOCK_ARG_PTR (platform_id));

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH_DIGEST, measurement.digest,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PCD_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA384_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const uint8_t *platform_id = PCD_TESTING.manifest.plat_id;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA384_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG_PTR (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, SHA384_HASH_LENGTH,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, &hash_out[5], SHA384_HASH_LENGTH, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0,
		MOCK_ARG_PTR (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PCD_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t hash_out[5 + SHA512_HASH_LENGTH];
	uint8_t hash_measurement[SHA256_HASH_LENGTH];
	uint32_t id = 0x1;
	const uint8_t *platform_id = PCD_TESTING.manifest.plat_id;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	memcpy (hash_out, &event, sizeof (event));
	hash_out[4] = 0;
	memset (&hash_out[5], 0x55, SHA512_HASH_LENGTH);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG_PTR (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, SHA512_HASH_LENGTH,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, &hash_out[5], SHA512_HASH_LENGTH, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pcd.mock, 0, &platform_id, sizeof (platform_id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.free_platform_id, &pcd, 0,
		MOCK_ARG_PTR (platform_id));

	CuAssertIntEquals (test, 0, status);

	status = hash.base.calculate_sha256 (&hash.base, hash_out, sizeof (hash_out), hash_measurement,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (hash_measurement, measurement.digest,
		sizeof (hash_measurement));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_PLATFORM_ID_HASH, platform_id_measurement.digest,
		PCD_PLATFORM_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_no_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (NO_MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (EMPTY_STRING_HASH, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (NULL, &manager.base);

	pcd_observer_pcr_record_measurement (&observer, NULL);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG_PTR (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_get_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG_PTR (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH_DIGEST, measurement.digest,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_record_measurement_get_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t id = 0x1;
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager,
		MOCK_RETURN_PTR (&pcd));
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG_PTR (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, PCD_TESTING.manifest.hash_len,
		MOCK_ARG_PTR (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_TESTING.manifest.hash,
		PCD_TESTING.manifest.hash_len, 2);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_id, &pcd, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd.mock, 0, &id, sizeof (id), -1);

	status |= mock_expect (&pcd.mock, pcd.base.base.get_platform_id, &pcd, MANIFEST_GET_ID_FAILED,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_HASH_DIGEST, measurement.digest,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (MANIFEST_ID_HASH, id_measurement.digest, MANIFEST_ID_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_on_clear_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
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
	struct pcd_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcr_measurement id_measurement;
	struct pcr_measurement platform_id_measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 0), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 1), event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store, PCR_MEASUREMENT (0, 2), event);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0),
		PCR_MEASUREMENT (0, 1), PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_clear_active (&observer.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 1), &id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (NO_MANIFEST_ID_HASH, id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 2), &platform_id_measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (EMPTY_STRING_HASH, platform_id_measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


// *INDENT-OFF*
TEST_SUITE_START (pcd_observer_pcr);

TEST (pcd_observer_pcr_test_init);
TEST (pcd_observer_pcr_test_init_null);
TEST (pcd_observer_pcr_test_init_bad_measurement_type);
TEST (pcd_observer_pcr_test_init_same_measurement_type);
TEST (pcd_observer_pcr_test_release_null);
TEST (pcd_observer_pcr_test_on_pcd_activated);
TEST (pcd_observer_pcr_test_on_pcd_activated_sha384);
TEST (pcd_observer_pcr_test_on_pcd_activated_sha512);
TEST (pcd_observer_pcr_test_on_pcd_activated_hash_error);
TEST (pcd_observer_pcr_test_on_pcd_activated_get_id_error);
TEST (pcd_observer_pcr_test_on_pcd_activated_get_platform_id_error);
TEST (pcd_observer_pcr_test_record_measurement);
TEST (pcd_observer_pcr_test_record_measurement_sha384);
TEST (pcd_observer_pcr_test_record_measurement_sha512);
TEST (pcd_observer_pcr_test_record_measurement_no_active);
TEST (pcd_observer_pcr_test_record_measurement_null);
TEST (pcd_observer_pcr_test_record_measurement_hash_error);
TEST (pcd_observer_pcr_test_record_measurement_get_id_error);
TEST (pcd_observer_pcr_test_record_measurement_get_platform_id_error);
TEST (pcd_observer_pcr_test_on_clear_active);

TEST_SUITE_END;
// *INDENT-ON*
