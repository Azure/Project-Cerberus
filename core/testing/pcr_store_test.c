// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "attestation/pcr_store.h"
#include "mock/hash_mock.h"


static const char *SUITE = "pcr_store";


/**
 * Helper function to setup for testing
 *
 * @param test The test framework
 * @param store PCR store to initialize
 * @param hash The hashing engine to initialize
 * @param num_measurements0 Number of measurements to setup PCR 0 to hold
 * @param num_measurements1 Number of measurements to setup PCR 1 to hold
 */
static void setup_pcr_store_mock_test (CuTest *test, struct pcr_store *store,
	struct hash_engine_mock *hash, uint8_t num_measurements0, uint8_t num_measurements1)
{
	int status;
	uint8_t num_pcr_measurements[2] = {num_measurements0, num_measurements1};

	status = hash_mock_init (hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release mock instances

 * @param test The test framework
 * @param store PCR store to release
 * @param hash The hashing engine to release
 */
static void complete_pcr_store_mock_test (CuTest *test, struct pcr_store *store,
	struct hash_engine_mock *hash)
{
	int status;

	status = hash_mock_validate_and_release (hash);
	CuAssertIntEquals (test, 0, status);

	pcr_store_release (store);
}

/*******************
 * Test cases
 *******************/

static void pcr_store_test_init (CuTest *test)
{
	struct pcr_store store;
	uint8_t num_pcr_measurements[2] = {6, 6};
	int status;

	TEST_START;

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	pcr_store_release (&store);
}

static void pcr_store_test_init_explicit (CuTest *test)
{
	struct pcr_store store;
	uint8_t num_pcr_measurements[2] = {6, 0};
	int status;

	TEST_START;

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	pcr_store_release (&store);
}

static void pcr_store_test_init_invalid_arg (CuTest *test)
{
	struct pcr_store store;
	uint8_t num_pcr_measurements[2] = {6, 6};
	int status;

	TEST_START;

	status = pcr_store_init (NULL, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_init (&store, NULL, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_init (&store, num_pcr_measurements, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_release_null (CuTest *test)
{
	TEST_START;

	pcr_store_release (NULL);
}

static void pcr_store_test_check_measurement_type (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_check_measurement_type (&store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_check_measurement_type_explicit (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 0);

	status = pcr_store_check_measurement_type (&store, PCR_MEASUREMENT (1, 0));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_check_measurement_type_bad_bank (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_check_measurement_type (&store, PCR_MEASUREMENT (2, 0));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_check_measurement_type_bad_index (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_check_measurement_type (&store, PCR_MEASUREMENT (1, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_check_measurement_type_bad_index_explicit (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 0);

	status = pcr_store_check_measurement_type (&store, PCR_MEASUREMENT (1, 1));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_check_measurement_type_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_check_measurement_type (NULL, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_update_digest (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 1), digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&store.banks[1], 1, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_update_digest_invalid_arg (CuTest *test)
{
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	status = pcr_store_update_digest (NULL, 5, digest, sizeof (digest));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_update_digest_invalid_pcr (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_digest (&store, (((uint16_t)4 << 8) | 1), digest, sizeof (digest));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_update_digest_update_fail (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_digest (&store, (((uint16_t)1 << 8) | 10), digest, sizeof (digest));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_update_buffer (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t digest[] = {
		0x38,0x38,0x38,0x4f,0x7f,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0xfc
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer, sizeof (buffer)), MOCK_ARG (sizeof (buffer)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store, &hash.base, 5, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&store.banks[0], 5, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_update_buffer_invalid_arg (CuTest *test)
{
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 0);

	status = pcr_store_update_buffer (NULL, &hash.base, 5, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_update_buffer_invalid_pcr (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_buffer (&store, &hash.base, (((uint16_t)4 << 8) | 1), buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_update_buffer_update_fail (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (buffer, sizeof (buffer)), MOCK_ARG (sizeof (buffer)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store, &hash.base, 5, buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_compute (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint8_t digest1[] = {
		0x91,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
	uint8_t digest2[] = {
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e,
		0x91,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e
	};
	uint8_t digest3[] = {
		0x7f,0xe6,0x9c,0x6f,0x7f,0x38,0x9d,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e,
		0x91,0xe6,0xe9,0x4f,0x48,0x1a,0x4f,0x8d,0x1d,0x3d,0xf6,0x5b,0x12,0xc7,0xe7,0x6e
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 0);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer1, sizeof (buffer1)), MOCK_ARG (sizeof (buffer1)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest1, sizeof (digest1), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digest1, sizeof (digest1)), MOCK_ARG (sizeof (digest1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (invalid_measurement, sizeof (invalid_measurement)),
		MOCK_ARG (sizeof (invalid_measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest2, sizeof (digest2), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digest2, sizeof (digest2)), MOCK_ARG (sizeof (digest2)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (invalid_measurement, sizeof (invalid_measurement)),
		MOCK_ARG (sizeof (invalid_measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest3, sizeof (digest3), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute (&store, &hash.base, 0, measurement);
	CuAssertIntEquals (test, 3, status);

	status = testing_validate_array (digest3, measurement, sizeof (digest3));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_compute_explicit (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t digest[] = {
		0x91,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 0);

	status = pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 0), digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute (&store, &hash.base, 1, measurement);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (digest, measurement, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_compute_invalid_arg (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 0);

	status = pcr_store_compute (NULL, &hash.base, 0, measurement);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_compute_compute_fail (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 0);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute (&store, &hash.base, 0, measurement);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_compute_invalid_pcr (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 2, 0);

	status = pcr_store_compute (&store, &hash.base, 4, measurement);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_measurement (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 1), digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_measurement_invalid_arg (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_get_measurement (NULL, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 1), NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_measurement_invalid_pcr (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (2, 0), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_measurement_fail (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 6), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_num_banks (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 1), digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_num_banks_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_get_num_banks (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_get_tcg_log_size (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_get_tcg_log_size (&store);
	CuAssertIntEquals (test, 12 * sizeof (struct pcr_store_tcg_log_entry), status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_size_explicit (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 0);

	status = pcr_store_get_tcg_log_size (&store);
	CuAssertIntEquals (test, 6 * sizeof (struct pcr_store_tcg_log_entry), status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_size_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_get_tcg_log_size (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_get_tcg_log (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, (uint8_t*) buf, sizeof (buf));
	CuAssertIntEquals (test, 6 * sizeof (struct pcr_store_tcg_log_entry), status);

	status = testing_validate_array ((uint8_t*) exp_buf, (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_invalid_entry (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 2; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, (uint8_t*) buf, sizeof (buf));
	CuAssertIntEquals (test, 6 * sizeof (struct pcr_store_tcg_log_entry), status);

	status = testing_validate_array ((uint8_t*) exp_buf, (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_explicit (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		exp_buf[i_measurement].entry.measurement_index = i_measurement;
		exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 0);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 0), digests[3], PCR_DIGEST_LENGTH);

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, (uint8_t*) buf, sizeof (buf));
	CuAssertIntEquals (test, 3 * sizeof (struct pcr_store_tcg_log_entry), status);

	status = testing_validate_array ((uint8_t*) exp_buf, (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_non_zero_offset (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, 3 * sizeof (struct pcr_store_tcg_log_entry),
		(uint8_t*) buf, 6 * sizeof (struct pcr_store_tcg_log_entry));
	CuAssertIntEquals (test, 3 * sizeof (struct pcr_store_tcg_log_entry), status);

	status = testing_validate_array ((uint8_t*) &exp_buf[3], (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_partial_measurement (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base,
		2 * sizeof (struct pcr_store_tcg_log_entry) + 5, (uint8_t*) buf,
		6 * sizeof (struct pcr_store_tcg_log_entry));
	CuAssertIntEquals (test, 4 * sizeof (struct pcr_store_tcg_log_entry) - 5, status);

	status = testing_validate_array (((uint8_t*) &exp_buf[2]) + 5, (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_small_buffer (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, (uint8_t*) buf,
		sizeof (struct pcr_store_tcg_log_entry));
	CuAssertIntEquals (test, sizeof (struct pcr_store_tcg_log_entry), status);

	status = testing_validate_array ((uint8_t*) exp_buf, (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_small_buffer_not_entry_aligned (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, (uint8_t*) buf,
		sizeof (struct pcr_store_tcg_log_entry) + 10);
	CuAssertIntEquals (test, sizeof (struct pcr_store_tcg_log_entry) + 10, status);

	status = testing_validate_array ((uint8_t*) exp_buf, (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_small_buffer_nonzero_offset (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, sizeof (struct pcr_store_tcg_log_entry),
		(uint8_t*) buf, 3 * sizeof (struct pcr_store_tcg_log_entry));
	CuAssertIntEquals (test, 3 * sizeof (struct pcr_store_tcg_log_entry), status);

	status = testing_validate_array ((uint8_t*) &exp_buf[1], (uint8_t*) buf, status);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_invalid_offset (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	struct pcr_store_tcg_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		}
	};
	int i_measurement;
	int status;

	TEST_START;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));

		if (i_measurement >= 3) {
			exp_buf[i_measurement].entry.measurement_index = i_measurement - 3;
			exp_buf[i_measurement].entry.measurement_type =
				PCR_MEASUREMENT (1, (i_measurement - 3));
		}
		else {
			exp_buf[i_measurement].entry.measurement_index = i_measurement;
			exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);
		}
	}

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (0, i_measurement), digests[i_measurement],
			PCR_DIGEST_LENGTH);
	}

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		pcr_store_update_digest (&store, PCR_MEASUREMENT (1, i_measurement),
			digests[3 + i_measurement], PCR_DIGEST_LENGTH);
	}

	status = pcr_store_get_tcg_log (&store, &hash.base, 6 * sizeof (struct pcr_store_tcg_log_entry),
		(uint8_t*) buf, 6 * sizeof (struct pcr_store_tcg_log_entry));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_invalid_arg (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = pcr_store_get_tcg_log (NULL, &hash.base, 0, (uint8_t*)buf, 1);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_tcg_log (&store, NULL, 0, (uint8_t*)buf, 1);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, NULL, 1);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_get_tcg_log_compute_fail (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_store_tcg_log_entry buf[6];
	uint8_t digest[] = {
		0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 3, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	pcr_store_update_digest (&store, PCR_MEASUREMENT (0, 0), digest, PCR_DIGEST_LENGTH);

	status = pcr_store_get_tcg_log (&store, &hash.base, 0, (uint8_t*)buf,
		6 * sizeof (struct pcr_store_tcg_log_entry));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_invalidate_measurement (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 1), digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_invalidate_measurement (&store, PCR_MEASUREMENT (1, 1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_invalidate_measurement_explicit (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 0);

	status = pcr_store_update_digest (&store, PCR_MEASUREMENT (1, 0), digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);
	status = pcr_store_invalidate_measurement (&store, PCR_MEASUREMENT (1, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (1, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_invalidate_measurement_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_invalidate_measurement (NULL, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_invalidate_measurement_invalid_pcr (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_invalidate_measurement (&store, PCR_MEASUREMENT (4, 1));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}

static void pcr_store_test_invalidate_measurement_bad_index (CuTest *test)
{
	struct pcr_store store;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_store_mock_test (test, &store, &hash, 6, 6);

	status = pcr_store_invalidate_measurement (&store, PCR_MEASUREMENT (1, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_store_mock_test (test, &store, &hash);
}


CuSuite* get_pcr_store_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcr_store_test_init);
	SUITE_ADD_TEST (suite, pcr_store_test_init_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_init_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_release_null);
	SUITE_ADD_TEST (suite, pcr_store_test_check_measurement_type);
	SUITE_ADD_TEST (suite, pcr_store_test_check_measurement_type_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_check_measurement_type_bad_bank);
	SUITE_ADD_TEST (suite, pcr_store_test_check_measurement_type_bad_index);
	SUITE_ADD_TEST (suite, pcr_store_test_check_measurement_type_bad_index_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_check_measurement_type_null);
	SUITE_ADD_TEST (suite, pcr_store_test_update_digest);
	SUITE_ADD_TEST (suite, pcr_store_test_update_digest_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_update_digest_invalid_pcr);
	SUITE_ADD_TEST (suite, pcr_store_test_update_digest_update_fail);
	SUITE_ADD_TEST (suite, pcr_store_test_update_buffer);
	SUITE_ADD_TEST (suite, pcr_store_test_update_buffer_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_update_buffer_invalid_pcr);
	SUITE_ADD_TEST (suite, pcr_store_test_update_buffer_update_fail);
	SUITE_ADD_TEST (suite, pcr_store_test_compute);
	SUITE_ADD_TEST (suite, pcr_store_test_compute_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_compute_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_compute_invalid_pcr);
	SUITE_ADD_TEST (suite, pcr_store_test_compute_compute_fail);
	SUITE_ADD_TEST (suite, pcr_store_test_get_measurement);
	SUITE_ADD_TEST (suite, pcr_store_test_get_measurement_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_get_measurement_invalid_pcr);
	SUITE_ADD_TEST (suite, pcr_store_test_get_measurement_fail);
	SUITE_ADD_TEST (suite, pcr_store_test_get_num_banks);
	SUITE_ADD_TEST (suite, pcr_store_test_get_num_banks_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_size);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_size_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_size_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_invalid_entry);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_non_zero_offset);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_partial_measurement);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_small_buffer);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_small_buffer_not_entry_aligned);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_small_buffer_nonzero_offset);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_store_test_get_tcg_log_compute_fail);
	SUITE_ADD_TEST (suite, pcr_store_test_invalidate_measurement);
	SUITE_ADD_TEST (suite, pcr_store_test_invalidate_measurement_explicit);
	SUITE_ADD_TEST (suite, pcr_store_test_invalidate_measurement_null);
	SUITE_ADD_TEST (suite, pcr_store_test_invalidate_measurement_invalid_pcr);
	SUITE_ADD_TEST (suite, pcr_store_test_invalidate_measurement_bad_index);

	return suite;
}
