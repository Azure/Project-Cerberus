// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "attestation/pcr.h"
#include "attestation/pcr_data.h"
#include "attestation/pcr_store.h"
#include "flash/flash.h"
#include "mock/hash_mock.h"
#include "mock/logging_mock.h"
#include "mock/flash_mock.h"


static const char *SUITE = "pcr";


/**
 * Helper function to setup for testing
 *
 * @param test The test framework
 * @param pcr PCR to initialize
 * @param hash The hashing engine to initialize
 * @param num_measurements Number of measurements to setup PCR to hold
 */
static void setup_pcr_mock_test (CuTest *test, struct pcr_bank *pcr, struct hash_engine_mock *hash,
	uint8_t num_measurements)
{
	int status;

	status = hash_mock_init (hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_init (pcr, num_measurements);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release mock instances
 *
 * @param test The test framework
 * @param pcr PCR bank to release
 * @param hash The hashing engine to release
 * @param logger The logger instance to release
 */
static void complete_pcr_mock_test (CuTest *test, struct pcr_bank *pcr,
	struct hash_engine_mock *hash)
{
	int status;

	status = hash_mock_validate_and_release (hash);
	CuAssertIntEquals (test, 0, status);

	pcr_release (pcr);
}

/**
 * Callback function to test callback based PCR measurement data.
 *
 * @param context The data to return from the callback.  It is assumed to be 4 bytes of data.
 * @param offset The offset for the requested data.
 * @param buffer Output buffer the data.
 * @param length Size of the output buffer.
 *
 * @return The number of bytes returned.
 */
static int pcr_test_measurement_data_callback (void *context, size_t offset, uint8_t *buffer,
	size_t length)
{
	int bytes = (4 - offset);

	if (context == NULL) {
		return PCR_NO_MEMORY;
	}

	if (bytes <= 0) {
		return 0;
	}

	bytes = (bytes <= length) ? bytes : length;
	memcpy (buffer, &((uint8_t*) context)[offset], bytes);

	return bytes;
}

/*******************
 * Test cases
 *******************/

static void pcr_test_init (CuTest *test)
{
	struct pcr_bank pcr;
	int status;

	TEST_START;

	status = pcr_init (&pcr, 5);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, pcr.num_measurements);
	CuAssertPtrNotNull (test, pcr.measurement_list);

	pcr_release (&pcr);
}

static void pcr_test_init_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	int status;

	TEST_START;

	status = pcr_init (&pcr, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, pcr.num_measurements);
	CuAssertPtrNotNull (test, pcr.measurement_list);

	pcr_release (&pcr);
}

static void pcr_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_init (NULL, 5);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_release_null (CuTest *test)
{
	TEST_START;

	pcr_release (NULL);
}

static void pcr_test_check_measurement_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_check_measurement_index (&pcr, 4);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_check_measurement_index_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_check_measurement_index (&pcr, 0);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_check_measurement_index_bad_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_check_measurement_index (&pcr, 5);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_check_measurement_index_bad_index_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_check_measurement_index (&pcr, 1);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_check_measurement_index_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_check_measurement_index (NULL, 4);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_update_digest (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_digest (&pcr, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, pcr.measurement_list[2].digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_digest_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, pcr.measurement_list[0].digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_digest_invalid_arg (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_digest (NULL, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_digest (&pcr, 2, NULL, sizeof (digest));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_digest (&pcr, 2, digest, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_digest_unsupported_algo (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = { 0xfc };
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_digest (&pcr, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_digest_invalid_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 1);

	status = pcr_update_digest (&pcr, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_buffer (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
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

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer, sizeof (buffer)), MOCK_ARG (sizeof (buffer)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr, &hash.base, 2, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, pcr.measurement_list[2].digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_buffer_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
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

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer, sizeof (buffer)), MOCK_ARG (sizeof (buffer)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr, &hash.base, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, pcr.measurement_list[0].digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_buffer_invalid_arg (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_buffer (NULL, &hash.base, 2, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_buffer (&pcr, NULL, 2, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_buffer (&pcr, &hash.base, 2, NULL, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_buffer (&pcr, &hash.base, 2, buffer, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_buffer_hash_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, -1,
		MOCK_ARG_PTR_CONTAINS (buffer, sizeof (buffer)), MOCK_ARG (sizeof (buffer)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr, &hash.base, 2, buffer, sizeof (buffer));
	CuAssertIntEquals (test, -1, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_buffer_update_digest_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
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

	setup_pcr_mock_test (test, &pcr, &hash, 1);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer, sizeof (buffer)), MOCK_ARG (sizeof (buffer)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr, &hash.base, 2, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_event_type (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_event_type (&pcr, 2, 0x0A);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0A, pcr.measurement_list[2].event_type);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_event_type_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_event_type (&pcr, 0, 0x0A);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0A, pcr.measurement_list[0].event_type);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_event_type_invalid_arg (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_event_type (NULL, 2, 0x0A);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_update_event_type_invalid_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 1);

	status = pcr_update_event_type (&pcr, 2, 0x0A);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer2[] = {
		0xe6,0xe6,0x91,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
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
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

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
		MOCK_ARG_PTR_CONTAINS (buffer2, sizeof (buffer2)), MOCK_ARG (sizeof (buffer2)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest3, sizeof (digest3), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 2, buffer2, sizeof (buffer2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, 3, status);

	status = testing_validate_array (digest3, measurement, sizeof (digest3));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t digest[] = {
		0x91,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (digest, measurement, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_no_lock (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer2[] = {
		0xe6,0xe6,0x91,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
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
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

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
		MOCK_ARG_PTR_CONTAINS (buffer2, sizeof (buffer2)), MOCK_ARG (sizeof (buffer2)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest3, sizeof (digest3), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 2, buffer2, sizeof (buffer2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_lock (&pcr);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, false);
	CuAssertIntEquals (test, 3, status);

	status = testing_validate_array (digest3, measurement, sizeof (digest3));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_no_out (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer2[] = {
		0xe6,0xe6,0x91,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
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
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

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
		MOCK_ARG_PTR_CONTAINS (buffer2, sizeof (buffer2)), MOCK_ARG (sizeof (buffer2)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest3, sizeof (digest3), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 2, buffer2, sizeof (buffer2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, NULL, true);
	CuAssertIntEquals (test, 3, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_no_valid_measurements (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t expected[PCR_DIGEST_LENGTH] = {
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e,
		0x91,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e
	};
	uint8_t digest[] = {
		0x7f,0xe6,0x9c,0x6f,0x7f,0x38,0x9d,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e,
		0x91,0xe6,0xe9,0x4f,0x48,0x1a,0x4f,0x8d,0x1d,0x3d,0xf6,0x5b,0x12,0xc7,0xe7,0x6e
	};;
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	int status;

	TEST_START;

	memset (expected, 0, sizeof (expected));
	memset (measurement, 1, sizeof (measurement));

	setup_pcr_mock_test (test, &pcr, &hash, 2);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest, sizeof (digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digest, sizeof (digest)), MOCK_ARG (sizeof (digest)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, expected, sizeof (expected), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, 2, status);

	status = testing_validate_array (expected, measurement, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_no_valid_measurements_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t expected[PCR_DIGEST_LENGTH] = {0};
	int status;

	TEST_START;

	memset (expected, 0, sizeof (expected));
	memset (measurement, 1, sizeof (measurement));

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (expected, measurement, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_invalid_arg (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 2);

	status = pcr_compute (NULL, &hash.base, measurement, true);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_compute (&pcr, NULL, measurement, true);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_start_hash_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_hash_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_extend_hash_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (buffer1, sizeof (buffer1)), MOCK_ARG (sizeof (buffer1)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_compute_finish_hash_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 3);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer1, sizeof (buffer1)), MOCK_ARG (sizeof (buffer1)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr, &hash.base, measurement, true);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_digest (&pcr, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr, 2, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr, 0, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_invalid_arg (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_get_measurement (NULL, 2, &measurement);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_measurement (&pcr, 2, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_invalid_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_get_measurement (&pcr, PCR_MEASUREMENT (0, 6), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_num_measurements (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_digest (&pcr, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_num_measurements (&pcr);
	CuAssertIntEquals (test, 5, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_num_measurements_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_num_measurements (&pcr);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_num_measurements_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_get_num_measurements (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_get_all_measurements (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measurement *measurement_list;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t digest1[] = {
		0x91,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 2);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr, 1, digest1, sizeof (digest1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr, (const uint8_t**) &measurement_list);
	CuAssertIntEquals (test, 2, status);

	status = testing_validate_array (digest, measurement_list[0].digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest1, measurement_list[1].digest, sizeof (digest1));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_all_measurements_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measurement *measurement_list;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr, (const uint8_t**) &measurement_list);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (digest, measurement_list[0].digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_all_measurements_invalid_arg (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t const *measurement_list;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_get_all_measurements (NULL, &measurement_list);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_all_measurements (&pcr, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_lock_then_unlock (CuTest *test)
{
	struct pcr_bank pcr;
	int status;

	TEST_START;

	status = pcr_init (&pcr, 1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_lock (&pcr);
	CuAssertIntEquals (test, 0, status);

	status = pcr_unlock (&pcr);
	CuAssertIntEquals (test, 0, status);

	status = pcr_lock (&pcr);
	CuAssertIntEquals (test, 0, status);

	status = pcr_unlock (&pcr);
	CuAssertIntEquals (test, 0, status);

	pcr_release (&pcr);
}

static void pcr_test_lock_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_lock (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_unlock_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_unlock (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_invalidate_measurement_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_update_digest (&pcr, 2, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr, 2, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_invalidate_measurement_index (&pcr, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr, 2, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_invalidate_measurement_index_explicit (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 0);

	status = pcr_update_digest (&pcr, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr, 0, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_invalidate_measurement_index (&pcr, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr, 0, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_invalidate_measurement_index_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_invalidate_measurement_index (NULL, 2);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_invalidate_measurement_index_bad_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_invalidate_measurement_index (&pcr, 5);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_set_measurement_data (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t data_mem[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (
		&data, (uint8_t*) &pcr.measurement_list[2].measured_data->data.value_1byte, 1);
	CuAssertIntEquals (test, 0, status);

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data_mem;
	measurement_data.data.memory.length = sizeof (data_mem);

	status = pcr_set_measurement_data (&pcr, 4, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (
		(uint8_t*) &data_mem, (uint8_t*) pcr.measurement_list[4].measured_data->data.memory.buffer,
		pcr.measurement_list[4].measured_data->data.memory.length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_set_measurement_data_null (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (NULL, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_set_measurement_data (&pcr, 2, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	memset (&measurement_data, 0, sizeof (measurement_data));

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_MEASURED_DATA_INVALID_MEMORY, status);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_MEASURED_DATA_INVALID_FLASH_DEVICE, status);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_MEASURED_DATA_INVALID_CALLBACK, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_set_measurement_data_bad_measurement_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 6, &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_set_measurement_data_bad_measurement_data_type (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = NUM_PCR_DATA_TYPE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_DATA_TYPE, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_1byte (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (&data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_1byte_zero_length (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[1];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, 0);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_1byte_invalid_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 1, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_2byte (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 2, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_2byte_with_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 1, buffer, length);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (((uint8_t*) &data + 1), buffer, 1);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_2byte_small_buffer (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[1];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (((uint8_t*) &data + 0), buffer, 1);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_2byte_small_buffer_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 1, buffer, 0);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_2byte_invalid_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 2, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_4byte (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 4, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_4byte_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 2, buffer, length);
	CuAssertIntEquals (test, 2, status);

	status = testing_validate_array (((uint8_t*) &data + 2), buffer, 2);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_4byte_small_buffer (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 2, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_4byte_small_buffer_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 1, buffer, length);
	CuAssertIntEquals (test, 2, status);

	status = testing_validate_array (((uint8_t*) &data + 1), buffer, 2);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_4byte_invalid_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 4, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_8byte (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 8, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, 8);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_8byte_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 2, buffer, length);
	CuAssertIntEquals (test, 6, status);

	status = testing_validate_array ((uint8_t*) &data + 2, buffer, 6);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_8byte_small_buffer (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_8byte_small_buffer_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_8byte_invalid_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 8, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_memory (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_memory_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 10, buffer, length);
	CuAssertIntEquals (test, (sizeof (data) - 10), status);

	status = testing_validate_array ((uint8_t*) &data + 10, buffer, (sizeof (data) - 10));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_memory_small_buffer (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[20];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_memory_small_buffer_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[20];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 12, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) &data + 12, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_memory_invalid_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, sizeof (data), buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_flash (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[32];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11223344),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_flash_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t offset = 15;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11223344 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - offset));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, offset, buffer, length);
	CuAssertIntEquals (test, sizeof (data) - offset, status);

	status = testing_validate_array ((uint8_t*) &data + offset, buffer, sizeof (data) - offset);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_flash_small_buffer (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[22];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11223344),
		MOCK_ARG_NOT_NULL, MOCK_ARG (length));
	status |= mock_expect_output (&flash.mock, 1, data, length, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_flash_small_buffer_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[22];
	size_t length = sizeof (buffer);
	size_t offset = 5;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11223344 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (length));
	status |= mock_expect_output (&flash.mock, 1, data + offset, length, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, offset, buffer, length);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array ((uint8_t*) &data + offset, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_flash_invalid_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t offset = 32;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 32;

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, offset, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_flash_read_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 32;

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_callback (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x12345678;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_test_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_callback_offset (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x12345678;
	uint8_t *data_addr = (uint8_t*) &data;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_test_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 2, buffer, length);
	CuAssertIntEquals (test, sizeof (data) - 2, status);

	status = testing_validate_array (data_addr + 2, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_callback_fail (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_test_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_null (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_get_measurement_data (NULL, 2, 0, buffer, length);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_measurement_data (&pcr, 2, 0, NULL, length);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_bad_measurement_index (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t buffer[1];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_get_measurement_data (&pcr, 6, 0, buffer, length);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_no_data (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	uint8_t buffer[1];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, 0, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}

static void pcr_test_get_measurement_data_bad_measurement_data_type (CuTest *test)
{
	struct pcr_bank pcr;
	struct hash_engine_mock hash;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	setup_pcr_mock_test (test, &pcr, &hash, 5);

	status = pcr_set_measurement_data (&pcr, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	pcr.measurement_list[2].measured_data->type = NUM_PCR_DATA_TYPE;

	status = pcr_get_measurement_data (&pcr, 2, 0, buffer, length);
	CuAssertIntEquals (test, PCR_INVALID_DATA_TYPE, status);

	complete_pcr_mock_test (test, &pcr, &hash);
}


CuSuite* get_pcr_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcr_test_init);
	SUITE_ADD_TEST (suite, pcr_test_init_explicit);
	SUITE_ADD_TEST (suite, pcr_test_init_null);
	SUITE_ADD_TEST (suite, pcr_test_release_null);
	SUITE_ADD_TEST (suite, pcr_test_check_measurement_index);
	SUITE_ADD_TEST (suite, pcr_test_check_measurement_index_explicit);
	SUITE_ADD_TEST (suite, pcr_test_check_measurement_index_bad_index);
	SUITE_ADD_TEST (suite, pcr_test_check_measurement_index_bad_index_explicit);
	SUITE_ADD_TEST (suite, pcr_test_check_measurement_index_null);
	SUITE_ADD_TEST (suite, pcr_test_update_digest);
	SUITE_ADD_TEST (suite, pcr_test_update_digest_explicit);
	SUITE_ADD_TEST (suite, pcr_test_update_digest_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_update_digest_unsupported_algo);
	SUITE_ADD_TEST (suite, pcr_test_update_digest_invalid_index);
	SUITE_ADD_TEST (suite, pcr_test_update_buffer);
	SUITE_ADD_TEST (suite, pcr_test_update_buffer_explicit);
	SUITE_ADD_TEST (suite, pcr_test_update_buffer_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_update_buffer_hash_fail);
	SUITE_ADD_TEST (suite, pcr_test_update_buffer_update_digest_fail);
	SUITE_ADD_TEST (suite, pcr_test_update_event_type);
	SUITE_ADD_TEST (suite, pcr_test_update_event_type_explicit);
	SUITE_ADD_TEST (suite, pcr_test_update_event_type_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_update_event_type_invalid_index);
	SUITE_ADD_TEST (suite, pcr_test_compute);
	SUITE_ADD_TEST (suite, pcr_test_compute_explicit);
	SUITE_ADD_TEST (suite, pcr_test_compute_no_lock);
	SUITE_ADD_TEST (suite, pcr_test_compute_no_out);
	SUITE_ADD_TEST (suite, pcr_test_compute_no_valid_measurements);
	SUITE_ADD_TEST (suite, pcr_test_compute_no_valid_measurements_explicit);
	SUITE_ADD_TEST (suite, pcr_test_compute_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_compute_start_hash_fail);
	SUITE_ADD_TEST (suite, pcr_test_compute_hash_fail);
	SUITE_ADD_TEST (suite, pcr_test_compute_extend_hash_fail);
	SUITE_ADD_TEST (suite, pcr_test_compute_finish_hash_fail);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_explicit);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_invalid_index);
	SUITE_ADD_TEST (suite, pcr_test_get_num_measurements);
	SUITE_ADD_TEST (suite, pcr_test_get_num_measurements_explicit);
	SUITE_ADD_TEST (suite, pcr_test_get_num_measurements_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_get_all_measurements);
	SUITE_ADD_TEST (suite, pcr_test_get_all_measurements_explicit);
	SUITE_ADD_TEST (suite, pcr_test_get_all_measurements_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_lock_then_unlock);
	SUITE_ADD_TEST (suite, pcr_test_lock_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_unlock_invalid_arg);
	SUITE_ADD_TEST (suite, pcr_test_invalidate_measurement_index);
	SUITE_ADD_TEST (suite, pcr_test_invalidate_measurement_index_explicit);
	SUITE_ADD_TEST (suite, pcr_test_invalidate_measurement_index_null);
	SUITE_ADD_TEST (suite, pcr_test_invalidate_measurement_index_bad_index);
	SUITE_ADD_TEST (suite, pcr_test_set_measurement_data);
	SUITE_ADD_TEST (suite, pcr_test_set_measurement_data_null);
	SUITE_ADD_TEST (suite, pcr_test_set_measurement_data_bad_measurement_index);
	SUITE_ADD_TEST (suite, pcr_test_set_measurement_data_bad_measurement_data_type);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_1byte);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_1byte_zero_length);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_1byte_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_2byte);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_2byte_with_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_2byte_small_buffer);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_2byte_small_buffer_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_2byte_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_4byte);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_4byte_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_4byte_small_buffer);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_4byte_small_buffer_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_4byte_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_8byte);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_8byte_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_8byte_small_buffer);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_8byte_small_buffer_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_8byte_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_memory);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_memory_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_memory_small_buffer);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_memory_small_buffer_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_memory_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_flash);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_flash_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_flash_small_buffer);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_flash_small_buffer_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_flash_invalid_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_flash_read_fail);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_callback);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_callback_offset);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_callback_fail);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_null);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_bad_measurement_index);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_no_data);
	SUITE_ADD_TEST (suite, pcr_test_get_measurement_data_bad_measurement_data_type);

	return suite;
}
