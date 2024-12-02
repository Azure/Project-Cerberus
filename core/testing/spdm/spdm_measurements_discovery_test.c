// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "common/array_size.h"
#include "spdm/spdm_discovery.h"
#include "spdm/spdm_measurements_discovery.h"
#include "spdm/spdm_measurements_discovery_static.h"
#include "testing/attestation/pcr_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"


TEST_SUITE_LABEL ("spdm_measurements_discovery");


/**
 * SHA-256 hash of the device ID measurement data.
 */
const uint8_t SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256[] = {
	0x3c, 0xd8, 0x1b, 0x49, 0x95, 0xa8, 0x16, 0x45, 0x82, 0xd1, 0x08, 0x68, 0xc3, 0x2f, 0xca, 0x38,
	0x1f, 0xfc, 0x8f, 0xf2, 0x99, 0xf4, 0xbe, 0x32, 0x04, 0x28, 0xbd, 0x29, 0x95, 0xe5, 0x8f, 0x8c
};

/**
 * SHA-384 hash of the device ID measurement data.
 */
const uint8_t SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA384[] = {
	0x22, 0xcf, 0xac, 0xa3, 0xd9, 0x5f, 0xb5, 0x46, 0x9c, 0xfc, 0x44, 0xe5, 0x0f, 0x01, 0x44, 0x98,
	0xf7, 0x57, 0x5d, 0x06, 0xec, 0xe0, 0xe0, 0xa3, 0x0f, 0x78, 0x84, 0x63, 0x48, 0xa4, 0xfe, 0x59,
	0x0e, 0x5c, 0xfd, 0x60, 0x04, 0x3f, 0xaa, 0x4f, 0x40, 0x6f, 0xb3, 0x8c, 0xe5, 0xd4, 0xa4, 0xf4
};

/**
 * SHA-512 hash of the device ID measurement data.
 */
const uint8_t SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA512[] = {
	0x2f, 0xfe, 0x09, 0x66, 0xf8, 0xaf, 0x53, 0x14, 0x5e, 0x21, 0x32, 0x8f, 0xdc, 0xe5, 0xf6, 0x6a,
	0xf0, 0x4e, 0x16, 0x23, 0x51, 0x3e, 0x8e, 0xa6, 0x93, 0x12, 0x63, 0x87, 0x85, 0xb8, 0x0c, 0x21,
	0x95, 0x27, 0x40, 0x0b, 0xb5, 0x4c, 0x47, 0x55, 0xd1, 0x85, 0xba, 0xb8, 0x47, 0x7d, 0x12, 0x8f,
	0xb2, 0x01, 0x44, 0xfe, 0xb7, 0x51, 0xb1, 0xbd, 0x95, 0x32, 0xc5, 0x96, 0xf2, 0xa8, 0x80, 0x3e
};


/**
 * Dependencies for testing SPDM measurement handling.
 */
struct spdm_measurements_discovery_testing {
	HASH_TESTING_ENGINE (hash);					/**< Hash engine for testing measurements. */
	HASH_TESTING_ENGINE (hash2);				/**< A second hash engine for testing summary hashes. */
	struct hash_engine_mock hash_mock;			/**< Mock for hash operations. */
	struct flash_mock flash;					/**< Mock for measurement flash operations. */
	struct pcr_store store;						/**< Measurement storage. */
	struct spdm_discovery_device_id device_id;	/**< Device ID measurement bit stream. */
	struct spdm_measurements_discovery test;	/**< PCR store under test. */
};


/**
 * Initialize dependencies for testing SPDM measurement handling.
 *
 * @param test The test framework.
 * @param handler The testing dependencies.
 * @param config List of configuration for each supported PCR.
 * @param num_pcr Number of PCRs in the list.
 */
static void spdm_measurements_discovery_testing_init_dependencies (CuTest *test,
	struct spdm_measurements_discovery_testing *handler, const struct pcr_config *config,
	size_t num_pcr)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&handler->hash);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&handler->hash2);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&handler->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&handler->flash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&handler->store, config, num_pcr);
	CuAssertIntEquals (test, 0, status);

	spdm_discovery_device_id_init (&handler->device_id, 0x1234, 0x5678, 0x99aa, 0xbbcc);
}

/**
 * Release dependencies for SPDM measurement testing and validate mocks.
 *
 * @param test The test framework.
 * @param handler The testing dependencies.
 */
static void spdm_measurements_discovery_testing_release_dependencies (CuTest *test,
	struct spdm_measurements_discovery_testing *handler)
{
	int status;

	status = hash_mock_validate_and_release (&handler->hash_mock);
	status |= flash_mock_validate_and_release (&handler->flash);

	CuAssertIntEquals (test, 0, status);

	pcr_store_release (&handler->store);
	HASH_TESTING_ENGINE_RELEASE (&handler->hash);
	HASH_TESTING_ENGINE_RELEASE (&handler->hash2);
}

/**
 * Initialize a SPDM measurement handler for testing.
 *
 * @param test The test framework.
 * @param handler The testing components to initialize.
 * @param config List of configuration for each supported PCR.
 * @param num_pcr Number of PCRs in the list.
 */
static void spdm_measurements_discovery_testing_init (CuTest *test,
	struct spdm_measurements_discovery_testing *handler, const struct pcr_config *config,
	size_t num_pcr)
{
	int status;

	spdm_measurements_discovery_testing_init_dependencies (test, handler, config, num_pcr);

	status = spdm_measurements_discovery_init (&handler->test, &handler->store,
		&handler->device_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test SPDM measurement handler and all dependencies
 *
 * @param test The test framework.
 * @param handler The testing components to release.
 */
static void spdm_measurements_discovery_testing_release (CuTest *test,
	struct spdm_measurements_discovery_testing *handler)
{
	spdm_measurements_discovery_release (&handler->test);

	spdm_measurements_discovery_testing_release_dependencies (test, handler);
}


/*******************
 * Test cases
 *******************/

static void spdm_measurements_discovery_test_init (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	status = spdm_measurements_discovery_init (&handler.test, &handler.store, &handler.device_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base.get_measurement_count);
	CuAssertPtrNotNull (test, handler.test.base.get_measurement_block);
	CuAssertPtrNotNull (test, handler.test.base.get_measurement_block_length);
	CuAssertPtrNotNull (test, handler.test.base.get_all_measurement_blocks);
	CuAssertPtrNotNull (test, handler.test.base.get_all_measurement_blocks_length);
	CuAssertPtrNotNull (test, handler.test.base.get_measurement_summary_hash);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_init_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	status = spdm_measurements_discovery_init (NULL, &handler.store, &handler.device_id);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = spdm_measurements_discovery_init (&handler.test, NULL, &handler.device_id);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = spdm_measurements_discovery_init (&handler.test, &handler.store, NULL);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release_dependencies (test, &handler);
}

static void spdm_measurements_discovery_test_static_init (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};

	TEST_START;

	CuAssertPtrNotNull (test, handler.test.base.get_measurement_count);
	CuAssertPtrNotNull (test, handler.test.base.get_measurement_block);
	CuAssertPtrNotNull (test, handler.test.base.get_measurement_block_length);
	CuAssertPtrNotNull (test, handler.test.base.get_all_measurement_blocks);
	CuAssertPtrNotNull (test, handler.test.base.get_all_measurement_blocks_length);
	CuAssertPtrNotNull (test, handler.test.base.get_measurement_summary_hash);

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_release_null (CuTest *test)
{
	TEST_START;

	spdm_measurements_discovery_release (NULL);
}

static void spdm_measurements_discovery_test_get_measurement_count (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_count (&handler.test.base);
	CuAssertIntEquals (test, 10, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_count_static_init (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_count (&handler.test.base);
	CuAssertIntEquals (test, 11, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_count_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_count (NULL);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_digest (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 4;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 3);
	uint8_t buffer[exp_length * 2];

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 1;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[sizeof (*header)], SHA256_FULL_BLOCK_512_HASH, SHA256_HASH_LENGTH);

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
		PCR_DMTF_VALUE_TYPE_FIRMWARE, false);
	status |= pcr_store_set_measurement_data (&handler.store, measurement_type, &measurement_data);
	status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
		measurement_data.data.memory.buffer, measurement_data.data.memory.length, false);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_raw_bit_stream (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	int status;
	const size_t exp_length = spdm_measurements_block_size (HASH_TESTING_FULL_BLOCK_512_LEN);
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 9;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 2);
	uint8_t buffer[exp_length * 2];

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size =
		spdm_measurements_measurement_size (measurement_data.data.memory.length);

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 0;
	header->dmtf.measurement_value_size = measurement_data.data.memory.length;

	memcpy (&expected[sizeof (*header)], measurement_data.data.memory.buffer,
		measurement_data.data.memory.length);

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
		PCR_DMTF_VALUE_TYPE_ROM, false);
	status |= pcr_store_set_measurement_data (&handler.store, measurement_type, &measurement_data);
	status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
		measurement_data.data.memory.buffer, measurement_data.data.memory.length, false);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (sizeof (handler.device_id));

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = sizeof (handler.device_id);

	memcpy (&expected[sizeof (*header)], &handler.device_id, sizeof (handler.device_id));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream_no_hash
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (sizeof (handler.device_id));

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = sizeof (handler.device_id);

	memcpy (&expected[sizeof (*header)], &handler.device_id, sizeof (handler.device_id));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, true, NULL,
		HASH_TYPE_INVALID, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream_full_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));
	handler.device_id.descriptor[0].descriptor_data ^= 0x55aa;

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (sizeof (handler.device_id));

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = sizeof (handler.device_id);

	memcpy (&expected[sizeof (*header)], &handler.device_id, sizeof (handler.device_id));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_digest_sha256 (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[sizeof (*header)], SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256,
		SHA256_HASH_LENGTH);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_digest_sha384 (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA384_HASH_LENGTH);
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA384_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA384_HASH_LENGTH;

	memcpy (&expected[sizeof (*header)], SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA384,
		SHA384_HASH_LENGTH);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA384, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_digest_sha512 (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA512_HASH_LENGTH);
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA512_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA512_HASH_LENGTH;

	memcpy (&expected[sizeof (*header)], SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA512,
		SHA512_HASH_LENGTH);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA512, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_full_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[sizeof (*header)], SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256,
		SHA256_HASH_LENGTH);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_static_init (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header = (void*) expected;
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	memset (expected, 0, sizeof (expected));
	header->index = block_id;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (sizeof (handler.device_id));

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = sizeof (handler.device_id);

	memcpy (&expected[sizeof (*header)], &handler.device_id, sizeof (handler.device_id));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[64];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block (NULL, 0xef, false, &handler.hash.base,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_measurement_block (&handler.test.base, 0xef, false, NULL,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_measurement_block (&handler.test.base, 0xef, false,
		&handler.hash.base, HASH_TYPE_SHA256, NULL, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_buffer_less_than_min (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t block_id = 0xef;
	uint8_t buffer[spdm_measurements_block_size (0)];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer) - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_reserved_block_id (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[64];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block (&handler.test.base, 0, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_RESERVED_BLOCK_ID, status);

	status = handler.test.base.get_measurement_block (&handler.test.base, 0xff, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_RESERVED_BLOCK_ID, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_invalid_block_id (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[64];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block (&handler.test.base, 10, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_SEQUENTIAL_ID, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream_small_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer) - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_digest_small_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer) - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_device_id_digest_error (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	uint8_t block_id = 0xef;
	uint8_t buffer[exp_length * 2];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.calculate_sha256,
		&handler.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (&handler.device_id, sizeof (handler.device_id)),
		MOCK_ARG (sizeof (handler.device_id)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_block (&handler.test.base, block_id, false,
		&handler.hash_mock.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_length (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	int status;
	uint8_t block_id = 4;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 3);
	const size_t exp_length = spdm_measurements_block_size (HASH_TESTING_FULL_BLOCK_512_LEN);

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_measurement_data (&handler.store, measurement_type, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_block_length (&handler.test.base, block_id);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_length_device_id (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t block_id = 0xef;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block_length (&handler.test.base, block_id);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_length_device_id_static_init (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t block_id = 0xef;
	const size_t exp_length = spdm_measurements_block_size (sizeof (handler.device_id));

	TEST_START;

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block_length (&handler.test.base, block_id);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_length_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t block_id = 0xef;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block_length (NULL, block_id);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_block_length_reserved_block_id (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_block_length (&handler.test.base, 0);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_RESERVED_BLOCK_ID, status);

	status = handler.test.base.get_measurement_block_length (&handler.test.base, 0xff);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_RESERVED_BLOCK_ID, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_digest_sha256 (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_digest_sha384 (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[4] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		(uint8_t*) &handler.device_id
	};
	const size_t length[4] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[4] = {
		SHA384_FULL_BLOCK_512_HASH, SHA384_FULL_BLOCK_1024_HASH, SHA384_FULL_BLOCK_2048_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA384
	};
	struct pcr_measured_data measurement_data[3];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA384_HASH_LENGTH) * 4;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA384_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA384_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA384_HASH_LENGTH);
			pos += SHA384_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA384_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA384_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA384_HASH_LENGTH);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA384, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_digest_sha512 (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[7] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440,
		HASH_TESTING_PARTIAL_BLOCK_960, (uint8_t*) &handler.device_id
	};
	const size_t length[7] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, HASH_TESTING_PARTIAL_BLOCK_960_LEN,
		sizeof (handler.device_id)
	};
	const uint8_t *digests[7] = {
		SHA512_FULL_BLOCK_512_HASH, SHA512_FULL_BLOCK_1024_HASH, SHA512_FULL_BLOCK_2048_HASH,
		SHA512_FULL_BLOCK_4096_HASH, SHA512_PARTIAL_BLOCK_440_HASH, SHA512_PARTIAL_BLOCK_960_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA512
	};
	struct pcr_measured_data measurement_data[6];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA512_HASH_LENGTH) * 7;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA512_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA512_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA512_HASH_LENGTH);
			pos += SHA512_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA512_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA512_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA512_HASH_LENGTH);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA512, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_digest_full_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	const size_t block_count = 6;
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * block_count;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, exp_length);
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_raw_bit_stream (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const size_t block_length[6] = {
		spdm_measurements_block_size (length[0]), spdm_measurements_block_size (length[1]),
		spdm_measurements_block_size (length[2]), spdm_measurements_block_size (length[3]),
		spdm_measurements_block_size (length[4]), spdm_measurements_block_size (length[5])
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = block_length[0] + block_length[1] + block_length[2] +
		block_length[3] + block_length[4] + block_length[5];
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (length[j]);

			header->dmtf.raw_bit_stream = 1;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = length[j];

			memcpy (&expected[pos], data[j], length[j]);
			pos += length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (length[j]);

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = length[j];

	memcpy (&expected[pos], data[j], length[j]);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_raw_bit_stream_full_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[7] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440,
		HASH_TESTING_PARTIAL_BLOCK_960, (uint8_t*) &handler.device_id
	};
	const size_t length[7] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, HASH_TESTING_PARTIAL_BLOCK_960_LEN,
		sizeof (handler.device_id)
	};
	const size_t block_length[7] = {
		spdm_measurements_block_size (length[0]), spdm_measurements_block_size (length[1]),
		spdm_measurements_block_size (length[2]), spdm_measurements_block_size (length[3]),
		spdm_measurements_block_size (length[4]), spdm_measurements_block_size (length[5]),
		spdm_measurements_block_size (length[6])
	};
	struct pcr_measured_data measurement_data[6];
	int status;
	const size_t exp_length = block_length[0] + block_length[1] + block_length[2] +
		block_length[3] + block_length[4] + block_length[5] + block_length[6];
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (length[j]);

			header->dmtf.raw_bit_stream = 1;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = length[j];

			memcpy (&expected[pos], data[j], length[j]);
			pos += length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (length[j]);

	header->dmtf.raw_bit_stream = 1;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = length[j];

	memcpy (&expected[pos], data[j], length[j]);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, exp_length);
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_static_init (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, exp_length, status);

	status = testing_validate_array (expected, buffer, exp_length);
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[128];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks (NULL, false, &handler.hash.base,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false, NULL,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA256, NULL, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_all_measurement_blocks_device_id_buffer_less_than_min (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t buffer_length = (spdm_measurements_block_size (SHA256_HASH_LENGTH) * 5) +
		spdm_measurements_block_size (0);
	uint16_t measurement_type;
	uint8_t buffer[buffer_length];
	size_t i;
	size_t j;
	size_t k;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, sizeof (buffer) - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_digest_small_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, exp_length - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_digest_error (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.calculate_sha256,
		&handler.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (&handler.device_id, sizeof (handler.device_id)),
		MOCK_ARG (sizeof (handler.device_id)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, false,
		&handler.hash_mock.base, HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_raw_bit_stream_small_buffer
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const size_t block_length[6] = {
		spdm_measurements_block_size (length[0]), spdm_measurements_block_size (length[1]),
		spdm_measurements_block_size (length[2]), spdm_measurements_block_size (length[3]),
		spdm_measurements_block_size (length[4]), spdm_measurements_block_size (length[5])
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = block_length[0] + block_length[1] + block_length[2] +
		block_length[3] + block_length[4] + block_length[5];
	uint16_t measurement_type;
	uint8_t buffer[exp_length * 2];
	size_t i;
	size_t j;
	size_t k;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = handler.test.base.get_all_measurement_blocks (&handler.test.base, true,
		&handler.hash.base, HASH_TYPE_SHA256, buffer, exp_length - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_digest_sha256 (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks_length (&handler.test.base, false,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_digest_sha384 (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA384_HASH_LENGTH) * 5;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks_length (&handler.test.base, false,
		HASH_TYPE_SHA384);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_digest_sha512 (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA512_HASH_LENGTH) * 7;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks_length (&handler.test.base, false,
		HASH_TYPE_SHA512);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_raw_bit_stream (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[5] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440
	};
	const size_t length[5] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN
	};
	const size_t block_length[5] = {
		spdm_measurements_block_size (length[0]), spdm_measurements_block_size (length[1]),
		spdm_measurements_block_size (length[2]), spdm_measurements_block_size (length[3]),
		spdm_measurements_block_size (length[4])
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = block_length[0] + block_length[1] + block_length[2] +
		block_length[3] + block_length[4] +
		spdm_measurements_block_size (sizeof (handler.device_id));
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = handler.test.base.get_all_measurement_blocks_length (&handler.test.base, true,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_static_init (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;

	TEST_START;

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks_length (&handler.test.base, false,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, exp_length, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks_length (NULL, false, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_all_measurement_blocks_length_unknown_hash (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_all_measurement_blocks_length (&handler.test.base, false,
		HASH_TYPE_INVALID);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha256_meas_sha256_all_blocks
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA256_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.hash.base.calculate_sha256 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_digest, buffer, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha384_meas_sha256_only_tcb (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[5] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440
	};
	const size_t length[5] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN
	};
	const uint8_t *digests[5] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 5;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA384_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = handler.hash.base.calculate_sha384 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA384, &handler.hash2.base, HASH_TYPE_SHA256, true, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_digest, buffer, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha512_meas_sha256
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA512_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.hash.base.calculate_sha512 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA512, &handler.hash2.base, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_digest, buffer, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha256_meas_sha384_all_blocks
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[5] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, (uint8_t*) &handler.device_id
	};
	const size_t length[5] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		sizeof (handler.device_id)
	};
	const uint8_t *digests[5] = {
		SHA384_FULL_BLOCK_512_HASH, SHA384_FULL_BLOCK_1024_HASH, SHA384_FULL_BLOCK_2048_HASH,
		SHA384_FULL_BLOCK_4096_HASH, SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA384
	};
	struct pcr_measured_data measurement_data[4];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA384_HASH_LENGTH) * 5;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA256_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA384_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA384_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA384_HASH_LENGTH);
			pos += SHA384_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA384_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA384_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA384_HASH_LENGTH);

	status = handler.hash.base.calculate_sha256 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA384, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_digest, buffer, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_static_init (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler = {
		.test = spdm_measurements_discovery_static_init (&handler.store, &handler.device_id),
	};
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[6] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440, (uint8_t*) &handler.device_id
	};
	const size_t length[6] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN, sizeof (handler.device_id)
	};
	const uint8_t *digests[6] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 6;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA256_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init_dependencies (test, &handler, pcr_config,
		ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.hash.base.calculate_sha256 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_digest, buffer, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_null (CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_summary_hash (NULL, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, NULL,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, NULL, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false, NULL, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_INVALID_ARGUMENT, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_same_hash_engine (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash.base, HASH_TYPE_SHA256, false, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_SAME_HASH_ENGINE, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_start_error (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.start_sha256,
		&handler.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base,
		&handler.hash_mock.base, HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false,
		buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_update_error
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[5] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_PARTIAL_BLOCK_440
	};
	const size_t length[5] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN
	};
	const uint8_t *digests[5] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH, SHA256_FULL_BLOCK_2048_HASH,
		SHA256_FULL_BLOCK_4096_HASH, SHA256_PARTIAL_BLOCK_440_HASH
	};
	struct pcr_measured_data measurement_data[5];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 5;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA256_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = handler.hash.base.calculate_sha256 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.start_sha256,
		&handler.hash_mock, 0);
	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.cancel,
		&handler.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base,
		&handler.hash_mock.base, HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false,
		buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void
spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_device_id_update_error (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[3] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, (uint8_t*) &handler.device_id
	};
	const size_t length[3] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		sizeof (handler.device_id)
	};
	const uint8_t *digests[3] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[2];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 3;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA256_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.hash.base.calculate_sha256 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.start_sha256,
		&handler.hash_mock, 0);

	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (expected, spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	pos = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&expected[pos], spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	pos += spdm_measurements_block_size (SHA256_HASH_LENGTH);
	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&expected[pos], spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.cancel,
		&handler.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base,
		&handler.hash_mock.base, HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false,
		buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_finish_error
(
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[3] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, (uint8_t*) &handler.device_id
	};
	const size_t length[3] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		sizeof (handler.device_id)
	};
	const uint8_t *digests[3] = {
		SHA256_FULL_BLOCK_512_HASH, SHA256_FULL_BLOCK_1024_HASH,
		SPDM_MEASUREMENTS_DISCOVERY_TESTING_DEVICE_ID_SHA256
	};
	struct pcr_measured_data measurement_data[2];
	int status;
	const size_t exp_length = spdm_measurements_block_size (SHA256_HASH_LENGTH) * 3;
	uint8_t expected[exp_length];
	struct spdm_measurements_measurement_block *header;
	uint16_t measurement_type;
	uint8_t exp_digest[SHA256_HASH_LENGTH];
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;
	size_t pos;

	TEST_START;

	memset (expected, 0, sizeof (expected));

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0, pos = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			header = (struct spdm_measurements_measurement_block*) &expected[pos];
			pos += sizeof (*header);

			header->index = j + 1;
			header->measurement_specification = 1;
			header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

			header->dmtf.raw_bit_stream = 0;
			header->dmtf.measurement_value_type = j % 5;
			header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

			memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);
			pos += SHA256_HASH_LENGTH;

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	/* Add the device ID measurement block. */
	header = (struct spdm_measurements_measurement_block*) &expected[pos];
	pos += sizeof (*header);

	header->index = 0xef;
	header->measurement_specification = 1;
	header->measurement_size = spdm_measurements_measurement_size (SHA256_HASH_LENGTH);

	header->dmtf.raw_bit_stream = 0;
	header->dmtf.measurement_value_type = 2;
	header->dmtf.measurement_value_size = SHA256_HASH_LENGTH;

	memcpy (&expected[pos], digests[j], SHA256_HASH_LENGTH);

	status = handler.hash.base.calculate_sha256 (&handler.hash.base, expected, exp_length,
		exp_digest, sizeof (exp_digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.start_sha256,
		&handler.hash_mock, 0);

	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (expected, spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	pos = spdm_measurements_block_size (SHA256_HASH_LENGTH);
	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&expected[pos], spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	pos += spdm_measurements_block_size (SHA256_HASH_LENGTH);
	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.update,
		&handler.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&expected[pos], spdm_measurements_block_size (SHA256_HASH_LENGTH)),
		MOCK_ARG (spdm_measurements_block_size (SHA256_HASH_LENGTH)));

	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.finish,
		&handler.hash_mock, HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.cancel,
		&handler.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base,
		&handler.hash_mock.base, HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false,
		buffer, sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_small_buffer (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t buffer[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash2.base, HASH_TYPE_SHA256, false, buffer,
		SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, SPDM_MEASUREMENTS_BUFFER_TOO_SMALL, status);

	spdm_measurements_discovery_testing_release (test, &handler);
}

static void spdm_measurements_discovery_test_get_measurement_summary_hash_device_id_hash_error (
	CuTest *test)
{
	struct spdm_measurements_discovery_testing handler;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	const uint8_t *data[4] = {
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_4096
	};
	const size_t length[4] = {
		HASH_TESTING_FULL_BLOCK_512_LEN, HASH_TESTING_FULL_BLOCK_1024_LEN,
		HASH_TESTING_FULL_BLOCK_2048_LEN, HASH_TESTING_FULL_BLOCK_4096_LEN
	};
	struct pcr_measured_data measurement_data[4];
	int status;
	uint16_t measurement_type;
	uint8_t buffer[SHA512_HASH_LENGTH];
	size_t i;
	size_t j;
	size_t k;

	TEST_START;

	spdm_measurements_discovery_testing_init (test, &handler, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			measurement_data[j].type = PCR_DATA_TYPE_MEMORY;
			measurement_data[j].data.memory.buffer = data[j];
			measurement_data[j].data.memory.length = length[j];

			status = pcr_store_set_dmtf_value_type (&handler.store, measurement_type,
				(enum pcr_dmtf_value_type) j % 5, false);
			status |= pcr_store_set_measurement_data (&handler.store, measurement_type,
				&measurement_data[j]);
			status |= pcr_store_update_buffer (&handler.store, &handler.hash.base, measurement_type,
				data[j], length[j], false);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = mock_expect (&handler.hash_mock.mock, handler.hash_mock.base.calculate_sha256,
		&handler.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (&handler.device_id, sizeof (handler.device_id)),
		MOCK_ARG (sizeof (handler.device_id)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.get_measurement_summary_hash (&handler.test.base, &handler.hash.base,
		HASH_TYPE_SHA256, &handler.hash_mock.base, HASH_TYPE_SHA256, false, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	/* Test that the summary hash has not been left active. */
	status = handler.hash.base.start_sha256 (&handler.hash.base);
	CuAssertIntEquals (test, 0, status);

	handler.hash.base.cancel (&handler.hash.base);

	spdm_measurements_discovery_testing_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (spdm_measurements_discovery);

TEST (spdm_measurements_discovery_test_init);
TEST (spdm_measurements_discovery_test_init_null);
TEST (spdm_measurements_discovery_test_static_init);
TEST (spdm_measurements_discovery_test_release_null);
TEST (spdm_measurements_discovery_test_get_measurement_count);
TEST (spdm_measurements_discovery_test_get_measurement_count_static_init);
TEST (spdm_measurements_discovery_test_get_measurement_count_null);
TEST (spdm_measurements_discovery_test_get_measurement_block_digest);
TEST (spdm_measurements_discovery_test_get_measurement_block_raw_bit_stream);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream_no_hash);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream_full_buffer);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_digest_sha256);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_digest_sha384);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_digest_sha512);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_full_buffer);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_static_init);
TEST (spdm_measurements_discovery_test_get_measurement_block_null);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_buffer_less_than_min);
TEST (spdm_measurements_discovery_test_get_measurement_block_reserved_block_id);
TEST (spdm_measurements_discovery_test_get_measurement_block_invalid_block_id);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_raw_bit_stream_small_buffer);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_digest_small_buffer);
TEST (spdm_measurements_discovery_test_get_measurement_block_device_id_digest_error);
TEST (spdm_measurements_discovery_test_get_measurement_block_length);
TEST (spdm_measurements_discovery_test_get_measurement_block_length_device_id);
TEST (spdm_measurements_discovery_test_get_measurement_block_length_device_id_static_init);
TEST (spdm_measurements_discovery_test_get_measurement_block_length_null);
TEST (spdm_measurements_discovery_test_get_measurement_block_length_reserved_block_id);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_digest_sha256);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_digest_sha384);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_digest_sha512);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_digest_full_buffer);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_raw_bit_stream);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_raw_bit_stream_full_buffer);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_static_init);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_null);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_device_id_buffer_less_than_min);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_digest_small_buffer);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_digest_error);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_raw_bit_stream_small_buffer);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_digest_sha256);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_digest_sha384);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_digest_sha512);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_raw_bit_stream);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_static_init);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_null);
TEST (spdm_measurements_discovery_test_get_all_measurement_blocks_length_unknown_hash);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha256_meas_sha256_all_blocks);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha384_meas_sha256_only_tcb);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha512_meas_sha256);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_sha256_meas_sha384_all_blocks);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_static_init);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_null);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_same_hash_engine);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_start_error);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_update_error);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_device_id_update_error);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_summary_hash_finish_error);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_small_buffer);
TEST (spdm_measurements_discovery_test_get_measurement_summary_hash_device_id_hash_error);

TEST_SUITE_END;
// *INDENT-ON*
