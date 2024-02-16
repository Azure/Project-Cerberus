// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "attestation/pcr_store.h"
#include "common/array_size.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/attestation/pcr_testing.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("pcr_store");


/**
 * Dependencies for testing PCR storage.
 */
struct pcr_store_testing {
	HASH_TESTING_ENGINE hash;				/**< Hash engine for testing measurements. */
	struct hash_engine_mock hash_mock;		/**< Mock for hash operations. */
	struct pcr_store test;					/**< PCR store under test. */
};


/**
 * Initialize dependencies for testing PCR storage.
 *
 * @param test The test framework.
 * @param store The testing dependencies.
 */
static void pcr_store_testing_init_dependencies (CuTest *test, struct pcr_store_testing *store)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&store->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&store->hash_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release dependencies for PCR storage testing and validate mocks.
 *
 * @param test The test framework.
 * @param store The testing dependencies.
 */
static void pcr_store_testing_release_dependencies (CuTest *test, struct pcr_store_testing *store)
{
	int status;

	status = hash_mock_validate_and_release (&store->hash_mock);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&store->hash);
}

/**
 * Initialize PCR storage for testing.
 *
 * @param test The test framework.
 * @param store The testing components to initialize.
 * @param config List of configuration for each supported PCR.
 * @param num_pcr Number of PCRs in the list.
 */
static void pcr_store_testing_init (CuTest *test, struct pcr_store_testing *store,
	const struct pcr_config *config, size_t num_pcr)
{
	int status;

	pcr_store_testing_init_dependencies (test, store);

	status = pcr_store_init (&store->test, config, num_pcr);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test PCR store and all dependencies
 *
 * @param test The test framework.
 * @param store The testing components to release.
 */
static void pcr_store_testing_release (CuTest *test, struct pcr_store_testing *store)
{
	pcr_store_release (&store->test);

	pcr_store_testing_release_dependencies (test, store);
}

/**
 * Set up expectations to mock the PCR computation for a single PCR using SHA-256
 *
 * @param test The test framework.
 * @param store The testing components to use for PCR computation.
 * @param digests List of measurement digests to use for extending the PCR.
 * @param measurements List of extended PCR values for each measurement.
 * @param length Length of each digest and measurement array entry.
 * @param count The number of measurements in the lists.
 * @param digest_length Length of the PCR digests.
 */
static void pcr_store_testing_mock_pcr_compute (CuTest *test, struct pcr_store_testing *store,
	const uint8_t *digests, const uint8_t *measurements, size_t length, size_t count,
	size_t digest_length)
{
	uint8_t buffer0[SHA512_HASH_LENGTH] = {0};
	size_t i;
	int status;

	for (i = 0; i < count; i++) {
		switch (digest_length) {
			default:
			case SHA256_HASH_LENGTH:
				status = mock_expect (&store->hash_mock.mock, store->hash_mock.base.start_sha256,
					&store->hash_mock, 0);
				break;

			case SHA384_HASH_LENGTH:
				status = mock_expect (&store->hash_mock.mock, store->hash_mock.base.start_sha384,
					&store->hash_mock, 0);
				break;

			case SHA512_HASH_LENGTH:
				status = mock_expect (&store->hash_mock.mock, store->hash_mock.base.start_sha512,
					&store->hash_mock, 0);
				break;
		}

		if (i == 0) {
			status |= mock_expect (&store->hash_mock.mock, store->hash_mock.base.update,
				&store->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP (buffer0, digest_length),
				MOCK_ARG (digest_length));
		}
		else {
			status |= mock_expect (&store->hash_mock.mock, store->hash_mock.base.update,
				&store->hash_mock, 0,
				MOCK_ARG_PTR_CONTAINS (&measurements[(i - 1) * length], digest_length),
				MOCK_ARG (digest_length));
		}

		status |= mock_expect (&store->hash_mock.mock, store->hash_mock.base.update,
			&store->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&digests[i * length], digest_length),
			MOCK_ARG (digest_length));

		status |= mock_expect (&store->hash_mock.mock, store->hash_mock.base.finish,
			&store->hash_mock,  0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (digest_length));
		status |= mock_expect_output (&store->hash_mock.mock, 0, &measurements[i * length],
			digest_length, -1);

		CuAssertIntEquals (test, 0, status);
	}
}


/*******************
 * Test cases
 *******************/

static void pcr_store_test_init_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 2, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 11, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 0);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_init_sha256_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 2, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 6, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 1);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_init_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 3, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 14, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 2);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_store_testing_release_dependencies (test, &store);
#endif
}

static void pcr_store_test_init_sha384_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 1, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 0);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_store_testing_release_dependencies (test, &store);
#endif
}

static void pcr_store_test_init_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 6, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 21, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 4);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_store_testing_release_dependencies (test, &store);
#endif
}

static void pcr_store_test_init_sha512_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		},
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 3, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 8, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 1);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_store_testing_release_dependencies (test, &store);
#endif
}

static void pcr_store_test_init_mixed_hash_algos (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
#if defined HASH_ENABLE_SHA384 && defined HASH_ENABLE_SHA512 && \
	(PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_num_pcrs (&store.test);
	CuAssertIntEquals (test, 6, status);

	status = pcr_store_get_num_total_measurements (&store.test);
	CuAssertIntEquals (test, 21, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 0);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 1);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 2);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 3);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 4);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 5);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	pcr_store_testing_release (test, &store);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_store_testing_release_dependencies (test, &store);
#endif
}

static void pcr_store_test_init_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (NULL, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_init (&store.test, NULL, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_init (&store.test, pcr_config, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release_dependencies (test, &store);
}

static void pcr_store_test_init_pcr_init_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_INVALID
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_store_testing_release_dependencies (test, &store);
}

static void pcr_store_test_release_null (CuTest *test)
{
	TEST_START;

	pcr_store_release (NULL);
}

static void pcr_store_test_get_num_pcrs_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_get_num_pcrs (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_get_num_total_measurements_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_get_num_total_measurements (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_get_pcr_digest_length_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_get_pcr_digest_length (NULL, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_get_pcr_digest_length_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init_dependencies (test, &store);

	status = pcr_store_init (&store.test, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_pcr_digest_length (&store.test, 2);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_check_measurement_type (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_check_measurement_type (&store.test, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_check_measurement_type (&store.test, PCR_MEASUREMENT (1, 5));
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_check_measurement_type_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_check_measurement_type (&store.test, PCR_MEASUREMENT (1, 0));
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_check_measurement_type_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_check_measurement_type (NULL, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_check_measurement_type_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_check_measurement_type (&store.test, PCR_MEASUREMENT (2, 0));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_check_measurement_type_invalid_index (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_check_measurement_type (&store.test, PCR_MEASUREMENT (1, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_check_measurement_type_invalid_index_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_check_measurement_type (&store.test, PCR_MEASUREMENT (1, 1));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_num_pcr_measurements (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_num_pcr_measurements (&store.test, 0);
	CuAssertIntEquals (test, 6, status);

	status = pcr_store_get_num_pcr_measurements (&store.test, 1);
	CuAssertIntEquals (test, 4, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_num_pcr_measurements_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_num_pcr_measurements (&store.test, 1);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_num_pcr_measurements_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_num_pcr_measurements (NULL, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_num_pcr_measurements_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_num_pcr_measurements (&store.test, 2);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_digest_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 1), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_update_digest_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 3), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 3), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (2, 2), SHA384_TEST_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (2, 2), &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_update_digest_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 5), SHA512_TEST_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 5), &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_update_digest_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_update_digest (NULL, 5, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_update_digest_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (2, 1), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_digest_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 10), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement (NULL, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 1), NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (2, 0), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 6), &measurement);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 5);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha256_with_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 3);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha256_with_event_without_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 3);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_update_buffer_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_buffer (&store.test, &store.hash.base, PCR_MEASUREMENT (0, 5),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 5), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, PCR_MEASUREMENT (1, 0),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 0), &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha384_with_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 3);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha384_with_event_without_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 3);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_update_buffer_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_buffer (&store.test, &store.hash.base, PCR_MEASUREMENT (1, 5),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 5), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, PCR_MEASUREMENT (0, 0),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha512_with_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 3);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_sha512_with_event_without_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 3);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_update_buffer_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_buffer (NULL, &store.hash.base, PCR_MEASUREMENT (0, 5),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_update_buffer (&store.test, NULL, PCR_MEASUREMENT (0, 5),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_buffer (&store.test, &store.hash.base, PCR_MEASUREMENT (4, 1),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&store.hash_mock.mock, store.hash_mock.base.start_sha256,
		&store.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash_mock.base, PCR_MEASUREMENT (0, 5),
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_buffer_with_event_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 5);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash_mock.mock, store.hash_mock.base.start_sha256,
		&store.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_buffer (&store.test, &store.hash_mock.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 5);
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_sha256_with_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 3);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_EVENT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_update_versioned_buffer_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base,
		PCR_MEASUREMENT (1, 5), HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 5), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base,
		PCR_MEASUREMENT (0, 4), HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 4), &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_sha384_with_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 3);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_EVENT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_update_versioned_buffer_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base,
		PCR_MEASUREMENT (0, 5), HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 5), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base,
		PCR_MEASUREMENT (1, 2), HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 2), &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_sha512_with_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (1, 3);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, measurement_type, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, version, measurement.version);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_EVENT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_update_versioned_buffer_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint16_t measurement_type = PCR_MEASUREMENT (0, 5);
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_versioned_buffer (NULL, &store.hash.base, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_update_versioned_buffer (&store.test, NULL, measurement_type,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash.base,
		PCR_MEASUREMENT (4, 1), HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false,
		version);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 5);
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&store.hash_mock.mock, store.hash_mock.base.start_sha256,
		&store.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash_mock.base,
		measurement_type, HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false,
		version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_update_versioned_buffer_with_event_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint16_t measurement_type = PCR_MEASUREMENT (0, 5);
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&store.hash_mock.mock, store.hash_mock.base.start_sha256,
		&store.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_versioned_buffer (&store.test, &store.hash_mock.base,
		measurement_type, HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true,
		version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_store_get_measurement (&store.test, measurement_type, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_tcg_event_type_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_set_tcg_event_type (NULL, 5, 0x0A);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_set_tcg_event_type_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (2, 0), 0x0A);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_tcg_event_type_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 10), 0x0A);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_invalidate_measurement (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 1), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_invalidate_measurement (&store.test, PCR_MEASUREMENT (1, 1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 1), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_invalidate_measurement_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);
	status = pcr_store_invalidate_measurement (&store.test, PCR_MEASUREMENT (1, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (1, 0), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
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
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_invalidate_measurement (&store.test, PCR_MEASUREMENT (4, 1));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_invalidate_measurement_invalid_index (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_invalidate_measurement (&store.test, PCR_MEASUREMENT (1, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA256_TEST2_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha256_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 1, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha256_no_measurement_out (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA256_TEST2_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, NULL, 0);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 2), &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2, measurement.measurement,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_compute_pcr_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA384_TEST_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA384_TEST2_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha384_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t measurement[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), SHA384_TEST_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 1, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha384_no_measurement_out (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA384_TEST_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA384_TEST2_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, NULL, 0);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 2), &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_MEASUREMENT2, measurement.measurement,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_compute_pcr_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA512_TEST_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA512_TEST2_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha512_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t measurement[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), SHA512_TEST_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 1, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha512_no_measurement_out (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA512_TEST_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA512_TEST2_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, NULL, 0);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = pcr_store_get_measurement (&store.test, PCR_MEASUREMENT (0, 2), &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_MEASUREMENT2, measurement.measurement,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_compute_pcr_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_compute_pcr (NULL, &store.hash.base, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_compute_pcr (&store.test, NULL, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_sha256_small_output_buffer (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA256_TEST2_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, measurement,
		sizeof (measurement) - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_compute_pcr_sha384_small_output_buffer (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA384_TEST_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA384_TEST2_HASH,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, measurement,
		sizeof (measurement) - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_compute_pcr_sha512_small_output_buffer (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA512_TEST_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA512_TEST2_HASH,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 0, measurement,
		sizeof (measurement) - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_compute_pcr_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_compute_pcr (&store.test, &store.hash.base, 3, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_compute_pcr_compute_pcr_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&store.hash_mock.mock, store.hash_mock.base.start_sha256,
		&store.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_compute_pcr (&store.test, &store.hash_mock.base, 0, measurement,
		sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_measurement_data (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t data_mem[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, 2),
		&measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 1, status);

	status = pcr_store_get_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), 0, buffer,
		length);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (&data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data_mem;
	measurement_data.data.memory.length = sizeof (data_mem);

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (1, 4));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 4),
		&measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (1, 4));
	CuAssertIntEquals (test, 1, status);

	status = pcr_store_get_measurement_data (&store.test, PCR_MEASUREMENT (1, 4), 0, buffer,
		length);
	CuAssertIntEquals (test, sizeof (data_mem), status);

	status = testing_validate_array (data_mem, buffer, sizeof (data_mem));
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_measurement_data_remove (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, 2),
		&measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 1, status);

	status = pcr_store_get_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), 0, buffer,
		length);
	CuAssertIntEquals (test, 1, status);

	status = testing_validate_array (&data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), 0, buffer,
		length);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_measurement_data_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_measurement_data (NULL, PCR_MEASUREMENT (0, 2), &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_measurement_data_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (2, 0),
		&measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_measurement_data_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = NUM_PCR_DATA_TYPE;
	measurement_data.data.value_1byte = data;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, 2),
		&measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_DATA_TYPE, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_is_measurement_data_available_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_is_measurement_data_available (NULL, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_is_measurement_data_available_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_is_measurement_data_available (&store.test, PCR_MEASUREMENT (2, 0));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_no_data (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), 0, buffer,
		length);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data (NULL, PCR_MEASUREMENT (0, 2), 0, buffer, length);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data (&store.test, PCR_MEASUREMENT (2, 0), 0, buffer,
		length);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_hash_measurement_data (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 2), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_hash_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), &store.hash.base,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 4), SHA256_TEST2_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_hash_measurement_data (&store.test, PCR_MEASUREMENT (1, 4), &store.hash.base,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST2_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_hash_measurement_data_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_hash_measurement_data (NULL, PCR_MEASUREMENT (0, 2), &store.hash.base,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_hash_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), NULL,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_hash_measurement_data (&store.test, PCR_MEASUREMENT (0, 2), &store.hash.base,
		HASH_TYPE_SHA256, NULL, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_hash_measurement_data_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_hash_measurement_data (&store.test, PCR_MEASUREMENT (2, 0), &store.hash.base,
		HASH_TYPE_SHA256, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_hash_measurement_data_error (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_hash_measurement_data (&store.test, PCR_MEASUREMENT (0, 3), &store.hash.base,
		HASH_TYPE_SHA256, buffer, SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_length (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	struct pcr_measured_data measurement_data;
	uint8_t data_mem[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data_mem;
	measurement_data.data.memory.length = sizeof (data_mem);

	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 4),
		&measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement_data_length (&store.test, PCR_MEASUREMENT (1, 4));
	CuAssertIntEquals (test, sizeof (data_mem), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_length_no_data (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data_length (&store.test, PCR_MEASUREMENT (0, 2));
	CuAssertIntEquals (test, PCR_MEASURED_DATA_NOT_AVIALABLE, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_length_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data_length (NULL, PCR_MEASUREMENT (1, 4));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_length_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data_length (&store.test, PCR_MEASUREMENT (2, 0));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_data_length_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_data_length (&store.test, PCR_MEASUREMENT (0, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
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

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test, 9 * sizeof (struct pcr_store_attestation_log_entry_sha256), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha256_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test, 6 * sizeof (struct pcr_store_attestation_log_entry_sha256), status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_get_attestation_log_size_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test, 8 * sizeof (struct pcr_store_attestation_log_entry_sha384), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha384_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test, 4 * sizeof (struct pcr_store_attestation_log_entry_sha384), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha256_and_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test,
		(5 * sizeof (struct pcr_store_attestation_log_entry_sha256)) +
			(2 * sizeof (struct pcr_store_attestation_log_entry_sha384)),
		status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha384_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test,
		(5 * sizeof (struct pcr_store_attestation_log_entry_sha384)) +
			(4 * sizeof (struct pcr_store_attestation_log_entry_sha256)),
		status);

	pcr_store_testing_release (test, &store);
}

#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_get_attestation_log_size_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 8,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test, 10 * sizeof (struct pcr_store_attestation_log_entry_sha512), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha512_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test, 3 * sizeof (struct pcr_store_attestation_log_entry_sha512), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha256_and_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 8,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test,
		(2 * sizeof (struct pcr_store_attestation_log_entry_sha256)) +
			(8 * sizeof (struct pcr_store_attestation_log_entry_sha512)),
		status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_size_sha512_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 7,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log_size (&store.test);
	CuAssertIntEquals (test,
		(4 * sizeof (struct pcr_store_attestation_log_entry_sha512)) +
			(7 * sizeof (struct pcr_store_attestation_log_entry_sha256)),
		status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_get_attestation_log_size_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_store_get_attestation_log_size (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_store_test_get_attestation_log_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
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
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha256_invalid_entry (CuTest *test)
{
	struct pcr_store_testing store;
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
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha256_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
	};
	uint8_t measurements[5][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
	};
	struct pcr_store_attestation_log_entry_sha256 expected[5];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_store_test_get_attestation_log_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t digests[6][SHA384_HASH_LENGTH] = {
		{
			0xe0,0x26,0x8c,0xee,0xd9,0xaf,0x17,0xe1,0xce,0xee,0xab,0x9a,0x5b,0xd9,0xec,0x29,
			0x4f,0xfa,0xf8,0xd2,0x3b,0x8d,0x8e,0x88,0x45,0x7c,0xec,0x1b,0xb6,0x7e,0xd6,0x05,
			0x4e,0x4c,0x84,0x95,0x85,0xcb,0x01,0x54,0x42,0xee,0xf3,0x71,0x08,0x47,0x42,0xff
		},
		{
			0xb5,0x1d,0xb8,0x0d,0x49,0x71,0x72,0x1e,0x1c,0x06,0x99,0x8a,0xd5,0x0b,0x34,0x3b,
			0xb0,0x7b,0xf7,0x4a,0x30,0x8f,0x03,0x72,0xfd,0x6b,0x71,0x28,0x10,0x79,0x01,0xdb,
			0xb0,0xcc,0xee,0xd3,0x48,0x91,0xb4,0xb5,0x33,0xbc,0x91,0x58,0x45,0x63,0x73,0x34
		},
		{
			0xff,0xf8,0x42,0xf2,0x8e,0xd1,0xd5,0x4a,0xac,0xef,0x63,0x94,0x23,0xad,0x94,0x61,
			0x6a,0xa7,0xf6,0x03,0x6a,0x82,0x60,0x88,0x8d,0x72,0x06,0xb4,0x99,0xe1,0x88,0x5c,
			0x6b,0xe1,0xb8,0x35,0x37,0x4b,0x7a,0x37,0x87,0xdb,0x2e,0x76,0x62,0xab,0x6f,0xdd
		},
		{
			0x66,0x64,0xa9,0x5c,0x50,0x4e,0x3f,0xa5,0x3b,0xc8,0xa9,0x72,0x08,0xd1,0x4a,0xa8,
			0x1a,0x14,0xff,0x63,0x96,0xa8,0xe9,0xc9,0x73,0x92,0x3e,0xb0,0x52,0xf9,0xaf,0xb4,
			0xb6,0xf3,0xbc,0x42,0xbc,0x98,0x22,0x21,0x00,0x1e,0xe5,0xee,0xfa,0x89,0x95,0x42
		},
		{
			0xee,0x9d,0xad,0x64,0x9f,0x1d,0xc1,0xd4,0x24,0x43,0x75,0xae,0x02,0xec,0x12,0xc7,
			0x01,0x50,0x86,0x82,0xbf,0x54,0x5d,0x44,0x62,0xcf,0x11,0xfd,0x06,0xed,0x5d,0xd6,
			0x62,0x46,0x03,0xfe,0xd3,0xa0,0xda,0x7a,0x46,0x90,0x15,0x1f,0x0e,0x64,0xa6,0xb4
		},
		{
			0x06,0xcf,0x86,0xa2,0x59,0xd6,0x1d,0x00,0x2b,0xea,0xc8,0xbe,0x76,0x31,0x40,0x25,
			0xe9,0x85,0xfc,0x45,0x51,0x9c,0x7d,0xe7,0xc6,0xf0,0xcd,0x1b,0x8d,0xb5,0x2c,0x73,
			0xdd,0x8e,0xdd,0x43,0x98,0x4d,0xcb,0x00,0x47,0xaf,0x91,0x45,0x22,0xb6,0x26,0x69
		}
	};
	uint8_t measurements[6][SHA384_HASH_LENGTH] = {
		{
			0xc4,0x47,0xac,0x69,0xc4,0xf6,0xec,0xc3,0x82,0xb2,0x43,0x87,0xc2,0x64,0x12,0x12,
			0xd1,0xe1,0xa8,0xd1,0x01,0xf8,0x4b,0xe5,0x5f,0xad,0xb3,0xea,0xc1,0x48,0x12,0x7b,
			0x68,0xc6,0xf8,0x22,0x3c,0xb7,0xf1,0x28,0xac,0x86,0x27,0x8c,0xfe,0xd4,0xa3,0xd7
		},
		{
			0x07,0xbe,0xa3,0x33,0x42,0x5e,0x29,0x6d,0x6b,0x84,0xf0,0x9e,0x7c,0x1d,0x53,0xd9,
			0x06,0x74,0x03,0xf0,0x96,0x3d,0xcf,0x73,0x4a,0xe8,0x1f,0x43,0xdd,0xec,0xf6,0x04,
			0x8c,0xca,0x0a,0xd8,0x71,0xc0,0x43,0x59,0x20,0x03,0xf8,0x5f,0x1e,0x34,0x9c,0x4b
		},
		{
			0xe6,0xc4,0x81,0x28,0xd2,0x13,0x67,0xec,0xb9,0x53,0xf3,0xf6,0xda,0x31,0x5a,0x93,
			0xc4,0x0b,0x40,0xb5,0x19,0xd8,0x08,0xfb,0xbc,0xef,0xb6,0xd9,0xaa,0x69,0xd2,0xfc,
			0xdc,0x14,0xe0,0x16,0x2c,0xbe,0xad,0xd1,0x0d,0x4d,0xe0,0x1b,0x94,0xaf,0x68,0x5b
		},
		{
			0x61,0xbb,0xc5,0x59,0x25,0x95,0x1b,0x8f,0xdb,0xf7,0x55,0x80,0x0a,0x63,0x00,0xd8,
			0x20,0x6b,0x31,0x17,0x07,0x1e,0x01,0x1f,0xd4,0x08,0xff,0xec,0x29,0x9b,0x84,0x08,
			0x92,0xf2,0x23,0xd3,0xba,0x7b,0x07,0xb6,0xd0,0x8c,0x40,0xb9,0x69,0xe5,0xe6,0xd0
		},
		{
			0xed,0xfc,0x52,0x5c,0x47,0x13,0x80,0x56,0xdd,0x9c,0x72,0x10,0x62,0xcd,0x98,0x3f,
			0xbb,0x80,0x0f,0x62,0x3f,0xda,0x91,0xc6,0xb7,0x0e,0xc7,0x67,0xd2,0x65,0x91,0xca,
			0x7b,0x9f,0x3a,0x0b,0xb1,0x10,0x07,0x66,0x55,0xf4,0x10,0xef,0xaf,0x81,0x85,0x16
		},
		{
			0x52,0xd8,0x2e,0xc3,0x3d,0x2e,0xe6,0x8b,0x3c,0x04,0xdb,0x76,0x9e,0x79,0xc8,0x0d,
			0x88,0x82,0x8e,0xcc,0x36,0xed,0x26,0x3c,0x5e,0x17,0x42,0x95,0x0c,0x85,0xb6,0xe6,
			0x37,0xe0,0x62,0x89,0xf5,0xd8,0x34,0x9b,0xca,0x2e,0x33,0x09,0xa3,0x88,0x7e,0x63
		}
	};
	struct pcr_store_attestation_log_entry_sha384 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA384_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha384);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0C;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x1A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA384_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA384_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA384_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA384_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x1A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha384_invalid_entry (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t digests[6][SHA384_HASH_LENGTH] = {
		{
			0xe0,0x26,0x8c,0xee,0xd9,0xaf,0x17,0xe1,0xce,0xee,0xab,0x9a,0x5b,0xd9,0xec,0x29,
			0x4f,0xfa,0xf8,0xd2,0x3b,0x8d,0x8e,0x88,0x45,0x7c,0xec,0x1b,0xb6,0x7e,0xd6,0x05,
			0x4e,0x4c,0x84,0x95,0x85,0xcb,0x01,0x54,0x42,0xee,0xf3,0x71,0x08,0x47,0x42,0xff
		},
		{
			0xb5,0x1d,0xb8,0x0d,0x49,0x71,0x72,0x1e,0x1c,0x06,0x99,0x8a,0xd5,0x0b,0x34,0x3b,
			0xb0,0x7b,0xf7,0x4a,0x30,0x8f,0x03,0x72,0xfd,0x6b,0x71,0x28,0x10,0x79,0x01,0xdb,
			0xb0,0xcc,0xee,0xd3,0x48,0x91,0xb4,0xb5,0x33,0xbc,0x91,0x58,0x45,0x63,0x73,0x34
		},
		{
			0xff,0xf8,0x42,0xf2,0x8e,0xd1,0xd5,0x4a,0xac,0xef,0x63,0x94,0x23,0xad,0x94,0x61,
			0x6a,0xa7,0xf6,0x03,0x6a,0x82,0x60,0x88,0x8d,0x72,0x06,0xb4,0x99,0xe1,0x88,0x5c,
			0x6b,0xe1,0xb8,0x35,0x37,0x4b,0x7a,0x37,0x87,0xdb,0x2e,0x76,0x62,0xab,0x6f,0xdd
		},
		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		},
		{
			0xee,0x9d,0xad,0x64,0x9f,0x1d,0xc1,0xd4,0x24,0x43,0x75,0xae,0x02,0xec,0x12,0xc7,
			0x01,0x50,0x86,0x82,0xbf,0x54,0x5d,0x44,0x62,0xcf,0x11,0xfd,0x06,0xed,0x5d,0xd6,
			0x62,0x46,0x03,0xfe,0xd3,0xa0,0xda,0x7a,0x46,0x90,0x15,0x1f,0x0e,0x64,0xa6,0xb4
		},
		{
			0x06,0xcf,0x86,0xa2,0x59,0xd6,0x1d,0x00,0x2b,0xea,0xc8,0xbe,0x76,0x31,0x40,0x25,
			0xe9,0x85,0xfc,0x45,0x51,0x9c,0x7d,0xe7,0xc6,0xf0,0xcd,0x1b,0x8d,0xb5,0x2c,0x73,
			0xdd,0x8e,0xdd,0x43,0x98,0x4d,0xcb,0x00,0x47,0xaf,0x91,0x45,0x22,0xb6,0x26,0x69
		}
	};
	uint8_t measurements[6][SHA384_HASH_LENGTH] = {
		{
			0xc4,0x47,0xac,0x69,0xc4,0xf6,0xec,0xc3,0x82,0xb2,0x43,0x87,0xc2,0x64,0x12,0x12,
			0xd1,0xe1,0xa8,0xd1,0x01,0xf8,0x4b,0xe5,0x5f,0xad,0xb3,0xea,0xc1,0x48,0x12,0x7b,
			0x68,0xc6,0xf8,0x22,0x3c,0xb7,0xf1,0x28,0xac,0x86,0x27,0x8c,0xfe,0xd4,0xa3,0xd7
		},
		{
			0x07,0xbe,0xa3,0x33,0x42,0x5e,0x29,0x6d,0x6b,0x84,0xf0,0x9e,0x7c,0x1d,0x53,0xd9,
			0x06,0x74,0x03,0xf0,0x96,0x3d,0xcf,0x73,0x4a,0xe8,0x1f,0x43,0xdd,0xec,0xf6,0x04,
			0x8c,0xca,0x0a,0xd8,0x71,0xc0,0x43,0x59,0x20,0x03,0xf8,0x5f,0x1e,0x34,0x9c,0x4b
		},
		{
			0xe6,0xc4,0x81,0x28,0xd2,0x13,0x67,0xec,0xb9,0x53,0xf3,0xf6,0xda,0x31,0x5a,0x93,
			0xc4,0x0b,0x40,0xb5,0x19,0xd8,0x08,0xfb,0xbc,0xef,0xb6,0xd9,0xaa,0x69,0xd2,0xfc,
			0xdc,0x14,0xe0,0x16,0x2c,0xbe,0xad,0xd1,0x0d,0x4d,0xe0,0x1b,0x94,0xaf,0x68,0x5b
		},
		{
			0x61,0xbb,0xc5,0x59,0x25,0x95,0x1b,0x8f,0xdb,0xf7,0x55,0x80,0x0a,0x63,0x00,0xd8,
			0x20,0x6b,0x31,0x17,0x07,0x1e,0x01,0x1f,0xd4,0x08,0xff,0xec,0x29,0x9b,0x84,0x08,
			0x92,0xf2,0x23,0xd3,0xba,0x7b,0x07,0xb6,0xd0,0x8c,0x40,0xb9,0x69,0xe5,0xe6,0xd0
		},
		{
			0xed,0xfc,0x52,0x5c,0x47,0x13,0x80,0x56,0xdd,0x9c,0x72,0x10,0x62,0xcd,0x98,0x3f,
			0xbb,0x80,0x0f,0x62,0x3f,0xda,0x91,0xc6,0xb7,0x0e,0xc7,0x67,0xd2,0x65,0x91,0xca,
			0x7b,0x9f,0x3a,0x0b,0xb1,0x10,0x07,0x66,0x55,0xf4,0x10,0xef,0xaf,0x81,0x85,0x16
		},
		{
			0x52,0xd8,0x2e,0xc3,0x3d,0x2e,0xe6,0x8b,0x3c,0x04,0xdb,0x76,0x9e,0x79,0xc8,0x0d,
			0x88,0x82,0x8e,0xcc,0x36,0xed,0x26,0x3c,0x5e,0x17,0x42,0x95,0x0c,0x85,0xb6,0xe6,
			0x37,0xe0,0x62,0x89,0xf5,0xd8,0x34,0x9b,0xca,0x2e,0x33,0x09,0xa3,0x88,0x7e,0x63
		}
	};
	struct pcr_store_attestation_log_entry_sha384 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA384_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha384);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0C;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x1A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA384_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA384_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA384_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA384_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x1A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha384_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xe0,0x26,0x8c,0xee,0xd9,0xaf,0x17,0xe1,0xce,0xee,0xab,0x9a,0x5b,0xd9,0xec,0x29,
			0x4f,0xfa,0xf8,0xd2,0x3b,0x8d,0x8e,0x88,0x45,0x7c,0xec,0x1b,0xb6,0x7e,0xd6,0x05,
			0x4e,0x4c,0x84,0x95,0x85,0xcb,0x01,0x54,0x42,0xee,0xf3,0x71,0x08,0x47,0x42,0xff
		},
		{
			0xb5,0x1d,0xb8,0x0d,0x49,0x71,0x72,0x1e,0x1c,0x06,0x99,0x8a,0xd5,0x0b,0x34,0x3b,
			0xb0,0x7b,0xf7,0x4a,0x30,0x8f,0x03,0x72,0xfd,0x6b,0x71,0x28,0x10,0x79,0x01,0xdb,
			0xb0,0xcc,0xee,0xd3,0x48,0x91,0xb4,0xb5,0x33,0xbc,0x91,0x58,0x45,0x63,0x73,0x34
		},
		{
			0xff,0xf8,0x42,0xf2,0x8e,0xd1,0xd5,0x4a,0xac,0xef,0x63,0x94,0x23,0xad,0x94,0x61,
			0x6a,0xa7,0xf6,0x03,0x6a,0x82,0x60,0x88,0x8d,0x72,0x06,0xb4,0x99,0xe1,0x88,0x5c,
			0x6b,0xe1,0xb8,0x35,0x37,0x4b,0x7a,0x37,0x87,0xdb,0x2e,0x76,0x62,0xab,0x6f,0xdd
		},
		{
			0x66,0x64,0xa9,0x5c,0x50,0x4e,0x3f,0xa5,0x3b,0xc8,0xa9,0x72,0x08,0xd1,0x4a,0xa8,
			0x1a,0x14,0xff,0x63,0x96,0xa8,0xe9,0xc9,0x73,0x92,0x3e,0xb0,0x52,0xf9,0xaf,0xb4,
			0xb6,0xf3,0xbc,0x42,0xbc,0x98,0x22,0x21,0x00,0x1e,0xe5,0xee,0xfa,0x89,0x95,0x42
		},
		{
			0xee,0x9d,0xad,0x64,0x9f,0x1d,0xc1,0xd4,0x24,0x43,0x75,0xae,0x02,0xec,0x12,0xc7,
			0x01,0x50,0x86,0x82,0xbf,0x54,0x5d,0x44,0x62,0xcf,0x11,0xfd,0x06,0xed,0x5d,0xd6,
			0x62,0x46,0x03,0xfe,0xd3,0xa0,0xda,0x7a,0x46,0x90,0x15,0x1f,0x0e,0x64,0xa6,0xb4
		}
	};
	uint8_t measurements[5][SHA384_HASH_LENGTH] = {
		{
			0xc4,0x47,0xac,0x69,0xc4,0xf6,0xec,0xc3,0x82,0xb2,0x43,0x87,0xc2,0x64,0x12,0x12,
			0xd1,0xe1,0xa8,0xd1,0x01,0xf8,0x4b,0xe5,0x5f,0xad,0xb3,0xea,0xc1,0x48,0x12,0x7b,
			0x68,0xc6,0xf8,0x22,0x3c,0xb7,0xf1,0x28,0xac,0x86,0x27,0x8c,0xfe,0xd4,0xa3,0xd7
		},
		{
			0x07,0xbe,0xa3,0x33,0x42,0x5e,0x29,0x6d,0x6b,0x84,0xf0,0x9e,0x7c,0x1d,0x53,0xd9,
			0x06,0x74,0x03,0xf0,0x96,0x3d,0xcf,0x73,0x4a,0xe8,0x1f,0x43,0xdd,0xec,0xf6,0x04,
			0x8c,0xca,0x0a,0xd8,0x71,0xc0,0x43,0x59,0x20,0x03,0xf8,0x5f,0x1e,0x34,0x9c,0x4b
		},
		{
			0xe6,0xc4,0x81,0x28,0xd2,0x13,0x67,0xec,0xb9,0x53,0xf3,0xf6,0xda,0x31,0x5a,0x93,
			0xc4,0x0b,0x40,0xb5,0x19,0xd8,0x08,0xfb,0xbc,0xef,0xb6,0xd9,0xaa,0x69,0xd2,0xfc,
			0xdc,0x14,0xe0,0x16,0x2c,0xbe,0xad,0xd1,0x0d,0x4d,0xe0,0x1b,0x94,0xaf,0x68,0x5b
		},
		{
			0x61,0xbb,0xc5,0x59,0x25,0x95,0x1b,0x8f,0xdb,0xf7,0x55,0x80,0x0a,0x63,0x00,0xd8,
			0x20,0x6b,0x31,0x17,0x07,0x1e,0x01,0x1f,0xd4,0x08,0xff,0xec,0x29,0x9b,0x84,0x08,
			0x92,0xf2,0x23,0xd3,0xba,0x7b,0x07,0xb6,0xd0,0x8c,0x40,0xb9,0x69,0xe5,0xe6,0xd0
		},
		{
			0xed,0xfc,0x52,0x5c,0x47,0x13,0x80,0x56,0xdd,0x9c,0x72,0x10,0x62,0xcd,0x98,0x3f,
			0xbb,0x80,0x0f,0x62,0x3f,0xda,0x91,0xc6,0xb7,0x0e,0xc7,0x67,0xd2,0x65,0x91,0xca,
			0x7b,0x9f,0x3a,0x0b,0xb1,0x10,0x07,0x66,0x55,0xf4,0x10,0xef,0xaf,0x81,0x85,0x16
		}
	};
	struct pcr_store_attestation_log_entry_sha384 expected[5];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA384_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha384);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0C;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x1A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA384_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA384_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA384_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA384_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x1A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha256_and_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t digests[6][SHA384_HASH_LENGTH] = {
		{
			0xe0,0x26,0x8c,0xee,0xd9,0xaf,0x17,0xe1,0xce,0xee,0xab,0x9a,0x5b,0xd9,0xec,0x29,
			0x4f,0xfa,0xf8,0xd2,0x3b,0x8d,0x8e,0x88,0x45,0x7c,0xec,0x1b,0xb6,0x7e,0xd6,0x05
		},
		{
			0xb5,0x1d,0xb8,0x0d,0x49,0x71,0x72,0x1e,0x1c,0x06,0x99,0x8a,0xd5,0x0b,0x34,0x3b,
			0xb0,0xcc,0xee,0xd3,0x48,0x91,0xb4,0xb5,0x33,0xbc,0x91,0x58,0x45,0x63,0x73,0x34
		},
		{
			0x6a,0xa7,0xf6,0x03,0x6a,0x82,0x60,0x88,0x8d,0x72,0x06,0xb4,0x99,0xe1,0x88,0x5c,
			0x6b,0xe1,0xb8,0x35,0x37,0x4b,0x7a,0x37,0x87,0xdb,0x2e,0x76,0x62,0xab,0x6f,0xdd
		},
		{
			0x66,0x64,0xa9,0x5c,0x50,0x4e,0x3f,0xa5,0x3b,0xc8,0xa9,0x72,0x08,0xd1,0x4a,0xa8,
			0x1a,0x14,0xff,0x63,0x96,0xa8,0xe9,0xc9,0x73,0x92,0x3e,0xb0,0x52,0xf9,0xaf,0xb4
		},
		{
			0xee,0x9d,0xad,0x64,0x9f,0x1d,0xc1,0xd4,0x24,0x43,0x75,0xae,0x02,0xec,0x12,0xc7,
			0x01,0x50,0x86,0x82,0xbf,0x54,0x5d,0x44,0x62,0xcf,0x11,0xfd,0x06,0xed,0x5d,0xd6,
			0x62,0x46,0x03,0xfe,0xd3,0xa0,0xda,0x7a,0x46,0x90,0x15,0x1f,0x0e,0x64,0xa6,0xb4
		},
		{
			0x06,0xcf,0x86,0xa2,0x59,0xd6,0x1d,0x00,0x2b,0xea,0xc8,0xbe,0x76,0x31,0x40,0x25,
			0xe9,0x85,0xfc,0x45,0x51,0x9c,0x7d,0xe7,0xc6,0xf0,0xcd,0x1b,0x8d,0xb5,0x2c,0x73,
			0xdd,0x8e,0xdd,0x43,0x98,0x4d,0xcb,0x00,0x47,0xaf,0x91,0x45,0x22,0xb6,0x26,0x69
		}
	};
	uint8_t measurements[6][SHA384_HASH_LENGTH] = {
		{
			0xc4,0x47,0xac,0x69,0xc4,0xf6,0xec,0xc3,0x82,0xb2,0x43,0x87,0xc2,0x64,0x12,0x12,
			0xd1,0xe1,0xa8,0xd1,0x01,0xf8,0x4b,0xe5,0x5f,0xad,0xb3,0xea,0xc1,0x48,0x12,0x7b
		},
		{
			0x07,0xbe,0xa3,0x33,0x42,0x5e,0x29,0x6d,0x6b,0x84,0xf0,0x9e,0x7c,0x1d,0x53,0xd9,
			0x8c,0xca,0x0a,0xd8,0x71,0xc0,0x43,0x59,0x20,0x03,0xf8,0x5f,0x1e,0x34,0x9c,0x4b
		},
		{
			0xc4,0x0b,0x40,0xb5,0x19,0xd8,0x08,0xfb,0xbc,0xef,0xb6,0xd9,0xaa,0x69,0xd2,0xfc,
			0xdc,0x14,0xe0,0x16,0x2c,0xbe,0xad,0xd1,0x0d,0x4d,0xe0,0x1b,0x94,0xaf,0x68,0x5b
		},
		{
			0x61,0xbb,0xc5,0x59,0x25,0x95,0x1b,0x8f,0xdb,0xf7,0x55,0x80,0x0a,0x63,0x00,0xd8,
			0x20,0x6b,0x31,0x17,0x07,0x1e,0x01,0x1f,0xd4,0x08,0xff,0xec,0x29,0x9b,0x84,0x08
		},
		{
			0xed,0xfc,0x52,0x5c,0x47,0x13,0x80,0x56,0xdd,0x9c,0x72,0x10,0x62,0xcd,0x98,0x3f,
			0xbb,0x80,0x0f,0x62,0x3f,0xda,0x91,0xc6,0xb7,0x0e,0xc7,0x67,0xd2,0x65,0x91,0xca,
			0x7b,0x9f,0x3a,0x0b,0xb1,0x10,0x07,0x66,0x55,0xf4,0x10,0xef,0xaf,0x81,0x85,0x16
		},
		{
			0x52,0xd8,0x2e,0xc3,0x3d,0x2e,0xe6,0x8b,0x3c,0x04,0xdb,0x76,0x9e,0x79,0xc8,0x0d,
			0x88,0x82,0x8e,0xcc,0x36,0xed,0x26,0x3c,0x5e,0x17,0x42,0x95,0x0c,0x85,0xb6,0xe6,
			0x37,0xe0,0x62,0x89,0xf5,0xd8,0x34,0x9b,0xca,0x2e,0x33,0x09,0xa3,0x88,0x7e,0x63
		}
	};
	const size_t expected_length = (4 * sizeof (struct pcr_store_attestation_log_entry_sha256)) +
		(2 * sizeof (struct pcr_store_attestation_log_entry_sha384));
	uint8_t expected[expected_length];
	uint8_t output[sizeof (expected) * 2];
	struct pcr_store_attestation_log_entry_sha256 *expected_sha256 = (void*) expected;
	struct pcr_store_attestation_log_entry_sha384 *expected_sha384 =
		(void*) &expected[4 * sizeof (struct pcr_store_attestation_log_entry_sha256)];
	uint16_t measurement_type;
	size_t digest_length;
	size_t i;
	size_t j;
	size_t k;
	size_t id;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, id = 0; k < ARRAY_SIZE (pcr_config); k++) {
		digest_length = hash_get_hash_length (pcr_config[k].measurement_algo);

		pcr_store_testing_mock_pcr_compute (test, &store, digests[id], measurements[id],
			sizeof (digests[0]), pcr_config[k].num_measurements, digest_length);

		for (i = 0, j = 0; i < pcr_config[k].num_measurements; i++, j++, id++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			if (pcr_config[k].measurement_algo == HASH_TYPE_SHA256) {
				expected_sha256[j].base.header.log_magic = 0xCB;
				expected_sha256[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha256);
				expected_sha256[j].base.header.entry_id = id;

				expected_sha256[j].base.info.digest_algorithm_id = 0x0B;
				expected_sha256[j].base.info.digest_count = 1;
				expected_sha256[j].base.info.event_type = 0x5A + id;
				expected_sha256[j].base.info.measurement_type = measurement_type;

				expected_sha256[j].entry.measurement_size = SHA256_HASH_LENGTH;
				memcpy (expected_sha256[j].entry.digest, digests[id], SHA256_HASH_LENGTH);
				memcpy (expected_sha256[j].entry.measurement, measurements[id], SHA256_HASH_LENGTH);
			}
			else {
				expected_sha384[j].base.header.log_magic = 0xCB;
				expected_sha384[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha384);
				expected_sha384[j].base.header.entry_id = id;

				expected_sha384[j].base.info.digest_algorithm_id = 0x0C;
				expected_sha384[j].base.info.digest_count = 1;
				expected_sha384[j].base.info.event_type = 0x5A + id;
				expected_sha384[j].base.info.measurement_type = measurement_type;

				expected_sha384[j].entry.measurement_size = SHA384_HASH_LENGTH;
				memcpy (expected_sha384[j].entry.digest, digests[id], SHA384_HASH_LENGTH);
				memcpy (expected_sha384[j].entry.measurement, measurements[id], SHA384_HASH_LENGTH);
			}

			status = pcr_store_update_digest (&store.test, measurement_type, digests[id],
				digest_length);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x5A + id);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha384_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t digests[6][SHA384_HASH_LENGTH] = {
		{
			0xe0,0x26,0x8c,0xee,0xd9,0xaf,0x17,0xe1,0xce,0xee,0xab,0x9a,0x5b,0xd9,0xec,0x29,
			0x4f,0xfa,0xf8,0xd2,0x3b,0x8d,0x8e,0x88,0x45,0x7c,0xec,0x1b,0xb6,0x7e,0xd6,0x05,
			0x4e,0x4c,0x84,0x95,0x85,0xcb,0x01,0x54,0x42,0xee,0xf3,0x71,0x08,0x47,0x42,0xff
		},
		{
			0xb5,0x1d,0xb8,0x0d,0x49,0x71,0x72,0x1e,0x1c,0x06,0x99,0x8a,0xd5,0x0b,0x34,0x3b,
			0xb0,0x7b,0xf7,0x4a,0x30,0x8f,0x03,0x72,0xfd,0x6b,0x71,0x28,0x10,0x79,0x01,0xdb,
			0xb0,0xcc,0xee,0xd3,0x48,0x91,0xb4,0xb5,0x33,0xbc,0x91,0x58,0x45,0x63,0x73,0x34
		},
		{
			0xff,0xf8,0x42,0xf2,0x8e,0xd1,0xd5,0x4a,0xac,0xef,0x63,0x94,0x23,0xad,0x94,0x61,
			0x6a,0xa7,0xf6,0x03,0x6a,0x82,0x60,0x88,0x8d,0x72,0x06,0xb4,0x99,0xe1,0x88,0x5c,
			0x6b,0xe1,0xb8,0x35,0x37,0x4b,0x7a,0x37,0x87,0xdb,0x2e,0x76,0x62,0xab,0x6f,0xdd
		},
		{
			0x66,0x64,0xa9,0x5c,0x50,0x4e,0x3f,0xa5,0x3b,0xc8,0xa9,0x72,0x08,0xd1,0x4a,0xa8,
			0x1a,0x14,0xff,0x63,0x96,0xa8,0xe9,0xc9,0x73,0x92,0x3e,0xb0,0x52,0xf9,0xaf,0xb4
		},
		{
			0xee,0x9d,0xad,0x64,0x9f,0x1d,0xc1,0xd4,0x24,0x43,0x75,0xae,0x02,0xec,0x12,0xc7,
			0x62,0x46,0x03,0xfe,0xd3,0xa0,0xda,0x7a,0x46,0x90,0x15,0x1f,0x0e,0x64,0xa6,0xb4
		},
		{
			0xe9,0x85,0xfc,0x45,0x51,0x9c,0x7d,0xe7,0xc6,0xf0,0xcd,0x1b,0x8d,0xb5,0x2c,0x73,
			0xdd,0x8e,0xdd,0x43,0x98,0x4d,0xcb,0x00,0x47,0xaf,0x91,0x45,0x22,0xb6,0x26,0x69
		}
	};
	uint8_t measurements[6][SHA384_HASH_LENGTH] = {
		{
			0xc4,0x47,0xac,0x69,0xc4,0xf6,0xec,0xc3,0x82,0xb2,0x43,0x87,0xc2,0x64,0x12,0x12,
			0xd1,0xe1,0xa8,0xd1,0x01,0xf8,0x4b,0xe5,0x5f,0xad,0xb3,0xea,0xc1,0x48,0x12,0x7b,
			0x68,0xc6,0xf8,0x22,0x3c,0xb7,0xf1,0x28,0xac,0x86,0x27,0x8c,0xfe,0xd4,0xa3,0xd7
		},
		{
			0x07,0xbe,0xa3,0x33,0x42,0x5e,0x29,0x6d,0x6b,0x84,0xf0,0x9e,0x7c,0x1d,0x53,0xd9,
			0x06,0x74,0x03,0xf0,0x96,0x3d,0xcf,0x73,0x4a,0xe8,0x1f,0x43,0xdd,0xec,0xf6,0x04,
			0x8c,0xca,0x0a,0xd8,0x71,0xc0,0x43,0x59,0x20,0x03,0xf8,0x5f,0x1e,0x34,0x9c,0x4b
		},
		{
			0xe6,0xc4,0x81,0x28,0xd2,0x13,0x67,0xec,0xb9,0x53,0xf3,0xf6,0xda,0x31,0x5a,0x93,
			0xc4,0x0b,0x40,0xb5,0x19,0xd8,0x08,0xfb,0xbc,0xef,0xb6,0xd9,0xaa,0x69,0xd2,0xfc,
			0xdc,0x14,0xe0,0x16,0x2c,0xbe,0xad,0xd1,0x0d,0x4d,0xe0,0x1b,0x94,0xaf,0x68,0x5b
		},
		{
			0x61,0xbb,0xc5,0x59,0x25,0x95,0x1b,0x8f,0xdb,0xf7,0x55,0x80,0x0a,0x63,0x00,0xd8,
			0x20,0x6b,0x31,0x17,0x07,0x1e,0x01,0x1f,0xd4,0x08,0xff,0xec,0x29,0x9b,0x84,0x08
		},
		{
			0xed,0xfc,0x52,0x5c,0x47,0x13,0x80,0x56,0xdd,0x9c,0x72,0x10,0x62,0xcd,0x98,0x3f,
			0x7b,0x9f,0x3a,0x0b,0xb1,0x10,0x07,0x66,0x55,0xf4,0x10,0xef,0xaf,0x81,0x85,0x16
		},
		{
			0x88,0x82,0x8e,0xcc,0x36,0xed,0x26,0x3c,0x5e,0x17,0x42,0x95,0x0c,0x85,0xb6,0xe6,
			0x37,0xe0,0x62,0x89,0xf5,0xd8,0x34,0x9b,0xca,0x2e,0x33,0x09,0xa3,0x88,0x7e,0x63
		}
	};
	const size_t expected_length = (3 * sizeof (struct pcr_store_attestation_log_entry_sha384)) +
		(3 * sizeof (struct pcr_store_attestation_log_entry_sha256));
	uint8_t expected[expected_length];
	uint8_t output[sizeof (expected) * 2];
	struct pcr_store_attestation_log_entry_sha384 *expected_sha384 = (void*) expected;
	struct pcr_store_attestation_log_entry_sha256 *expected_sha256 =
		(void*) &expected[3 * sizeof (struct pcr_store_attestation_log_entry_sha384)];
	uint16_t measurement_type;
	size_t digest_length;
	size_t i;
	size_t j;
	size_t k;
	size_t id;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, id = 0; k < ARRAY_SIZE (pcr_config); k++) {
		digest_length = hash_get_hash_length (pcr_config[k].measurement_algo);

		pcr_store_testing_mock_pcr_compute (test, &store, digests[id], measurements[id],
			sizeof (digests[0]), pcr_config[k].num_measurements, digest_length);

		for (i = 0, j = 0; i < pcr_config[k].num_measurements; i++, j++, id++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			if (pcr_config[k].measurement_algo == HASH_TYPE_SHA256) {
				expected_sha256[j].base.header.log_magic = 0xCB;
				expected_sha256[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha256);
				expected_sha256[j].base.header.entry_id = id;

				expected_sha256[j].base.info.digest_algorithm_id = 0x0B;
				expected_sha256[j].base.info.digest_count = 1;
				expected_sha256[j].base.info.event_type = 0x5A + id;
				expected_sha256[j].base.info.measurement_type = measurement_type;

				expected_sha256[j].entry.measurement_size = SHA256_HASH_LENGTH;
				memcpy (expected_sha256[j].entry.digest, digests[id], SHA256_HASH_LENGTH);
				memcpy (expected_sha256[j].entry.measurement, measurements[id], SHA256_HASH_LENGTH);
			}
			else {
				expected_sha384[j].base.header.log_magic = 0xCB;
				expected_sha384[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha384);
				expected_sha384[j].base.header.entry_id = id;

				expected_sha384[j].base.info.digest_algorithm_id = 0x0C;
				expected_sha384[j].base.info.digest_count = 1;
				expected_sha384[j].base.info.event_type = 0x5A + id;
				expected_sha384[j].base.info.measurement_type = measurement_type;

				expected_sha384[j].entry.measurement_size = SHA384_HASH_LENGTH;
				memcpy (expected_sha384[j].entry.digest, digests[id], SHA384_HASH_LENGTH);
				memcpy (expected_sha384[j].entry.measurement, measurements[id], SHA384_HASH_LENGTH);
			}

			status = pcr_store_update_digest (&store.test, measurement_type, digests[id],
				digest_length);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x5A + id);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_store_test_get_attestation_log_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t digests[6][SHA512_HASH_LENGTH] = {
		{
			0x59,0x41,0x6f,0xe1,0x3b,0x5e,0xad,0x57,0x8e,0x08,0x3c,0x22,0xbe,0xd6,0xcf,0x79,
			0xa3,0xd3,0xfc,0x23,0x6e,0x79,0xb2,0xdf,0xff,0x52,0x5a,0xd7,0xca,0x70,0x48,0x7e,
			0xf0,0x63,0x2a,0xc7,0x28,0xcf,0x07,0x8a,0x88,0xe2,0x76,0x0e,0xa6,0x86,0x01,0x8f,
			0xfc,0x95,0xaf,0x5b,0xc7,0x01,0x49,0x41,0x39,0xeb,0x5b,0xc6,0x5d,0x59,0x0d,0xc2
		},
		{
			0x19,0x71,0x35,0x8a,0x21,0x61,0x17,0x12,0xb8,0x27,0xc1,0xdb,0x6b,0x5c,0xf0,0x1e,
			0xca,0x6d,0xa3,0xe1,0xb4,0x70,0x32,0xae,0xe5,0x06,0xff,0x23,0x77,0x31,0x6d,0x71,
			0x1f,0x0e,0x53,0x55,0x03,0x25,0xab,0xc8,0xd8,0xb2,0x70,0x5b,0x05,0x44,0xa6,0xf2,
			0xee,0x15,0x17,0xc1,0x1f,0xb1,0xb6,0x2f,0x33,0x5e,0x7a,0x5a,0xe1,0xdc,0x71,0x3a
		},
		{
			0x5b,0xdb,0x6c,0x00,0xb1,0xed,0xfc,0xd0,0xb5,0x6a,0x8b,0x31,0xe1,0x32,0x2f,0x3d,
			0xbc,0x99,0x12,0x82,0x77,0xb5,0x95,0x10,0x3c,0xe3,0xc9,0x6b,0xae,0x75,0x13,0x51,
			0xd2,0x9a,0xaf,0x94,0xf7,0x10,0xbf,0xbd,0xe1,0x86,0x53,0xc6,0xa2,0x4c,0x3e,0xed,
			0x38,0xc0,0xc8,0x7c,0x3a,0xdf,0xe9,0x2c,0x64,0x9c,0x2f,0xa1,0x54,0xe1,0x40,0x59
		},
		{
			0x9e,0x61,0x8e,0xc4,0x16,0x3a,0xa5,0x2a,0x20,0x60,0x54,0xaa,0x82,0x4a,0x14,0x03,
			0x59,0x36,0x05,0x99,0xa6,0x04,0xf6,0xbf,0x73,0x07,0xc9,0x7f,0x4d,0x1e,0xa5,0xb2,
			0xc2,0x0f,0x61,0x56,0xb5,0xea,0xa2,0x0f,0xf0,0x73,0x30,0x80,0xc5,0xfc,0xe6,0xd0,
			0x47,0x30,0xd8,0x53,0xf8,0x83,0x89,0x91,0xa9,0xcd,0x4b,0x55,0x1f,0xc3,0xb3,0xa8
		},
		{
			0x19,0xef,0x8b,0x4e,0x7b,0xea,0x86,0x79,0xc3,0x31,0xa0,0xd3,0x8c,0xa8,0x69,0x0b,
			0xc1,0x60,0x28,0x4e,0x9e,0xae,0x88,0x1f,0xf6,0x25,0x7a,0x40,0xe0,0xa6,0x69,0xa2,
			0x26,0x08,0x99,0x44,0x2c,0x83,0x44,0x8e,0xb1,0xfe,0xb2,0x26,0xed,0x03,0x1b,0x38,
			0xa2,0x2d,0x43,0x3d,0x55,0xdf,0x12,0x7c,0xc0,0xe4,0x8f,0x69,0x04,0x50,0x1b,0xa4
		},
		{
			0xe0,0x71,0x03,0xa9,0x37,0xa7,0x9e,0x9f,0x4e,0xd2,0x4f,0x06,0x1e,0x12,0x3c,0x84,
			0x36,0xaa,0xe3,0x30,0x79,0xa1,0x15,0xa7,0x36,0xf5,0x09,0xae,0x68,0x23,0x00,0x1c,
			0xe2,0x54,0x03,0xe7,0x19,0x1a,0x28,0x8f,0xbd,0x9a,0x18,0x8f,0x1a,0xfe,0x71,0xf5,
			0xc1,0x33,0x12,0xb1,0xda,0xdf,0xe4,0x97,0x7b,0x76,0x8e,0xa3,0x0b,0x28,0x94,0xc7
		}
	};
	uint8_t measurements[6][SHA512_HASH_LENGTH] = {
		{
			0xa5,0xeb,0x17,0x77,0x62,0x22,0xe5,0x61,0x2c,0x50,0xc3,0x63,0x1e,0xcb,0x19,0x60,
			0xc0,0x8b,0xd3,0xfd,0x90,0xd1,0x4d,0x0c,0x05,0xc3,0x60,0xd3,0x43,0x10,0x04,0x66,
			0xcd,0xce,0xf1,0x88,0x34,0xdb,0xa4,0xbf,0x24,0x6d,0x52,0x33,0xa3,0x78,0xd6,0x04,
			0x50,0xbe,0x43,0x54,0xf2,0x1f,0xa5,0xc3,0x53,0xaa,0x88,0x5a,0x7d,0x07,0xfe,0x6f
		},
		{
			0xd6,0x40,0x4b,0x06,0x36,0xb4,0x9a,0x63,0x44,0x2b,0xef,0x6c,0x8f,0xa7,0xb8,0x0a,
			0x03,0xf2,0x13,0x9d,0xea,0x7a,0x53,0xd9,0x38,0x01,0x15,0x5b,0xcb,0x4f,0x0d,0x67,
			0xe7,0xca,0xea,0xc0,0x4a,0x7a,0xdf,0x25,0x70,0x97,0x95,0xba,0xde,0x94,0xef,0xc6,
			0x6a,0x63,0x40,0xfe,0xcf,0xc4,0x59,0x9b,0xc9,0x68,0x1b,0xf5,0x10,0x3b,0xb7,0x82
		},
		{
			0xb8,0x76,0xbd,0xc9,0x22,0x43,0xa0,0x01,0xcb,0xfd,0x91,0x26,0xac,0xc0,0xf8,0xae,
			0xeb,0xfd,0xbb,0x16,0xff,0xa3,0x80,0xab,0x51,0x29,0x26,0xdf,0x50,0x37,0xe1,0x6c,
			0x11,0x17,0x66,0x47,0xc6,0x9e,0x00,0xea,0xb7,0xe1,0xd2,0xae,0x64,0xc4,0x6f,0x4c,
			0x54,0x2b,0xb0,0x8a,0x58,0xed,0xc3,0x81,0x26,0x23,0xec,0xfd,0x83,0xec,0xe0,0x17
		},
		{
			0xdd,0xee,0x99,0x00,0x79,0x01,0x21,0x20,0xba,0x5a,0x84,0xdb,0x80,0xf6,0x4b,0x29,
			0x95,0xd5,0x0d,0xcf,0xbe,0xdd,0x14,0x1e,0xf0,0x6e,0xa2,0x83,0xe8,0xb3,0x37,0xe5,
			0xed,0xc4,0x78,0x74,0x8a,0x38,0xc1,0xb3,0x03,0xcc,0xe8,0xec,0xcd,0xf0,0x86,0x96,
			0x10,0xdb,0x7a,0xf6,0x4f,0xef,0x25,0x4b,0xc8,0x26,0xd2,0xc2,0x57,0xad,0x5a,0xfb
		},
		{
			0x22,0xe5,0x5b,0xa8,0xb7,0x18,0x90,0x6e,0x4d,0xa5,0xb9,0x28,0x4b,0x3a,0xaf,0x1c,
			0x9d,0xb4,0xb8,0x02,0x03,0x8f,0x8e,0xf2,0xaa,0xb7,0x68,0xfa,0xc8,0x0f,0xcc,0x33,
			0x82,0x51,0x40,0xa2,0xed,0x93,0xa5,0x07,0x81,0x16,0xbf,0xef,0x6b,0xba,0xc6,0xf8,
			0x1e,0x97,0x6d,0x56,0x0b,0xc2,0xa0,0x48,0x7c,0x2f,0x75,0xfc,0x5c,0x44,0x75,0x47
		},
		{
			0x02,0xb0,0xa0,0x9b,0x63,0x0f,0xe8,0xb0,0x59,0x02,0x91,0xd9,0x65,0x28,0xaa,0xc2,
			0x25,0x35,0xea,0x16,0x2c,0xb5,0x4a,0x93,0x4c,0xeb,0x39,0xfb,0xd8,0x45,0x67,0x99,
			0x38,0xa4,0xb1,0x30,0x4c,0x91,0xc1,0x9f,0x63,0xac,0x03,0x1b,0xc1,0xcd,0x3c,0x34,
			0x24,0x4a,0xf4,0x0f,0x06,0x8c,0xc9,0x1d,0x3f,0x29,0x9f,0xd6,0xd2,0xd3,0x8e,0xff
		}
	};
	struct pcr_store_attestation_log_entry_sha512 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA512_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha512);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0D;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x2A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA512_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA512_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA512_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA512_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x2A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha512_invalid_entry (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t digests[6][SHA512_HASH_LENGTH] = {
		{
			0x59,0x41,0x6f,0xe1,0x3b,0x5e,0xad,0x57,0x8e,0x08,0x3c,0x22,0xbe,0xd6,0xcf,0x79,
			0xa3,0xd3,0xfc,0x23,0x6e,0x79,0xb2,0xdf,0xff,0x52,0x5a,0xd7,0xca,0x70,0x48,0x7e,
			0xf0,0x63,0x2a,0xc7,0x28,0xcf,0x07,0x8a,0x88,0xe2,0x76,0x0e,0xa6,0x86,0x01,0x8f,
			0xfc,0x95,0xaf,0x5b,0xc7,0x01,0x49,0x41,0x39,0xeb,0x5b,0xc6,0x5d,0x59,0x0d,0xc2
		},
		{
			0x19,0x71,0x35,0x8a,0x21,0x61,0x17,0x12,0xb8,0x27,0xc1,0xdb,0x6b,0x5c,0xf0,0x1e,
			0xca,0x6d,0xa3,0xe1,0xb4,0x70,0x32,0xae,0xe5,0x06,0xff,0x23,0x77,0x31,0x6d,0x71,
			0x1f,0x0e,0x53,0x55,0x03,0x25,0xab,0xc8,0xd8,0xb2,0x70,0x5b,0x05,0x44,0xa6,0xf2,
			0xee,0x15,0x17,0xc1,0x1f,0xb1,0xb6,0x2f,0x33,0x5e,0x7a,0x5a,0xe1,0xdc,0x71,0x3a
		},
		{
			0x5b,0xdb,0x6c,0x00,0xb1,0xed,0xfc,0xd0,0xb5,0x6a,0x8b,0x31,0xe1,0x32,0x2f,0x3d,
			0xbc,0x99,0x12,0x82,0x77,0xb5,0x95,0x10,0x3c,0xe3,0xc9,0x6b,0xae,0x75,0x13,0x51,
			0xd2,0x9a,0xaf,0x94,0xf7,0x10,0xbf,0xbd,0xe1,0x86,0x53,0xc6,0xa2,0x4c,0x3e,0xed,
			0x38,0xc0,0xc8,0x7c,0x3a,0xdf,0xe9,0x2c,0x64,0x9c,0x2f,0xa1,0x54,0xe1,0x40,0x59
		},
		{
			0x9e,0x61,0x8e,0xc4,0x16,0x3a,0xa5,0x2a,0x20,0x60,0x54,0xaa,0x82,0x4a,0x14,0x03,
			0x59,0x36,0x05,0x99,0xa6,0x04,0xf6,0xbf,0x73,0x07,0xc9,0x7f,0x4d,0x1e,0xa5,0xb2,
			0xc2,0x0f,0x61,0x56,0xb5,0xea,0xa2,0x0f,0xf0,0x73,0x30,0x80,0xc5,0xfc,0xe6,0xd0,
			0x47,0x30,0xd8,0x53,0xf8,0x83,0x89,0x91,0xa9,0xcd,0x4b,0x55,0x1f,0xc3,0xb3,0xa8
		},
		{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		},
		{
			0xe0,0x71,0x03,0xa9,0x37,0xa7,0x9e,0x9f,0x4e,0xd2,0x4f,0x06,0x1e,0x12,0x3c,0x84,
			0x36,0xaa,0xe3,0x30,0x79,0xa1,0x15,0xa7,0x36,0xf5,0x09,0xae,0x68,0x23,0x00,0x1c,
			0xe2,0x54,0x03,0xe7,0x19,0x1a,0x28,0x8f,0xbd,0x9a,0x18,0x8f,0x1a,0xfe,0x71,0xf5,
			0xc1,0x33,0x12,0xb1,0xda,0xdf,0xe4,0x97,0x7b,0x76,0x8e,0xa3,0x0b,0x28,0x94,0xc7
		}
	};
	uint8_t measurements[6][SHA512_HASH_LENGTH] = {
		{
			0xa5,0xeb,0x17,0x77,0x62,0x22,0xe5,0x61,0x2c,0x50,0xc3,0x63,0x1e,0xcb,0x19,0x60,
			0xc0,0x8b,0xd3,0xfd,0x90,0xd1,0x4d,0x0c,0x05,0xc3,0x60,0xd3,0x43,0x10,0x04,0x66,
			0xcd,0xce,0xf1,0x88,0x34,0xdb,0xa4,0xbf,0x24,0x6d,0x52,0x33,0xa3,0x78,0xd6,0x04,
			0x50,0xbe,0x43,0x54,0xf2,0x1f,0xa5,0xc3,0x53,0xaa,0x88,0x5a,0x7d,0x07,0xfe,0x6f
		},
		{
			0xd6,0x40,0x4b,0x06,0x36,0xb4,0x9a,0x63,0x44,0x2b,0xef,0x6c,0x8f,0xa7,0xb8,0x0a,
			0x03,0xf2,0x13,0x9d,0xea,0x7a,0x53,0xd9,0x38,0x01,0x15,0x5b,0xcb,0x4f,0x0d,0x67,
			0xe7,0xca,0xea,0xc0,0x4a,0x7a,0xdf,0x25,0x70,0x97,0x95,0xba,0xde,0x94,0xef,0xc6,
			0x6a,0x63,0x40,0xfe,0xcf,0xc4,0x59,0x9b,0xc9,0x68,0x1b,0xf5,0x10,0x3b,0xb7,0x82
		},
		{
			0xb8,0x76,0xbd,0xc9,0x22,0x43,0xa0,0x01,0xcb,0xfd,0x91,0x26,0xac,0xc0,0xf8,0xae,
			0xeb,0xfd,0xbb,0x16,0xff,0xa3,0x80,0xab,0x51,0x29,0x26,0xdf,0x50,0x37,0xe1,0x6c,
			0x11,0x17,0x66,0x47,0xc6,0x9e,0x00,0xea,0xb7,0xe1,0xd2,0xae,0x64,0xc4,0x6f,0x4c,
			0x54,0x2b,0xb0,0x8a,0x58,0xed,0xc3,0x81,0x26,0x23,0xec,0xfd,0x83,0xec,0xe0,0x17
		},
		{
			0xdd,0xee,0x99,0x00,0x79,0x01,0x21,0x20,0xba,0x5a,0x84,0xdb,0x80,0xf6,0x4b,0x29,
			0x95,0xd5,0x0d,0xcf,0xbe,0xdd,0x14,0x1e,0xf0,0x6e,0xa2,0x83,0xe8,0xb3,0x37,0xe5,
			0xed,0xc4,0x78,0x74,0x8a,0x38,0xc1,0xb3,0x03,0xcc,0xe8,0xec,0xcd,0xf0,0x86,0x96,
			0x10,0xdb,0x7a,0xf6,0x4f,0xef,0x25,0x4b,0xc8,0x26,0xd2,0xc2,0x57,0xad,0x5a,0xfb
		},
		{
			0x22,0xe5,0x5b,0xa8,0xb7,0x18,0x90,0x6e,0x4d,0xa5,0xb9,0x28,0x4b,0x3a,0xaf,0x1c,
			0x9d,0xb4,0xb8,0x02,0x03,0x8f,0x8e,0xf2,0xaa,0xb7,0x68,0xfa,0xc8,0x0f,0xcc,0x33,
			0x82,0x51,0x40,0xa2,0xed,0x93,0xa5,0x07,0x81,0x16,0xbf,0xef,0x6b,0xba,0xc6,0xf8,
			0x1e,0x97,0x6d,0x56,0x0b,0xc2,0xa0,0x48,0x7c,0x2f,0x75,0xfc,0x5c,0x44,0x75,0x47
		},
		{
			0x02,0xb0,0xa0,0x9b,0x63,0x0f,0xe8,0xb0,0x59,0x02,0x91,0xd9,0x65,0x28,0xaa,0xc2,
			0x25,0x35,0xea,0x16,0x2c,0xb5,0x4a,0x93,0x4c,0xeb,0x39,0xfb,0xd8,0x45,0x67,0x99,
			0x38,0xa4,0xb1,0x30,0x4c,0x91,0xc1,0x9f,0x63,0xac,0x03,0x1b,0xc1,0xcd,0x3c,0x34,
			0x24,0x4a,0xf4,0x0f,0x06,0x8c,0xc9,0x1d,0x3f,0x29,0x9f,0xd6,0xd2,0xd3,0x8e,0xff
		}
	};
	struct pcr_store_attestation_log_entry_sha512 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA512_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha512);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0D;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x2A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA512_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA512_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA512_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA512_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x2A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha512_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x59,0x41,0x6f,0xe1,0x3b,0x5e,0xad,0x57,0x8e,0x08,0x3c,0x22,0xbe,0xd6,0xcf,0x79,
			0xa3,0xd3,0xfc,0x23,0x6e,0x79,0xb2,0xdf,0xff,0x52,0x5a,0xd7,0xca,0x70,0x48,0x7e,
			0xf0,0x63,0x2a,0xc7,0x28,0xcf,0x07,0x8a,0x88,0xe2,0x76,0x0e,0xa6,0x86,0x01,0x8f,
			0xfc,0x95,0xaf,0x5b,0xc7,0x01,0x49,0x41,0x39,0xeb,0x5b,0xc6,0x5d,0x59,0x0d,0xc2
		},
		{
			0x19,0x71,0x35,0x8a,0x21,0x61,0x17,0x12,0xb8,0x27,0xc1,0xdb,0x6b,0x5c,0xf0,0x1e,
			0xca,0x6d,0xa3,0xe1,0xb4,0x70,0x32,0xae,0xe5,0x06,0xff,0x23,0x77,0x31,0x6d,0x71,
			0x1f,0x0e,0x53,0x55,0x03,0x25,0xab,0xc8,0xd8,0xb2,0x70,0x5b,0x05,0x44,0xa6,0xf2,
			0xee,0x15,0x17,0xc1,0x1f,0xb1,0xb6,0x2f,0x33,0x5e,0x7a,0x5a,0xe1,0xdc,0x71,0x3a
		},
		{
			0x5b,0xdb,0x6c,0x00,0xb1,0xed,0xfc,0xd0,0xb5,0x6a,0x8b,0x31,0xe1,0x32,0x2f,0x3d,
			0xbc,0x99,0x12,0x82,0x77,0xb5,0x95,0x10,0x3c,0xe3,0xc9,0x6b,0xae,0x75,0x13,0x51,
			0xd2,0x9a,0xaf,0x94,0xf7,0x10,0xbf,0xbd,0xe1,0x86,0x53,0xc6,0xa2,0x4c,0x3e,0xed,
			0x38,0xc0,0xc8,0x7c,0x3a,0xdf,0xe9,0x2c,0x64,0x9c,0x2f,0xa1,0x54,0xe1,0x40,0x59
		},
		{
			0x9e,0x61,0x8e,0xc4,0x16,0x3a,0xa5,0x2a,0x20,0x60,0x54,0xaa,0x82,0x4a,0x14,0x03,
			0x59,0x36,0x05,0x99,0xa6,0x04,0xf6,0xbf,0x73,0x07,0xc9,0x7f,0x4d,0x1e,0xa5,0xb2,
			0xc2,0x0f,0x61,0x56,0xb5,0xea,0xa2,0x0f,0xf0,0x73,0x30,0x80,0xc5,0xfc,0xe6,0xd0,
			0x47,0x30,0xd8,0x53,0xf8,0x83,0x89,0x91,0xa9,0xcd,0x4b,0x55,0x1f,0xc3,0xb3,0xa8
		},
		{
			0x19,0xef,0x8b,0x4e,0x7b,0xea,0x86,0x79,0xc3,0x31,0xa0,0xd3,0x8c,0xa8,0x69,0x0b,
			0xc1,0x60,0x28,0x4e,0x9e,0xae,0x88,0x1f,0xf6,0x25,0x7a,0x40,0xe0,0xa6,0x69,0xa2,
			0x26,0x08,0x99,0x44,0x2c,0x83,0x44,0x8e,0xb1,0xfe,0xb2,0x26,0xed,0x03,0x1b,0x38,
			0xa2,0x2d,0x43,0x3d,0x55,0xdf,0x12,0x7c,0xc0,0xe4,0x8f,0x69,0x04,0x50,0x1b,0xa4
		}
	};
	uint8_t measurements[5][SHA512_HASH_LENGTH] = {
		{
			0xa5,0xeb,0x17,0x77,0x62,0x22,0xe5,0x61,0x2c,0x50,0xc3,0x63,0x1e,0xcb,0x19,0x60,
			0xc0,0x8b,0xd3,0xfd,0x90,0xd1,0x4d,0x0c,0x05,0xc3,0x60,0xd3,0x43,0x10,0x04,0x66,
			0xcd,0xce,0xf1,0x88,0x34,0xdb,0xa4,0xbf,0x24,0x6d,0x52,0x33,0xa3,0x78,0xd6,0x04,
			0x50,0xbe,0x43,0x54,0xf2,0x1f,0xa5,0xc3,0x53,0xaa,0x88,0x5a,0x7d,0x07,0xfe,0x6f
		},
		{
			0xd6,0x40,0x4b,0x06,0x36,0xb4,0x9a,0x63,0x44,0x2b,0xef,0x6c,0x8f,0xa7,0xb8,0x0a,
			0x03,0xf2,0x13,0x9d,0xea,0x7a,0x53,0xd9,0x38,0x01,0x15,0x5b,0xcb,0x4f,0x0d,0x67,
			0xe7,0xca,0xea,0xc0,0x4a,0x7a,0xdf,0x25,0x70,0x97,0x95,0xba,0xde,0x94,0xef,0xc6,
			0x6a,0x63,0x40,0xfe,0xcf,0xc4,0x59,0x9b,0xc9,0x68,0x1b,0xf5,0x10,0x3b,0xb7,0x82
		},
		{
			0xb8,0x76,0xbd,0xc9,0x22,0x43,0xa0,0x01,0xcb,0xfd,0x91,0x26,0xac,0xc0,0xf8,0xae,
			0xeb,0xfd,0xbb,0x16,0xff,0xa3,0x80,0xab,0x51,0x29,0x26,0xdf,0x50,0x37,0xe1,0x6c,
			0x11,0x17,0x66,0x47,0xc6,0x9e,0x00,0xea,0xb7,0xe1,0xd2,0xae,0x64,0xc4,0x6f,0x4c,
			0x54,0x2b,0xb0,0x8a,0x58,0xed,0xc3,0x81,0x26,0x23,0xec,0xfd,0x83,0xec,0xe0,0x17
		},
		{
			0xdd,0xee,0x99,0x00,0x79,0x01,0x21,0x20,0xba,0x5a,0x84,0xdb,0x80,0xf6,0x4b,0x29,
			0x95,0xd5,0x0d,0xcf,0xbe,0xdd,0x14,0x1e,0xf0,0x6e,0xa2,0x83,0xe8,0xb3,0x37,0xe5,
			0xed,0xc4,0x78,0x74,0x8a,0x38,0xc1,0xb3,0x03,0xcc,0xe8,0xec,0xcd,0xf0,0x86,0x96,
			0x10,0xdb,0x7a,0xf6,0x4f,0xef,0x25,0x4b,0xc8,0x26,0xd2,0xc2,0x57,0xad,0x5a,0xfb
		},
		{
			0x22,0xe5,0x5b,0xa8,0xb7,0x18,0x90,0x6e,0x4d,0xa5,0xb9,0x28,0x4b,0x3a,0xaf,0x1c,
			0x9d,0xb4,0xb8,0x02,0x03,0x8f,0x8e,0xf2,0xaa,0xb7,0x68,0xfa,0xc8,0x0f,0xcc,0x33,
			0x82,0x51,0x40,0xa2,0xed,0x93,0xa5,0x07,0x81,0x16,0xbf,0xef,0x6b,0xba,0xc6,0xf8,
			0x1e,0x97,0x6d,0x56,0x0b,0xc2,0xa0,0x48,0x7c,0x2f,0x75,0xfc,0x5c,0x44,0x75,0x47
		}
	};
	struct pcr_store_attestation_log_entry_sha512 expected[5];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA512_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha512);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0D;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x2A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA512_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA512_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA512_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA512_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x2A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha256_and_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t digests[6][SHA512_HASH_LENGTH] = {
		{
			0x59,0x41,0x6f,0xe1,0x3b,0x5e,0xad,0x57,0x8e,0x08,0x3c,0x22,0xbe,0xd6,0xcf,0x79,
			0xa3,0xd3,0xfc,0x23,0x6e,0x79,0xb2,0xdf,0xff,0x52,0x5a,0xd7,0xca,0x70,0x48,0x7e,
		},
		{
			0x19,0x71,0x35,0x8a,0x21,0x61,0x17,0x12,0xb8,0x27,0xc1,0xdb,0x6b,0x5c,0xf0,0x1e,
			0xee,0x15,0x17,0xc1,0x1f,0xb1,0xb6,0x2f,0x33,0x5e,0x7a,0x5a,0xe1,0xdc,0x71,0x3a
		},
		{
			0x5b,0xdb,0x6c,0x00,0xb1,0xed,0xfc,0xd0,0xb5,0x6a,0x8b,0x31,0xe1,0x32,0x2f,0x3d,
			0xbc,0x99,0x12,0x82,0x77,0xb5,0x95,0x10,0x3c,0xe3,0xc9,0x6b,0xae,0x75,0x13,0x51,
			0xd2,0x9a,0xaf,0x94,0xf7,0x10,0xbf,0xbd,0xe1,0x86,0x53,0xc6,0xa2,0x4c,0x3e,0xed,
			0x38,0xc0,0xc8,0x7c,0x3a,0xdf,0xe9,0x2c,0x64,0x9c,0x2f,0xa1,0x54,0xe1,0x40,0x59
		},
		{
			0x9e,0x61,0x8e,0xc4,0x16,0x3a,0xa5,0x2a,0x20,0x60,0x54,0xaa,0x82,0x4a,0x14,0x03,
			0x59,0x36,0x05,0x99,0xa6,0x04,0xf6,0xbf,0x73,0x07,0xc9,0x7f,0x4d,0x1e,0xa5,0xb2,
			0xc2,0x0f,0x61,0x56,0xb5,0xea,0xa2,0x0f,0xf0,0x73,0x30,0x80,0xc5,0xfc,0xe6,0xd0,
			0x47,0x30,0xd8,0x53,0xf8,0x83,0x89,0x91,0xa9,0xcd,0x4b,0x55,0x1f,0xc3,0xb3,0xa8
		},
		{
			0x19,0xef,0x8b,0x4e,0x7b,0xea,0x86,0x79,0xc3,0x31,0xa0,0xd3,0x8c,0xa8,0x69,0x0b,
			0xc1,0x60,0x28,0x4e,0x9e,0xae,0x88,0x1f,0xf6,0x25,0x7a,0x40,0xe0,0xa6,0x69,0xa2,
			0x26,0x08,0x99,0x44,0x2c,0x83,0x44,0x8e,0xb1,0xfe,0xb2,0x26,0xed,0x03,0x1b,0x38,
			0xa2,0x2d,0x43,0x3d,0x55,0xdf,0x12,0x7c,0xc0,0xe4,0x8f,0x69,0x04,0x50,0x1b,0xa4
		},
		{
			0xe0,0x71,0x03,0xa9,0x37,0xa7,0x9e,0x9f,0x4e,0xd2,0x4f,0x06,0x1e,0x12,0x3c,0x84,
			0x36,0xaa,0xe3,0x30,0x79,0xa1,0x15,0xa7,0x36,0xf5,0x09,0xae,0x68,0x23,0x00,0x1c,
			0xe2,0x54,0x03,0xe7,0x19,0x1a,0x28,0x8f,0xbd,0x9a,0x18,0x8f,0x1a,0xfe,0x71,0xf5,
			0xc1,0x33,0x12,0xb1,0xda,0xdf,0xe4,0x97,0x7b,0x76,0x8e,0xa3,0x0b,0x28,0x94,0xc7
		}
	};
	uint8_t measurements[6][SHA512_HASH_LENGTH] = {
		{
			0xcd,0xce,0xf1,0x88,0x34,0xdb,0xa4,0xbf,0x24,0x6d,0x52,0x33,0xa3,0x78,0xd6,0x04,
			0x50,0xbe,0x43,0x54,0xf2,0x1f,0xa5,0xc3,0x53,0xaa,0x88,0x5a,0x7d,0x07,0xfe,0x6f
		},
		{
			0xd6,0x40,0x4b,0x06,0x36,0xb4,0x9a,0x63,0x44,0x2b,0xef,0x6c,0x8f,0xa7,0xb8,0x0a,
			0x03,0xf2,0x13,0x9d,0xea,0x7a,0x53,0xd9,0x38,0x01,0x15,0x5b,0xcb,0x4f,0x0d,0x67
		},
		{
			0xb8,0x76,0xbd,0xc9,0x22,0x43,0xa0,0x01,0xcb,0xfd,0x91,0x26,0xac,0xc0,0xf8,0xae,
			0xeb,0xfd,0xbb,0x16,0xff,0xa3,0x80,0xab,0x51,0x29,0x26,0xdf,0x50,0x37,0xe1,0x6c,
			0x11,0x17,0x66,0x47,0xc6,0x9e,0x00,0xea,0xb7,0xe1,0xd2,0xae,0x64,0xc4,0x6f,0x4c,
			0x54,0x2b,0xb0,0x8a,0x58,0xed,0xc3,0x81,0x26,0x23,0xec,0xfd,0x83,0xec,0xe0,0x17
		},
		{
			0xdd,0xee,0x99,0x00,0x79,0x01,0x21,0x20,0xba,0x5a,0x84,0xdb,0x80,0xf6,0x4b,0x29,
			0x95,0xd5,0x0d,0xcf,0xbe,0xdd,0x14,0x1e,0xf0,0x6e,0xa2,0x83,0xe8,0xb3,0x37,0xe5,
			0xed,0xc4,0x78,0x74,0x8a,0x38,0xc1,0xb3,0x03,0xcc,0xe8,0xec,0xcd,0xf0,0x86,0x96,
			0x10,0xdb,0x7a,0xf6,0x4f,0xef,0x25,0x4b,0xc8,0x26,0xd2,0xc2,0x57,0xad,0x5a,0xfb
		},
		{
			0x22,0xe5,0x5b,0xa8,0xb7,0x18,0x90,0x6e,0x4d,0xa5,0xb9,0x28,0x4b,0x3a,0xaf,0x1c,
			0x9d,0xb4,0xb8,0x02,0x03,0x8f,0x8e,0xf2,0xaa,0xb7,0x68,0xfa,0xc8,0x0f,0xcc,0x33,
			0x82,0x51,0x40,0xa2,0xed,0x93,0xa5,0x07,0x81,0x16,0xbf,0xef,0x6b,0xba,0xc6,0xf8,
			0x1e,0x97,0x6d,0x56,0x0b,0xc2,0xa0,0x48,0x7c,0x2f,0x75,0xfc,0x5c,0x44,0x75,0x47
		},
		{
			0x02,0xb0,0xa0,0x9b,0x63,0x0f,0xe8,0xb0,0x59,0x02,0x91,0xd9,0x65,0x28,0xaa,0xc2,
			0x25,0x35,0xea,0x16,0x2c,0xb5,0x4a,0x93,0x4c,0xeb,0x39,0xfb,0xd8,0x45,0x67,0x99,
			0x38,0xa4,0xb1,0x30,0x4c,0x91,0xc1,0x9f,0x63,0xac,0x03,0x1b,0xc1,0xcd,0x3c,0x34,
			0x24,0x4a,0xf4,0x0f,0x06,0x8c,0xc9,0x1d,0x3f,0x29,0x9f,0xd6,0xd2,0xd3,0x8e,0xff
		}
	};
	const size_t expected_length = (2 * sizeof (struct pcr_store_attestation_log_entry_sha256)) +
		(4 * sizeof (struct pcr_store_attestation_log_entry_sha512));
	uint8_t expected[expected_length];
	uint8_t output[sizeof (expected) * 2];
	struct pcr_store_attestation_log_entry_sha256 *expected_sha256 = (void*) expected;
	struct pcr_store_attestation_log_entry_sha512 *expected_sha512 =
		(void*) &expected[2 * sizeof (struct pcr_store_attestation_log_entry_sha256)];
	uint16_t measurement_type;
	size_t digest_length;
	size_t i;
	size_t j;
	size_t k;
	size_t id;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, id = 0; k < ARRAY_SIZE (pcr_config); k++) {
		digest_length = hash_get_hash_length (pcr_config[k].measurement_algo);

		pcr_store_testing_mock_pcr_compute (test, &store, digests[id], measurements[id],
			sizeof (digests[0]), pcr_config[k].num_measurements, digest_length);

		for (i = 0, j = 0; i < pcr_config[k].num_measurements; i++, j++, id++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			if (pcr_config[k].measurement_algo == HASH_TYPE_SHA256) {
				expected_sha256[j].base.header.log_magic = 0xCB;
				expected_sha256[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha256);
				expected_sha256[j].base.header.entry_id = id;

				expected_sha256[j].base.info.digest_algorithm_id = 0x0B;
				expected_sha256[j].base.info.digest_count = 1;
				expected_sha256[j].base.info.event_type = 0x7A + id;
				expected_sha256[j].base.info.measurement_type = measurement_type;

				expected_sha256[j].entry.measurement_size = SHA256_HASH_LENGTH;
				memcpy (expected_sha256[j].entry.digest, digests[id], SHA256_HASH_LENGTH);
				memcpy (expected_sha256[j].entry.measurement, measurements[id], SHA256_HASH_LENGTH);
			}
			else {
				expected_sha512[j].base.header.log_magic = 0xCB;
				expected_sha512[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha512);
				expected_sha512[j].base.header.entry_id = id;

				expected_sha512[j].base.info.digest_algorithm_id = 0x0D;
				expected_sha512[j].base.info.digest_count = 1;
				expected_sha512[j].base.info.event_type = 0x7A + id;
				expected_sha512[j].base.info.measurement_type = measurement_type;

				expected_sha512[j].entry.measurement_size = SHA512_HASH_LENGTH;
				memcpy (expected_sha512[j].entry.digest, digests[id], SHA512_HASH_LENGTH);
				memcpy (expected_sha512[j].entry.measurement, measurements[id], SHA512_HASH_LENGTH);
			}

			status = pcr_store_update_digest (&store.test, measurement_type, digests[id],
				digest_length);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x7A + id);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_sha512_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t digests[6][SHA512_HASH_LENGTH] = {
		{
			0x59,0x41,0x6f,0xe1,0x3b,0x5e,0xad,0x57,0x8e,0x08,0x3c,0x22,0xbe,0xd6,0xcf,0x79,
			0xa3,0xd3,0xfc,0x23,0x6e,0x79,0xb2,0xdf,0xff,0x52,0x5a,0xd7,0xca,0x70,0x48,0x7e,
			0xf0,0x63,0x2a,0xc7,0x28,0xcf,0x07,0x8a,0x88,0xe2,0x76,0x0e,0xa6,0x86,0x01,0x8f,
			0xfc,0x95,0xaf,0x5b,0xc7,0x01,0x49,0x41,0x39,0xeb,0x5b,0xc6,0x5d,0x59,0x0d,0xc2
		},
		{
			0x19,0x71,0x35,0x8a,0x21,0x61,0x17,0x12,0xb8,0x27,0xc1,0xdb,0x6b,0x5c,0xf0,0x1e,
			0xca,0x6d,0xa3,0xe1,0xb4,0x70,0x32,0xae,0xe5,0x06,0xff,0x23,0x77,0x31,0x6d,0x71,
			0x1f,0x0e,0x53,0x55,0x03,0x25,0xab,0xc8,0xd8,0xb2,0x70,0x5b,0x05,0x44,0xa6,0xf2,
			0xee,0x15,0x17,0xc1,0x1f,0xb1,0xb6,0x2f,0x33,0x5e,0x7a,0x5a,0xe1,0xdc,0x71,0x3a
		},
		{
			0x5b,0xdb,0x6c,0x00,0xb1,0xed,0xfc,0xd0,0xb5,0x6a,0x8b,0x31,0xe1,0x32,0x2f,0x3d,
			0xbc,0x99,0x12,0x82,0x77,0xb5,0x95,0x10,0x3c,0xe3,0xc9,0x6b,0xae,0x75,0x13,0x51,
			0xd2,0x9a,0xaf,0x94,0xf7,0x10,0xbf,0xbd,0xe1,0x86,0x53,0xc6,0xa2,0x4c,0x3e,0xed,
			0x38,0xc0,0xc8,0x7c,0x3a,0xdf,0xe9,0x2c,0x64,0x9c,0x2f,0xa1,0x54,0xe1,0x40,0x59
		},
		{
			0x9e,0x61,0x8e,0xc4,0x16,0x3a,0xa5,0x2a,0x20,0x60,0x54,0xaa,0x82,0x4a,0x14,0x03,
			0x59,0x36,0x05,0x99,0xa6,0x04,0xf6,0xbf,0x73,0x07,0xc9,0x7f,0x4d,0x1e,0xa5,0xb2
		},
		{
			0x19,0xef,0x8b,0x4e,0x7b,0xea,0x86,0x79,0xc3,0x31,0xa0,0xd3,0x8c,0xa8,0x69,0x0b,
			0xa2,0x2d,0x43,0x3d,0x55,0xdf,0x12,0x7c,0xc0,0xe4,0x8f,0x69,0x04,0x50,0x1b,0xa4
		},
		{
			0xe2,0x54,0x03,0xe7,0x19,0x1a,0x28,0x8f,0xbd,0x9a,0x18,0x8f,0x1a,0xfe,0x71,0xf5,
			0xc1,0x33,0x12,0xb1,0xda,0xdf,0xe4,0x97,0x7b,0x76,0x8e,0xa3,0x0b,0x28,0x94,0xc7
		}
	};
	uint8_t measurements[6][SHA512_HASH_LENGTH] = {
		{
			0xa5,0xeb,0x17,0x77,0x62,0x22,0xe5,0x61,0x2c,0x50,0xc3,0x63,0x1e,0xcb,0x19,0x60,
			0xc0,0x8b,0xd3,0xfd,0x90,0xd1,0x4d,0x0c,0x05,0xc3,0x60,0xd3,0x43,0x10,0x04,0x66,
			0xcd,0xce,0xf1,0x88,0x34,0xdb,0xa4,0xbf,0x24,0x6d,0x52,0x33,0xa3,0x78,0xd6,0x04,
			0x50,0xbe,0x43,0x54,0xf2,0x1f,0xa5,0xc3,0x53,0xaa,0x88,0x5a,0x7d,0x07,0xfe,0x6f
		},
		{
			0xd6,0x40,0x4b,0x06,0x36,0xb4,0x9a,0x63,0x44,0x2b,0xef,0x6c,0x8f,0xa7,0xb8,0x0a,
			0x03,0xf2,0x13,0x9d,0xea,0x7a,0x53,0xd9,0x38,0x01,0x15,0x5b,0xcb,0x4f,0x0d,0x67,
			0xe7,0xca,0xea,0xc0,0x4a,0x7a,0xdf,0x25,0x70,0x97,0x95,0xba,0xde,0x94,0xef,0xc6,
			0x6a,0x63,0x40,0xfe,0xcf,0xc4,0x59,0x9b,0xc9,0x68,0x1b,0xf5,0x10,0x3b,0xb7,0x82
		},
		{
			0xb8,0x76,0xbd,0xc9,0x22,0x43,0xa0,0x01,0xcb,0xfd,0x91,0x26,0xac,0xc0,0xf8,0xae,
			0xeb,0xfd,0xbb,0x16,0xff,0xa3,0x80,0xab,0x51,0x29,0x26,0xdf,0x50,0x37,0xe1,0x6c,
			0x11,0x17,0x66,0x47,0xc6,0x9e,0x00,0xea,0xb7,0xe1,0xd2,0xae,0x64,0xc4,0x6f,0x4c,
			0x54,0x2b,0xb0,0x8a,0x58,0xed,0xc3,0x81,0x26,0x23,0xec,0xfd,0x83,0xec,0xe0,0x17
		},
		{
			0xdd,0xee,0x99,0x00,0x79,0x01,0x21,0x20,0xba,0x5a,0x84,0xdb,0x80,0xf6,0x4b,0x29,
			0x95,0xd5,0x0d,0xcf,0xbe,0xdd,0x14,0x1e,0xf0,0x6e,0xa2,0x83,0xe8,0xb3,0x37,0xe5
		},
		{
			0x22,0xe5,0x5b,0xa8,0xb7,0x18,0x90,0x6e,0x4d,0xa5,0xb9,0x28,0x4b,0x3a,0xaf,0x1c,
			0x1e,0x97,0x6d,0x56,0x0b,0xc2,0xa0,0x48,0x7c,0x2f,0x75,0xfc,0x5c,0x44,0x75,0x47
		},
		{
			0x38,0xa4,0xb1,0x30,0x4c,0x91,0xc1,0x9f,0x63,0xac,0x03,0x1b,0xc1,0xcd,0x3c,0x34,
			0x24,0x4a,0xf4,0x0f,0x06,0x8c,0xc9,0x1d,0x3f,0x29,0x9f,0xd6,0xd2,0xd3,0x8e,0xff
		}
	};
	const size_t expected_length = (3 * sizeof (struct pcr_store_attestation_log_entry_sha512)) +
		(3 * sizeof (struct pcr_store_attestation_log_entry_sha256));
	uint8_t expected[expected_length];
	uint8_t output[sizeof (expected) * 2];
	struct pcr_store_attestation_log_entry_sha512 *expected_sha512 = (void*) expected;
	struct pcr_store_attestation_log_entry_sha256 *expected_sha256 =
		(void*) &expected[3 * sizeof (struct pcr_store_attestation_log_entry_sha512)];
	uint16_t measurement_type;
	size_t digest_length;
	size_t i;
	size_t j;
	size_t k;
	size_t id;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, id = 0; k < ARRAY_SIZE (pcr_config); k++) {
		digest_length = hash_get_hash_length (pcr_config[k].measurement_algo);

		pcr_store_testing_mock_pcr_compute (test, &store, digests[id], measurements[id],
			sizeof (digests[0]), pcr_config[k].num_measurements, digest_length);

		for (i = 0, j = 0; i < pcr_config[k].num_measurements; i++, j++, id++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			if (pcr_config[k].measurement_algo == HASH_TYPE_SHA256) {
				expected_sha256[j].base.header.log_magic = 0xCB;
				expected_sha256[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha256);
				expected_sha256[j].base.header.entry_id = id;

				expected_sha256[j].base.info.digest_algorithm_id = 0x0B;
				expected_sha256[j].base.info.digest_count = 1;
				expected_sha256[j].base.info.event_type = 0x7A + id;
				expected_sha256[j].base.info.measurement_type = measurement_type;

				expected_sha256[j].entry.measurement_size = SHA256_HASH_LENGTH;
				memcpy (expected_sha256[j].entry.digest, digests[id], SHA256_HASH_LENGTH);
				memcpy (expected_sha256[j].entry.measurement, measurements[id], SHA256_HASH_LENGTH);
			}
			else {
				expected_sha512[j].base.header.log_magic = 0xCB;
				expected_sha512[j].base.header.length =
					sizeof (struct pcr_store_attestation_log_entry_sha512);
				expected_sha512[j].base.header.entry_id = id;

				expected_sha512[j].base.info.digest_algorithm_id = 0x0D;
				expected_sha512[j].base.info.digest_count = 1;
				expected_sha512[j].base.info.event_type = 0x7A + id;
				expected_sha512[j].base.info.measurement_type = measurement_type;

				expected_sha512[j].entry.measurement_size = SHA512_HASH_LENGTH;
				memcpy (expected_sha512[j].entry.digest, digests[id], SHA512_HASH_LENGTH);
				memcpy (expected_sha512[j].entry.measurement, measurements[id], SHA512_HASH_LENGTH);
			}

			status = pcr_store_update_digest (&store.test, measurement_type, digests[id],
				digest_length);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x7A + id);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

static void pcr_store_test_get_attestation_log_non_zero_offset (CuTest *test)
{
	struct pcr_store_testing store;
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
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base,
		3 * sizeof (struct pcr_store_attestation_log_entry_sha256), output, sizeof (output));
	CuAssertIntEquals (test, 3 * sizeof (struct pcr_store_attestation_log_entry_sha256), status);

	status = testing_validate_array ((uint8_t*) &expected[3], output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_partial_measurement (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base,
		(2 * sizeof (struct pcr_store_attestation_log_entry_sha256)) + 5, output, sizeof (output));
	CuAssertIntEquals (test, (4 * sizeof (struct pcr_store_attestation_log_entry_sha256)) - 5,
		status);

	status = testing_validate_array (((uint8_t*) &expected[2]) + 5, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_small_buffer (CuTest *test)
{
	struct pcr_store_testing store;
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
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	/* Only the first PCR will be computed due to the small output buffer. */
	pcr_store_testing_mock_pcr_compute (test, &store, digests[0], measurements[0],
		sizeof (digests[0]), pcr_config[0].num_measurements, SHA256_HASH_LENGTH);

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (struct pcr_store_attestation_log_entry_sha256));
	CuAssertIntEquals (test, sizeof (struct pcr_store_attestation_log_entry_sha256), status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_small_buffer_not_entry_aligned (CuTest *test)
{
	struct pcr_store_testing store;
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
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	/* Only the first PCR will be computed due to the small output buffer. */
	pcr_store_testing_mock_pcr_compute (test, &store, digests[0], measurements[0],
		sizeof (digests[0]), pcr_config[0].num_measurements, SHA256_HASH_LENGTH);

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (struct pcr_store_attestation_log_entry_sha256) + 10);
	CuAssertIntEquals (test, sizeof (struct pcr_store_attestation_log_entry_sha256) + 10, status);

	status = testing_validate_array ((uint8_t*) expected, output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_small_buffer_nonzero_offset (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base,
		sizeof (struct pcr_store_attestation_log_entry_sha256), output,
		3 * sizeof (struct pcr_store_attestation_log_entry_sha256));
	CuAssertIntEquals (test, 3 * sizeof (struct pcr_store_attestation_log_entry_sha256), status);

	status = testing_validate_array ((uint8_t*) &expected[1], output, status);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_invalid_offset (CuTest *test)
{
	struct pcr_store_testing store;
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
	uint8_t digests[6][SHA256_HASH_LENGTH] = {
		{
			0x24,0x80,0x93,0x84,0x92,0xaa,0x6c,0xbf,0x73,0xbe,0x56,0xa2,0xb7,0x45,0x46,0x36,
			0xdf,0x10,0xe5,0xaf,0xbc,0x3f,0x92,0xf2,0x72,0x77,0x23,0x33,0x6a,0xc6,0x23,0x39
		},
		{
			0x47,0x67,0xee,0xd7,0xd0,0xe2,0xcf,0xf9,0x03,0x91,0xe5,0x8f,0x33,0xd1,0x50,0x35,
			0x27,0xac,0x95,0xab,0xc8,0x25,0x66,0x00,0x64,0x68,0x83,0x32,0xb5,0xb6,0xeb,0x52
		},
		{
			0xaa,0x13,0xc5,0xb7,0x11,0xd9,0xd5,0x74,0xfb,0xc4,0x49,0x11,0x42,0x62,0x48,0x94,
			0x33,0x82,0x5e,0x48,0x3d,0x0c,0x79,0x91,0xd4,0xc0,0x89,0xb0,0x75,0x38,0xb2,0x37
		},
		{
			0xe7,0x11,0x78,0x3f,0xf8,0xdb,0xb8,0x8c,0x3d,0xad,0x3e,0xc9,0xcb,0x5b,0x4b,0x51,
			0xe9,0x43,0xe9,0x4a,0xe7,0xf0,0x82,0x61,0xf7,0x24,0x15,0x0d,0xd7,0x6e,0x89,0x6a
		},
		{
			0xd5,0x3d,0x5f,0x66,0xf2,0xf8,0x10,0x07,0x14,0x79,0x59,0x77,0xe9,0x4d,0x66,0x29,
			0xa0,0xcc,0xc3,0x13,0x86,0xf3,0xef,0x63,0xb7,0x4c,0x17,0xac,0x1a,0xa7,0xdb,0x24
		},
		{
			0x26,0xb5,0xef,0xb0,0x9c,0xcd,0x4c,0x6e,0x4c,0xde,0xbe,0x9d,0xff,0x87,0xcf,0xcf,
			0x62,0x02,0xa1,0x1f,0x65,0x42,0x24,0x05,0x5a,0x48,0x89,0xa1,0x01,0x19,0x1a,0x8b
		}
	};
	uint8_t measurements[6][SHA256_HASH_LENGTH] = {
		{
			0x30,0x1c,0x62,0x93,0x3d,0x9f,0x83,0x9d,0xf0,0xae,0x1f,0x37,0xaa,0xbb,0x2b,0x62,
			0x92,0x29,0xab,0x4f,0x09,0x06,0xca,0x27,0x81,0xfd,0x31,0xbb,0xc9,0xf1,0xed,0xd8
		},
		{
			0xc9,0x22,0xfe,0xae,0xf6,0xf4,0x58,0x25,0x42,0x41,0x9a,0xbc,0xca,0xb6,0x38,0xf5,
			0x8b,0x1d,0x3c,0xb8,0xdb,0x8a,0xcc,0xf7,0x7a,0x85,0xdb,0xc8,0xde,0x56,0x3d,0x88
		},
		{
			0x9b,0xd5,0x97,0xdb,0x66,0xb1,0x49,0x3c,0x93,0x82,0xa6,0xa5,0x24,0x86,0x9e,0x5c,
			0x69,0xbc,0xf8,0x3e,0x21,0x79,0xca,0xb5,0x5f,0xf7,0x02,0x74,0xa5,0x07,0x49,0xc7
		},
		{
			0x8f,0xfe,0xc1,0xef,0xcf,0x7c,0xc5,0x96,0x7e,0x8d,0x66,0xd9,0x35,0x53,0xa6,0x5a,
			0xac,0xb6,0xf5,0xad,0x75,0x6c,0xa6,0xc9,0xd7,0xdf,0x4c,0x01,0x91,0xec,0x21,0x23
		},
		{
			0x1d,0x21,0x09,0x96,0x64,0xcd,0x45,0x6d,0x55,0x83,0xbc,0x64,0xa1,0x25,0x04,0x1d,
			0x76,0xcc,0x83,0x92,0xaa,0xea,0xa0,0x3e,0x0d,0xa0,0x8e,0x1e,0x11,0xd8,0xd5,0x80
		},
		{
			0x51,0xf9,0x84,0x8b,0x01,0xd6,0x24,0x77,0x35,0x33,0x40,0x2c,0x68,0xd1,0x40,0x8c,
			0x7a,0x04,0x7b,0x45,0xdd,0xa7,0xa5,0xa6,0x95,0x84,0x1c,0xf8,0x14,0x2c,0x4d,0xfa
		}
	};
	struct pcr_store_attestation_log_entry_sha256 expected[6];
	uint8_t output[sizeof (expected) * 2];
	uint16_t measurement_type;
	size_t i;
	size_t j;
	size_t k;
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (digests[0]), sizeof (measurements[0]));

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (k = 0, j = 0; k < ARRAY_SIZE (pcr_config); k++) {
		pcr_store_testing_mock_pcr_compute (test, &store, digests[j], measurements[j],
			sizeof (digests[0]), pcr_config[k].num_measurements, SHA256_HASH_LENGTH);

		for (i = 0; i < pcr_config[k].num_measurements; i++, j++) {
			measurement_type = PCR_MEASUREMENT (k, i);

			expected[j].base.header.log_magic = 0xCB;
			expected[j].base.header.length = sizeof (struct pcr_store_attestation_log_entry_sha256);
			expected[j].base.header.entry_id = j;

			expected[j].base.info.digest_algorithm_id = 0x0B;
			expected[j].base.info.digest_count = 1;
			expected[j].base.info.event_type = 0x0A + j;
			expected[j].base.info.measurement_type = measurement_type;

			expected[j].entry.measurement_size = SHA256_HASH_LENGTH;
			memcpy (expected[j].entry.digest, digests[j], SHA256_HASH_LENGTH);
			memcpy (expected[j].entry.measurement, measurements[j], SHA256_HASH_LENGTH);

			status = pcr_store_update_digest (&store.test, measurement_type, digests[j],
				SHA256_HASH_LENGTH);
			status |= pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + j);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, sizeof (expected),
		output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t output[512];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_attestation_log (NULL, &store.hash.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_attestation_log (&store.test, NULL, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_attestation_log (&store.test, &store.hash.base, 0, NULL,
		sizeof (output));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_attestation_log_compute_pcr_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t output[512];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = mock_expect (&store.hash_mock.mock, store.hash_mock.base.start_sha256,
		&store.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, 0), SHA256_TEST_HASH,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_attestation_log (&store.test, &store.hash_mock.base, 0, output,
		sizeof (output));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header =
		(struct pcr_tcg_log_header*) ((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) ((uint8_t*) header + header_len);
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha256) * 5) +
			(sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
void pcr_store_test_get_tcg_log_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header =
		(struct pcr_tcg_log_header*) ((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha384 *event =
		(struct pcr_tcg_event2_sha384*) ((uint8_t*) header + header_len);
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha384) * 5) +
			(sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha256_and_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
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
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header =
		(struct pcr_tcg_log_header*) ((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 1);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha384 *event_sha384;
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha256) * 4) +
			(sizeof (struct pcr_tcg_event2_sha384) * 1) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 2, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha384 = (struct pcr_tcg_event2_sha384*) event;
	CuAssertIntEquals (test, 1, event_sha384->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event_sha384->header.event_type);
	CuAssertIntEquals (test, 1, event_sha384->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event_sha384->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event_sha384->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event_sha384) + sizeof (struct pcr_tcg_event2_sha384))[0]);

	status = testing_validate_array (digests[4], event_sha384->digest, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha384_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 1);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha384 *event =
		(struct pcr_tcg_event2_sha384*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha256 *event_sha256;
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha384) * 4) +
			(sizeof (struct pcr_tcg_event2_sha256) * 1) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 2, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha256 = (struct pcr_tcg_event2_sha256*) event;
	CuAssertIntEquals (test, 1, event_sha256->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event_sha256->header.event_type);
	CuAssertIntEquals (test, 1, event_sha256->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event_sha256->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event_sha256->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event_sha256) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event_sha256->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha384_and_sha256_and_sha256_and_sha384 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	uint8_t buffer[1024];
	uint8_t digests[10][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
		{
			0xc3,0x9f,0x03,0x11,0x61,0x8c,0x7f,0xde,0xc5,0x1e,0xf2,0x7f,0x9c,0xe9,0x2e,0x9f,
			0x72,0xaf,0x1b,0xdb,0x60,0x7d,0x10,0x1d,0x55,0x17,0x83,0x7b,0x37,0x41,0xaf,0x81,
			0x8f,0xc5,0x30,0x90,0x74,0x5a,0x58,0xc2,0xbb,0xb5,0x06,0x96,0x5a,0xdb,0xed,0x93
		},
		{
			0xc6,0xd9,0x19,0x62,0x2f,0x2a,0xbf,0x16,0x2d,0x22,0x25,0xfc,0x19,0xa2,0x12,0xd6,
			0x5c,0xd0,0xbd,0x76,0x56,0xa2,0x8c,0xae,0x41,0xf6,0x3d,0xc9,0x07,0x2c,0x31,0x91,
			0xf3,0xe8,0x41,0x8a,0x0b,0x40,0x73,0x75,0xa9,0x5d,0x6e,0x2c,0x68,0xc2,0x6f,0xb5
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 1);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha384 *event =
		(struct pcr_tcg_event2_sha384*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha256 *event_sha256;
	struct pcr_measured_data measurement[10];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	uint16_t measurement_type;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (0, i_measurement);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 5; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (1, i_measurement - 4);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 7; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (2, i_measurement - 5);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 10; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (3, i_measurement - 7);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha384) * 4) +
			(sizeof (struct pcr_tcg_event2_sha256) * 1) +
			(sizeof (struct pcr_tcg_event2_sha256) * 2) +
			(sizeof (struct pcr_tcg_event2_sha384) * 3) + (sizeof (uint8_t) * 10),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 2, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha256 = (struct pcr_tcg_event2_sha256*) event;
	for (; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 1, event_sha256->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha256->header.event_type);
		CuAssertIntEquals (test, 1, event_sha256->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event_sha256->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha256->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha256) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha256->digest,
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha256 = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event_sha256 + 1) + 1);
	}

	for (; i_measurement < 7; ++i_measurement) {
		CuAssertIntEquals (test, 2, event_sha256->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha256->header.event_type);
		CuAssertIntEquals (test, 1, event_sha256->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event_sha256->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha256->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha256) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha256->digest,
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha256 = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event_sha256 + 1) + 1);
	}

	event = (struct pcr_tcg_event2_sha384*) event_sha256;
	for (; i_measurement < 10; ++i_measurement) {
		CuAssertIntEquals (test, 3, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
void pcr_store_test_get_tcg_log_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha512 *event =
		(struct pcr_tcg_event2_sha512*) ((uint8_t*) header + header_len);
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha512) * 5) +
			(sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha256_and_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
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
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 1);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha512 *event_sha512;
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha256) * 4) +
			(sizeof (struct pcr_tcg_event2_sha512) * 1) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 2, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha512 = (struct pcr_tcg_event2_sha512*) event;
	CuAssertIntEquals (test, 1, event_sha512->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event_sha512->header.event_type);
	CuAssertIntEquals (test, 1, event_sha512->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event_sha512->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event_sha512->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event_sha512) + sizeof (struct pcr_tcg_event2_sha512))[0]);

	status = testing_validate_array (digests[4], event_sha512->digest, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha512_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 1);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha512 *event =
		(struct pcr_tcg_event2_sha512*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha256 *event_sha256;
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha512) * 4) +
			(sizeof (struct pcr_tcg_event2_sha256) * 1) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 2, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha256 = (struct pcr_tcg_event2_sha256*) event;
	CuAssertIntEquals (test, 1, event_sha256->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event_sha256->header.event_type);
	CuAssertIntEquals (test, 1, event_sha256->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event_sha256->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event_sha256->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event_sha256) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event_sha256->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}
#endif

#if defined HASH_ENABLE_SHA384 && defined HASH_ENABLE_SHA512 && \
	(PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
void pcr_store_test_get_tcg_log_sha256_and_sha384_and_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t buffer[512];
	uint8_t digests[6][SHA512_HASH_LENGTH] = {
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
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len = sizeof (struct pcr_tcg_log_header);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha384 *event_sha384;
	struct pcr_tcg_event2_sha512 *event_sha512;
	struct pcr_measured_data measurement[6];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	uint16_t measurement_type;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (0, i_measurement);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 4; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (1, i_measurement - 3);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 6; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (2, i_measurement - 4);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha256) * 3) +
			(sizeof (struct pcr_tcg_event2_sha384) * 1) +
			(sizeof (struct pcr_tcg_event2_sha512) * 2) + (sizeof (uint8_t) * 6),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 3, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, header->digest_size[2].digest_algorithm_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, header->digest_size[2].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha384 = (struct pcr_tcg_event2_sha384*) event;
	for (; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 1, event_sha384->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha384->header.event_type);
		CuAssertIntEquals (test, 1, event_sha384->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event_sha384->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha384->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha384) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha384->digest,
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha384 = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event_sha384 + 1) + 1);
	}

	event_sha512 = (struct pcr_tcg_event2_sha512*) event_sha384;
	for (; i_measurement < 6; ++i_measurement) {
		CuAssertIntEquals (test, 2, event_sha512->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha512->header.event_type);
		CuAssertIntEquals (test, 1, event_sha512->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event_sha512->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha512->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha512) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha512->digest,
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha512 = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event_sha512 + 1) + 1);
	}

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha384_and_sha256_and_sha512 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	uint8_t buffer[512];
	uint8_t digests[6][SHA512_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len = sizeof (struct pcr_tcg_log_header);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha384 *event =
		(struct pcr_tcg_event2_sha384*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha256 *event_sha256;
	struct pcr_tcg_event2_sha512 *event_sha512;
	struct pcr_measured_data measurement[6];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	uint16_t measurement_type;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (0, i_measurement);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 4; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (1, i_measurement - 3);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 6; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (2, i_measurement - 4);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha384) * 3) +
			(sizeof (struct pcr_tcg_event2_sha256) * 1) +
			(sizeof (struct pcr_tcg_event2_sha512) * 2) + (sizeof (uint8_t) * 6),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 3, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, header->digest_size[2].digest_algorithm_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, header->digest_size[2].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha256 = (struct pcr_tcg_event2_sha256*) event;
	for (; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 1, event_sha256->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha256->header.event_type);
		CuAssertIntEquals (test, 1, event_sha256->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event_sha256->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha256->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha256) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha256->digest,
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha256 = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event_sha256 + 1) + 1);
	}

	event_sha512 = (struct pcr_tcg_event2_sha512*) event_sha256;
	for (; i_measurement < 6; ++i_measurement) {
		CuAssertIntEquals (test, 2, event_sha512->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha512->header.event_type);
		CuAssertIntEquals (test, 1, event_sha512->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event_sha512->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha512->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha512) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha512->digest,
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha512 = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event_sha512 + 1) + 1);
	}

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_sha512_and_sha384_and_sha512_and_sha256 (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 2,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[1024];
	uint8_t digests[10][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
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
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*)
		((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	const size_t header_len = sizeof (struct pcr_tcg_log_header);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha512 *event =
		(struct pcr_tcg_event2_sha512*) ((uint8_t*) header + header_len);
	struct pcr_tcg_event2_sha384 *event_sha384;
	struct pcr_tcg_event2_sha256 *event_sha256;
	struct pcr_measured_data measurement[10];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	uint16_t measurement_type;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (0, i_measurement);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 5; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (1, i_measurement - 3);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 6; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (2, i_measurement - 5);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	for (; i_measurement < 10; ++i_measurement) {
		measurement_type = PCR_MEASUREMENT (3, i_measurement - 6);

		status = pcr_store_update_digest (&store.test, measurement_type, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, measurement_type, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;
		status = pcr_store_set_measurement_data (&store.test, measurement_type,
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		sizeof (struct pcr_tcg_event) + header_len + (sizeof (struct pcr_tcg_event2_sha512) * 3) +
			(sizeof (struct pcr_tcg_event2_sha384) * 2) +
			(sizeof (struct pcr_tcg_event2_sha512) * 1) +
			(sizeof (struct pcr_tcg_event2_sha256) * 4) + (sizeof (uint8_t) * 10),
		status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 3, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, header->digest_size[1].digest_algorithm_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, header->digest_size[1].digest_size);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[2].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[2].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 3; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha384 = (struct pcr_tcg_event2_sha384*) event;
	for (; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 1, event_sha384->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha384->header.event_type);
		CuAssertIntEquals (test, 1, event_sha384->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event_sha384->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha384->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha384) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha384->digest,
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha384 = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event_sha384 + 1) + 1);
	}

	event = (struct pcr_tcg_event2_sha512*) event_sha384;
	for (; i_measurement < 6; ++i_measurement) {
		CuAssertIntEquals (test, 2, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest,
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	event_sha256 = (struct pcr_tcg_event2_sha256*) event;
	for (; i_measurement < 10; ++i_measurement) {
		CuAssertIntEquals (test, 3, event_sha256->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event_sha256->header.event_type);
		CuAssertIntEquals (test, 1, event_sha256->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event_sha256->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event_sha256->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event_sha256) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event_sha256->digest,
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event_sha256 = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event_sha256 + 1) + 1);
	}

	pcr_store_testing_release (test, &store);
}
#endif

void pcr_store_test_get_tcg_log_offset_skip_v1_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*) buffer;
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) ((uint8_t*) header + header_len);
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, sizeof (struct pcr_tcg_event), buffer,
		sizeof (buffer));
	CuAssertIntEquals (test,
		header_len + (sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5), status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_into_v1_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	struct pcr_tcg_event v1_event;
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*) (buffer + 4);
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) ((uint8_t*) header + header_len);
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	memset (&v1_event, 0, sizeof (struct pcr_tcg_event));

	v1_event.event_type = PCR_TCG_EFI_NO_ACTION_EVENT_TYPE;
	v1_event.event_size = header_len;
	v1_event.pcr_index = 0;

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, sizeof (struct pcr_tcg_event) - 4, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test,
		4 + header_len + (sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5),
		status);

	status = testing_validate_array (((uint8_t*) &v1_event) + sizeof (struct pcr_tcg_event) - 4,
		buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_only_v1_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	struct pcr_tcg_event *v1_event = (struct pcr_tcg_event*) buffer;
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	struct pcr_measured_data measurement[5];
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, 0, buffer, sizeof (struct pcr_tcg_event));
	CuAssertIntEquals (test, sizeof (struct pcr_tcg_event), status);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, header_len, v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_index);

	status = testing_validate_array (v1_event_pcr, v1_event->digest, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_skip_header (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, sizeof (struct pcr_tcg_event) + header_len, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5),
		status);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_into_header (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	struct pcr_tcg_log_header header;
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) (buffer + 3);
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	memset (&header, 0, sizeof (struct pcr_tcg_log_header));

	memcpy (&header.signature, (const uint8_t*) PCR_TCG_LOG_SIGNATURE,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	header.platform_class = PCR_TCG_SERVER_PLATFORM_CLASS;
	header.spec_version_minor = 0;
	header.spec_version_major = 2;
	header.spec_errata = 0;
	header.uintn_size = PCR_TCG_UINT_SIZE_32;
	header.num_algorithms = 1;
	header.digest_size[0].digest_algorithm_id = PCR_TCG_SHA256_ALG_ID;
	header.digest_size[0].digest_size = SHA256_HASH_LENGTH;
	// header.vendor_info_size = 0; (Already cleared by memset and at the wrong memory for this test)

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, sizeof (struct pcr_tcg_event) + header_len - 3,
		buffer, sizeof (buffer));
	CuAssertIntEquals (test,
		3 + (sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5), status);

	status = testing_validate_array (((uint8_t*) &header) + (header_len - 3), buffer, 3);
	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_only_header (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	struct pcr_tcg_log_header *header = (struct pcr_tcg_log_header*) buffer;
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	uint8_t *vendor_info_size = ((uint8_t*) header) + (header_len - 1);
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, sizeof (struct pcr_tcg_event), buffer, header_len);
	CuAssertIntEquals (test, header_len, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size[0].digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size[0].digest_size);
	CuAssertIntEquals (test, 0, *vendor_info_size);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_skip_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test,
		sizeof (struct pcr_tcg_event) + header_len + sizeof (struct pcr_tcg_event2_sha256) +
			sizeof (uint8_t),
		buffer, sizeof (buffer));
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 4) + (sizeof (uint8_t) * 4),
		status);

	for (i_measurement = 1; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_into_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	struct pcr_tcg_event2_sha256 *event =
		(struct pcr_tcg_event2_sha256*) (buffer + sizeof (uint8_t));
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test,
		sizeof (struct pcr_tcg_event) + header_len + sizeof (struct pcr_tcg_event2_sha256), buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 4) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, 0xAA, buffer[0]);

	for (i_measurement = 1; i_measurement < 4; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	CuAssertIntEquals (test, 1, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A + 4, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA + 4,
		(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[4], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_offset_only_one_event (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
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
	};
	const size_t header_len =
		sizeof (struct pcr_tcg_log_header) - (sizeof (struct pcr_tcg_algorithm) * 2);
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	int i_measurement;
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	for (i_measurement = 0; i_measurement < 4; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (0, i_measurement),
			&measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_store_update_digest (&store.test, PCR_MEASUREMENT (1, 0), digests[4],
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&store.test, PCR_MEASUREMENT (1, 0), 0x0A + 4);
	CuAssertIntEquals (test, 0, status);

	measurement[4].type = PCR_DATA_TYPE_1BYTE;
	measurement[4].data.value_1byte = 0xAA + 4;
	status = pcr_store_set_measurement_data (&store.test, PCR_MEASUREMENT (1, 0), &measurement[4]);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_tcg_log (&store.test, sizeof (struct pcr_tcg_event) + header_len, buffer,
		sizeof (struct pcr_tcg_event2_sha256) + sizeof (uint8_t));
	CuAssertIntEquals (test, sizeof (struct pcr_tcg_event2_sha256) + sizeof (uint8_t), status);

	CuAssertIntEquals (test, 0, event->header.pcr_index);
	CuAssertIntEquals (test, 0x0A, event->header.event_type);
	CuAssertIntEquals (test, 1, event->header.digest_count);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
	CuAssertIntEquals (test, 1, event->event_size);
	CuAssertIntEquals (test, 0xAA, (((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

	status = testing_validate_array (digests[0], event->digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_store_testing_release (test, &store);
}

void pcr_store_test_get_tcg_log_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	uint8_t buffer[512];
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_tcg_log (NULL, 0, buffer, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_tcg_log (&store.test, 0, NULL, sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_dmtf_value_type (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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
	enum pcr_dmtf_value_type value;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_dmtf_value_type (&store.test, PCR_MEASUREMENT (0, 2),
		PCR_DMTF_VALUE_TYPE_HW_CONFIG);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_dmtf_value_type (&store.test, PCR_MEASUREMENT (0, 2), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCR_DMTF_VALUE_TYPE_HW_CONFIG, value);

	status = pcr_store_set_dmtf_value_type (&store.test, PCR_MEASUREMENT (1, 3),
		PCR_DMTF_VALUE_TYPE_MEAS_MANIFEST);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_dmtf_value_type (&store.test, PCR_MEASUREMENT (1, 3), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCR_DMTF_VALUE_TYPE_MEAS_MANIFEST, value);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_dmtf_value_type_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_dmtf_value_type (NULL, PCR_MEASUREMENT (0, 2),
		PCR_DMTF_VALUE_TYPE_HW_CONFIG);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_dmtf_value_type_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_dmtf_value_type (&store.test, PCR_MEASUREMENT (2, 0),
		PCR_DMTF_VALUE_TYPE_HW_CONFIG);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_set_dmtf_value_type_update_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_set_dmtf_value_type (&store.test, PCR_MEASUREMENT (0, 6),
		PCR_DMTF_VALUE_TYPE_HW_CONFIG);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_dmtf_value_type_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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
	enum pcr_dmtf_value_type value;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_dmtf_value_type (NULL, PCR_MEASUREMENT (0, 2), &value);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_store_get_dmtf_value_type (&store.test, PCR_MEASUREMENT (0, 2), NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_dmtf_value_type_invalid_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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
	enum pcr_dmtf_value_type value;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_dmtf_value_type (&store.test, PCR_MEASUREMENT (2, 0), &value);
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_dmtf_value_type_get_fail (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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
	enum pcr_dmtf_value_type value;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_dmtf_value_type (&store.test, PCR_MEASUREMENT (0, 6), &value);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_type_first_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_type (&store.test, 0);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 1);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 2);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 3);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 3), status);

	status = pcr_store_get_measurement_type (&store.test, 4);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 4), status);

	status = pcr_store_get_measurement_type (&store.test, 5);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 5), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_type_multiple_pcr (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 4,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_type (&store.test, 0);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 1);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 2);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 3);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 3), status);

	status = pcr_store_get_measurement_type (&store.test, 4);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 4), status);

	status = pcr_store_get_measurement_type (&store.test, 5);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 5), status);

	status = pcr_store_get_measurement_type (&store.test, 6);
	CuAssertIntEquals (test, PCR_MEASUREMENT (1, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 7);
	CuAssertIntEquals (test, PCR_MEASUREMENT (1, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 8);
	CuAssertIntEquals (test, PCR_MEASUREMENT (1, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 9);
	CuAssertIntEquals (test, PCR_MEASUREMENT (2, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 10);
	CuAssertIntEquals (test, PCR_MEASUREMENT (2, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 11);
	CuAssertIntEquals (test, PCR_MEASUREMENT (2, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 12);
	CuAssertIntEquals (test, PCR_MEASUREMENT (2, 3), status);

	status = pcr_store_get_measurement_type (&store.test, 13);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 14);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 15);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 16);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 3), status);

	status = pcr_store_get_measurement_type (&store.test, 17);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 4), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_type_explicit (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 3,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 5,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_type (&store.test, 0);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 1);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 2);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 3);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 3), status);

	status = pcr_store_get_measurement_type (&store.test, 4);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 4), status);

	status = pcr_store_get_measurement_type (&store.test, 5);
	CuAssertIntEquals (test, PCR_MEASUREMENT (0, 5), status);

	status = pcr_store_get_measurement_type (&store.test, 6);
	CuAssertIntEquals (test, PCR_MEASUREMENT (1, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 7);
	CuAssertIntEquals (test, PCR_MEASUREMENT (1, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 8);
	CuAssertIntEquals (test, PCR_MEASUREMENT (1, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 9);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 0), status);

	status = pcr_store_get_measurement_type (&store.test, 10);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 1), status);

	status = pcr_store_get_measurement_type (&store.test, 11);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 2), status);

	status = pcr_store_get_measurement_type (&store.test, 12);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 3), status);

	status = pcr_store_get_measurement_type (&store.test, 13);
	CuAssertIntEquals (test, PCR_MEASUREMENT (3, 4), status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_type_null (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_type (NULL, 0);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_store_testing_release (test, &store);
}

static void pcr_store_test_get_measurement_type_invalid_sequential_id (CuTest *test)
{
	struct pcr_store_testing store;
	const struct pcr_config pcr_config[] = {
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

	TEST_START;

	pcr_store_testing_init (test, &store, pcr_config, ARRAY_SIZE (pcr_config));

	status = pcr_store_get_measurement_type (&store.test, 12);
	CuAssertIntEquals (test, PCR_INVALID_SEQUENTIAL_ID, status);

	pcr_store_testing_release (test, &store);
}


TEST_SUITE_START (pcr_store);

TEST (pcr_store_test_init_sha256);
TEST (pcr_store_test_init_sha256_explicit);
TEST (pcr_store_test_init_sha384);
TEST (pcr_store_test_init_sha384_explicit);
TEST (pcr_store_test_init_sha512);
TEST (pcr_store_test_init_sha512_explicit);
TEST (pcr_store_test_init_mixed_hash_algos);
TEST (pcr_store_test_init_null);
TEST (pcr_store_test_init_pcr_init_fail);
TEST (pcr_store_test_release_null);
TEST (pcr_store_test_get_num_pcrs_null);
TEST (pcr_store_test_get_num_total_measurements_null);
TEST (pcr_store_test_get_pcr_digest_length_null);
TEST (pcr_store_test_get_pcr_digest_length_invalid_pcr);
TEST (pcr_store_test_check_measurement_type);
TEST (pcr_store_test_check_measurement_type_explicit);
TEST (pcr_store_test_check_measurement_type_null);
TEST (pcr_store_test_check_measurement_type_invalid_pcr);
TEST (pcr_store_test_check_measurement_type_invalid_index);
TEST (pcr_store_test_check_measurement_type_invalid_index_explicit);
TEST (pcr_store_test_get_num_pcr_measurements);
TEST (pcr_store_test_get_num_pcr_measurements_explicit);
TEST (pcr_store_test_get_num_pcr_measurements_null);
TEST (pcr_store_test_get_num_pcr_measurements_invalid_pcr);
TEST (pcr_store_test_update_digest_sha256);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_update_digest_sha384);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_update_digest_sha512);
#endif
TEST (pcr_store_test_update_digest_null);
TEST (pcr_store_test_update_digest_invalid_pcr);
TEST (pcr_store_test_update_digest_update_fail);
TEST (pcr_store_test_get_measurement_null);
TEST (pcr_store_test_get_measurement_invalid_pcr);
TEST (pcr_store_test_get_measurement_fail);
TEST (pcr_store_test_update_buffer_sha256);
TEST (pcr_store_test_update_buffer_sha256_with_event);
TEST (pcr_store_test_update_buffer_sha256_with_event_without_event);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_update_buffer_sha384);
TEST (pcr_store_test_update_buffer_sha384_with_event);
TEST (pcr_store_test_update_buffer_sha384_with_event_without_event);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_update_buffer_sha512);
TEST (pcr_store_test_update_buffer_sha512_with_event);
TEST (pcr_store_test_update_buffer_sha512_with_event_without_event);
#endif
TEST (pcr_store_test_update_buffer_null);
TEST (pcr_store_test_update_buffer_invalid_pcr);
TEST (pcr_store_test_update_buffer_update_fail);
TEST (pcr_store_test_update_buffer_with_event_update_fail);
TEST (pcr_store_test_update_versioned_buffer_sha256);
TEST (pcr_store_test_update_versioned_buffer_sha256_with_event);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_update_versioned_buffer_sha384);
TEST (pcr_store_test_update_versioned_buffer_sha384_with_event);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_update_versioned_buffer_sha512);
TEST (pcr_store_test_update_versioned_buffer_sha512_with_event);
#endif
TEST (pcr_store_test_update_versioned_buffer_null);
TEST (pcr_store_test_update_versioned_buffer_invalid_pcr);
TEST (pcr_store_test_update_versioned_buffer_update_fail);
TEST (pcr_store_test_update_versioned_buffer_with_event_update_fail);
TEST (pcr_store_test_set_tcg_event_type_null);
TEST (pcr_store_test_set_tcg_event_type_invalid_pcr);
TEST (pcr_store_test_set_tcg_event_type_update_fail);
TEST (pcr_store_test_invalidate_measurement);
TEST (pcr_store_test_invalidate_measurement_explicit);
TEST (pcr_store_test_invalidate_measurement_null);
TEST (pcr_store_test_invalidate_measurement_invalid_pcr);
TEST (pcr_store_test_invalidate_measurement_invalid_index);
TEST (pcr_store_test_compute_pcr_sha256);
TEST (pcr_store_test_compute_pcr_sha256_explicit);
TEST (pcr_store_test_compute_pcr_sha256_no_measurement_out);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_compute_pcr_sha384);
TEST (pcr_store_test_compute_pcr_sha384_explicit);
TEST (pcr_store_test_compute_pcr_sha384_no_measurement_out);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_compute_pcr_sha512);
TEST (pcr_store_test_compute_pcr_sha512_explicit);
TEST (pcr_store_test_compute_pcr_sha512_no_measurement_out);
#endif
TEST (pcr_store_test_compute_pcr_null);
TEST (pcr_store_test_compute_pcr_sha256_small_output_buffer);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_compute_pcr_sha384_small_output_buffer);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_compute_pcr_sha512_small_output_buffer);
#endif
TEST (pcr_store_test_compute_pcr_invalid_pcr);
TEST (pcr_store_test_compute_pcr_compute_pcr_fail);
TEST (pcr_store_test_set_measurement_data);
TEST (pcr_store_test_set_measurement_data_remove);
TEST (pcr_store_test_set_measurement_data_null);
TEST (pcr_store_test_set_measurement_data_invalid_pcr);
TEST (pcr_store_test_set_measurement_data_fail);
TEST (pcr_store_test_is_measurement_data_available_null);
TEST (pcr_store_test_is_measurement_data_available_invalid_pcr);
TEST (pcr_store_test_get_measurement_data_no_data);
TEST (pcr_store_test_get_measurement_data_null);
TEST (pcr_store_test_get_measurement_data_invalid_pcr);
TEST (pcr_store_test_hash_measurement_data);
TEST (pcr_store_test_hash_measurement_data_null);
TEST (pcr_store_test_hash_measurement_data_invalid_pcr);
TEST (pcr_store_test_hash_measurement_data_error);
TEST (pcr_store_test_get_measurement_data_length);
TEST (pcr_store_test_get_measurement_data_length_no_data);
TEST (pcr_store_test_get_measurement_data_length_null);
TEST (pcr_store_test_get_measurement_data_length_invalid_pcr);
TEST (pcr_store_test_get_measurement_data_length_fail);
TEST (pcr_store_test_get_attestation_log_size_sha256);
TEST (pcr_store_test_get_attestation_log_size_sha256_explicit);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_get_attestation_log_size_sha384);
TEST (pcr_store_test_get_attestation_log_size_sha384_explicit);
TEST (pcr_store_test_get_attestation_log_size_sha256_and_sha384);
TEST (pcr_store_test_get_attestation_log_size_sha384_and_sha256);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_get_attestation_log_size_sha512);
TEST (pcr_store_test_get_attestation_log_size_sha512_explicit);
TEST (pcr_store_test_get_attestation_log_size_sha256_and_sha512);
TEST (pcr_store_test_get_attestation_log_size_sha512_and_sha256);
#endif
TEST (pcr_store_test_get_attestation_log_size_null);
TEST (pcr_store_test_get_attestation_log_sha256);
TEST (pcr_store_test_get_attestation_log_sha256_invalid_entry);
TEST (pcr_store_test_get_attestation_log_sha256_explicit);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_get_attestation_log_sha384);
TEST (pcr_store_test_get_attestation_log_sha384_invalid_entry);
TEST (pcr_store_test_get_attestation_log_sha384_explicit);
TEST (pcr_store_test_get_attestation_log_sha256_and_sha384);
TEST (pcr_store_test_get_attestation_log_sha384_and_sha256);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_get_attestation_log_sha512);
TEST (pcr_store_test_get_attestation_log_sha512_invalid_entry);
TEST (pcr_store_test_get_attestation_log_sha512_explicit);
TEST (pcr_store_test_get_attestation_log_sha256_and_sha512);
TEST (pcr_store_test_get_attestation_log_sha512_and_sha256);
#endif
TEST (pcr_store_test_get_attestation_log_non_zero_offset);
TEST (pcr_store_test_get_attestation_log_partial_measurement);
TEST (pcr_store_test_get_attestation_log_small_buffer);
TEST (pcr_store_test_get_attestation_log_small_buffer_not_entry_aligned);
TEST (pcr_store_test_get_attestation_log_small_buffer_nonzero_offset);
TEST (pcr_store_test_get_attestation_log_invalid_offset);
TEST (pcr_store_test_get_attestation_log_null);
TEST (pcr_store_test_get_attestation_log_compute_pcr_fail);
TEST (pcr_store_test_get_tcg_log_sha256);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_store_test_get_tcg_log_sha384);
TEST (pcr_store_test_get_tcg_log_sha256_and_sha384);
TEST (pcr_store_test_get_tcg_log_sha384_and_sha256);
TEST (pcr_store_test_get_tcg_log_sha384_and_sha256_and_sha256_and_sha384);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_get_tcg_log_sha512);
TEST (pcr_store_test_get_tcg_log_sha256_and_sha512);
TEST (pcr_store_test_get_tcg_log_sha512_and_sha256);
#endif
#if defined HASH_ENABLE_SHA384 && defined HASH_ENABLE_SHA512 && \
	(PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_store_test_get_tcg_log_sha256_and_sha384_and_sha512);
TEST (pcr_store_test_get_tcg_log_sha384_and_sha256_and_sha512);
TEST (pcr_store_test_get_tcg_log_sha512_and_sha384_and_sha512_and_sha256);
#endif
TEST (pcr_store_test_get_tcg_log_offset_skip_v1_event);
TEST (pcr_store_test_get_tcg_log_offset_into_v1_event);
TEST (pcr_store_test_get_tcg_log_offset_only_v1_event);
TEST (pcr_store_test_get_tcg_log_offset_skip_header);
TEST (pcr_store_test_get_tcg_log_offset_into_header);
TEST (pcr_store_test_get_tcg_log_offset_only_header);
TEST (pcr_store_test_get_tcg_log_offset_skip_event);
TEST (pcr_store_test_get_tcg_log_offset_into_event);
TEST (pcr_store_test_get_tcg_log_offset_only_one_event);
TEST (pcr_store_test_get_tcg_log_null);
TEST (pcr_store_test_set_dmtf_value_type);
TEST (pcr_store_test_set_dmtf_value_type_null);
TEST (pcr_store_test_set_dmtf_value_type_invalid_pcr);
TEST (pcr_store_test_set_dmtf_value_type_update_fail);
TEST (pcr_store_test_get_dmtf_value_type_null);
TEST (pcr_store_test_get_dmtf_value_type_invalid_pcr);
TEST (pcr_store_test_get_dmtf_value_type_get_fail);
TEST (pcr_store_test_get_measurement_type_first_pcr);
TEST (pcr_store_test_get_measurement_type_multiple_pcr);
TEST (pcr_store_test_get_measurement_type_explicit);
TEST (pcr_store_test_get_measurement_type_null);
TEST (pcr_store_test_get_measurement_type_invalid_sequential_id);

TEST_SUITE_END;
