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

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
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

	status = cfm_observer_pcr_init (NULL, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, CFM_OBSERVER_INVALID_ARGUMENT, status);

	status = cfm_observer_pcr_init (&observer, NULL, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, CFM_OBSERVER_INVALID_ARGUMENT, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, NULL, PCR_MEASUREMENT (0, 0));
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

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

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
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, CFM_HASH_LEN);
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
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_cfm_activated (&observer.base, &cfm.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) &cfm);
	status |= mock_expect (&manager.mock, manager.base.free_cfm, &manager, 0, MOCK_ARG (&cfm));

	status |= mock_expect (&cfm.mock, cfm.base.base.get_hash, &cfm, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cfm.mock, 1, CFM_HASH, CFM_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (CFM_HASH, measurement.digest, CFM_HASH_LEN);
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
	struct cfm_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_cfm, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	cfm_observer_pcr_record_measurement (NULL, &manager.base);

	cfm_observer_pcr_record_measurement (&observer, NULL);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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

	status = cfm_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_release_null);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_on_cfm_activated);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_on_cfm_activated_hash_error);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_no_active);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_null);
	SUITE_ADD_TEST (suite, cfm_observer_pcr_test_record_measurement_hash_error);

	return suite;
}
