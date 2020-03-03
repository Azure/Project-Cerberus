// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_observer_pcr.h"
#include "attestation/pcr_store.h"
#include "mock/pcd_mock.h"
#include "mock/pcd_manager_mock.h"
#include "engines/hash_testing_engine.h"
#include "pcd_testing.h"


static const char *SUITE = "pcd_observer_pcr";


/*******************
 * Test cases
 *******************/

static void pcd_observer_pcr_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_pcd_verified);	
	CuAssertPtrNotNull (test, observer.base.on_pcd_activated);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (NULL, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, PCD_OBSERVER_INVALID_ARGUMENT, status);

	status = pcd_observer_pcr_init (&observer, NULL, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, PCD_OBSERVER_INVALID_ARGUMENT, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, NULL, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, PCD_OBSERVER_INVALID_ARGUMENT, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_observer_pcr_test_init_bad_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

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
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_HASH, PCD_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCD_HASH, measurement.digest, PCD_HASH_LEN);
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
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);
	
	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_pcd_activated (&observer.base, &pcd.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);
	
	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) &pcd);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&pcd.mock, 1, PCD_HASH, PCD_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCD_HASH, measurement.digest, PCD_HASH_LEN);
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
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);
	
	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);
	
	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (NULL, &manager.base);

	pcd_observer_pcr_record_measurement (&observer, NULL);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
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
	uint8_t num_pcr_measurements[] = {6, 6};
	struct pcd_observer_pcr observer;
	int status;
	struct pcd_mock pcd;
	struct pcr_measurement measurement;
	struct pcd_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_pcr_init (&observer, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);
	
	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_pcd, &manager, (intptr_t) &pcd);
	status |= mock_expect (&manager.mock, manager.base.free_pcd, &manager, 0, MOCK_ARG (&pcd));

	status |= mock_expect (&pcd.mock, pcd.base.base.get_hash, &pcd, MANIFEST_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);
	
	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcd_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	pcd_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


CuSuite* get_pcd_observer_pcr_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_init);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_init_null);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_init_bad_measurement_type);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_release_null);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_on_pcd_activated);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_on_pcd_activated_hash_error);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_record_measurement);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_record_measurement_no_active);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_record_measurement_null);
	SUITE_ADD_TEST (suite, pcd_observer_pcr_test_record_measurement_hash_error);

	return suite;
}
