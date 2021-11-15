// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "recovery/recovery_image_observer_pcr.h"
#include "attestation/pcr_store.h"
#include "state_manager/state_manager.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/manifest_observer_pcr_testing.h"
#include "testing/recovery/recovery_image_testing.h"


TEST_SUITE_LABEL ("recovery_image_observer_pcr");


/*******************
 * Test cases
 *******************/

static void recovery_image_observer_pcr_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, observer.base.on_recovery_image_activated);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (NULL, &hash.base, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, RECOVERY_IMAGE_OBSERVER_INVALID_ARGUMENT, status);

	status = recovery_image_observer_pcr_init (&observer, NULL, &store, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, RECOVERY_IMAGE_OBSERVER_INVALID_ARGUMENT, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, NULL, PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, RECOVERY_IMAGE_OBSERVER_INVALID_ARGUMENT, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_init_bad_measurement_type (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 6));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_release_null (CuTest *test)
{
	TEST_START;

	recovery_image_observer_pcr_release (NULL);
}

static void recovery_image_observer_pcr_test_on_recovery_image_activated (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct recovery_image_mock image;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash.base),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_activated (&observer.base, &image.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH_DIGEST, measurement.digest,
		RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_on_recovery_image_activated_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct recovery_image_mock image;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, RECOVERY_IMAGE_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_activated (&observer.base, &image.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_record_measurement (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct recovery_image_mock image;
	struct pcr_measurement measurement;
	struct recovery_image_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_recovery_image, &manager,
		(intptr_t) &image);

	status |= mock_expect (&manager.mock, manager.base.free_recovery_image, &manager, 0,
		MOCK_ARG (&image));

	status |= mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH_DIGEST, measurement.digest,
		RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_record_measurement_no_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct recovery_image_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_recovery_image, &manager,
		(intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_record_measurement_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct pcr_measurement measurement;
	struct recovery_image_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_record_measurement (&observer, NULL);

	recovery_image_observer_pcr_record_measurement (NULL, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_record_measurement_hash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct recovery_image_mock image;
	struct pcr_measurement measurement;
	struct recovery_image_manager_mock manager;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_recovery_image, &manager,
		(intptr_t) &image);

	status |= mock_expect (&manager.mock, manager.base.free_recovery_image, &manager, 0,
		MOCK_ARG (&image));

	status |= mock_expect (&image.mock, image.base.get_hash, &image, RECOVERY_IMAGE_GET_HASH_FAILED,
		MOCK_ARG (&hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_record_measurement (&observer, &manager.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_observer_pcr_test_on_recovery_image_deactivated (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct pcr_store store;
	uint8_t num_pcr_measurements[] = {6, 6};
	struct recovery_image_observer_pcr observer;
	int status;
	struct recovery_image_mock image;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[SHA256_HASH_LENGTH] = {0};
	uint32_t event = 0xaabbccdd;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_pcr_init (&observer, &hash.base, &store,
		PCR_MEASUREMENT (0, 0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_event_type (&store.banks[0], 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (invalid_measurement, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash.base),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_activated (&observer.base, &image.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH_DIGEST, measurement.digest,
		RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_deactivated (&observer.base);

	status = pcr_store_get_measurement (&store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ZERO_BUFFER_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_observer_pcr_release (&observer);

	pcr_store_release (&store);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

TEST_SUITE_START (recovery_image_observer_pcr);

TEST (recovery_image_observer_pcr_test_init);
TEST (recovery_image_observer_pcr_test_init_null);
TEST (recovery_image_observer_pcr_test_init_bad_measurement_type);
TEST (recovery_image_observer_pcr_test_release_null);
TEST (recovery_image_observer_pcr_test_on_recovery_image_activated);
TEST (recovery_image_observer_pcr_test_on_recovery_image_activated_hash_error);
TEST (recovery_image_observer_pcr_test_record_measurement);
TEST (recovery_image_observer_pcr_test_record_measurement_no_active);
TEST (recovery_image_observer_pcr_test_record_measurement_null);
TEST (recovery_image_observer_pcr_test_record_measurement_hash_error);
TEST (recovery_image_observer_pcr_test_on_recovery_image_deactivated);

TEST_SUITE_END;

