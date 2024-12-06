// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_transcript_manager_static.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"


TEST_SUITE_LABEL ("spdm_transcript_manager");


#define HASH_ENGINE_COUNT	SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT + \
	(SPDM_MAX_SESSION_COUNT * SPDM_TRANSCRIPT_MANAGER_SESSION_HASH_ENGINE_REQUIRED_COUNT)

#define SESSION_0_L1L2_HASH_CONTEXT_INDEX	2
#define SESSION_0_TH_HASH_CONTEXT_INDEX		3

/**
 * Dependencies for testing.
 */
struct spdm_transcript_manager_testing {
	struct spdm_transcript_manager transcript_manager;					/**< The transcript manager being tested. */
	struct spdm_transcript_manager_state state;							/**< The transcript manager state. */
	struct hash_engine_mock hash_engine_mock[HASH_ENGINE_COUNT];		/**< Mock hash engines. */
	HASH_TESTING_ENGINE_ARRAY (hash_engine_real, HASH_ENGINE_COUNT);	/**< Real hash engines. */
	const struct hash_engine *hash_engine[HASH_ENGINE_COUNT];			/**< Hash engines. */
	bool use_mock;														/**< Use mocks object. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void spdm_transcript_manager_testing_init_dependencies (CuTest *test,
	struct spdm_transcript_manager_testing *testing, bool use_mock)
{
	int status;
	uint8_t idx;

	testing->use_mock = use_mock;
	for (idx = 0; idx < HASH_ENGINE_COUNT; idx++) {
		if (testing->use_mock == true) {
			status = hash_mock_init (&testing->hash_engine_mock[idx]);
			testing->hash_engine[idx] = &testing->hash_engine_mock[idx].base;
		}
		else {
			status = HASH_TESTING_ENGINE_INIT_ARRAY (&testing->hash_engine_real, idx);
			testing->hash_engine[idx] = &testing->hash_engine_real[idx].base;
		}

		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void spdm_transcript_manager_testing_release_dependencies (CuTest *test,
	struct spdm_transcript_manager_testing *testing)
{
	int status;
	uint8_t idx;

	for (idx = 0; idx < HASH_ENGINE_COUNT; idx++) {
		if (testing->use_mock == true) {
			status = hash_mock_validate_and_release (&testing->hash_engine_mock[idx]);
			CuAssertIntEquals (test, 0, status);
		}
		else {
			HASH_TESTING_ENGINE_RELEASE (&testing->hash_engine_real[idx]);
		}
	}
}

/**
 * Initialize the transcript manager for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void spdm_transcript_manager_testing_init (CuTest *test,
	struct spdm_transcript_manager_testing *testing, bool use_mock)
{
	int status;

	spdm_transcript_manager_testing_init_dependencies (test, testing, use_mock);

	status = spdm_transcript_manager_init (&testing->transcript_manager, &testing->state,
		testing->hash_engine, ARRAY_SIZE (testing->hash_engine));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release transcript manager and validate all mocks.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void spdm_transcript_manager_testing_release (CuTest *test,
	struct spdm_transcript_manager_testing *testing)
{
	spdm_transcript_manager_release (&testing->transcript_manager);

	spdm_transcript_manager_testing_release_dependencies (test, testing);
}


/*******************
 * Test cases
 *******************/

static void spdm_transcript_manager_test_static_init (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;

	TEST_START;

	spdm_transcript_manager_testing_init_dependencies (test, &testing, true);

	const struct spdm_transcript_manager transcript_manager =
		spdm_transcript_manager_static_init (&testing.state, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine));

	status = spdm_transcript_manager_init_state (&transcript_manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, transcript_manager.set_hash_algo);
	CuAssertPtrNotNull (test, transcript_manager.set_spdm_version);
	CuAssertPtrNotNull (test, transcript_manager.update);
	CuAssertPtrNotNull (test, transcript_manager.get_hash);
	CuAssertPtrNotNull (test, transcript_manager.reset_transcript);
	CuAssertPtrNotNull (test, transcript_manager.reset);
	CuAssertPtrNotNull (test, transcript_manager.reset_session_transcript);

	spdm_transcript_manager_release (&transcript_manager);

	spdm_transcript_manager_testing_release_dependencies (test, &testing);
}

static void spdm_transcript_manager_test_static_init_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	const struct hash_engine *backup;

	TEST_START;

	spdm_transcript_manager_testing_init_dependencies (test, &testing, true);

	/* transcript_manager = NULL */
	status = spdm_transcript_manager_init_state (NULL);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* state_ptr = NULL */
	const struct spdm_transcript_manager transcript_manager =
		spdm_transcript_manager_static_init (NULL, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine));

	status = spdm_transcript_manager_init_state (&transcript_manager);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine array = NULL */
	const struct spdm_transcript_manager transcript_manager2 =
		spdm_transcript_manager_static_init (&testing.state, NULL,
		ARRAY_SIZE (testing.hash_engine));

	status = spdm_transcript_manager_init_state (&transcript_manager2);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine_count = 0 */
	const struct spdm_transcript_manager transcript_manager3 =
		spdm_transcript_manager_static_init (&testing.state, testing.hash_engine, 0);

	status = spdm_transcript_manager_init_state (&transcript_manager3);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* Hash engine instance = NULL */
	backup = testing.hash_engine[0];
	testing.hash_engine[0] = NULL;
	const struct spdm_transcript_manager transcript_manager4 =
		spdm_transcript_manager_static_init (&testing.state, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine));

	status = spdm_transcript_manager_init_state (&transcript_manager4);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);
	testing.hash_engine[0] = backup;

	spdm_transcript_manager_testing_release_dependencies (test, &testing);
}

static void spdm_transcript_manager_test_init (CuTest *test)
{
	struct spdm_transcript_manager_testing testing;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);

	CuAssertPtrNotNull (test, testing.transcript_manager.set_hash_algo);
	CuAssertPtrNotNull (test, testing.transcript_manager.set_spdm_version);
	CuAssertPtrNotNull (test, testing.transcript_manager.update);
	CuAssertPtrNotNull (test, testing.transcript_manager.get_hash);
	CuAssertPtrNotNull (test, testing.transcript_manager.reset_transcript);
	CuAssertPtrNotNull (test, testing.transcript_manager.reset);
	CuAssertPtrNotNull (test, testing.transcript_manager.reset_session_transcript);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_init_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	const struct hash_engine *backup;

	TEST_START;

	spdm_transcript_manager_testing_init_dependencies (test, &testing, true);

	/* transcript_manager = NULL */
	status = spdm_transcript_manager_init (NULL, &testing.state, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine));
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* state = NULL */
	status = spdm_transcript_manager_init (&testing.transcript_manager, NULL, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine));
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine array = NULL */
	status = spdm_transcript_manager_init (&testing.transcript_manager, &testing.state, NULL,
		ARRAY_SIZE (testing.hash_engine));
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine_count < SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT */
	status = spdm_transcript_manager_init (&testing.transcript_manager, &testing.state,
		testing.hash_engine, SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT - 1);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* Hash engine = NULL */
	backup = testing.hash_engine[0];
	testing.hash_engine[0] = NULL;
	status = spdm_transcript_manager_init (&testing.transcript_manager, &testing.state,
		testing.hash_engine, ARRAY_SIZE (testing.hash_engine));
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);
	testing.hash_engine[0] = backup;
}

static void spdm_transcript_manager_test_release_null (CuTest *test)
{
	TEST_START;
	spdm_transcript_manager_release (NULL);
}

static void spdm_transcript_manager_test_reset (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	char *str = "Hello";

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, transcript_manager->state->hash_algo);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	/* Update VCA */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	/* Update M1M2 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	/* Update L1L2 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);

	/* Update Session L1L2 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(const uint8_t*) str, strlen (str), true, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].l1l2.hash_started);

	/* Update TH */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(const uint8_t*) str, strlen (str), true, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].th.hash_started);

	transcript_manager->reset (transcript_manager);

	CuAssertIntEquals (test, HASH_TYPE_INVALID, transcript_manager->state->hash_algo);
	CuAssertIntEquals (test, 0, transcript_manager->state->message_vca.buffer_size);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started == false);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started == false);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[0].l1l2.hash_started == false);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].th.hash_started == false);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	char *str = "Hello";

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, transcript_manager->state->hash_algo);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	/* Update VCA */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	/* Update M1M2 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	/* Update L1L2 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);

	/* Update Session L1L2 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(const uint8_t*) str, strlen (str), true, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].l1l2.hash_started);

	/* Update TH */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(const uint8_t*) str, strlen (str), true, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].th.hash_started);

	transcript_manager->reset (NULL);

	CuAssertIntEquals (test, HASH_TYPE_SHA384, transcript_manager->state->hash_algo);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].l1l2.hash_started);
	CuAssertTrue (test, transcript_manager->state->session_transcript[0].th.hash_started);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_vca (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	char *str = "Hello";

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	str = "SPDM";
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	str = "World!";
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	str = "HelloSPDMWorld!";
	status = strcmp ((const char*) transcript_manager->state->message_vca.buffer, str);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	const void *message = (const uint8_t*) 0xDEADBEEF;
	size_t message_size = 100;
	bool use_session_context = false;
	uint8_t session_idx = 0;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	/* transcript manager = NULL */
	status = transcript_manager->update (NULL, TRANSCRIPT_CONTEXT_TYPE_VCA, message, message_size,
		use_session_context, session_idx);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* transcript context type invalid */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_MAX, message,
		message_size, use_session_context, session_idx);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE, status);

	/* message = NULL */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, NULL,
		message_size, use_session_context, session_idx);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* message_size = 0 */
	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, message,
		0, use_session_context, session_idx);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_vca_buffer_full (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	const void *message = (const uint8_t*) 0xDEADBEEF;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA, message,
		ARRAY_SIZE (transcript_manager->state->message_vca.buffer) + 1, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_BUFFER_FULL, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA256 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA256_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xd9, 0xe0, 0xd4, 0xc3, 0x85, 0x0a, 0xa1, 0x30, 0xf9, 0x09,
		0xe1, 0xbc, 0xaf, 0xeb, 0xea, 0x98, 0xa1, 0x67, 0x00, 0xe0, 0x21, 0x71, 0xc1, 0xdf, 0x5a,
		0x2f, 0xe3, 0x17, 0x89, 0xd9, 0x4b, 0x0f
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA256_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA256_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		SPDM_TRANSCRIPT_MANAGER_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA256_second_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		SPDM_TRANSCRIPT_MANAGER_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA384 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA384_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xe1, 0x28, 0x84, 0x30, 0xfb, 0xb2, 0xd4, 0x63, 0xa1, 0xbd,
		0xdf, 0x76, 0x2c, 0x04, 0x62, 0xa8, 0xc3, 0xde, 0xb8, 0x88, 0x3c, 0x3e, 0x6d, 0x0c, 0x12,
		0x1c, 0xa7, 0xd6, 0xc5, 0x25, 0x3b, 0x7a, 0x7b, 0xc6, 0x25, 0x52, 0x99, 0x41, 0x37, 0x1b,
		0x74, 0x7a, 0x89, 0x83, 0x45, 0xde, 0x84, 0x67
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = testing.transcript_manager.set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA384_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA384_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA384_second_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA512 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA512_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0x0a, 0x12, 0x15, 0xf3, 0x1a, 0xcd, 0x40, 0xae, 0x63, 0x89,
		0x9d, 0xa3, 0x1e, 0xa7, 0x25, 0xf7, 0x6b, 0x78, 0x8f, 0x2d, 0xdb, 0x5d, 0x13, 0x1f, 0x19,
		0xc2, 0xd9, 0x2d, 0x16, 0x50, 0x56, 0xba, 0x38, 0x17, 0xb6, 0x7d, 0xc8, 0x3b, 0x59, 0xc9,
		0x56, 0x08, 0x02, 0x91, 0xeb, 0xce, 0x74, 0xcb, 0x57, 0x12, 0xc3, 0x60, 0xdd, 0x93, 0x2e,
		0x3f, 0x92, 0x65, 0xf2, 0x8e, 0x22, 0x3c, 0x38, 0x48
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA512_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA512_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_m1m2_SHA512_second_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_PTR (transcript_manager->state->message_vca.buffer), MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_unsupported_hash_algo (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_unsupported_context_type (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH + 1,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_vca (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	char *str = "Hello";

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, transcript_manager->state->message_vca.buffer_size);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_vca_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	char *str = "Hello";

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_VCA,
		(const uint8_t*) str, strlen (str), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	/* transcript_manager = NULL */
	transcript_manager->reset_transcript (NULL, TRANSCRIPT_CONTEXT_TYPE_VCA, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, strlen (str), transcript_manager->state->message_vca.buffer_size);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_m1m2 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = testing.transcript_manager.set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started == false);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_m1m2_invalid_params (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = testing.transcript_manager.set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	/* transcript_manager = NULL */
	transcript_manager->reset_transcript (NULL, TRANSCRIPT_CONTEXT_TYPE_M1M2, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	/* use_session_context = true */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	/* Invalid context type */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_MAX, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->m1m2.hash_started);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_l1l2 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = testing.transcript_manager.set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);

	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,	false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started == false);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_l1l2_invalid_params (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = testing.transcript_manager.set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);

	/* transcript_manager = NULL */
	transcript_manager->reset_transcript (NULL, TRANSCRIPT_CONTEXT_TYPE_L1L2, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);

	/* Invalid context type */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_MAX, false,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test, transcript_manager->state->l1l2.hash_started);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_session_l1l2 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t session_index = 0;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, session_index);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].l1l2.hash_started);

	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,	true,
		session_index);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].l1l2.hash_started == false);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_session_l1l2_invalid_params (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t session_index = 0;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, session_index);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].l1l2.hash_started);

	/* Invalid session index */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,	true,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].l1l2.hash_started);

	/* Invalid context type */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_MAX, true,
		session_index);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].l1l2.hash_started);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_th (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t session_index = 0;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, session_index);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started);

	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		session_index);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started == false);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_reset_context_th_invalid_params (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t session_index = 0;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, session_index);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started);

	/* transcript_manager = NULL */
	transcript_manager->reset_transcript (NULL, TRANSCRIPT_CONTEXT_TYPE_TH, true, session_index);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started);

	/* use_session_context = false */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, false,
		session_index);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started);

	/* Invalid session index */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		SPDM_MAX_SESSION_COUNT);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started);

	/* Invalid context type */
	transcript_manager->reset_transcript (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_MAX, true,
		session_index);
	CuAssertTrue (test,
		transcript_manager->state->session_transcript[session_index].th.hash_started);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA256_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xd9, 0xe0, 0xd4, 0xc3, 0x85, 0x0a, 0xa1, 0x30, 0xf9, 0x09,
		0xe1, 0xbc, 0xaf, 0xeb, 0xea, 0x98, 0xa1, 0x67, 0x00, 0xe0, 0x21, 0x71, 0xc1, 0xdf, 0x5a,
		0x2f, 0xe3, 0x17, 0x89, 0xd9, 0x4b, 0x0f
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA384_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xe1, 0x28, 0x84, 0x30, 0xfb, 0xb2, 0xd4, 0x63, 0xa1, 0xbd,
		0xdf, 0x76, 0x2c, 0x04, 0x62, 0xa8, 0xc3, 0xde, 0xb8, 0x88, 0x3c, 0x3e, 0x6d, 0x0c, 0x12,
		0x1c, 0xa7, 0xd6, 0xc5, 0x25, 0x3b, 0x7a, 0x7b, 0xc6, 0x25, 0x52, 0x99, 0x41, 0x37, 0x1b,
		0x74, 0x7a, 0x89, 0x83, 0x45, 0xde, 0x84, 0x67
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA512_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0x0a, 0x12, 0x15, 0xf3, 0x1a, 0xcd, 0x40, 0xae, 0x63, 0x89,
		0x9d, 0xa3, 0x1e, 0xa7, 0x25, 0xf7, 0x6b, 0x78, 0x8f, 0x2d, 0xdb, 0x5d, 0x13, 0x1f, 0x19,
		0xc2, 0xd9, 0x2d, 0x16, 0x50, 0x56, 0xba, 0x38, 0x17, 0xb6, 0x7d, 0xc8, 0x3b, 0x59, 0xc9,
		0x56, 0x08, 0x02, 0x91, 0xeb, 0xce, 0x74, 0xcb, 0x57, 0x12, 0xc3, 0x60, 0xdd, 0x93, 0x2e,
		0x3f, 0x92, 0x65, 0xf2, 0x8e, 0x22, 0x3c, 0x38, 0x48
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_1 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA256_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xd9, 0xe0, 0xd4, 0xc3, 0x85, 0x0a, 0xa1, 0x30, 0xf9, 0x09,
		0xe1, 0xbc, 0xaf, 0xeb, 0xea, 0x98, 0xa1, 0x67, 0x00, 0xe0, 0x21, 0x71, 0xc1, 0xdf, 0x5a,
		0x2f, 0xe3, 0x17, 0x89, 0xd9, 0x4b, 0x0f
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_1_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA256_v_1_1_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_1 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA384_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xe1, 0x28, 0x84, 0x30, 0xfb, 0xb2, 0xd4, 0x63, 0xa1, 0xbd,
		0xdf, 0x76, 0x2c, 0x04, 0x62, 0xa8, 0xc3, 0xde, 0xb8, 0x88, 0x3c, 0x3e, 0x6d, 0x0c, 0x12,
		0x1c, 0xa7, 0xd6, 0xc5, 0x25, 0x3b, 0x7a, 0x7b, 0xc6, 0x25, 0x52, 0x99, 0x41, 0x37, 0x1b,
		0x74, 0x7a, 0x89, 0x83, 0x45, 0xde, 0x84, 0x67
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_1_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA384_v_1_1_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_1 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA512_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0x0a, 0x12, 0x15, 0xf3, 0x1a, 0xcd, 0x40, 0xae, 0x63, 0x89,
		0x9d, 0xa3, 0x1e, 0xa7, 0x25, 0xf7, 0x6b, 0x78, 0x8f, 0x2d, 0xdb, 0x5d, 0x13, 0x1f, 0x19,
		0xc2, 0xd9, 0x2d, 0x16, 0x50, 0x56, 0xba, 0x38, 0x17, 0xb6, 0x7d, 0xc8, 0x3b, 0x59, 0xc9,
		0x56, 0x08, 0x02, 0x91, 0xeb, 0xce, 0x74, 0xcb, 0x57, 0x12, 0xc3, 0x60, 0xdd, 0x93, 0x2e,
		0x3f, 0x92, 0x65, 0xf2, 0x8e, 0x22, 0x3c, 0x38, 0x48
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_1_start_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_update_l1l2_SHA512_v_1_1_update_hash_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA256_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xd9, 0xe0, 0xd4, 0xc3, 0x85, 0x0a, 0xa1, 0x30, 0xf9, 0x09,
		0xe1, 0xbc, 0xaf, 0xeb, 0xea, 0x98, 0xa1, 0x67, 0x00, 0xe0, 0x21, 0x71, 0xc1, 0xdf, 0x5a,
		0x2f, 0xe3, 0x17, 0x89, 0xd9, 0x4b, 0x0f
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA384_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xe1, 0x28, 0x84, 0x30, 0xfb, 0xb2, 0xd4, 0x63, 0xa1, 0xbd,
		0xdf, 0x76, 0x2c, 0x04, 0x62, 0xa8, 0xc3, 0xde, 0xb8, 0x88, 0x3c, 0x3e, 0x6d, 0x0c, 0x12,
		0x1c, 0xa7, 0xd6, 0xc5, 0x25, 0x3b, 0x7a, 0x7b, 0xc6, 0x25, 0x52, 0x99, 0x41, 0x37, 0x1b,
		0x74, 0x7a, 0x89, 0x83, 0x45, 0xde, 0x84, 0x67
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA512_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0x0a, 0x12, 0x15, 0xf3, 0x1a, 0xcd, 0x40, 0xae, 0x63, 0x89,
		0x9d, 0xa3, 0x1e, 0xa7, 0x25, 0xf7, 0x6b, 0x78, 0x8f, 0x2d, 0xdb, 0x5d, 0x13, 0x1f, 0x19,
		0xc2, 0xd9, 0x2d, 0x16, 0x50, 0x56, 0xba, 0x38, 0x17, 0xb6, 0x7d, 0xc8, 0x3b, 0x59, 0xc9,
		0x56, 0x08, 0x02, 0x91, 0xeb, 0xce, 0x74, 0xcb, 0x57, 0x12, 0xc3, 0x60, 0xdd, 0x93, 0x2e,
		0x3f, 0x92, 0x65, 0xf2, 0x8e, 0x22, 0x3c, 0x38, 0x48
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_1 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA256_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xd9, 0xe0, 0xd4, 0xc3, 0x85, 0x0a, 0xa1, 0x30, 0xf9, 0x09,
		0xe1, 0xbc, 0xaf, 0xeb, 0xea, 0x98, 0xa1, 0x67, 0x00, 0xe0, 0x21, 0x71, 0xc1, 0xdf, 0x5a,
		0x2f, 0xe3, 0x17, 0x89, 0xd9, 0x4b, 0x0f
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_1_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_1_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_1 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA384_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xe1, 0x28, 0x84, 0x30, 0xfb, 0xb2, 0xd4, 0x63, 0xa1, 0xbd,
		0xdf, 0x76, 0x2c, 0x04, 0x62, 0xa8, 0xc3, 0xde, 0xb8, 0x88, 0x3c, 0x3e, 0x6d, 0x0c, 0x12,
		0x1c, 0xa7, 0xd6, 0xc5, 0x25, 0x3b, 0x7a, 0x7b, 0xc6, 0x25, 0x52, 0x99, 0x41, 0x37, 0x1b,
		0x74, 0x7a, 0x89, 0x83, 0x45, 0xde, 0x84, 0x67
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_1_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_1_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_1 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA512_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0x0a, 0x12, 0x15, 0xf3, 0x1a, 0xcd, 0x40, 0xae, 0x63, 0x89,
		0x9d, 0xa3, 0x1e, 0xa7, 0x25, 0xf7, 0x6b, 0x78, 0x8f, 0x2d, 0xdb, 0x5d, 0x13, 0x1f, 0x19,
		0xc2, 0xd9, 0x2d, 0x16, 0x50, 0x56, 0xba, 0x38, 0x17, 0xb6, 0x7d, 0xc8, 0x3b, 0x59, 0xc9,
		0x56, 0x08, 0x02, 0x91, 0xeb, 0xce, 0x74, 0xcb, 0x57, 0x12, 0xc3, 0x60, 0xdd, 0x93, 0x2e,
		0x3f, 0x92, 0x65, 0xf2, 0x8e, 0x22, 0x3c, 0x38, 0x48
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_1_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_1_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_1);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_l1l2_invalid_session_idx (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA256 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA256_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xd9, 0xe0, 0xd4, 0xc3, 0x85, 0x0a, 0xa1, 0x30, 0xf9, 0x09,
		0xe1, 0xbc, 0xaf, 0xeb, 0xea, 0x98, 0xa1, 0x67, 0x00, 0xe0, 0x21, 0x71, 0xc1, 0xdf, 0x5a,
		0x2f, 0xe3, 0x17, 0x89, 0xd9, 0x4b, 0x0f
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA256_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA256_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA256_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha256, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA384 (CuTest *test)
{
	int status;
	const uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA384_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0xe1, 0x28, 0x84, 0x30, 0xfb, 0xb2, 0xd4, 0x63, 0xa1, 0xbd,
		0xdf, 0x76, 0x2c, 0x04, 0x62, 0xa8, 0xc3, 0xde, 0xb8, 0x88, 0x3c, 0x3e, 0x6d, 0x0c, 0x12,
		0x1c, 0xa7, 0xd6, 0xc5, 0x25, 0x3b, 0x7a, 0x7b, 0xc6, 0x25, 0x52, 0x99, 0x41, 0x37, 0x1b,
		0x74, 0x7a, 0x89, 0x83, 0x45, 0xde, 0x84, 0x67
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA384_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA384_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA384_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA512 (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	uint8_t hash[SHA512_HASH_LENGTH];
	const uint8_t expected_hash[] = {
		0x0a, 0x12, 0x15, 0xf3, 0x1a, 0xcd, 0x40, 0xae, 0x63, 0x89,
		0x9d, 0xa3, 0x1e, 0xa7, 0x25, 0xf7, 0x6b, 0x78, 0x8f, 0x2d, 0xdb, 0x5d, 0x13, 0x1f, 0x19,
		0xc2, 0xd9, 0x2d, 0x16, 0x50, 0x56, 0xba, 0x38, 0x17, 0xb6, 0x7d, 0xc8, 0x3b, 0x59, 0xc9,
		0x56, 0x08, 0x02, 0x91, 0xeb, 0xce, 0x74, 0xcb, 0x57, 0x12, 0xc3, 0x60, 0xdd, 0x93, 0x2e,
		0x3f, 0x92, 0x65, 0xf2, 0x8e, 0x22, 0x3c, 0x38, 0x48
	};
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		true, 0, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, 0, status);

	status = memcmp (hash, expected_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA512_start_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx],
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA512_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_SHA512_second_update_hash_fail (
	CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_TH_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha512, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx],
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_update_th_invalid_session_idx (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH,
		(uint8_t*) &data, sizeof (data), true, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_reset_session_transcript (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SESSION_0_L1L2_HASH_CONTEXT_INDEX;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2,
		(uint8_t*) &data, sizeof (data), true, 0);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->reset_session_transcript (transcript_manager, 0);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_reset_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	transcript_manager->set_spdm_version (transcript_manager, SPDM_VERSION_1_2);

	/* transcript_manager = NULL */
	transcript_manager->reset_session_transcript (NULL, 0);

	/* session index >= session_transcript_count */
	transcript_manager->reset_session_transcript (transcript_manager,
		transcript_manager->state->session_transcript_count);

	transcript_manager->reset_session_transcript (transcript_manager,
		transcript_manager->state->session_transcript_count + 1);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_set_hash_algo_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	/* transcript manager = NULL*/
	status = transcript_manager->set_hash_algo (NULL, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* invalid hash_type */
	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_INVALID);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_INVALID + 1);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_set_hash_algo_multiple_set (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_HASH_ALGO_ALREADY_SET, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_get_hash_invalid_params (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t *hash = (uint8_t*) 0xDEADBEEF;
	size_t hash_size = 100;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	/* transcript_manager = NULL */
	status = transcript_manager->get_hash (NULL, TRANSCRIPT_CONTEXT_TYPE_M1M2, true, false,
		SPDM_MAX_SESSION_COUNT, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* transcript context = TRANSCRIPT_CONTEXT_TYPE_MAX */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_MAX, true,
		false, SPDM_MAX_SESSION_COUNT, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE, status);

	/* hash = NULL */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, NULL, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* hash_size = 0 */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, 0);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* use_session_context == true && hash_type == TRANSCRIPT_CONTEXT_TYPE_M1M2 */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		true, SPDM_MAX_SESSION_COUNT, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	/* use_session_context == false && hash_type == TRANSCRIPT_CONTEXT_TYPE_TH */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH, true,
		false, SPDM_MAX_SESSION_COUNT, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_get_hash_invalid_session_idx (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t *hash = (uint8_t*) 0xDEADBEEF;
	size_t hash_size = 100;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_L1L2, true,
		true, transcript_manager->state->session_transcript_count, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_get_hash_unsupported_hash_type (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t *hash = (uint8_t*) 0xDEADBEEF;
	size_t hash_size = 100;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_TH + 1, true,
		false, SPDM_MAX_SESSION_COUNT, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_get_hash_not_started (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t *hash = (uint8_t*) 0xDEADBEEF;
	size_t hash_size = 100;

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, hash_size);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_HASH_NOT_STARTED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_get_hash_double_get (CuTest *test)
{
	int status;
	struct spdm_transcript_manager_testing testing;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, false);
	transcript_manager = &testing.transcript_manager;

	status = testing.transcript_manager.set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	/* First get_hash. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	/* Secong get_hash. */
	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, sizeof (hash));
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_HASH_NOT_STARTED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

static void spdm_transcript_manager_test_session_get_hash_finish_fail (CuTest *test)
{
	int status;
	uint32_t data = 0xDEADBEEF;
	struct spdm_transcript_manager_testing testing;
	struct spdm_transcript_manager *transcript_manager;
	uint8_t idx = SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	spdm_transcript_manager_testing_init (test, &testing, true);
	transcript_manager = &testing.transcript_manager;

	status = transcript_manager->set_hash_algo (transcript_manager, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.start_sha384, &testing.hash_engine_mock[idx], 0);

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (0));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.update, &testing.hash_engine_mock[idx], 0,
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.finish, &testing.hash_engine_mock[idx],
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[idx].mock,
		testing.hash_engine_mock[idx].base.cancel, &testing.hash_engine_mock[idx], 0);

	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->update (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2,
		(uint8_t*) &data, sizeof (data), false, SPDM_MAX_SESSION_COUNT);
	CuAssertIntEquals (test, 0, status);

	status = transcript_manager->get_hash (transcript_manager, TRANSCRIPT_CONTEXT_TYPE_M1M2, true,
		false, SPDM_MAX_SESSION_COUNT, hash, ARRAY_SIZE (hash));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	spdm_transcript_manager_testing_release (test, &testing);
}

// *INDENT-OFF*
TEST_SUITE_START (spdm_transcript_manager);

TEST (spdm_transcript_manager_test_static_init);
TEST (spdm_transcript_manager_test_static_init_invalid_params);
TEST (spdm_transcript_manager_test_init);
TEST (spdm_transcript_manager_test_init_invalid_params);
TEST (spdm_transcript_manager_test_release_null);
TEST (spdm_transcript_manager_test_reset);
TEST (spdm_transcript_manager_test_reset_invalid_params);
TEST (spdm_transcript_manager_test_update_vca);
TEST (spdm_transcript_manager_test_update_invalid_params);
TEST (spdm_transcript_manager_test_vca_buffer_full);
TEST (spdm_transcript_manager_test_update_m1m2_SHA256);
TEST (spdm_transcript_manager_test_update_m1m2_SHA256_start_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA256_update_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA256_second_update_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA384);
TEST (spdm_transcript_manager_test_update_m1m2_SHA384_start_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA384_update_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA384_second_update_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA512);
TEST (spdm_transcript_manager_test_update_m1m2_SHA512_start_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA512_update_hash_fail);
TEST (spdm_transcript_manager_test_update_m1m2_SHA512_second_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2_start_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_2_second_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2_start_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_2_second_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2_start_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_2_second_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_1);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_1_start_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA256_v_1_1_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_1);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_1_start_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA384_v_1_1_update_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_1);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_1_start_hash_fail);
TEST (spdm_transcript_manager_test_update_l1l2_SHA512_v_1_1_update_hash_fail);
TEST (spdm_transcript_manager_test_update_unsupported_hash_algo);
TEST (spdm_transcript_manager_test_update_unsupported_context_type);
TEST (spdm_transcript_manager_test_reset_context_vca);
TEST (spdm_transcript_manager_test_reset_context_vca_invalid_params);
TEST (spdm_transcript_manager_test_reset_context_m1m2);
TEST (spdm_transcript_manager_test_reset_context_m1m2_invalid_params);
TEST (spdm_transcript_manager_test_reset_context_l1l2);
TEST (spdm_transcript_manager_test_reset_context_l1l2_invalid_params);
TEST (spdm_transcript_manager_test_reset_context_session_l1l2);
TEST (spdm_transcript_manager_test_reset_context_session_l1l2_invalid_params);
TEST (spdm_transcript_manager_test_reset_context_th);
TEST (spdm_transcript_manager_test_reset_context_th_invalid_params);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_2_second_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_2_second_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_2_second_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_1);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_1_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA256_v_1_1_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_1);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_1_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA384_v_1_1_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_1);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_1_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_SHA512_v_1_1_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_l1l2_invalid_session_idx);
TEST (spdm_transcript_manager_test_session_update_th_SHA256);
TEST (spdm_transcript_manager_test_session_update_th_SHA256_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA256_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA256_second_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA384);
TEST (spdm_transcript_manager_test_session_update_th_SHA384_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA384_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA384_second_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA512);
TEST (spdm_transcript_manager_test_session_update_th_SHA512_start_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA512_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_SHA512_second_update_hash_fail);
TEST (spdm_transcript_manager_test_session_update_th_invalid_session_idx);
TEST (spdm_transcript_manager_test_session_reset_session_transcript);
TEST (spdm_transcript_manager_test_session_reset_invalid_params);
TEST (spdm_transcript_manager_test_session_set_hash_algo_invalid_params);
TEST (spdm_transcript_manager_test_session_set_hash_algo_multiple_set);
TEST (spdm_transcript_manager_test_session_get_hash_invalid_params);
TEST (spdm_transcript_manager_test_session_get_hash_invalid_session_idx);
TEST (spdm_transcript_manager_test_session_get_hash_unsupported_hash_type);
TEST (spdm_transcript_manager_test_session_get_hash_not_started);
TEST (spdm_transcript_manager_test_session_get_hash_double_get);
TEST (spdm_transcript_manager_test_session_get_hash_finish_fail);


TEST_SUITE_END;
// *INDENT-ON*
