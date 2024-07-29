// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "common/array_size.h"
#include "keystore/key_cache_flash.h"
#include "keystore/key_cache_flash_static.h"
#include "keystore/keystore_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/flash/flash_store_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("key_cache_flash");


/**
 * Maximum number of key slot information this implementation of key cache can handle
 */
#define KEY_CACHE_FLASH_TESTING_MAX_KEY_SLOT_INFO			512

/**
 * Maximum number of requestors for keys from the cache.
 */
#define	KEY_CACHE_FLASH_TESTING_MAX_REQUESTORS				65

/**
 * Dependencies for testing key_cache_flash_testing
 */
struct key_cache_flash_testing {
	struct flash_store_mock flash_mock;	/**< Mock implementation of Flash storage for keys. */
	struct key_cache_flash_state state;	/**< State of the key cache in flash. */
	struct key_cache_flash cache_flash;	/**< Key cache implementation using flash.*/
	struct logging_mock debug;			/**< Debug log mock object */
	size_t max_requestors;				/**< Max requestors allowed for this instance. */
	size_t num_flash_block;				/**< Maximum number of allocated flash blocks */
	uint8_t max_credit;					/**< Maximum key credit value per requestor. */

	/**
	 * Array of key info structures for use by the cache.
	 */
	struct key_cache_flash_key_info key_info[KEY_CACHE_FLASH_TESTING_MAX_KEY_SLOT_INFO];

	/**
	 * Array for tracking requestor credits used by the cache.
	 */
	uint8_t requestor_credit[KEY_CACHE_FLASH_TESTING_MAX_REQUESTORS];
};

/**
 * Describe the state of the cache flash at init time.
 */
struct key_cache_flash_testing_flash_contents {
	size_t block_count;	/**< Then number of sequential flash blocks that share this state. */
	size_t length;		/**< Length of the key data in the block. */
	bool length_fail;	/**< Length request fails. */
	bool read_fail;		/**< Read request fails. */
	bool erase_fail;	/**< Erase request fails. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The testing framework.
 * @param cache_flash_test The testing dependencies to initialize.
 * @param max_requestors The maximum requestor ID value.
 * @param max_credit The maximum credit value per requestor.
 * @param num_flash_block The number of flash blocks allocated to store the keys.
 *
 * @return 0 if the key cache was successfully initialized or an error code.
 */
static void key_cache_flash_testing_init_dependencies (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test, size_t max_requestors, uint8_t max_credit,
	size_t num_flash_block)
{
	int status;

	debug_log = NULL;

	/* Default assignment for max requestor and max Credit  */
	cache_flash_test->max_requestors = max_requestors;
	cache_flash_test->max_credit = max_credit;
	cache_flash_test->num_flash_block = num_flash_block;

	CuAssertTrue (test, (num_flash_block <= KEY_CACHE_FLASH_TESTING_MAX_KEY_SLOT_INFO));
	CuAssertTrue (test, (max_requestors <= KEY_CACHE_FLASH_TESTING_MAX_REQUESTORS));

	status = flash_store_mock_init (&cache_flash_test->flash_mock);
	CuAssertIntEquals (test, 0, status);

	/* Debug log mock init */
	status = logging_mock_init (&cache_flash_test->debug);
	CuAssertIntEquals (test, 0, status);

	debug_log = &cache_flash_test->debug.base;
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The testing framework.
 * @param cache_flash_test The testing dependencies to release.
 */
static void key_cache_flash_testing_release_dependencies (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test)
{
	int status;

	debug_log = NULL;

	status = flash_store_mock_validate_and_release (&cache_flash_test->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&cache_flash_test->debug);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper initialize the flash block with valid key data or blank sector.  It will verify basic
 * setup condition.
 *
 * @param test The testing framework.
 * @param cache_flash_test The testing dependencies.
 * @param flash_index A flash sector that needs to be verified.
 * @param get_data_length_mock_status Mock Output status for flash get_data_length API.
 * @param read_mock_status Mock Output status for flash read API.
 * @param erase_mock_status Mock Output status for flash erase API.
 */
static void key_cache_flash_testing_read_key_and_validate_flash_sector_mock_setup (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test, int flash_index,
	int get_data_length_mock_status, int read_mock_status, int erase_mock_status)
{
	int status;

	status = mock_expect (&cache_flash_test->flash_mock.mock,
		cache_flash_test->flash_mock.base.get_data_length, &cache_flash_test->flash_mock,
		get_data_length_mock_status, MOCK_ARG (flash_index));
	CuAssertIntEquals (test, 0, status);

	if (ROT_IS_ERROR (get_data_length_mock_status)) {
		if (get_data_length_mock_status != FLASH_STORE_NO_DATA) {
			struct debug_log_entry_info entry = {
				.format = DEBUG_LOG_ENTRY_FORMAT,
				.severity = DEBUG_LOG_SEVERITY_ERROR,
				.component = DEBUG_LOG_COMPONENT_KEYSTORE,
				.msg_index = KEYSTORE_LOGGING_CACHE_READ_AND_VALIDATE_FAIL,
				.arg1 = flash_index,
				.arg2 = get_data_length_mock_status
			};

			status |= mock_expect (&cache_flash_test->debug.mock,
				cache_flash_test->debug.base.create_entry, &cache_flash_test->debug, 0,
				MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry,
				LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry)));
			CuAssertIntEquals (test, 0, status);
		}

		goto exit_erase;
	}

	status = mock_expect (&cache_flash_test->flash_mock.mock,
		cache_flash_test->flash_mock.base.read,	&cache_flash_test->flash_mock, read_mock_status,
		MOCK_ARG (flash_index), MOCK_ARG_NOT_NULL, MOCK_ARG (get_data_length_mock_status));
	CuAssertIntEquals (test, 0, status);

	if (ROT_IS_ERROR (read_mock_status)) {
		struct debug_log_entry_info entry = {
			.format = DEBUG_LOG_ENTRY_FORMAT,
			.severity = DEBUG_LOG_SEVERITY_ERROR,
			.component = DEBUG_LOG_COMPONENT_KEYSTORE,
			.msg_index = KEYSTORE_LOGGING_CACHE_READ_AND_VALIDATE_FAIL,
			.arg1 = flash_index,
			.arg2 = read_mock_status
		};

		status |= mock_expect (&cache_flash_test->debug.mock,
			cache_flash_test->debug.base.create_entry, &cache_flash_test->debug, 0,
			MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
			MOCK_ARG (sizeof (entry)));
		CuAssertIntEquals (test, 0, status);

		goto exit_erase;
	}

	return;

exit_erase:
	status = mock_expect (&cache_flash_test->flash_mock.mock,
		cache_flash_test->flash_mock.base.erase, &cache_flash_test->flash_mock,	erase_mock_status,
		MOCK_ARG (flash_index));
	CuAssertIntEquals (test, 0, status);

	if (ROT_IS_ERROR (erase_mock_status)) {
		struct debug_log_entry_info entry = {
			.format = DEBUG_LOG_ENTRY_FORMAT,
			.severity = DEBUG_LOG_SEVERITY_ERROR,
			.component = DEBUG_LOG_COMPONENT_KEYSTORE,
			.msg_index = KEYSTORE_LOGGING_CACHE_BLOCK_CORRUPTED,
			.arg1 = flash_index,
			.arg2 = erase_mock_status
		};

		status |= mock_expect (&cache_flash_test->debug.mock,
			cache_flash_test->debug.base.create_entry, &cache_flash_test->debug, 0,
			MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
			MOCK_ARG (sizeof (entry)));
		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Set up expectations for inspecting the flash during cache initialization.
 *
 * @param test The test framework.
 * @param cache_flash_test The testing dependencies.
 * @param flash_state A list containing the state of the cache flash blocks at init time.
 * @param count The number of distinct states in the list.
 *
 */
static void key_cache_flash_testing_expect_cache_init (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test,
	struct key_cache_flash_testing_flash_contents *flash_state, size_t count)
{
	size_t i;
	size_t j;
	size_t block_id;
	int length_result;
	int read_result;
	int erase_result;

	for (i = 0, block_id = 0; i < count; i++) {
		for (j = 0; j < flash_state[i].block_count; j++, block_id++) {
			if (flash_state[i].length_fail) {
				length_result = FLASH_STORE_GET_LENGTH_FAILED;
			}
			else if (flash_state[i].length == 0) {
				length_result = FLASH_STORE_NO_DATA;
			}
			else {
				length_result = flash_state[i].length;
			}

			if (flash_state[i].read_fail) {
				read_result = FLASH_STORE_READ_FAILED;
			}
			else if (flash_state[i].length == 0) {
				read_result = FLASH_STORE_NO_DATA;
			}
			else {
				read_result = flash_state[i].length;
			}

			if (flash_state[i].erase_fail) {
				erase_result = FLASH_STORE_ERASE_FAILED;
			}
			else {
				erase_result = 0;
			}

			key_cache_flash_testing_read_key_and_validate_flash_sector_mock_setup (test,
				cache_flash_test, block_id, length_result, read_result, erase_result);
		}
	}
}

/**
 * Initialize a key cache in flash for testing.
 *
 * @param test The test framework.
 * @param cache_flash_test Testing components to initialize.
 * @param flash_state A list containing the state of the cache flash blocks at init time.
 * @param count The number of distinct states in the list.
 * @param max_requestors The maximum requestor ID value.
 * @param max_credit The maximum credit value per requestor.
 * @param num_flash_block The number of flash blocks allocated to store the keys.
 */
static void key_cache_flash_testing_init (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test,
	struct key_cache_flash_testing_flash_contents *flash_state, size_t count, size_t max_requestors,
	uint8_t max_credit, size_t num_flash_block)
{
	int status;

	key_cache_flash_testing_init_dependencies (test, cache_flash_test, max_requestors, max_credit,
		num_flash_block);

	status = mock_expect (&cache_flash_test->flash_mock.mock,
		cache_flash_test->flash_mock.base.get_num_blocks, &cache_flash_test->flash_mock,
		num_flash_block);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, cache_flash_test, flash_state, count);

	status = key_cache_flash_init (&cache_flash_test->cache_flash, &cache_flash_test->state,
		&cache_flash_test->flash_mock.base, cache_flash_test->key_info, num_flash_block,
		cache_flash_test->requestor_credit, cache_flash_test->max_requestors,
		cache_flash_test->max_credit);
	CuAssertIntEquals (test, 0, status);

	status =
		cache_flash_test->cache_flash.base.initialize_cache (&cache_flash_test->cache_flash.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for a key cache in flash for testing.
 *
 * @param test The test framework.
 * @param cache_flash_test Testing components to initialize.
 * @param flash_state A list containing the state of the cache flash blocks at init time.
 * @param count The number of distinct states in the list.
 * @param max_requestors The maximum requestor ID value.
 * @param max_credit The maximum credit value per requestor.
 * @param num_flash_block The number of flash blocks allocated to store the keys.
 */
static void key_cache_flash_testing_init_static (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test,
	struct key_cache_flash_testing_flash_contents *flash_state, size_t count, size_t max_requestors,
	uint8_t max_credit, size_t num_flash_block)
{
	int status;

	key_cache_flash_testing_init_dependencies (test, cache_flash_test, max_requestors, max_credit,
		num_flash_block);

	status = mock_expect (&cache_flash_test->flash_mock.mock,
		cache_flash_test->flash_mock.base.get_num_blocks, &cache_flash_test->flash_mock,
		num_flash_block);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, cache_flash_test, flash_state, count);

	status = key_cache_flash_init_state (&cache_flash_test->cache_flash);
	CuAssertIntEquals (test, 0, status);

	status =
		cache_flash_test->cache_flash.base.initialize_cache (&cache_flash_test->cache_flash.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release key cache components and validate all mocks.
 *
 * @param test The test framework.
 * @param cache_flash_test Testing components to release.
 */
static void key_cache_flash_testing_release (CuTest *test,
	struct key_cache_flash_testing *cache_flash_test)
{
	key_cache_flash_release (&cache_flash_test->cache_flash);

	key_cache_flash_testing_release_dependencies (test, cache_flash_test);
}

/*******************
 * Test cases
 *******************/

static void key_cache_flash_test_init (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_initialized);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_error_state);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_full);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_empty);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.initialize_cache);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.add);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.remove);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_init_with_more_valid_keys_than_required (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits + 1;
	size_t flash_blocks = keys;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_init_null (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = key_cache_flash_init (NULL, &cache_flash_test.state, &cache_flash_test.flash_mock.base,
		cache_flash_test.key_info, flash_blocks, cache_flash_test.requestor_credit,
		cache_flash_test.max_requestors, cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, NULL,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state, NULL,
		cache_flash_test.key_info, flash_blocks, cache_flash_test.requestor_credit,
		cache_flash_test.max_requestors, cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, NULL, flash_blocks, cache_flash_test.requestor_credit,
		cache_flash_test.max_requestors, cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks, NULL,
		cache_flash_test.max_requestors, cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, 0, cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,	0);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_init_with_insufficient_flash_blocks_for_keys (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_INSUFFICIENT_STORAGE, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_init_with_insufficient_flash_blocks_in_store (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks - 1);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, KEY_CACHE_STORAGE_MISMATCH, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_init_failed_with_get_num_block (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		FLASH_STORE_NUM_BLOCKS_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, FLASH_STORE_NUM_BLOCKS_FAILED, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init (CuTest *test)
{
	size_t requestors = 24;
	uint8_t credits = 1;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_initialized);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_error_state);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_full);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.is_empty);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.initialize_cache);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.add);
	CuAssertPtrNotNull (test, cache_flash_test.cache_flash.base.remove);

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init_with_more_valid_keys_than_required (CuTest *test)
{
	size_t requestors = 24;
	uint8_t credits = 1;
	size_t keys = requestors * credits + 1;
	size_t flash_blocks = keys;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init_null (CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	struct key_cache_flash null_state = key_cache_flash_static_init (NULL,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, requestors, credits);
	struct key_cache_flash null_flash = key_cache_flash_static_init (&cache_flash_test.state, NULL,
		cache_flash_test.key_info, flash_blocks, cache_flash_test.requestor_credit, requestors,
		credits);
	struct key_cache_flash null_key_info = key_cache_flash_static_init (&cache_flash_test.state,
		&cache_flash_test.flash_mock.base, NULL, flash_blocks, cache_flash_test.requestor_credit,
		requestors, credits);
	struct key_cache_flash null_credits = key_cache_flash_static_init (&cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks, NULL,
		requestors, credits);
	struct key_cache_flash zero_requestors = key_cache_flash_static_init (&cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, 0, credits);
	struct key_cache_flash zero_credits = key_cache_flash_static_init (&cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, requestors, 0);
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = key_cache_flash_init_state (NULL);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init_state (&null_state);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init_state (&null_flash);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init_state (&null_key_info);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init_state (&null_credits);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init_state (&zero_requestors);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = key_cache_flash_init_state (&zero_credits);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init_with_insufficient_flash_blocks_for_keys (CuTest *test)
{
	size_t requestors = 30;
	uint8_t credits = 3;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, KEY_CACHE_INSUFFICIENT_STORAGE, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init_with_insufficient_flash_blocks_in_store (CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks - 1);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, KEY_CACHE_STORAGE_MISMATCH, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init_failed_with_get_num_block (CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		FLASH_STORE_NUM_BLOCKS_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, FLASH_STORE_NUM_BLOCKS_FAILED, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_cache_empty (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_cache_full (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 32;
	uint8_t credits = 4;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_cache_with_different_flash_states (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 10;
	uint8_t credits = 25;
	size_t flash_blocks = KEY_CACHE_FLASH_TESTING_MAX_KEY_SLOT_INFO;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Corrupted blocks */
			.block_count = 5,
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		},
		{	/* Read failure */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = true,
			.erase_fail = false
		},
		{	/* Corrupted blocks after read failure */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = true,
			.erase_fail = true
		},
		{	/* Key Available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 25,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_cache_flash_extra_blocks (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 32;
	uint8_t credits = 4;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks + 1);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_with_more_valid_keys_than_required (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 32;
	uint8_t credits = 4;
	size_t keys = requestors * credits + 1;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_with_valid_keys_in_all_flash_sectors (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 32;
	uint8_t credits = 4;
	size_t keys = requestors * credits + 1;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_cache_null (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status = cache_flash_test.cache_flash.base.initialize_cache (NULL);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_initialized_cache_too_many_corrupted_blocks (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = keys - 1,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Corrupted blocks */
			.block_count = flash_blocks - (keys - 1),
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		}
	};

	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_CACHE_UNAVAILABLE_STORAGE,
		.arg1 = flash_blocks - 1,
		.arg2 = keys + 1
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = mock_expect (&cache_flash_test.debug.mock, cache_flash_test.debug.base.create_entry,
		&cache_flash_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init (&cache_flash_test.cache_flash, &cache_flash_test.state,
		&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
		cache_flash_test.requestor_credit, cache_flash_test.max_requestors,
		cache_flash_test.max_credit);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_error_state (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_cache_empty (CuTest *test)
{
	size_t requestors = 24;
	uint8_t credits = 1;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_cache_full (CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_cache_with_different_flash_states (CuTest *test)
{
	size_t requestors = 54;
	uint8_t credits = 7;
	size_t flash_blocks = KEY_CACHE_FLASH_TESTING_MAX_KEY_SLOT_INFO;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Corrupted blocks */
			.block_count = 5,
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		},
		{	/* Read failure */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = true,
			.erase_fail = false
		},
		{	/* Corrupted blocks after read failure */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = true,
			.erase_fail = true
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 20,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_cache_flash_extra_blocks (CuTest *test)
{
	size_t requestors = 32;
	uint8_t credits = 4;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks + 1);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_with_more_valid_keys_than_required (
	CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits + 1;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_with_valid_keys_in_all_flash_sectors (
	CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits + 2;
	size_t flash_blocks = keys;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_full (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.is_empty (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_static_initialized_cache_null (CuTest *test)
{
	size_t requestors = 32;
	uint8_t credits = 4;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks + 1);
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status = cache_flash_test.cache_flash.base.initialize_cache (NULL);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_static_init_too_many_corrupted_blocks (CuTest *test)
{
	size_t requestors = 40;
	uint8_t credits = 4;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = keys - 1,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Corrupted blocks */
			.block_count = flash_blocks - (keys - 1),
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		}
	};

	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_CACHE_UNAVAILABLE_STORAGE,
		.arg1 = flash_blocks - 1,
		.arg2 = keys + 1
	};

	TEST_START;

	key_cache_flash_testing_init_dependencies (test, &cache_flash_test,	requestors, credits,
		flash_blocks);

	status = mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.get_num_blocks, &cache_flash_test.flash_mock,
		flash_blocks);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_expect_cache_init (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state));

	status = mock_expect (&cache_flash_test.debug.mock, cache_flash_test.debug.base.create_entry,
		&cache_flash_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = key_cache_flash_init_state (&cache_flash_test.cache_flash);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	status =
		cache_flash_test.cache_flash.base.initialize_cache (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	key_cache_flash_testing_release_dependencies (test, &cache_flash_test);
}

static void key_cache_flash_test_release_null (CuTest *test)
{
	TEST_START;

	key_cache_flash_release (NULL);
}

static void key_cache_flash_test_is_initialize_null (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.is_initialized (NULL);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_is_error_state_null (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.is_error_state (NULL);
	CuAssertIntEquals (test, true, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_is_full_null (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - keys,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.is_full (NULL);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_is_empty_null (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = keys + 1;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.is_empty (NULL);
	CuAssertIntEquals (test, true, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

// /* TODO:  There are too many references to internal fields in these tests (there should be none).
//  * The tests need to reworked to generate and check the desired conditions using the public APIs.
//  * Only in scenarios where this is impossible should internal fields be modified. */

// /* TODO:  This seems a fairly complicated module to only have one "good" test case for remove and
//  * add calls.  Seems there should be more tests covering different scenarios.  Primarily, different
//  * states of the flash when adding/removing. */

//  /* TODO:  There should be tests covering add/remove with different configurations of requestors
//   * and credits.  All the tests here use the same parameters.  It would seem particularly
//   * interesting to add tests where there is 1 requestor with several credits and several requestors
//   * with only 1 credit. */

static void key_cache_flash_test_remove (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, 1192,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_PTR (key),
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock, 0,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	/* Call Remove Key API */
	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_with_all_flash_sector_with_valid_key (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = ((requestors * credits) * 2) + 1;
	size_t flash_blocks = keys;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, 1192,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_PTR (key),
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock, 0,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	/* Call Remove Key API */
	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_with_static_init (CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_static (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state), requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, 1192,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock, 0,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_invalid_argument (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.remove (NULL, requestor_id, key, sizeof (key),
		&key_length);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, NULL, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), NULL);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.remove (NULL, requestor_id, NULL, sizeof (key),
		NULL);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_invalid_requestor_id (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 200;	// Set invalid requestor ID
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{							/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_REQUESTOR_ID, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_fatal_error (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Fatal error flag is true */
	cache_flash_test.cache_flash.state->is_cache_initialized = false;

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_NOT_INITIALIZED, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_failed_with_error_state (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Fatal error flag is true */
	cache_flash_test.cache_flash.state->is_error_state = true;

	status = cache_flash_test.cache_flash.base.is_error_state (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_UNAVAILABLE_STORAGE, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_with_invalid_remove_index (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	cache_flash_test.cache_flash.state->remove_index = 2000;	// Set invalid remove index

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_REMOVE_INDEX, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_with_no_valid_key_on_flash_sector (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Setup: Invalid flash status */
	cache_flash_test.cache_flash.key_info[cache_flash_test.cache_flash.state->remove_index].valid =
		KEY_CACHE_FLASH_INVALID;

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_KEY_NOT_FOUND_AT_INDEX, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_with_physical_id (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Setup: Invalid physical memory */
	cache_flash_test.cache_flash.key_info[cache_flash_test.cache_flash.state->remove_index].
	physical_id = 1023;

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_MEMORY_CORRUPTED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_with_queue_is_empty (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 2;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_QUEUE_IS_EMPTY, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_all_credit_used (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 5;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, KEY_CACHE_CREDIT_NOT_AVAILABLE, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_failed_with_small_input_buffer (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[1048];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, FLASH_STORE_BUFFER_TOO_SMALL,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock, 0,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_read_failed (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, FLASH_STORE_NO_DATA,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock, 0,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_read_and_erase_failed (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t flash_blocks = 133;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_CACHE_BLOCK_CORRUPTED,
		.arg1 = 0,
		.arg2 = FLASH_STORE_ERASE_FAILED,
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.debug.mock, cache_flash_test.debug.base.create_entry,
		&cache_flash_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, FLASH_STORE_NO_DATA,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock,
		FLASH_STORE_ERASE_FAILED, MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_remove_read_and_erase_failed_with_fatal_error (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t flash_blocks = 133;
	uint8_t key[4096];
	size_t key_length = 0;
	uint16_t requestor_id = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 6,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Corrupt block */
			.block_count = 1,
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		}
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_CACHE_BLOCK_CORRUPTED,
		.arg1 = 0,
		.arg2 = FLASH_STORE_ERASE_FAILED,
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock Definition for remove function */
	status = mock_expect (&cache_flash_test.debug.mock, cache_flash_test.debug.base.create_entry,
		&cache_flash_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.read,
		&cache_flash_test.flash_mock, FLASH_STORE_NO_DATA,
		MOCK_ARG (cache_flash_test.cache_flash.state->remove_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (key)));
	status |= mock_expect (&cache_flash_test.flash_mock.mock,
		cache_flash_test.flash_mock.base.erase,	&cache_flash_test.flash_mock,
		FLASH_STORE_ERASE_FAILED, MOCK_ARG (cache_flash_test.cache_flash.state->remove_index));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.remove (&cache_flash_test.cache_flash.base,
		requestor_id, key, sizeof (key), &key_length);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock the write function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.write,
		&cache_flash_test.flash_mock, 0, MOCK_ARG (cache_flash_test.cache_flash.state->add_index),
		MOCK_ARG_PTR_CONTAINS (key, sizeof (key)), MOCK_ARG (sizeof (key)));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_with_empty_cache (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Empty blocks */
			.block_count = flash_blocks,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock the write function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.write,
		&cache_flash_test.flash_mock, 0, MOCK_ARG (cache_flash_test.cache_flash.state->add_index),
		MOCK_ARG_PTR_CONTAINS (key, sizeof (key)), MOCK_ARG (sizeof (key)));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_with_static_init (CuTest *test)
{
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	struct key_cache_flash_testing cache_flash_test = {
		.cache_flash = key_cache_flash_static_init (&cache_flash_test.state,
			&cache_flash_test.flash_mock.base, cache_flash_test.key_info, flash_blocks,
			cache_flash_test.requestor_credit, requestors, credits),
	};
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init_static (test, &cache_flash_test, flash_state,
		ARRAY_SIZE (flash_state), requestors, credits, flash_blocks);

	/* Mock the write function */
	status = mock_expect (&cache_flash_test.flash_mock.mock, cache_flash_test.flash_mock.base.write,
		&cache_flash_test.flash_mock, 0, MOCK_ARG (cache_flash_test.cache_flash.state->add_index),
		MOCK_ARG_PTR_CONTAINS (key, sizeof (key)), MOCK_ARG (sizeof (key)));
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, 0, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_invalid_argument (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.add (NULL, key, key_length);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, NULL,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key, 0);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	status = cache_flash_test.cache_flash.base.add (NULL, NULL, 0);
	CuAssertIntEquals (test, KEY_CACHE_INVALID_ARGUMENT, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_failed_with_error_state (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Setup for fatal error */
	cache_flash_test.cache_flash.state->is_error_state = true;

	status = cache_flash_test.cache_flash.base.is_error_state (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, true, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_UNAVAILABLE_STORAGE, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_fatal_error (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Setup for fatal error */
	cache_flash_test.cache_flash.state->is_cache_initialized = false;

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_NOT_INITIALIZED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_failed_with_queue_full (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 130,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 130,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_QUEUE_IS_FULL, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_invalid_add_index (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Setup: Invalid add index */
	cache_flash_test.cache_flash.state->add_index = 200;
	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_MEMORY_CORRUPTED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_with_all_flash_sector_with_valid_key (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits + 2;
	size_t flash_blocks = keys;
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = keys,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_QUEUE_IS_FULL, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_invalid_requestor_id (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int add_index = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Setup for fatal error */
	add_index = cache_flash_test.cache_flash.state->add_index;
	cache_flash_test.cache_flash.key_info[add_index].requestor_id = 131;

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_MEMORY_CORRUPTED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_with_no_physical_memory_available (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits;
	size_t flash_blocks = (keys * 2) + 1;
	uint8_t key[4] = {0};
	size_t key_length = 4;
	int add_index = 0;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	add_index = cache_flash_test.cache_flash.state->add_index;
	/* Setup: Invalid physical memory */
	cache_flash_test.cache_flash.key_info[add_index].physical_id = 130;
	cache_flash_test.cache_flash.num_flash_sectors = 100;

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, KEY_CACHE_MEMORY_CORRUPTED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_write_failed_without_fatal_error (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t flash_blocks = 133;
	size_t i;
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 5,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	/* Mock the write and erase function */
	for (i = 0; i < KEY_CACHE_FLASH_MAX_ADD_RETRY; i++) {
		status = mock_expect (&cache_flash_test.flash_mock.mock,
			cache_flash_test.flash_mock.base.write,	&cache_flash_test.flash_mock,
			FLASH_STORE_WRITE_FAILED, MOCK_ARG (cache_flash_test.cache_flash.state->add_index),
			MOCK_ARG_PTR_CONTAINS (key, sizeof (key)), MOCK_ARG (sizeof (key)));
	}
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_failed_unavailable_new_sector (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t keys = requestors * credits + 1;
	size_t flash_blocks = 133;
	size_t i;
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 7,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Corrupted blocks */
			.block_count = 2,
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		},
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_KEYSTORE,
		.msg_index = KEYSTORE_LOGGING_CACHE_UNAVAILABLE_STORAGE,
		.arg1 = flash_blocks - 2,
		.arg2 = keys,
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	status = mock_expect (&cache_flash_test.debug.mock, cache_flash_test.debug.base.create_entry,
		&cache_flash_test.debug, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Mock the write and erase function */
	for (i = 0; i < KEY_CACHE_FLASH_MAX_ADD_RETRY; i++) {
		status |= mock_expect (&cache_flash_test.flash_mock.mock,
			cache_flash_test.flash_mock.base.write,	&cache_flash_test.flash_mock,
			FLASH_STORE_WRITE_FAILED, MOCK_ARG (cache_flash_test.cache_flash.state->add_index),
			MOCK_ARG_PTR_CONTAINS (key, sizeof (key)), MOCK_ARG (sizeof (key)));
	}
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	status = cache_flash_test.cache_flash.base.is_initialized (&cache_flash_test.cache_flash.base);
	CuAssertIntEquals (test, false, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}

static void key_cache_flash_test_add_write_failed_with_fatal_error (CuTest *test)
{
	struct key_cache_flash_testing cache_flash_test;
	size_t requestors = 65;
	uint8_t credits = 2;
	size_t flash_blocks = 133;
	uint8_t key[512] = {0};
	size_t key_length = 512;
	int status;
	struct key_cache_flash_testing_flash_contents flash_state[] = {
		{	/* Keys available */
			.block_count = 5,
			.length = 1192,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{	/* Empty blocks */
			.block_count = flash_blocks - 6,
			.length = 0,
			.length_fail = false,
			.read_fail = false,
			.erase_fail = false
		},
		{
			.block_count = 1,
			.length = 0,
			.length_fail = true,
			.read_fail = false,
			.erase_fail = true
		}
	};

	TEST_START;

	key_cache_flash_testing_init (test, &cache_flash_test, flash_state, ARRAY_SIZE (flash_state),
		requestors, credits, flash_blocks);

	for (int i = 0; i < KEY_CACHE_FLASH_MAX_ADD_RETRY; i++) {
		status = mock_expect (&cache_flash_test.flash_mock.mock,
			cache_flash_test.flash_mock.base.write,	&cache_flash_test.flash_mock,
			FLASH_STORE_WRITE_FAILED, MOCK_ARG (cache_flash_test.cache_flash.state->add_index),
			MOCK_ARG_PTR_CONTAINS (key, sizeof (key)), MOCK_ARG (sizeof (key)));
	}
	CuAssertIntEquals (test, 0, status);

	status = cache_flash_test.cache_flash.base.add (&cache_flash_test.cache_flash.base, key,
		key_length);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	key_cache_flash_testing_release (test, &cache_flash_test);
}


// *INDENT-OFF*
TEST_SUITE_START (key_cache_flash);

TEST (key_cache_flash_test_init);
TEST (key_cache_flash_test_init_with_more_valid_keys_than_required);
TEST (key_cache_flash_test_init_null);
TEST (key_cache_flash_test_init_with_insufficient_flash_blocks_for_keys);
TEST (key_cache_flash_test_init_with_insufficient_flash_blocks_in_store);
TEST (key_cache_flash_test_init_failed_with_get_num_block);
TEST (key_cache_flash_test_static_init);
TEST (key_cache_flash_test_static_init_with_more_valid_keys_than_required);
TEST (key_cache_flash_test_static_init_null);
TEST (key_cache_flash_test_static_init_with_insufficient_flash_blocks_for_keys);
TEST (key_cache_flash_test_static_init_with_insufficient_flash_blocks_in_store);
TEST (key_cache_flash_test_static_init_failed_with_get_num_block);
TEST (key_cache_flash_test_initialized_cache_empty);
TEST (key_cache_flash_test_initialized_cache_full);
TEST (key_cache_flash_test_initialized_cache_with_different_flash_states);
TEST (key_cache_flash_test_initialized_cache_flash_extra_blocks);
TEST (key_cache_flash_test_initialized_with_more_valid_keys_than_required);
TEST (key_cache_flash_test_initialized_with_valid_keys_in_all_flash_sectors);
TEST (key_cache_flash_test_initialized_cache_null);
TEST (key_cache_flash_test_initialized_cache_too_many_corrupted_blocks);
TEST (key_cache_flash_test_static_initialized_cache_empty);
TEST (key_cache_flash_test_static_initialized_cache_full);
TEST (key_cache_flash_test_static_initialized_cache_with_different_flash_states);
TEST (key_cache_flash_test_static_initialized_cache_flash_extra_blocks);
TEST (key_cache_flash_test_static_initialized_with_more_valid_keys_than_required);
TEST (key_cache_flash_test_static_initialized_with_valid_keys_in_all_flash_sectors);
TEST (key_cache_flash_test_static_initialized_cache_null);
TEST (key_cache_flash_test_static_init_too_many_corrupted_blocks);
TEST (key_cache_flash_test_release_null);
TEST (key_cache_flash_test_is_initialize_null);
TEST (key_cache_flash_test_is_error_state_null);
TEST (key_cache_flash_test_is_full_null);
TEST (key_cache_flash_test_is_empty_null);
TEST (key_cache_flash_test_remove);
TEST (key_cache_flash_test_remove_with_all_flash_sector_with_valid_key);
TEST (key_cache_flash_test_remove_with_static_init);
TEST (key_cache_flash_test_remove_invalid_argument);
TEST (key_cache_flash_test_remove_invalid_requestor_id);
TEST (key_cache_flash_test_remove_fatal_error);
TEST (key_cache_flash_test_remove_failed_with_error_state);
TEST (key_cache_flash_test_remove_with_invalid_remove_index);
TEST (key_cache_flash_test_remove_with_no_valid_key_on_flash_sector);
TEST (key_cache_flash_test_remove_with_physical_id);
TEST (key_cache_flash_test_remove_with_queue_is_empty);
TEST (key_cache_flash_test_remove_all_credit_used);
TEST (key_cache_flash_test_remove_failed_with_small_input_buffer);
TEST (key_cache_flash_test_remove_read_failed);
TEST (key_cache_flash_test_remove_read_and_erase_failed);
TEST (key_cache_flash_test_remove_read_and_erase_failed_with_fatal_error);
TEST (key_cache_flash_test_add);
TEST (key_cache_flash_test_add_with_empty_cache);
TEST (key_cache_flash_test_add_with_static_init);
TEST (key_cache_flash_test_add_invalid_argument);
TEST (key_cache_flash_test_add_fatal_error);
TEST (key_cache_flash_test_add_failed_with_error_state);
TEST (key_cache_flash_test_add_failed_with_queue_full);
TEST (key_cache_flash_test_add_invalid_add_index);
TEST (key_cache_flash_test_add_with_all_flash_sector_with_valid_key);
TEST (key_cache_flash_test_add_invalid_requestor_id);
TEST (key_cache_flash_test_add_with_no_physical_memory_available);
TEST (key_cache_flash_test_add_write_failed_without_fatal_error);
TEST (key_cache_flash_test_add_failed_unavailable_new_sector);
TEST (key_cache_flash_test_add_write_failed_with_fatal_error);

TEST_SUITE_END;
// *INDENT-ON*
