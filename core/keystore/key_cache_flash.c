// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "keystore/key_cache_flash.h"
#include "keystore/keystore_logging.h"

/**
 * Increment Index by one and if the index reaches to length value rollover to zero value.
 *
 * @param cache_flash The key cache flash instance.
 * @param index Index that needs to be updated
 * @param length Maximum length up to that index can be updated
 *
 * @return Return updated index Value
 */
static size_t key_cache_flash_increment_queue_index (const struct key_cache_flash *cache_flash,
	size_t index, size_t length)
{
	size_t new_index = 0;

	if (index < length) {
		new_index = ((index + 1) % length);
	}
	else {
		/* Queue index must not be greater than queue length */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_INVALID_QUEUE_INDEX, index, length);

		/* Reinitialized state and log an error. */
		cache_flash->state->is_cache_initialized = false;
	}

	return new_index;
}

/**
 * Decrement Index by one and if the index reaches to length value rollover to zero value.
 *
 * @param cache_flash The key cache flash instance.
 * @param index Index that needs to be updated
 * @param length Maximum length up to that index can be updated
 *
 * @return Return updated index Value
 */
static size_t key_cache_flash_decrement_queue_index (const struct key_cache_flash *cache_flash,
	size_t index, size_t length)
{
	size_t new_index = 0;

	if (index == 0) {
		new_index = length - 1;
	}
	else if (index < length) {
		new_index = (index - 1);
	}
	else {
		/* Queue index must not be greater than queue length */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_INVALID_QUEUE_INDEX, index, length);

		/* Reinitialized cache */
		cache_flash->state->is_cache_initialized = false;
	}

	return new_index;
}

/**
 * Try to erase the flash sector and validate whether that flash sector is accessible or not.
 *
 * @param cache_flash The key cache flash instance.
 * @param flash_id The flash sector ID to erase.
 *
 * @return enum type key_cache_flash_sector_status.
 */
static enum key_cache_flash_sector_status key_cache_flash_try_erase (
	const struct key_cache_flash *cache_flash, uint32_t flash_id)
{
	int status;

	/* Clean the Flash section after reading Key from the memory */
	status = cache_flash->store->erase (cache_flash->store, flash_id);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_BLOCK_CORRUPTED, flash_id, status);

		return KEY_CACHE_FLASH_SECTOR_STATUS_CORRUPTED;
	}

	return KEY_CACHE_FLASH_SECTOR_STATUS_WITH_NO_KEY;
}

/**
 * Read the flash sector and verify whether the key is stored on the flash or not.  The flash sector
 * doesn't have key data then it will try to clean the sector and validate whether that flash sector
 * is accessible or not.
 *
 * @param cache_flash The key cache flash instance.
 * @param flash_id The flash sector ID to read.
 *
 * @return enum type key_cache_flash_sector_status.
 */
static enum key_cache_flash_sector_status key_cache_flash_read_key_and_validate_flash_sector (
	const struct key_cache_flash *cache_flash, uint32_t flash_id)
{
	uint8_t *key;
	int key_length;
	int read_status;
	enum key_cache_flash_sector_status status = KEY_CACHE_FLASH_SECTOR_STATUS_WITH_VALID_KEY;

	/* Read the key from the flash to check for corruption in the data.  The actual key data itself
	 * is not interesting at this point. */
	key_length = cache_flash->store->get_data_length (cache_flash->store, flash_id);
	if (ROT_IS_ERROR (key_length)) {
		/* Flash has no data or the flash sector is corrupted.
		 * Make sure that the flash sector is clear and can be used for storing the keys. */
		if (key_length != FLASH_STORE_NO_DATA) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
				KEYSTORE_LOGGING_CACHE_READ_AND_VALIDATE_FAIL, flash_id, key_length);
		}

		return key_cache_flash_try_erase (cache_flash, flash_id);
	}

	key = platform_malloc (key_length);
	if (key == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_READ_AND_VALIDATE_FAIL, flash_id, KEY_CACHE_NO_MEMORY);

		/* If allocation has failed, assume the key is no good and erase it. */
		return key_cache_flash_try_erase (cache_flash, flash_id);
	}

	read_status = cache_flash->store->read (cache_flash->store, flash_id, key, key_length);
	platform_free (key);

	if (ROT_IS_ERROR (read_status)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_READ_AND_VALIDATE_FAIL, flash_id, read_status);

		/* Make sure that the flash sector is clear and can be used for storing the keys */
		return key_cache_flash_try_erase (cache_flash, flash_id);
	}

	return status;
}

/**
 * Update the initialized key information with a new physical ID for the affected key info.
 *
 * @param cache_flash The key cache flash instance.
 * @param logical_id Logical index to update the key info
 */
static void key_cache_flash_update_key_info_in_flash_error (
	const struct key_cache_flash *cache_flash, size_t logical_id)
{
	uint32_t corrupted_physical_id;
	uint32_t new_physical_id;
	size_t new_sector_index = cache_flash->state->free_index_dec;

	/* First validate that a valid flash sector is available for use */
	/* Cannot find new good flash sector */
	if (new_sector_index <= cache_flash->num_keys) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_UNAVAILABLE_STORAGE, new_sector_index, cache_flash->num_keys);
		/* Reinitialized cache */
		cache_flash->state->is_cache_initialized = false;

		return;
	}

	corrupted_physical_id = cache_flash->key_info[logical_id].physical_id;
	new_physical_id = cache_flash->key_info[new_sector_index].physical_id;

	/* Assign the new physical ID key info */
	cache_flash->key_info[logical_id].physical_id = new_physical_id;

	/* Assign the corrupted physical ID to the current free index */
	cache_flash->key_info[new_sector_index].physical_id = corrupted_physical_id;

	/* Update the lkg_flash_sector_id */
	cache_flash->state->free_index_dec--;
}

/**
 * Update the add index and requestor credit after consuming a key.
 *
 * @param cache_flash The key cache flash instance.
 * @param requestor_id The requestor ID for the key.
 */
static void key_cache_flash_update_add_index (const struct key_cache_flash *cache_flash,
	uint16_t requestor_id)
{
	size_t remove_index = cache_flash->state->remove_index;
	size_t previous_remove_index;

	/* Update the credit value in case of pass or fail */
	if (cache_flash->requestor_credit[requestor_id] > 0) {
		cache_flash->requestor_credit[requestor_id]--;
	}

	/* Get the previous element index to update the requestor data as we have lock lockless queue
	 * with one element extra */
	previous_remove_index = key_cache_flash_decrement_queue_index (cache_flash, remove_index,
		cache_flash->num_keys);

	/* Update the Key information */
	cache_flash->key_info[previous_remove_index].requestor_id = requestor_id;
	cache_flash->key_info[remove_index].requestor_id = KEY_CACHE_FLASH_UNASSIGNED_REQUESTOR_ID;
	cache_flash->key_info[remove_index].valid = KEY_CACHE_FLASH_INVALID;

	/* Move the add index */
	cache_flash->state->remove_index =
		key_cache_flash_increment_queue_index (cache_flash, remove_index, cache_flash->num_keys);
}

/**
 * Arrange the key_info elements so that sectors with valid keys come first, followed by sectors
 * with no keys, and finally corrupted sectors
 *
 * @param cache_flash The key cache flash instance.
 * @param num_flash_block The number of flash blocks available for storing keys.
 *
 * @return 0 in case of success or an appropriate error code.
 */
static int key_cache_flash_arrange_key_info (const struct key_cache_flash *cache_flash)
{
	size_t low_index = 0;
	size_t mid_index = 0;
	size_t high_index = 0;
	struct key_cache_flash_key_info key_info_temp;

	if ((cache_flash == NULL) || (cache_flash->num_flash_sectors == 0)) {
		return KEY_CACHE_INVALID_ARGUMENT;
	}

	high_index = cache_flash->num_flash_sectors - 1;

	while (mid_index < high_index) {
		switch (cache_flash->key_info[mid_index].valid) {
			case KEY_CACHE_FLASH_VALID:
				if (cache_flash->key_info[low_index].valid !=
					cache_flash->key_info[mid_index].valid) {
					key_info_temp = cache_flash->key_info[low_index];
					cache_flash->key_info[low_index] = cache_flash->key_info[mid_index];
					cache_flash->key_info[mid_index] = key_info_temp;
				}
				low_index++;
				mid_index++;
				break;

			case KEY_CACHE_FLASH_INVALID:
				mid_index++;
				break;

			case KEY_CACHE_FLASH_CORRUPTED:
				if (cache_flash->key_info[mid_index].valid !=
					cache_flash->key_info[high_index].valid) {
					key_info_temp = cache_flash->key_info[mid_index];
					cache_flash->key_info[mid_index] = cache_flash->key_info[high_index];
					cache_flash->key_info[high_index] = key_info_temp;
				}
				if (high_index > 0) {
					high_index--;
				}
				break;

			default:
				return KEY_CACHE_INVALID_ARGUMENT;
		}
	}

	/* Setup consumer index at zero as all the valid ley are kept on top of the key_info or
	 * in case of no valid key it will point to the empty key_info element */
	cache_flash->state->remove_index = 0;

	/* Save index will point to the first empty location to save the new key on that key_info
	 * key_info_index currently pointing to the first empty element */
	if (low_index >= cache_flash->num_keys) {
		/* More valid key than expected set add index on the last index of queue */
		cache_flash->state->add_index = cache_flash->num_keys - 1;
	}
	else {
		cache_flash->state->add_index = low_index;
	}

	/* Validate that the total valid flash sectors are more than the num_keys*/
	if ((high_index + 1) < cache_flash->num_keys) {
		/* Not enough storage available to store the keys */
		cache_flash->state->is_error_state = true;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_KEYSTORE,
			KEYSTORE_LOGGING_CACHE_UNAVAILABLE_STORAGE, high_index + 1, cache_flash->num_keys);
	}

	/* Assign the next free index to be used for bad sector replacement as the max flash sector
	 * index */
	cache_flash->state->free_index_dec = high_index;

	return 0;
}

bool key_cache_flash_is_initialized (const struct key_cache *cache)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);

	if (cache_flash == NULL) {
		return false;
	}

	return cache_flash->state->is_cache_initialized;
}

bool key_cache_flash_is_error_state (const struct key_cache *cache)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);

	if (cache_flash == NULL) {
		return true;
	}

	return cache_flash->state->is_error_state;
}

bool key_cache_flash_is_full (const struct key_cache *cache)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);
	size_t new_save_index;

	if (cache_flash == NULL) {
		return false;
	}

	new_save_index = key_cache_flash_increment_queue_index (cache_flash,
		cache_flash->state->add_index, cache_flash->num_keys);

	return (new_save_index == cache_flash->state->remove_index);
}

bool key_cache_flash_is_empty (const struct key_cache *cache)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);

	if (cache_flash == NULL) {
		return true;
	}

	return (cache_flash->state->add_index == cache_flash->state->remove_index);
}

int key_cache_flash_initialize_cache (const struct key_cache *cache)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);
	uint16_t requestor_id;
	size_t i;
	int status;

	if ((cache_flash == NULL) || (cache_flash->state == NULL) || (cache_flash->store == NULL)) {
		return KEY_CACHE_INVALID_ARGUMENT;
	}

	/* Read all the flash blocks and update the status for the keys */
	for (i = 0; i < cache_flash->num_flash_sectors; i++) {
		cache_flash->key_info[i].valid =
			key_cache_flash_read_key_and_validate_flash_sector (cache_flash, i);
		cache_flash->key_info[i].physical_id = i;
	}

	/*
	 * Reorder the key_info elements so that sectors with valid keys come first, followed by
	 * sectors with no keys, and finally corrupted sectors
	 */
	status = key_cache_flash_arrange_key_info (cache_flash);
	if (status != 0) {
		return status;
	}

	requestor_id = 0;
	/* Updated requestors' credit for all the valid & invalid keys for the num_keys managed */
	for (i = 0; i < cache_flash->num_keys; i++) {
		cache_flash->key_info[i].requestor_id = requestor_id;

		if (cache_flash->key_info[i].valid == KEY_CACHE_FLASH_VALID) {
			if (cache_flash->requestor_credit[requestor_id] < cache_flash->max_credit) {
				cache_flash->requestor_credit[requestor_id]++;
				cache_flash->key_info[i].requestor_id = KEY_CACHE_FLASH_UNASSIGNED_REQUESTOR_ID;
			}
		}

		requestor_id = key_cache_flash_increment_queue_index (cache_flash, requestor_id,
			cache_flash->max_requestors);
	}

	cache_flash->state->is_cache_initialized = true;

	return status;
}

int key_cache_flash_add (const struct key_cache *cache, const uint8_t *key, size_t length)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);
	uint32_t physical_id;
	size_t add_index;
	uint16_t requestor_id;
	int i;
	int status;

	if ((cache == NULL) || (key == NULL) || (length == 0)) {
		return KEY_CACHE_INVALID_ARGUMENT;
	}

	status = platform_mutex_lock (&cache_flash->state->lock);
	if (status != 0) {
		return status;
	}

	do {
		if (cache_flash->state->is_cache_initialized == false) {
			status = KEY_CACHE_NOT_INITIALIZED;
			break;
		}

		/* Check if the cache is in error state */
		if (cache_flash->state->is_error_state == true) {
			status = KEY_CACHE_UNAVAILABLE_STORAGE;
			break;
		}

		add_index = cache_flash->state->add_index;
		if (add_index >= cache_flash->num_keys) {
			/* Key info is corrupted and the database cannot be trusted anymore */
			cache_flash->state->is_cache_initialized = false;
			status = KEY_CACHE_MEMORY_CORRUPTED;
			break;
		}

		requestor_id = cache_flash->key_info[add_index].requestor_id;
		if (requestor_id >= cache_flash->max_requestors) {
			/* Key info is corrupted and the database cannot be trusted anymore */
			cache_flash->state->is_cache_initialized = false;
			status = KEY_CACHE_MEMORY_CORRUPTED;
			break;
		}

		physical_id = cache_flash->key_info[add_index].physical_id;
		if (physical_id >= cache_flash->num_flash_sectors) {
			/* Key info is corrupted and the database cannot be trusted anymore */
			cache_flash->state->is_cache_initialized = false;
			status = KEY_CACHE_MEMORY_CORRUPTED;
			break;
		}

		if (cache_flash->base.is_full (&cache_flash->base)) {
			status = KEY_CACHE_QUEUE_IS_FULL;
			break;
		}

		/* Retry the Flash write operation if it fails as key generation is a time-consuming
		 * operation */
		for (i = 0; i < KEY_CACHE_FLASH_MAX_ADD_RETRY; i++) {
			status = cache_flash->store->write (cache_flash->store, physical_id, key, length);
			if (status == 0) {
				break;
			}
		}

		if (status == 0) {
			/* Increment the credit */
			if (cache_flash->requestor_credit[requestor_id] < cache_flash->max_credit) {
				cache_flash->requestor_credit[requestor_id]++;
			}

			/* Update the key information */
			cache_flash->key_info[add_index].requestor_id = KEY_CACHE_FLASH_UNASSIGNED_REQUESTOR_ID;
			cache_flash->key_info[add_index].valid = 1;

			/* Update the save index */
			add_index = key_cache_flash_increment_queue_index (cache_flash, add_index,
				cache_flash->num_keys);
			cache_flash->state->add_index = add_index;
		}
		else {
			/* Corrupted flash sector detected */
			key_cache_flash_update_key_info_in_flash_error (cache_flash, add_index);
			break;
		}
	} while (0);

	platform_mutex_unlock (&cache_flash->state->lock);

	return status;
}

int key_cache_flash_remove (const struct key_cache *cache, uint16_t requestor_id, uint8_t *key,
	size_t input_buffer_length, size_t *length)
{
	const struct key_cache_flash *cache_flash = TO_DERIVED_TYPE (cache,
		const struct key_cache_flash, base);
	size_t remove_index;
	uint32_t physical_id;
	int status;

	if ((cache == NULL) || (key == NULL) || (length == NULL)) {
		return KEY_CACHE_INVALID_ARGUMENT;
	}

	status = platform_mutex_lock (&cache_flash->state->lock);
	if (status != 0) {
		return status;
	}

	do {
		/* Critical Error encountered during the adding of a key, indicating a severe issue */
		if (cache_flash->state->is_cache_initialized == false) {
			status = KEY_CACHE_NOT_INITIALIZED;
			break;
		}

		/* Check if the cache is in error state */
		if (cache_flash->state->is_error_state == true) {
			status = KEY_CACHE_UNAVAILABLE_STORAGE;
			break;
		}

		/* Verify requestor ID */
		if (requestor_id >= cache_flash->max_requestors) {
			status = KEY_CACHE_INVALID_REQUESTOR_ID;
			break;
		}

		remove_index = cache_flash->state->remove_index;
		if (remove_index > cache_flash->num_keys) {
			// Key info is corrupted and the database cannot be trusted anymore
			cache_flash->state->is_cache_initialized = false;
			status = KEY_CACHE_INVALID_REMOVE_INDEX;
			break;
		}

		/* Validate the queue is not empty and make sure the add index is valid */
		if (cache_flash->base.is_empty (&cache_flash->base)) {
			status = KEY_CACHE_QUEUE_IS_EMPTY;
			break;
		}

		if (cache_flash->key_info[remove_index].valid != KEY_CACHE_FLASH_VALID) {
			key_cache_flash_update_add_index (cache_flash, requestor_id);
			status = KEY_CACHE_KEY_NOT_FOUND_AT_INDEX;
			break;
		}

		physical_id = cache_flash->key_info[remove_index].physical_id;
		if (physical_id >= cache_flash->num_flash_sectors) {
			// Key info is corrupted and the database cannot be trusted anymore
			cache_flash->state->is_cache_initialized = false;
			status = KEY_CACHE_MEMORY_CORRUPTED;
			break;
		}

		/* verify the credit */
		if (cache_flash->requestor_credit[requestor_id] == 0) {
			status = KEY_CACHE_CREDIT_NOT_AVAILABLE;
			break;
		}

		/* Read the key data from the flash */
		status = cache_flash->store->read (cache_flash->store, physical_id, key,
			input_buffer_length);
		if (!(ROT_IS_ERROR (status))) {
			*length = status;
			/* Update status to success in case no error */
			status = 0;
		}

		/* Clean the Flash section after reading Key from the memory */
		if (key_cache_flash_try_erase (cache_flash,
			physical_id) != KEY_CACHE_FLASH_SECTOR_STATUS_WITH_NO_KEY) {
			/* Corrupted flash sector detected */
			key_cache_flash_update_key_info_in_flash_error (cache_flash, remove_index);
		}

		/* Update the key info and add index for the add request */
		key_cache_flash_update_add_index (cache_flash, requestor_id);
	} while (0);

	platform_mutex_unlock (&cache_flash->state->lock);

	return status;
}

/**
 * Initialize a key cache implemented using a flash store.  The total number of keys managed by this
 * key cache is determined by multiplying max_requestors and max_credit.
 *
 * @param cache_flash The key cache to initialize.
 * @param state Variable context for the key cache.  This must be uninitialized.
 * @param store The flash store to use for storing the keys.
 * @param key_info An array of key metadata structures used for cache management.  The length of
 * this array is determined by the number of flash blocks being used by the key cache.
 * @param flash_blocks The number of key info structures in the list.  This represents the total
 * number of flash blocks available to use in the flash store.
 * @param requestor_credit An array for tracking available credits for different requestors.  The
 * length of this array must be equal to the number of supported requestors.
 * @param max_requestors The number of requestors supported by the cache.  Requestor IDs will be
 * assigned sequentially from 0 to max_requestors - 1.
 * @param max_credit The maximum credit value per requestor.
 *
 * @return 0 if the key cache was successfully initialized or an error code.
 */
int key_cache_flash_init (struct key_cache_flash *cache_flash, struct key_cache_flash_state *state,
	const struct flash_store *store, struct key_cache_flash_key_info *key_info, size_t flash_blocks,
	uint8_t *requestor_credit, size_t max_requestors, uint8_t max_credit)
{
	if (cache_flash == NULL) {
		return KEY_CACHE_INVALID_ARGUMENT;
	}

	memset (cache_flash, 0, sizeof (struct key_cache_flash));

	cache_flash->base.is_initialized = key_cache_flash_is_initialized;
	cache_flash->base.is_error_state = key_cache_flash_is_error_state;
	cache_flash->base.is_full = key_cache_flash_is_full;
	cache_flash->base.is_empty = key_cache_flash_is_empty;
	cache_flash->base.initialize_cache = key_cache_flash_initialize_cache;
	cache_flash->base.add = key_cache_flash_add;
	cache_flash->base.remove = key_cache_flash_remove;

	cache_flash->state = state;
	cache_flash->store = store;
	cache_flash->key_info = key_info;
	cache_flash->num_flash_sectors = flash_blocks;
	cache_flash->requestor_credit = requestor_credit;
	cache_flash->max_requestors = max_requestors;
	cache_flash->max_credit = max_credit;

	/* The total number of keys managed by the key cache flash is calculated as (max requestors *
	 * max credits per requestor) + 1 */
	cache_flash->num_keys = (cache_flash->max_requestors * cache_flash->max_credit) + 1;

	return key_cache_flash_init_state (cache_flash);
}

/**
 * Initialize only the variable state for a key cache in flash.  The rest of the key cache is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param cache_flash The key cache that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int key_cache_flash_init_state (const struct key_cache_flash *cache_flash)
{
	int num_flash_sectors;

	if ((cache_flash == NULL) || (cache_flash->state == NULL) || (cache_flash->store == NULL) ||
		(cache_flash->key_info == NULL) || (cache_flash->requestor_credit == NULL) ||
		(cache_flash->max_requestors == 0) || (cache_flash->max_credit == 0)) {
		return KEY_CACHE_INVALID_ARGUMENT;
	}

	if (cache_flash->num_flash_sectors < cache_flash->num_keys) {
		return KEY_CACHE_INSUFFICIENT_STORAGE;
	}

	memset (cache_flash->state, 0, sizeof (struct key_cache_flash_state));
	memset (cache_flash->key_info, 0,
		sizeof (*cache_flash->key_info) * cache_flash->num_flash_sectors);
	memset (cache_flash->requestor_credit, 0,
		sizeof (*cache_flash->requestor_credit) * cache_flash->max_requestors);

	/* Confirm the flash store has the expected number of blocks available. */
	num_flash_sectors = cache_flash->store->get_num_blocks (cache_flash->store);
	if (ROT_IS_ERROR (num_flash_sectors)) {
		return num_flash_sectors;
	}

	if ((size_t) num_flash_sectors < cache_flash->num_flash_sectors) {
		return KEY_CACHE_STORAGE_MISMATCH;
	}

	return platform_mutex_init (&cache_flash->state->lock);
}

/**
 * Release the resources used by the key cache.
 *
 * @param cache The key cache to release.
 */
void key_cache_flash_release (const struct key_cache_flash *cache_flash)
{
	if ((cache_flash == NULL) || (cache_flash->state == NULL)) {
		return;
	}

	platform_mutex_free (&cache_flash->state->lock);

	memset (cache_flash->state, 0, sizeof (struct key_cache_flash_state));
}
