// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEY_CACHE_FLASH_STATIC_H_
#define KEY_CACHE_FLASH_STATIC_H_

#include <stdbool.h>
#include <stdint.h>
#include "keystore/key_cache_flash.h"


/* Internal functions declared to allow for static initialization. */
bool key_cache_flash_is_initialized (const struct key_cache *cache);
bool key_cache_flash_is_error_state (const struct key_cache *cache);
bool key_cache_flash_is_full (const struct key_cache *cache);
bool key_cache_flash_is_empty (const struct key_cache *cache);
int key_cache_flash_initialize_cache (const struct key_cache *cache);
int key_cache_flash_add (const struct key_cache *cache, const uint8_t *key, size_t length);
int key_cache_flash_remove (const struct key_cache *cache, uint16_t requestor_id, uint8_t *key,
	size_t input_buffer_length, size_t *length);


/**
 * Constant initializer for the key cache flash API.
 */
#define	KEY_CACHE_FLASH_API_INIT { \
		.is_initialized = key_cache_flash_is_initialized, \
		.is_error_state = key_cache_flash_is_error_state, \
		.is_full = key_cache_flash_is_full, \
		.is_empty = key_cache_flash_is_empty, \
		.initialize_cache = key_cache_flash_initialize_cache, \
		.add = key_cache_flash_add, \
		.remove = key_cache_flash_remove \
	}

/**
 * Initialize a static instance of a key cache implemented using a flash store.  The total number of
 * keys managed by this key cache is determined by multiplying max_requestors_val and
 * max_credit_val.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for for the key cache.
 * @param store_ptr The flash store to use for storing the keys.
 * @param key_info_ptr An array of key metadata structures used for cache management.  The length of
 * this array is determined by the number of flash blocks being used by the key cache.
 * @param flash_blocks_val The number of key info structures in the list.  This represents the total
 * number of flash blocks available to use in the flash store.
 * @param requestor_credit_ptr An array for tracking available credits for different requestors.
 * The length of this array must be equal to the number of supported requestors.
 * @param max_requestors_val The number of requestors supported by the cache.  Requestor IDs will be
 * assigned sequentially from 0 to max_requestors - 1.
 * @param max_credit_val The maximum credit value per requestor.
 */
#define	key_cache_flash_static_init(state_ptr, store_ptr, key_info_ptr, flash_blocks_val, \
	requestor_credit_ptr, max_requestors_val, max_credit_val) { \
		.base = KEY_CACHE_FLASH_API_INIT, \
		.state = state_ptr, \
		.store = store_ptr, \
		.key_info = key_info_ptr, \
		.num_flash_sectors = flash_blocks_val, \
		.requestor_credit = requestor_credit_ptr, \
		.max_requestors = max_requestors_val, \
		.max_credit = max_credit_val, \
		.num_keys = (max_requestors_val * max_credit_val) + 1, \
	}


#endif	/* KEY_CACHE_FLASH_STATIC_H_ */
