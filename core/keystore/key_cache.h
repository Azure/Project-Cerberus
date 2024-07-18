// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEY_CACHE_H_
#define KEY_CACHE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * A cache for storing and retrieving pre-generated keys.  This enables scenarios that require key
 * generation without needing to spend time to generate these keys on demand.
 */
struct key_cache {
	/**
	 * Check if the key cache is full.
	 *
	 * @param cache The key cache to check.
	 *
	 * @return `true` if the cache is full or `false` if there is space available.
	 */
	bool (*is_full) (const struct key_cache *cache);

	/**
	 * Check if the key cache is empty.
	 *
	 * @param cache The key cache to check.
	 *
	 * @return `true` if the cache is empty or `false` if it is not.
	 */
	bool (*is_empty) (const struct key_cache *cache);

	/**
	 * Add/Write the key information to the cache.
	 *
	 * @param cache The key cache where the key should be saved.
	 * @param key The key data to store.
	 * @param length The length of the key data.
	 *
	 * @return 0 if the key was successfully stored or an error code.
	 */
	int (*add) (const struct key_cache *cache, const uint8_t *key, size_t length);

	/**
	 * Remove/Read the key from the cache for the given Requestor ID.
	 *
	 * The cache may implement rate limiting to ensure specific requestors cannot drain the cache,
	 * impacting other requestors.
	 *
	 * @param cache The key cache where the key is saved.
	 * @param requestor_id The Requestor ID for the key.
	 * @param key Output for the key data.
	 * @param key_buffer_size Length of the key buffer.
	 * @param length Length in bytes of the output key data.
	 *
	 * @return 0 if the key was successfully stored, or an error code.
	 */
	int (*remove) (const struct key_cache *cache, uint32_t requestor_id, uint8_t *key,
		size_t key_buffer_size, size_t *length);
};


#define	KEY_CACHE_ERROR(code)		ROT_ERROR (ROT_MODULE_KEY_CACHE, code)

/**
 * Error codes that can be generated by a key_cache.
 */
enum {
	KEY_CACHE_INVALID_ARGUMENT = KEY_CACHE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	KEY_CACHE_NO_MEMORY = KEY_CACHE_ERROR (0x01),				/**< Memory allocation failed. */
	KEY_CACHE_IS_FULL_FAILED = KEY_CACHE_ERROR (0x02),			/**< Failed to check if the key cache is full */
	KEY_CACHE_IS_EMPTY_FAILED = KEY_CACHE_ERROR (0x03),			/**< Failed to check if the key cache is empty */
	KEY_CACHE_ADD_KEY_FAILED = KEY_CACHE_ERROR (0x04),			/**< Failed to add/write the key on the persistent store */
	KEY_CACHE_REMOVE_KEY_FAILED = KEY_CACHE_ERROR (0x05),		/**< Failed to remove/read the key from the persistent store */
	KEY_CACHE_QUEUE_IS_EMPTY = KEY_CACHE_ERROR (0x06),			/**< No key available on the flash all the flash sectors are empty */
	KEY_CACHE_QUEUE_IS_FULL = KEY_CACHE_ERROR (0x07),			/**< No new flash sector available to store new key */
	KEY_CACHE_BAD_KEY = KEY_CACHE_ERROR (0x08),					/**< Key is corrupted */
	KEY_CACHE_ALL_CREDIT_USED = KEY_CACHE_ERROR (0x09),			/**< All credit is used for the Requestor */
	KEY_CACHE_INVALID_REQUESTOR_ID = KEY_CACHE_ERROR (0x0A),	/**< Invalid requestor ID */
	KEY_CACHE_INVALID_ADD_INDEX = KEY_CACHE_ERROR (0x0B),		/**< Invalid add/write index */
	KEY_CACHE_INVALID_REMOVE_INDEX = KEY_CACHE_ERROR (0x0C),	/**< Invalid remove/read index */
	KEY_CACHE_FATAL_ERROR = KEY_CACHE_ERROR (0x0D),				/**< A Critical error generated while accessing corrupted memory or Flash */
};


#endif	/* KEY_CACHE_H_ */
