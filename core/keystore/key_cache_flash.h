// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEY_CACHE_FLASH_H_
#define KEY_CACHE_FLASH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "key_cache.h"
#include "flash/flash_store.h"


/**
 * Requestor ID that is not assigned to any requestor.
 */
#define KEY_CACHE_FLASH_UNASSIGNED_REQUESTOR_ID		0xFFFF

/**
 * Max retries to add/write the key on the flash.
 */
#define KEY_CACHE_FLASH_MAX_ADD_RETRY				(3)


/**
 * The states that can be assigned to a single flash block in the key cache.
 * Ensure this enum is limited to 3 values maximum, corresponding to a 2-bit field within the
 * struct key_cache_flash_key_info.
 */
enum key_cache_flash_key_status {
	KEY_CACHE_FLASH_INVALID,	/**< The flash block is usable and does not contain a key. */
	KEY_CACHE_FLASH_VALID,		/**< The flash block contains a valid key. */
	KEY_CACHE_FLASH_CORRUPTED,	/**< The flash block is unusable for key storage. */
};

/**
 * Status values that are used when determining the state of a flash block.
 */
enum key_cache_flash_sector_status {
	KEY_CACHE_FLASH_SECTOR_STATUS_WITH_NO_KEY = 0,	/**< Flash sector is empty. */
	KEY_CACHE_FLASH_SECTOR_STATUS_WITH_VALID_KEY,	/**< Flash sector has a valid key stored. */
	KEY_CACHE_FLASH_SECTOR_STATUS_CORRUPTED,		/**< Flash sector is corrupted and not usable for future operations. */
};


/**
 * This is used to track the key information in the flash sector.
 */
struct key_cache_flash_key_info {
	/**
	 * Indicates if the flash sector has a valid key.
	 */
	enum key_cache_flash_key_status valid:2;

	/**
	 * Specifies the physical flash sector number to assign to a specific key slot.
	 */
	uint32_t physical_id:10;

	/**
	 * Reserved bits
	 */
	uint32_t reserved:4;

	/**
	 * Requestor ID the credit needs to be given if a new key is saved in this flash sector.
	 */
	uint32_t requestor_id:16;
};

/**
 * This is used to track the state of the key cache in the flash.
 */
struct key_cache_flash_state {
	/**
	 * Protect the key cache state from producer and consumer.
	 */
	platform_mutex lock;

	/**
	 * Index to which new keys needs to be saved in into the flash store.
	 */
	size_t add_index;

	/**
	 * Index from which an existing key in the flash store needs to be retrieved.
	 */
	size_t remove_index;

	/**
	 * Location of the free index in the flash to use when any existing sectors become bad during
	 * runtime. It will decrement on every update.
	 */
	size_t free_index_dec;

	/**
	 * Cache initialization status flag
	 */
	bool is_cache_initialized;

	/**
	 * Cache initialization error status flag
	 */
	bool is_error_state;
};

/**
 * Key cache implementation using Flash.
 */
struct key_cache_flash {
	struct key_cache base;						/**< Base key cache instance. */
	struct key_cache_flash_state *state;		/**< State of the key cache in flash. */
	const struct flash_store *store;			/**< Flash storage for keys. */
	struct key_cache_flash_key_info *key_info;	/**< Set of metadata for tracking the state of each flash block. */
	size_t num_flash_sectors;					/**< Number of entries in the key info list. */
	uint8_t *requestor_credit;					/**< Array of available credits for each requestor ID. */
	size_t max_requestors;						/**< Number of requestors allowed for this instance. */
	uint8_t max_credit;							/**< Maximum key credit value per requestor. */
	size_t num_keys;							/**< Number of keys managed by the cache. */
};


int key_cache_flash_init (struct key_cache_flash *cache_flash, struct key_cache_flash_state *state,
	const struct flash_store *store, struct key_cache_flash_key_info *key_info, size_t flash_blocks,
	uint8_t *requestor_credit, size_t max_requestors, uint8_t max_credit);
int key_cache_flash_init_state (const struct key_cache_flash *cache);
void key_cache_flash_release (const struct key_cache_flash *cache);


#endif	/* KEY_CACHE_FLASH_H_ */
