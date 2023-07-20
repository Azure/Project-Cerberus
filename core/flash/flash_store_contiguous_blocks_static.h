// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_STATIC_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_STATIC_H_

#include "flash/flash_store_contiguous_blocks.h"


/* Internal functions declared to allow for static initialization. */
int flash_store_contiguous_blocks_write_no_hash (const struct flash_store *flash_store,
	int id, const uint8_t *data, size_t length);
int flash_store_contiguous_blocks_write_with_hash (const struct flash_store *flash_store,
	int id, const uint8_t *data, size_t length);
int flash_store_contiguous_blocks_read_no_hash (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length);
int flash_store_contiguous_blocks_read_with_hash (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length);
int flash_store_contiguous_blocks_erase (const struct flash_store *flash_store, int id);
int flash_store_contiguous_blocks_erase_all (const struct flash_store *flash_store);
int flash_store_contiguous_blocks_get_data_length (const struct flash_store *flash_store, int id);
int flash_store_contiguous_blocks_has_data_stored (const struct flash_store *flash_store, int id);
int flash_store_contiguous_blocks_get_max_data_length (const struct flash_store *flash_store);
int flash_store_contiguous_blocks_get_flash_size (const struct flash_store *flash_store);
int flash_store_contiguous_blocks_get_num_blocks (const struct flash_store *flash_store);


/**
 * Constant initializer for the flash store API with hashing for read and write APIs.
 */
#define	FLASH_STORE_CONTIGUOUS_BLOCKS_WITH_HASH_API_INIT  { \
		.write = flash_store_contiguous_blocks_write_with_hash, \
		.read = flash_store_contiguous_blocks_read_with_hash, \
		.erase = flash_store_contiguous_blocks_erase, \
		.erase_all = flash_store_contiguous_blocks_erase_all, \
		.get_data_length = flash_store_contiguous_blocks_get_data_length, \
		.has_data_stored = flash_store_contiguous_blocks_has_data_stored, \
		.get_max_data_length = flash_store_contiguous_blocks_get_max_data_length, \
		.get_flash_size = flash_store_contiguous_blocks_get_flash_size, \
		.get_num_blocks = flash_store_contiguous_blocks_get_num_blocks \
	}

/**
 * Constant initializer for the flash store API without hashing for read and write APIs.
 */
#define	FLASH_STORE_CONTIGUOUS_BLOCKS_NO_HASH_API_INIT  { \
		.write = flash_store_contiguous_blocks_write_no_hash, \
		.read = flash_store_contiguous_blocks_read_no_hash, \
		.erase = flash_store_contiguous_blocks_erase, \
		.erase_all = flash_store_contiguous_blocks_erase_all, \
		.get_data_length = flash_store_contiguous_blocks_get_data_length, \
		.has_data_stored = flash_store_contiguous_blocks_has_data_stored, \
		.get_max_data_length = flash_store_contiguous_blocks_get_max_data_length, \
		.get_flash_size = flash_store_contiguous_blocks_get_flash_size, \
		.get_num_blocks = flash_store_contiguous_blocks_get_num_blocks \
	}


/**
 * Initialize static instance of flash storage for fixed sized contiguous blocks of data.
 *
 * There is no validation done on the arguments.
 *
 * @param api The API implementation that should be used.
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param hash_ptr Hash engine instance for integrity checking.  This should be null when using
 * FLASH_STORE_CONTIGUOUS_BLOCKS_NO_HASH_API_INIT.
 */
#define	flash_store_contiguous_blocks_static_init_fixed_storage(api, state_ptr, flash_addr, \
	flash_ptr, hash_ptr) { \
		.base = api, \
		.state = state_ptr, \
		.base_addr = flash_addr, \
		.decreasing = false, \
		.variable = false, \
		.flash = flash_ptr, \
		.hash = hash_ptr, \
	}

/**
 * Initialize flash storage for fixed sized contiguous blocks of data.  Blocks will be stored in
 * addresses decreasing from the first block.
 *
 * There is no validation done on the arguments.
 *
 * @param api The API implementation that should be used.
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param hash_ptr Hash engine instance for integrity checking.  This should be null when using
 * FLASH_STORE_CONTIGUOUS_BLOCKS_NO_HASH_API_INIT.
 */
#define	flash_store_contiguous_blocks_static_init_fixed_storage_decreasing(api, state_ptr, \
	flash_addr, flash_ptr, hash_ptr) { \
		.base = api, \
		.state = state_ptr, \
		.base_addr = flash_addr, \
		.decreasing = true, \
		.variable = false, \
		.flash = flash_ptr, \
		.hash = hash_ptr, \
	}

/**
 * Initialize static instance of flash storage for variable sized contiguous blocks of data.
 *
 * There is no validation done on the arguments.
 *
 * @param api The API implementation that should be used.
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param hash_ptr Hash engine instance for integrity checking.  This should be null when using
 * FLASH_STORE_CONTIGUOUS_BLOCKS_NO_HASH_API_INIT.
 */
#define	flash_store_contiguous_blocks_static_init_variable_storage(api, state_ptr, flash_addr, \
	flash_ptr, hash_ptr) { \
		.base = api, \
		.state = state_ptr, \
		.base_addr = flash_addr,\
		.decreasing = false, \
		.variable = true, \
		.flash = flash_ptr, \
		.hash = hash_ptr, \
	}

/**
 * Initialize static instance of a flash storage for variable sized contiguous blocks of data.
 * Blocks will be stored in addresses decreasing from the first block.
 *
 * There is no validation done on the arguments.
 *
 * @param api The API implementation that should be used.
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param hash_ptr Hash engine instance for integrity checking.  This should be null when using
 * FLASH_STORE_CONTIGUOUS_BLOCKS_NO_HASH_API_INIT.
 */
#define	flash_store_contiguous_blocks_static_init_variable_storage_decreasing(api, state_ptr, \
	flash_addr, flash_ptr, hash_ptr) { \
		.base = api, \
		.state = state_ptr, \
		.base_addr = flash_addr, \
		.decreasing = true, \
		.variable = true, \
		.flash = flash_ptr, \
		.hash = hash_ptr, \
	}


#endif /* FLASH_STORE_CONTIGUOUS_BLOCKS_STATIC_H_ */
