// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_STATIC_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_STATIC_H_

#include "flash_store_contiguous_blocks_key_wrap.h"
#include "flash_store_contiguous_blocks_static.h"


/* Internal functions declared to allow for static initialization. */
int flash_store_contiguous_blocks_key_wrap_write (const struct flash_store *flash_store, int id,
	const uint8_t *data, size_t length);
int flash_store_contiguous_blocks_key_wrap_read (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length);
int flash_store_contiguous_blocks_key_wrap_get_data_length (const struct flash_store *flash_store,
	int id);


/**
 * Constant initializer for the flash store API.
 */
#define	FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_API_INIT  { \
		.write = flash_store_contiguous_blocks_key_wrap_write, \
		.read = flash_store_contiguous_blocks_key_wrap_read, \
		.erase = flash_store_contiguous_blocks_erase, \
		.erase_all = flash_store_contiguous_blocks_erase_all, \
		.get_data_length = flash_store_contiguous_blocks_key_wrap_get_data_length, \
		.has_data_stored = flash_store_contiguous_blocks_has_data_stored, \
		.get_max_data_length = flash_store_contiguous_blocks_get_max_data_length, \
		.get_flash_size = flash_store_contiguous_blocks_get_flash_size, \
		.get_num_blocks = flash_store_contiguous_blocks_get_num_blocks, \
	}


/**
 * Initialize a static instance of flash storage for fixed sized contiguous encrypted blocks of data
 * using AES Key Wrap for encryption and integrity protection.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_ptr The flash device that is managed by the store.
 * @param base_addr_arg The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param block_count_arg The number of data blocks used for storage.
 * @param key_wrap_ptr The AES key wrap instance to use for data encryption.  The KEK for
 * wrap/unwrap operations must be managed and set separately from the flash storage.
 */
#define	flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage(state_ptr, flash_ptr, \
	base_addr_arg, block_count_arg, key_wrap_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_fixed_storage ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_API_INIT, state_ptr, base_addr_arg, \
			block_count_arg, flash_ptr, NULL), \
		.key_wrap = key_wrap_ptr, \
	}

/**
 * Initialize a static instance of flash storage for fixed sized contiguous encrypted blocks of data
 * using AES Key Wrap for encryption and integrity protection. Blocks will be stored in addresses
 * decreasing from the first block.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_ptr The flash device that is managed by the store.
 * @param base_addr_arg The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param block_count_arg The number of data blocks used for storage.
 * @param key_wrap_ptr The AES key wrap instance to use for data encryption.  The KEK for
 * wrap/unwrap operations must be managed and set separately from the flash storage.
 */
#define	flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing(state_ptr, \
	flash_ptr, base_addr_arg, block_count_arg, key_wrap_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_fixed_storage_decreasing ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_API_INIT, state_ptr, base_addr_arg, \
			block_count_arg, flash_ptr, NULL), \
		.key_wrap = key_wrap_ptr, \
	}

/**
 * Initialize a static instance of flash storage for variable sized contiguous encrypted blocks of
 * data using AES Key Wrap for encryption and integrity protection.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_ptr The flash device that is managed by the store.
 * @param base_addr_arg The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param block_count_arg The number of data blocks used for storage.
 * @param key_wrap_ptr The AES key wrap instance to use for data encryption.  The KEK for
 * wrap/unwrap operations must be managed and set separately from the flash storage.
 */
#define	flash_store_contiguous_blocks_key_wrap_static_init_variable_storage(state_ptr, flash_ptr, \
	base_addr_arg, block_count_arg, key_wrap_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_variable_storage ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_API_INIT, state_ptr, base_addr_arg, \
			block_count_arg, flash_ptr, NULL), \
		.key_wrap = key_wrap_ptr, \
	}

/**
 * Initialize a static instance of flash storage for variable sized contiguous encrypted blocks of
 * data using AES Key Wrap for encryption and integrity protection.  Blocks will be stored in
 * addresses decreasing from the first block
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_ptr The flash device that is managed by the store.
 * @param base_addr_arg The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param block_count_arg The number of data blocks used for storage.
 * @param key_wrap_ptr The AES key wrap instance to use for data encryption.  The KEK for
 * wrap/unwrap operations must be managed and set separately from the flash storage.
 */
#define	flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing(state_ptr, \
	flash_ptr, base_addr_arg, block_count_arg, key_wrap_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_variable_storage_decreasing ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_API_INIT, state_ptr, base_addr_arg, \
			block_count_arg, flash_ptr, NULL), \
		.key_wrap = key_wrap_ptr, \
	}


#endif	/* FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_STATIC_H_ */
