// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_STATIC_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_STATIC_H_

#include "flash_store_contiguous_blocks_static.h"


/* Internal functions declared to allow for static initialization. */
int flash_store_contiguous_blocks_encrypted_write (const struct flash_store *flash_store,
	int id, const uint8_t *data, size_t length);
int flash_store_contiguous_blocks_encrypted_read (const struct flash_store *flash_store,
	int id, uint8_t *data, size_t length);


/**
 * Constant initializer for the flash store API.
 */
#define	FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_API_INIT  { \
		.write = flash_store_contiguous_blocks_encrypted_write, \
		.read = flash_store_contiguous_blocks_encrypted_read, \
		.erase = flash_store_contiguous_blocks_erase, \
		.erase_all = flash_store_contiguous_blocks_erase_all, \
		.get_data_length = flash_store_contiguous_blocks_get_data_length, \
		.has_data_stored = flash_store_contiguous_blocks_has_data_stored, \
		.get_max_data_length = flash_store_contiguous_blocks_get_max_data_length, \
		.get_flash_size = flash_store_contiguous_blocks_get_flash_size, \
		.get_num_blocks = flash_store_contiguous_blocks_get_num_blocks, \
	}


/**
 * Initialize a static instance of a encrypted flash storage for fixed sized contiguous blocks of
 * data.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param aes_ptr AES engine instance for encryption.
 * @param rng_ptr RNG engine instance for encryption.
 */
#define	flash_store_contiguous_blocks_encrypted_static_init_fixed_storage(state_ptr, flash_addr, \
	flash_ptr, aes_ptr, rng_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_fixed_storage ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_API_INIT, state_ptr, flash_addr, flash_ptr, \
			NULL), \
		.aes = aes_ptr, \
		.rng = rng_ptr, \
	}

/**
 * Initialize a static instance of a encrypted flash storage for fixed sized contiguous blocks of
 * data.  Blocks will be stored in addresses decreasing from the first block.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param aes_ptr AES engine instance for encryption.
 * @param rng_ptr RNG engine instance for encryption.
 */
#define	flash_store_contiguous_blocks_encrypted_static_init_fixed_storage_decreasing(state_ptr, \
	flash_addr, flash_ptr, aes_ptr, rng_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_fixed_storage_decreasing ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_API_INIT, state_ptr, flash_addr, flash_ptr, \
			NULL), \
		.aes = aes_ptr, \
		.rng = rng_ptr, \
	}

/**
 * Initialize a static instance of a encrypted flash storage for variable sized contiguous blocks of
 * data.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param aes_ptr AES engine instance for encryption.
 * @param rng_ptr RNG engine instance for encryption.
 */
#define	flash_store_contiguous_blocks_encrypted_static_init_variable_storage(state_ptr, \
	flash_addr, flash_ptr, aes_ptr, rng_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_variable_storage ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_API_INIT, state_ptr, flash_addr, flash_ptr, \
			NULL), \
		.aes = aes_ptr, \
		.rng = rng_ptr, \
	}

/**
 * Initialize a static instance of a encrypted flash storage for variable sized contiguous blocks of
 * data.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the flash store.
 * @param flash_addr The address of the first storage block.  This must be aligned to a minimum
 * erase block.
 * @param flash_ptr The flash device that is managed by the store.
 * @param aes_ptr AES engine instance for encryption.
 * @param rng_ptr RNG engine instance for encryption.
 */
#define	flash_store_contiguous_blocks_encrypted_static_init_variable_storage_decreasing(state_ptr, \
	flash_addr, flash_ptr, aes_ptr, rng_ptr) { \
		.base = flash_store_contiguous_blocks_static_init_variable_storage_decreasing ( \
			FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_API_INIT, state_ptr, flash_addr, flash_ptr, \
			NULL), \
		.aes = aes_ptr, \
		.rng = rng_ptr, \
	}


#endif /* FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_STATIC_H_ */
