// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_H_

#include "flash_store_contiguous_blocks.h"
#include "crypto/aes_key_wrap_interface.h"


/**
 * Manage storage of indexed data blocks in flash.  Data stored in flash will be encrypted using the
 * AES Key Wrap algorithm.  The data blocks are aligned to flash erase boundaries to avoid
 * dependencies between data blocks.
 */
struct flash_store_contiguous_blocks_key_wrap {
	struct flash_store_contiguous_blocks base;		/**< Base flash storage instance. */
	const struct aes_key_wrap_interface *key_wrap;	/**< Key wrapping to use for data encryption. */
};


int flash_store_contiguous_blocks_key_wrap_init_fixed_storage (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length,
	const struct aes_key_wrap_interface *key_wrap);
int flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length,
	const struct aes_key_wrap_interface *key_wrap);

int flash_store_contiguous_blocks_key_wrap_init_variable_storage (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length,
	const struct aes_key_wrap_interface *key_wrap);
int flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length,
	const struct aes_key_wrap_interface *key_wrap);

int flash_store_contiguous_blocks_key_wrap_init_state (
	const struct flash_store_contiguous_blocks_key_wrap *store, size_t data_length);

void flash_store_contiguous_blocks_key_wrap_release (
	const struct flash_store_contiguous_blocks_key_wrap *store);


#endif	/* FLASH_STORE_CONTIGUOUS_BLOCKS_KEY_WRAP_H_ */
