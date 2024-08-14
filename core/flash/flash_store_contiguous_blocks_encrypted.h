// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_H_

#include "flash_store_contiguous_blocks.h"
#include "crypto/aes_gcm.h"
#include "crypto/rng.h"


/**
 * Manage storage of indexed data blocks in flash.  Data stored in flash will be encrypted.  The
 * data blocks are aligned to flash erase boundaries to avoid dependencies between data blocks.
 */
struct flash_store_contiguous_blocks_encrypted {
	struct flash_store_contiguous_blocks base;	/**< Base flash storage instance. */
	const struct aes_gcm_engine *aes;			/**< Engine to use for data encryption. */
	struct rng_engine *rng;						/**< Random number generator for encryption IVs. */
};


int flash_store_contiguous_blocks_encrypted_init_fixed_storage (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct aes_gcm_engine *aes,
	struct rng_engine *rng);
int flash_store_contiguous_blocks_encrypted_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct aes_gcm_engine *aes,
	struct rng_engine *rng);

int flash_store_contiguous_blocks_encrypted_init_variable_storage (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, const struct aes_gcm_engine *aes,
	struct rng_engine *rng);
int flash_store_contiguous_blocks_encrypted_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, const struct aes_gcm_engine *aes,
	struct rng_engine *rng);

int flash_store_contiguous_blocks_encrypted_init_state (
	const struct flash_store_contiguous_blocks_encrypted *store, size_t block_count,
	size_t data_length);

void flash_store_contiguous_blocks_encrypted_release (
	const struct flash_store_contiguous_blocks_encrypted *store);


#endif	/* FLASH_STORE_CONTIGUOUS_BLOCKS_ENCRYPTED_H_ */
