// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_ENCRYPTED_H_
#define FLASH_STORE_ENCRYPTED_H_

#include "flash_store.h"
#include "crypto/aes.h"
#include "crypto/rng.h"


/**
 * Manage storage of indexed data blocks in flash.  Data stored in flash will be encrypted.  The
 * data blocks are aligned to flash erase boundaries to avoid dependencies between data blocks.
 */
struct flash_store_encrypted {
	struct flash_store base;				/**< Base flash storage instance. */
	struct aes_engine *aes;					/**< Engine to use for data encryption. */
	struct rng_engine *rng;					/**< Random number generator for encryption IVs. */
};


int flash_store_encrypted_init_fixed_storage (struct flash_store_encrypted *store,
	struct flash *flash, uint32_t base_addr, size_t block_count, size_t data_length,
	struct aes_engine *aes, struct rng_engine *rng);
int flash_store_encrypted_init_fixed_storage_decreasing (struct flash_store_encrypted *store,
	struct flash *flash, uint32_t base_addr, size_t block_count, size_t data_length,
	struct aes_engine *aes, struct rng_engine *rng);

int flash_store_encrypted_init_variable_storage (struct flash_store_encrypted *store,
	struct flash *flash, uint32_t base_addr, size_t block_count, size_t min_length,
	struct aes_engine *aes, struct rng_engine *rng);
int flash_store_encrypted_init_variable_storage_decreasing (struct flash_store_encrypted *store,
	struct flash *flash, uint32_t base_addr, size_t block_count, size_t min_length,
	struct aes_engine *aes, struct rng_engine *rng);

void flash_store_encrypted_release (struct flash_store_encrypted *store);


#endif /* FLASH_STORE_ENCRYPTED_H_ */
