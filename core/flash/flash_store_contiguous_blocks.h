// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "platform_api.h"
#include "flash/flash.h"
#include "crypto/hash.h"
#include "flash_store.h"


/**
 * Manage storage of indexed data blocks in flash.  The data blocks are aligned to flash erase
 * boundaries to avoid dependencies between data blocks.
 */
struct flash_store_contiguous_blocks {
	struct flash_store base;		/**< Base flash_store. */
	const struct flash *flash;		/**< Flash device used for storage. */
	struct hash_engine *hash;		/**< Hash engine for integrity checking. */
	uint32_t base_addr;				/**< Base flash address for data storage. */
	bool decreasing;				/**< Flag indicating block storage grows down in the address space. */
	uint32_t max_size;				/**< Maximum amount of data per storage block. */
	bool variable;					/**< Flag indicating block storage is variable length. */
	uint32_t block_size;			/**< Flash size of each data block. */
	uint32_t blocks;				/**< The number of managed data blocks. */
#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	uint32_t page_size;				/**< Page programming size for the flash device. */
	uint8_t *page_buffer;			/**< Buffer for ensuring full page programming. */
	platform_mutex lock;			/**< Page buffer synchronization. */
#endif
	bool old_header;				/**< Flag indicating variable storage header only saves the length. */
};


int flash_store_contiguous_blocks_init_fixed_storage (struct flash_store_contiguous_blocks *store,
	const struct flash *flash,	uint32_t base_addr, size_t block_count, size_t data_length,
	struct hash_engine *hash);
int flash_store_contiguous_blocks_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks *store, const struct flash *flash, uint32_t base_addr,
	size_t block_count, size_t data_length, struct	hash_engine *hash);

int flash_store_contiguous_blocks_init_variable_storage (
	struct flash_store_contiguous_blocks *store, const struct flash *flash, uint32_t base_addr,
	size_t block_count, size_t min_length, struct hash_engine *hash);
int flash_store_contiguous_blocks_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks *store, const struct flash *flash, uint32_t base_addr,
	size_t block_count, size_t min_length, struct hash_engine *hash);

void flash_store_contiguous_blocks_release (struct flash_store_contiguous_blocks *store);

void flash_store_contiguous_blocks_use_length_only_header (
	struct flash_store_contiguous_blocks *store);

/* Internal functions for use by derived types. */
int flash_store_contiguous_blocks_init_storage_common (struct flash_store_contiguous_blocks *store,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t data_length,
	bool decreasing, bool variable, size_t extra_data);

int flash_store_contiguous_blocks_verify_write_params (struct flash_store_contiguous_blocks *flash,
	int id,	const uint8_t *data, size_t length);
int flash_store_contiguous_blocks_write_common (struct flash_store_contiguous_blocks *flash, int id,
	const uint8_t *data, size_t length, const uint8_t *extra_data, size_t extra_length);

int flash_store_contiguous_blocks_read_common (struct flash_store_contiguous_blocks *flash, int id,
	uint8_t *data, size_t length, uint8_t *extra_data, size_t extra_length, size_t *out_length);


#endif /* FLASH_STORE_CONTIGUOUS_BLOCKS_H_ */
