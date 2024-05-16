// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_CONTIGUOUS_BLOCKS_H_
#define FLASH_STORE_CONTIGUOUS_BLOCKS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "flash_store.h"
#include "platform_api.h"
#include "crypto/hash.h"
#include "flash/flash.h"


/**
 * Header on each block of variable length data.
 */
struct flash_store_header {
	uint8_t header_len;	/**< Total length of the header. */
	uint8_t marker;		/**< Marker byte indicating valid data. */
	uint16_t length;	/**< Length of the variable data. */
} __attribute__((__packed__));

#define	FLASH_STORE_HEADER_MARKER		0xa5
#define	FLASH_STORE_HEADER_LENGTH		(sizeof (struct flash_store_header))
#define	FLASH_STORE_HEADER_MIN_LENGTH	4

/**
 * Variable context for a flash store instance.
 */
struct flash_store_contiguous_blocks_state {
	uint32_t max_size;		/**< Maximum amount of data per storage block. */
	uint32_t block_size;	/**< Flash size of each data block. */
	uint32_t blocks;		/**< The number of managed data blocks. */
#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	uint32_t page_size;		/**< Page programming size for the flash device. */
	uint8_t *page_buffer;	/**< Buffer for ensuring full page programming. */
	platform_mutex lock;	/**< Page buffer synchronization. */
#endif
	bool old_header;		/**< Flag indicating variable storage header only saves the length. */
};

/**
 * Manage storage of indexed data blocks in flash.  The data blocks are aligned to flash erase
 * boundaries to avoid dependencies between data blocks.
 */
struct flash_store_contiguous_blocks {
	struct flash_store base;							/**< Base flash_store. */
	struct flash_store_contiguous_blocks_state *state;	/**< Variable context for the flash store instance. */
	uint32_t base_addr;									/**< Base flash address for data storage. */
	bool decreasing;									/**< Flag indicating block storage grows down in the address space. */
	bool variable;										/**< Flag indicating block storage is variable length. */
	const struct flash *flash;							/**< Flash device used for storage. */
	struct hash_engine *hash;							/**< Hash engine for integrity checking. */
};


int flash_store_contiguous_blocks_init_fixed_storage (struct flash_store_contiguous_blocks *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, struct hash_engine *hash);
int flash_store_contiguous_blocks_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks *store, struct flash_store_contiguous_blocks_state *state,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t data_length,
	struct	hash_engine *hash);

int flash_store_contiguous_blocks_init_variable_storage (
	struct flash_store_contiguous_blocks *store, struct flash_store_contiguous_blocks_state *state,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t min_length,
	struct hash_engine *hash);
int flash_store_contiguous_blocks_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks *store, struct flash_store_contiguous_blocks_state *state,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t min_length,
	struct hash_engine *hash);

int flash_store_contiguous_blocks_init_state (
	const struct flash_store_contiguous_blocks *store, size_t block_count, size_t data_length);

void flash_store_contiguous_blocks_release (const struct flash_store_contiguous_blocks *store);

void flash_store_contiguous_blocks_use_length_only_header (
	struct flash_store_contiguous_blocks *store);

/* Internal functions for use by derived types. */
int flash_store_contiguous_blocks_init_state_common (
	const struct flash_store_contiguous_blocks *store, size_t block_count, size_t data_length,
	size_t extra_data);

int flash_store_contiguous_blocks_init_storage_common (struct flash_store_contiguous_blocks *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, bool decreasing, bool variable);

int flash_store_contiguous_blocks_verify_write_params (
	const struct flash_store_contiguous_blocks *flash, int id, const uint8_t *data, size_t length);
int flash_store_contiguous_blocks_write_common (const struct flash_store_contiguous_blocks *flash,
	int id, const uint8_t *data, size_t length, const uint8_t *extra_data, size_t extra_length);

int flash_store_contiguous_blocks_read_common (const struct flash_store_contiguous_blocks *flash,
	int id, uint8_t *data, size_t length, uint8_t *extra_data, size_t extra_length,
	size_t *out_length);


#endif	/* FLASH_STORE_CONTIGUOUS_BLOCKS_H_ */
