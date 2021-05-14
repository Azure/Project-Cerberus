// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_H_
#define FLASH_STORE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "platform.h"
#include "status/rot_status.h"
#include "flash/flash.h"
#include "crypto/hash.h"


/**
 * Header on each block of variable length data.
 */
struct flash_store_header {
	uint8_t header_len;				/**< Total length of the header. */
	uint8_t marker;					/**< Marker byte indicating valid data. */
	uint16_t length;				/**< Length of the variable data. */
} __attribute__((__packed__));

#define	FLASH_STORE_HEADER_MARKER		0xa5
#define	FLASH_STORE_HEADER_LENGTH		(sizeof (struct flash_store_header))
#define	FLASH_STORE_HEADER_MIN_LENGTH	4


/**
 * Manage storage of indexed data blocks in flash.  The data blocks are aligned to flash erase
 * boundaries to avoid dependencies between data blocks.
 */
struct flash_store {
	/**
	 * Write a block of data to flash.
	 *
	 * @param flash The flash where the data should be written.
	 * @param id Block ID of the data.
	 * @param data The data to write.
	 * @param length Length of the data.
	 *
	 * @return 0 if the data was written successfully or an error code.
	 */
	int (*write) (struct flash_store *flash, int id, const uint8_t *data, size_t length);

	/**
	 * Read a block of data from flash.
	 *
	 * @param flash The flash that contains the requested data.
	 * @param id Block ID of the data.
	 * @param data Output buffer for the data.
	 * @param length Length of the data buffer.
	 *
	 * @return The number of bytes read from flash or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*read) (struct flash_store *flash, int id, uint8_t *data, size_t length);

	/**
	 * Erase a block of data.
	 *
	 * @param flash The flash containing the data block to erase.
	 * @param id Block ID of the data.
	 *
	 * @return 0 if the data was erased successfully or an error code.
	 */
	int (*erase) (struct flash_store *flash, int id);

	/**
	 * Erase all managed data.
	 *
	 * @param flash The flash to erase.
	 *
	 * @return 0 if all data was erase successfully or an error code.
	 */
	int (*erase_all) (struct flash_store *flash);

	/**
	 * Get the length of the data stored in flash block.
	 *
	 * @param flash The flash to query.
	 * @param id Block ID to query.
	 *
	 * @return The number of byte stored in the specified data block or an error code.  Use
	 * ROT_IS_ERROR to check the return value.  FLASH_STORE_NO_DATA is returned if there is not
	 * valid data stored in the block.
	 */
	int (*get_data_length) (struct flash_store *flash, int id);

	/**
	 * Determine if there is data stored in a flash block.
	 *
	 * @param flash The flash to query.
	 * @param id Block ID to query.
	 *
	 * @return 0 if there is no data stored, 1 if there is, or an error code.
	 */
	int (*has_data_stored) (struct flash_store *flash, int id);

	/**
	 * Get the maximum amount of data that can be stored in a single flash block.
	 *
	 * @param flash The flash to query.
	 *
	 * @return The maximum data length or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*get_max_data_length) (struct flash_store *flash);

	/**
	 * Gets the total amount of flash reserved for storage.  This includes all overhead for sector
	 * alignment and any additional metadata stored.
	 *
	 * @param flash The flash to query.
	 *
	 * @return The total flash reserved or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*get_flash_size) (struct flash_store *flash);

	/**
	 * Get the number of managed data blocks.
	 *
	 * @param flash The flash to query.
	 *
	 * @return The number of managed data blocks or an error code. Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*get_num_blocks) (struct flash_store *flash);

	struct flash *flash;		/**< Flash device used for storage. */
	struct hash_engine *hash;	/**< Hash engine for integrity checking. */
	uint32_t base_addr;			/**< Base flash address for data storage. */
	bool decreasing;			/**< Flag indicating block storage grows down in the address space. */
	uint32_t max_size;			/**< Maximum amount of data per storage block. */
	bool variable;				/**< Flag indicating block storage is variable length. */
	uint32_t block_size;		/**< Flash size of each data block. */
	uint32_t blocks;			/**< The number of managed data blocks. */
#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	uint32_t page_size;			/**< Page programming size for the flash device. */
	uint8_t *page_buffer;		/**< Buffer for ensuring full page programming. */
	platform_mutex lock;		/**< Page buffer synchronization. */
#endif
	bool old_header;			/**< Flag indicating variable storage header only saves the length. */
};


int flash_store_init_fixed_storage (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, struct hash_engine *hash);
int flash_store_init_fixed_storage_decreasing (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, struct hash_engine *hash);

int flash_store_init_variable_storage (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, struct hash_engine *hash);
int flash_store_init_variable_storage_decreasing (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, struct hash_engine *hash);

void flash_store_release (struct flash_store *store);

void flash_store_use_length_only_header (struct flash_store *store);

/* Internal functions for use by derived types. */
int flash_store_init_storage_common (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, bool decreasing, bool variable,
	size_t extra_data);

int flash_store_verify_write_params (struct flash_store *flash, int id, const uint8_t *data,
	size_t length);
int flash_store_write_common (struct flash_store *flash, int id, const uint8_t *data, size_t length,
	const uint8_t *extra_data, size_t extra_length);

int flash_store_read_common (struct flash_store *flash, int id, uint8_t *data, size_t length,
	uint8_t *extra_data, size_t extra_length, size_t *out_length);


#define	FLASH_STORE_ERROR(code)		ROT_ERROR (ROT_MODULE_FLASH_STORE, code)

/**
 * Error codes that can be generated by flash block storage.
 */
enum {
	FLASH_STORE_INVALID_ARGUMENT = FLASH_STORE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	FLASH_STORE_NO_MEMORY = FLASH_STORE_ERROR (0x01),				/**< Memory allocation failed. */
	FLASH_STORE_WRITE_FAILED = FLASH_STORE_ERROR (0x02),			/**< Failed to write data to flash. */
	FLASH_STORE_READ_FAILED = FLASH_STORE_ERROR (0x03),				/**< Failed to read data from flash. */
	FLASH_STORE_ERASE_FAILED = FLASH_STORE_ERROR (0x04),			/**< Failed to erase data from flash. */
	FLASH_STORE_ERASE_ALL_FAILED = FLASH_STORE_ERROR (0x05),		/**< Failed to erase all data from flash. */
	FLASH_STORE_GET_LENGTH_FAILED = FLASH_STORE_ERROR (0x06),		/**< Failed to determine length of stored data. */
	FLASH_STORE_DATA_CHECK_FAILED = FLASH_STORE_ERROR (0x07),		/**< Failed to determine if data is stored. */
	FLASH_STORE_GET_MAX_FAILED = FLASH_STORE_ERROR (0x08),			/**< Failed to determine the maximum data length. */
	FLASH_STORE_FLASH_SIZE_FAILED = FLASH_STORE_ERROR (0x09),		/**< Failed to determine the size of reserved flash. */
	FLASH_STORE_STORAGE_NOT_ALIGNED = FLASH_STORE_ERROR (0x0a),		/**< Memory for flash storage is not aligned correctly. */
	FLASH_STORE_NO_STORAGE = FLASH_STORE_ERROR (0x0b),				/**< The flash storage was created with no data blocks. */
	FLASH_STORE_INSUFFICIENT_STORAGE = FLASH_STORE_ERROR (0x0c),	/**< There is not enough storage space for the data. */
	FLASH_STORE_BAD_BASE_ADDRESS = FLASH_STORE_ERROR (0x0d),		/**< The base address is not valid for the device. */
	FLASH_STORE_BLOCK_TOO_LARGE = FLASH_STORE_ERROR (0x0e),			/**< The data block size is too large. */
	FLASH_STORE_BAD_DATA_LENGTH = FLASH_STORE_ERROR (0x0f),			/**< Data being stored is not the correct length. */
	FLASH_STORE_UNSUPPORTED_ID = FLASH_STORE_ERROR (0x10),			/**< Invalid block ID specified. */
	FLASH_STORE_CORRUPT_DATA = FLASH_STORE_ERROR (0x11),			/**< Data stored in flash is corrupt. */
	FLASH_STORE_BUFFER_TOO_SMALL = FLASH_STORE_ERROR (0x12),		/**< Output buffer is not large enough for stored data. */
	FLASH_STORE_NO_DATA = FLASH_STORE_ERROR (0x13),					/**< No data is stored in the flash block. */
	FLASH_STORE_NUM_BLOCKS_FAILED = FLASH_STORE_ERROR (0x14),		/**< Failed to determine the number of managed data blocks. */
};


#endif /* FLASH_STORE_H_ */
