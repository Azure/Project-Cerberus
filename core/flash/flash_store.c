// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "flash_store.h"
#include "flash_util.h"


/**
 * The maximum amount of data allowed in a single data block.
 */
#define	FLASH_STORE_MAX_DATA_SIZE		((64 * 1024) - 1)


/**
 * Verify that parameters are valid for writing to a flash data block.
 *
 * @param flash The flash where the data will be written.
 * @param id Block ID of the data.
 * @param data The data to write.
 * @param length Length of the data.
 *
 * @return 0 if the parameters are valid or an error code.
 */
int flash_store_verify_write_params (struct flash_store *flash, int id, const uint8_t *data,
	size_t length)
{
	if ((flash == NULL) || (data == NULL) || (length == 0)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	if (!flash->variable && (length != flash->max_size)) {
		return FLASH_STORE_BAD_DATA_LENGTH;
	}
	else if (length > flash->max_size) {
		return FLASH_STORE_BAD_DATA_LENGTH;
	}

	return 0;
}

/**
 * Write a block of data to flash, including any data for internal use.  Parameters must have been
 * prevalidated.
 *
 * @param flash The flash where the data should be written.
 * @param id Block ID of the data.
 * @param data The data to write.
 * @param length Length of the data.
 * @param extra_data Extra data to append to the end of the data block.  The flash store must have
 * been initialized to expect this extra data.  Can be null if no extra data is necessary.
 * @param extra_length Length of the extra data being written.
 *
 * @return 0 if the data was written successfully or an error code.
 */
int flash_store_write_common (struct flash_store *flash, int id, const uint8_t *data, size_t length,
	const uint8_t *extra_data, size_t extra_length)
{
	int base_offset;
	int offset;
	int status;

	base_offset = id * flash->block_size;
	if (flash->decreasing) {
		base_offset = -base_offset;
	}
	offset = base_offset;

	status = flash_sector_erase_region (flash->flash, flash->base_addr + base_offset,
		flash->block_size);
	if (status != 0) {
		return status;
	}

#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	if (flash->page_buffer) {
		/* It is necessary to ensure that no page is written more than once.  Internal buffering is
		 * necessary in three cases:
		 * 1. The first page of data for variable length storage, since that holds the data header.
		 * 2. The last page of data for storage that appends extra data to the end, but only in
		 * cases where the stored data does not align to page boundaries.
		 * 3. The entire amount of data (header, data, and extra data) fits into the first page.
		 *
		 * Data that is naturally aligned to full pages is not buffered and is written directly from
		 * the source data. */
		struct flash_store_header header = {
			.header_len = FLASH_STORE_HEADER_LENGTH,
			.marker = FLASH_STORE_HEADER_MARKER,
			.length = length
		};
		size_t header_len = (!flash->variable) ? 0 :
			(flash->old_header) ? sizeof (header.length) : sizeof (header);
		size_t first = flash->page_size - header_len;
		size_t remain = FLASH_REGION_OFFSET (length + header_len, flash->page_size);
		size_t write_extra = flash->page_size - remain;
		size_t middle = (length > remain) ? (length - remain) : length;
		bool extra_first = false;

		if (flash->variable) {
			if (middle > first) {
				middle -= first;
			}
			else {
				if (middle < first) {
					/* All the data fits into the first flash page. */
					extra_first = true;
				}
				first = middle;
				middle = 0;
			}
		}
		else {
			if (middle < first) {
				middle = 0;
			}
			first = 0;
		}

		if (extra_length == 0) {
			if (!extra_first) {
				middle += remain;
			}
			remain = 0;
			write_extra = 0;
		}
		else if (write_extra > extra_length) {
			write_extra = extra_length;
		}

		/* Write full pages of source data. */
		offset += first + header_len;

		if (middle != 0) {
			status = flash_write_and_verify (flash->flash, flash->base_addr + offset, &data[first],
				middle);
			if (status != 0) {
				return status;
			}

			offset += middle;
		}

		/* Write the additional data appended to the end. */
		if (!extra_first && (extra_length != 0)) {
			platform_mutex_lock (&flash->lock);
			memcpy (flash->page_buffer, &data[length - remain], remain);
			memcpy (&flash->page_buffer[remain], extra_data, write_extra);

			status = flash_write_and_verify (flash->flash, flash->base_addr + offset,
				flash->page_buffer, remain + write_extra);
			platform_mutex_unlock (&flash->lock);
			if (status != 0) {
				return status;
			}

			offset += remain + write_extra;
		}
		else {
			offset += write_extra;
		}

		if (write_extra < extra_length) {
			status = flash_write_and_verify (flash->flash, flash->base_addr + offset,
				&extra_data[write_extra], extra_length - write_extra);
			if (status != 0) {
				return status;
			}
		}

		/* For variable storage, write the first page with the data header. */
		if (first != 0) {
			platform_mutex_lock (&flash->lock);
			if (!flash->old_header) {
				memcpy (flash->page_buffer, (uint8_t*) &header, sizeof (header));
			}
			else {
				memcpy (flash->page_buffer, (uint8_t*) &header.length, sizeof (header.length));
			}
			memcpy (&flash->page_buffer[header_len], data, first);
			if (extra_first) {
				memcpy (&flash->page_buffer[header_len + first], extra_data, write_extra);
				header_len += write_extra;
			}

			status = flash_write_and_verify (flash->flash, flash->base_addr + base_offset,
				flash->page_buffer, first + header_len);
			platform_mutex_unlock (&flash->lock);
			if (status != 0) {
				return status;
			}
		}
	}
	else
#endif
	{
		/* Each page can be written multiple times without erasing. */
		if (flash->variable) {
			if (!flash->old_header) {
				offset += FLASH_STORE_HEADER_LENGTH;
			}
			else {
				offset += sizeof (uint16_t);
			}
		}

		status = flash_write_and_verify (flash->flash, flash->base_addr + offset, data, length);
		if (status != 0) {
			return status;
		}

		if (extra_data) {
			offset += length;
			status = flash_write_and_verify (flash->flash, flash->base_addr + offset, extra_data,
				extra_length);
			if (status != 0) {
				return status;
			}
		}

		if (flash->variable) {
			struct flash_store_header header = {
				.header_len = FLASH_STORE_HEADER_LENGTH,
				.marker = FLASH_STORE_HEADER_MARKER,
				.length = length
			};

			if (!flash->old_header) {
				status = flash_write_and_verify (flash->flash, flash->base_addr + base_offset,
					(uint8_t*) &header, sizeof (header));
			}
			else {
				status = flash_write_and_verify (flash->flash, flash->base_addr + base_offset,
					(uint8_t*) &header.length, sizeof (header.length));
			}
			if (status != 0) {
				return status;
			}
		}
	}

	return 0;
}

static int flash_store_write_no_hash (struct flash_store *flash, int id, const uint8_t *data,
	size_t length)
{
	int status;

	status = flash_store_verify_write_params (flash, id, data, length);
	if (status != 0) {
		return status;
	}

	return flash_store_write_common (flash, id, data, length, NULL, 0);
}

static int flash_store_write_with_hash (struct flash_store *flash, int id, const uint8_t *data,
	size_t length)
{
	uint8_t hash[SHA256_HASH_LENGTH];
	int status;

	status = flash_store_verify_write_params (flash, id, data, length);
	if (status != 0) {
		return status;
	}

	status = flash->hash->calculate_sha256 (flash->hash, data, length, hash, sizeof (hash));
	if (status != 0) {
		return status;
	}

	return flash_store_write_common (flash, id, data, length, hash, sizeof (hash));
}

/**
 * Read the header on variable length data.
 *
 * @param flash The flash store to access.
 * @param offset Address offset to read the header from.
 * @param header Output for the header data.
 *
 * @return 0 if the header was read and is valid or an error code.
 */
static int flash_store_read_header (struct flash_store *flash, int offset,
	struct flash_store_header *header)
{
	uint16_t old_length;
	int status;

	status = flash->flash->read (flash->flash, flash->base_addr + offset, (uint8_t*) header,
		sizeof (struct flash_store_header));
	if (status != 0) {
		return status;
	}

	if (header->marker != FLASH_STORE_HEADER_MARKER) {
		/* If the header marker does not match, we need to check the older format for backwards
		 * compatibility.  If the first two bytes represent a valid length, assume the data is
		 * stored in the old way.  This is not a perfect check since it could be corrupt in a way
		 * that looks valid.  At that point, we would count on the hash to catch this corruption. */
		old_length = *((uint16_t*) header);
		if (old_length > flash->max_size) {
			return FLASH_STORE_NO_DATA;
		}

		header->length = old_length;
		header->header_len = 2;
	}
	else if ((header->header_len < FLASH_STORE_HEADER_MIN_LENGTH) ||
		(header->length > flash->max_size)) {
		return FLASH_STORE_NO_DATA;
	}

	return 0;
}

/**
 * Read a block of data from flash.
 *
 * @param flash The flash that contains the requested data.
 * @param id Block ID of the data.
 * @param data Output buffer for the data.
 * @param length Length of the data buffer.
 * @param extra_data Output buffer for extra data that should be read from the data block.  Set to
 * null to read no extra data.
 * @param extra_length Length of the extra data to read.
 * @param out_length Output for the length of data that was read.
 *
 * @return 0 if the data was read successfully or an error code.
 */
int flash_store_read_common (struct flash_store *flash, int id, uint8_t *data, size_t length,
	uint8_t *extra_data, size_t extra_length, size_t *out_length)
{
	int offset;
	int status;

	if ((flash == NULL) || (data == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	if (!flash->variable && (length < flash->max_size)) {
		return FLASH_STORE_BUFFER_TOO_SMALL;
	}

	offset = id * flash->block_size;
	if (flash->decreasing) {
		offset = -offset;
	}

	if (flash->variable) {
		struct flash_store_header header;

		status = flash_store_read_header (flash, offset, &header);
		if (status != 0) {
			return status;
		}

		if (length < header.length) {
			return FLASH_STORE_BUFFER_TOO_SMALL;
		}

		offset += header.header_len;
		length = header.length;
	}
	else {
		length = flash->max_size;
	}

	status = flash->flash->read (flash->flash, flash->base_addr + offset, data, length);
	if (status != 0) {
		return status;
	}

	if (extra_data) {
		offset += length;
		status = flash->flash->read (flash->flash, flash->base_addr + offset, extra_data,
			extra_length);
		if (status != 0) {
			return status;
		}
	}

	*out_length = length;
	return 0;
}

static int flash_store_read_no_hash (struct flash_store *flash, int id, uint8_t *data,
	size_t length)
{
	int status = flash_store_read_common (flash, id, data, length, NULL, 0, &length);
	return (status == 0) ? (int) length : status;
}

static int flash_store_read_with_hash (struct flash_store *flash, int id, uint8_t *data,
	size_t length)
{
	uint8_t hash_mem[SHA256_HASH_LENGTH];
	uint8_t hash_flash[SHA256_HASH_LENGTH];
	int status;

	status = flash_store_read_common (flash, id, data, length, hash_flash, sizeof (hash_flash),
		&length);
	if (status != 0) {
		return status;
	}

	status = flash->hash->calculate_sha256 (flash->hash, data, length, hash_mem, sizeof (hash_mem));
	if (status != 0) {
		return status;
	}

	if (memcmp (hash_mem, hash_flash, SHA256_HASH_LENGTH) != 0) {
		return FLASH_STORE_CORRUPT_DATA;
	}

	return length;
}

static int flash_store_erase (struct flash_store *flash, int id)
{
	int offset;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	offset = id * flash->block_size;
	if (flash->decreasing) {
		offset = -offset;
	}

	return flash_sector_erase_region_and_verify (flash->flash, flash->base_addr + offset,
		flash->block_size);
}

static int flash_store_erase_all (struct flash_store *flash)
{
	int offset = 0;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if (flash->decreasing) {
		offset = flash->block_size * (flash->blocks - 1);
	}

	return flash_sector_erase_region_and_verify (flash->flash, flash->base_addr - offset,
		flash->block_size * flash->blocks);
}

static int flash_store_get_data_length (struct flash_store *flash, int id)
{
	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	if (flash->variable) {
		struct flash_store_header header;
		int offset;
		int status;

		offset = id * flash->block_size;
		if (flash->decreasing) {
			offset = -offset;
		}

		status = flash_store_read_header (flash, offset, &header);
		if (status != 0) {
			return status;
		}

		return header.length;
	}
	else {
		return flash->max_size;
	}
}

static int flash_store_has_data_stored (struct flash_store *flash, int id)
{
	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	if (flash->variable) {
		struct flash_store_header header;
		int offset;
		int status;

		offset = id * flash->block_size;
		if (flash->decreasing) {
			offset = -offset;
		}

		status = flash_store_read_header (flash, offset, &header);
		switch (status) {
			case 0:
				return 1;

			case FLASH_STORE_NO_DATA:
				return 0;

			default:
				return status;
		}
	}
	else {
		return 1;
	}
}

static int flash_store_get_max_data_length (struct flash_store *flash)
{
	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	return flash->max_size;
}

static int flash_store_get_flash_size (struct flash_store *flash)
{
	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	return flash->block_size * flash->blocks;
}

static int flash_store_get_num_blocks (struct flash_store *flash)
{
	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	return flash->blocks;
}

/**
 * Initialize flash storage for blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The minimum length of each data block.
 * @param decreasing Flag indicating if the storage grows down in the device address space.
 * @param variable Flag indicating if the blocks contain variable length data.
 * @param extra_data The length of extra internal data that will be added to each data block.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_init_storage_common (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, bool decreasing, bool variable,
	size_t extra_data)
{
	uint32_t sector_size;
	uint32_t device_size;
#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	uint32_t write_size;
#endif
	int status;

	if ((store == NULL) || (flash == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if (block_count == 0) {
		return FLASH_STORE_NO_STORAGE;
	}

	if (data_length > FLASH_STORE_MAX_DATA_SIZE) {
		return FLASH_STORE_BLOCK_TOO_LARGE;
	}

	memset (store, 0, sizeof (struct flash_store));

	status = flash->get_sector_size (flash, &sector_size);
	if (status != 0) {
		return status;
	}

	if (FLASH_REGION_OFFSET (base_addr, sector_size) != 0) {
		return FLASH_STORE_STORAGE_NOT_ALIGNED;
	}

	status = flash->get_device_size (flash, &device_size);
	if (status != 0) {
		return status;
	}

	if ((base_addr >= device_size) || (decreasing && (base_addr == 0))) {
		return FLASH_STORE_BAD_BASE_ADDRESS;
	}

	store->max_size = data_length;
	store->blocks = block_count;

	data_length += extra_data;
	if (variable) {
		data_length += FLASH_STORE_HEADER_LENGTH;
	}
	if (data_length > sector_size) {
		store->block_size = data_length;
	}
	else {
		store->block_size = sector_size;
	}

	store->block_size = (store->block_size + (sector_size - 1)) & FLASH_REGION_MASK (sector_size);
	if (!decreasing) {
		if ((base_addr + (store->block_size * store->blocks)) > device_size) {
			return FLASH_STORE_INSUFFICIENT_STORAGE;
		}
	}
	else {
		if ((store->block_size * (store->blocks - 1)) > base_addr) {
			return FLASH_STORE_INSUFFICIENT_STORAGE;
		}
	}

	if (variable) {
		store->max_size = store->block_size - FLASH_STORE_HEADER_LENGTH - extra_data;
		if (store->max_size > FLASH_STORE_MAX_DATA_SIZE) {
			return FLASH_STORE_BLOCK_TOO_LARGE;
		}
	}

#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	status = flash->get_page_size (flash, &store->page_size);
	if (status != 0) {
		return status;
	}

	status = flash->minimum_write_per_page (flash, &write_size);
	if (status != 0) {
		return status;
	}

	if ((write_size != 1) &&
		(variable || (!variable && extra_data &&
			FLASH_REGION_OFFSET (store->max_size, store->page_size) != 0))) {
		/* We need to buffer full page writes at the beginning and/or end of the data. */
		store->page_buffer = platform_malloc (store->page_size);
		if (store->page_buffer == NULL) {
			return FLASH_STORE_NO_MEMORY;
		}
	}

	status = platform_mutex_init (&store->lock);
	if (status != 0) {
		platform_free (store->page_buffer);
		return status;
	}
#endif

	store->erase = flash_store_erase;
	store->erase_all = flash_store_erase_all;
	store->get_data_length = flash_store_get_data_length;
	store->has_data_stored = flash_store_has_data_stored;
	store->get_max_data_length = flash_store_get_max_data_length;
	store->get_flash_size = flash_store_get_flash_size;
	store->get_num_blocks = flash_store_get_num_blocks;

	store->flash = flash;
	store->base_addr = base_addr;
	store->decreasing = decreasing;
	store->variable = variable;

	return 0;
}

/**
 * Initialize flash storage for blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The minimum length of each data block.
 * @param hash Optional hash engine to use for data validation.  If a hash engine is provided, data
 * integrity is checked when reading.
 * @param decreasing Flag indicating if the storage grows down in the device address space.
 * @param variable Flag indicating if the blocks contain variable length data.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
static int flash_store_init (struct flash_store *store, struct flash *flash, uint32_t base_addr,
	size_t block_count, size_t data_length, struct hash_engine *hash, bool decreasing,
	bool variable)
{
	int status;

	if (hash) {
		status = flash_store_init_storage_common (store, flash, base_addr, block_count, data_length,
			decreasing, variable, SHA256_HASH_LENGTH);
		if (status == 0) {
			store->write = flash_store_write_with_hash;
			store->read = flash_store_read_with_hash;

			store->hash = hash;
		}
	}
	else {
		status = flash_store_init_storage_common (store, flash, base_addr, block_count, data_length,
			decreasing, variable, 0);
		if (status == 0) {
			store->write = flash_store_write_no_hash;
			store->read = flash_store_read_no_hash;
		}
	}

	return status;
}

/**
 * Initialize flash storage for fixed sized blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The length of each data block.
 * @param hash Optional hash engine to use for data validation.  If a hash engine is provided, data
 * integrity is checked when reading.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_init_fixed_storage (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, struct hash_engine *hash)
{
	return flash_store_init (store, flash, base_addr, block_count, data_length, hash, false, false);
}

/**
 * Initialize flash storage for fixed sized blocks of data.  Blocks will be stored in addresses
 * decreasing from the first block.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The length of each data block.
 * @param hash Optional hash engine to use for data validation.  If a hash engine is provided, data
 * integrity is checked when reading.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_init_fixed_storage_decreasing (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, struct hash_engine *hash)
{
	return flash_store_init (store, flash, base_addr, block_count, data_length, hash, true, false);
}

/**
 * Initialize flash storage for variable sized blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param min_length The minimum length required for each data block.  The actual length length will
 * be determined by the flash sector size.
 * @param hash Optional hash engine to use for data validation.  If a hash engine is provided, data
 * integrity is checked when reading.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_init_variable_storage (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, struct hash_engine *hash)
{
	return flash_store_init (store, flash, base_addr, block_count, min_length, hash, false, true);
}

/**
 * Initialize flash storage for variable sized blocks of data.  Blocks will be stored in addresses
 * decreasing from the first block.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param min_length The minimum length required for each data block.  The actual length length will
 * be determined by the flash sector size.
 * @param hash Optional hash engine to use for data validation.  If a hash engine is provided, data
 * integrity is checked when reading.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_init_variable_storage_decreasing (struct flash_store *store, struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, struct hash_engine *hash)
{
	return flash_store_init (store, flash, base_addr, block_count, min_length, hash, true, true);
}

/**
 * Release the resources used for flash block storage.
 *
 * @param store The flash storage to release.
 */
void flash_store_release (struct flash_store *store)
{
#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	if (store) {
		platform_free (store->page_buffer);
		platform_mutex_free (&store->lock);
	}
#endif
}

/**
 * Configure the flash storage to write a backwards-compatible header on variable length data.  This
 * type of header is always accepted when reading variable length data.
 *
 * @param store The flash storage to configure.
 */
void flash_store_use_length_only_header (struct flash_store *store)
{
	if (store) {
		store->old_header = true;
	}
}
