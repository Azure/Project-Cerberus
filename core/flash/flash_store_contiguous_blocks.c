// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "flash_store_contiguous_blocks.h"
#include "flash_util.h"
#include "common/buffer_util.h"
#include "common/unused.h"


/**
 * The maximum amount of data allowed in a single data block.
 */
#define	FLASH_STORE_MAX_DATA_SIZE		((64 * 1024) - 1)


/**
 * Verify that parameters are valid for writing to a flash data block.
 *
 * @param flash_store The flash where the data will be written.
 * @param id Block ID of the data.
 * @param data The data to write.
 * @param length Length of the data.
 *
 * @return 0 if the parameters are valid or an error code.
 */
int flash_store_contiguous_blocks_verify_write_params (
	const struct flash_store_contiguous_blocks *flash, int id, const uint8_t *data, size_t length)
{
	if ((flash == NULL) || (data == NULL) || (length == 0)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	if (!flash->variable && (length != (flash->state->max_size - flash->state->overhead))) {
		return FLASH_STORE_BAD_DATA_LENGTH;
	}
	else if (length > (flash->state->max_size - flash->state->overhead)) {
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
int flash_store_contiguous_blocks_write_common (const struct flash_store_contiguous_blocks *flash,
	int id, const uint8_t *data, size_t length, const uint8_t *extra_data, size_t extra_length)
{
	int base_offset;
	int offset;
	int status;

	base_offset = id * flash->state->block_size;
	if (flash->decreasing) {
		base_offset = -base_offset;
	}
	offset = base_offset;

	status = flash_sector_erase_region (flash->flash, flash->base_addr + base_offset,
		flash->state->block_size);
	if (status != 0) {
		return status;
	}

#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	if (flash->state->page_buffer) {
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
				(flash->state->old_header) ? sizeof (header.length) : sizeof (header);
		size_t first = flash->state->page_size - header_len;
		size_t remain = FLASH_REGION_OFFSET (length + header_len, flash->state->page_size);
		size_t write_extra = flash->state->page_size - remain;
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
			platform_mutex_lock (&flash->state->lock);
			memcpy (flash->state->page_buffer, &data[length - remain], remain);
			memcpy (&flash->state->page_buffer[remain], extra_data, write_extra);

			status = flash_write_and_verify (flash->flash, flash->base_addr + offset,
				flash->state->page_buffer, remain + write_extra);
			platform_mutex_unlock (&flash->state->lock);
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
			platform_mutex_lock (&flash->state->lock);
			if (!flash->state->old_header) {
				memcpy (flash->state->page_buffer, (uint8_t*) &header, sizeof (header));
			}
			else {
				memcpy (flash->state->page_buffer, (uint8_t*) &header.length,
					sizeof (header.length));
			}
			memcpy (&flash->state->page_buffer[header_len], data, first);
			if (extra_first) {
				memcpy (&flash->state->page_buffer[header_len + first], extra_data, write_extra);
				header_len += write_extra;
			}

			status = flash_write_and_verify (flash->flash, flash->base_addr + base_offset,
				flash->state->page_buffer, first + header_len);
			platform_mutex_unlock (&flash->state->lock);
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
			if (!flash->state->old_header) {
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

			if (!flash->state->old_header) {
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

int flash_store_contiguous_blocks_write_no_hash (const struct flash_store *flash_store, int id,
	const uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;
	int status;

	status = flash_store_contiguous_blocks_verify_write_params (flash, id, data, length);
	if (status != 0) {
		return status;
	}

	return flash_store_contiguous_blocks_write_common (flash, id, data, length, NULL, 0);
}

int flash_store_contiguous_blocks_write_with_hash (const struct flash_store *flash_store, int id,
	const uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;
	uint8_t hash[SHA256_HASH_LENGTH];
	int status;

	status = flash_store_contiguous_blocks_verify_write_params (flash, id, data, length);
	if (status != 0) {
		return status;
	}

	status = flash->hash->calculate_sha256 (flash->hash, data, length, hash, sizeof (hash));
	if (status != 0) {
		return status;
	}

	return flash_store_contiguous_blocks_write_common (flash, id, data, length, hash,
		sizeof (hash));
}

/**
 * Read the header on variable length data.
 *
 * @param flash The flash store that manages contiguous blocks of memory.
 * @param offset Address offset to read the header from.
 * @param header Output for the header data.
 *
 * @return 0 if the header was read and is valid or an error code.
 */
static int flash_store_contiguous_blocks_read_header (
	const struct flash_store_contiguous_blocks *flash, int offset,
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
		if (old_length > flash->state->max_size) {
			return FLASH_STORE_NO_DATA;
		}

		header->length = old_length;
		header->header_len = 2;
	}
	else if ((header->header_len < FLASH_STORE_HEADER_MIN_LENGTH) ||
		(header->length > flash->state->max_size)) {
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
 * @param alignment Enforce a specific byte alignment on the length of the data in storage.  If the
 * length is not properly aligned, report that the block has no data.  Set this to 0 if there no
 * required alignment.
 * @param extra_data Output buffer for extra data that should be read from the data block.  Set to
 * null to read no extra data.
 * @param extra_length Length of the extra data to read.
 * @param out_length Output for the length of data that was read.
 *
 * @return 0 if the data was read successfully or an error code.
 */
int flash_store_contiguous_blocks_read_common (const struct flash_store_contiguous_blocks *flash,
	int id, uint8_t *data, size_t length, size_t alignment, uint8_t *extra_data,
	size_t extra_length, size_t *out_length)
{
	int offset;
	int status;

	if ((flash == NULL) || (data == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	if (!flash->variable && (length < flash->state->max_size)) {
		return FLASH_STORE_BUFFER_TOO_SMALL;
	}

	offset = id * flash->state->block_size;
	if (flash->decreasing) {
		offset = -offset;
	}

	if (flash->variable) {
		struct flash_store_header header;

		status = flash_store_contiguous_blocks_read_header (flash, offset, &header);
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
		length = flash->state->max_size;
	}

	if ((alignment != 0) && ((length % alignment) != 0)) {
		return FLASH_STORE_NO_DATA;
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

int flash_store_contiguous_blocks_read_no_hash (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;
	int status;

	status = flash_store_contiguous_blocks_read_common (flash, id, data, length, 0, NULL, 0,
		&length);

	return (status == 0) ? (int) length : status;
}

int flash_store_contiguous_blocks_read_with_hash (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;
	uint8_t hash_mem[SHA256_HASH_LENGTH];
	uint8_t hash_flash[SHA256_HASH_LENGTH];
	int status;

	status = flash_store_contiguous_blocks_read_common (flash, id, data, length, 0, hash_flash,
		sizeof (hash_flash), &length);
	if (status != 0) {
		return status;
	}

	status = flash->hash->calculate_sha256 (flash->hash, data, length, hash_mem, sizeof (hash_mem));
	if (status != 0) {
		return status;
	}

	if (buffer_compare (hash_mem, hash_flash, SHA256_HASH_LENGTH) != 0) {
		return FLASH_STORE_CORRUPT_DATA;
	}

	return length;
}

int flash_store_contiguous_blocks_erase (const struct flash_store *flash_store, int id)
{
	int offset;
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if ((id < 0) || ((uint32_t) id >= flash->blocks)) {
		return FLASH_STORE_UNSUPPORTED_ID;
	}

	offset = id * flash->state->block_size;
	if (flash->decreasing) {
		offset = -offset;
	}

	return flash_sector_erase_region_and_verify (flash->flash, flash->base_addr + offset,
		flash->state->block_size);
}

int flash_store_contiguous_blocks_erase_all (const struct flash_store *flash_store)
{
	int offset = 0;
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if (flash->decreasing) {
		offset = flash->state->block_size * (flash->blocks - 1);
	}

	return flash_sector_erase_region_and_verify (flash->flash, flash->base_addr - offset,
		flash->state->block_size * flash->blocks);
}

int flash_store_contiguous_blocks_get_data_length (const struct flash_store *flash_store, int id)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;

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

		offset = id * flash->state->block_size;
		if (flash->decreasing) {
			offset = -offset;
		}

		status = flash_store_contiguous_blocks_read_header (flash, offset, &header);
		if (status != 0) {
			return status;
		}

		return header.length;
	}
	else {
		return flash->state->max_size;
	}
}

int flash_store_contiguous_blocks_has_data_stored (const struct flash_store *flash_store, int id)
{
	int length;

	if (flash_store == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	length = flash_store->get_data_length (flash_store, id);
	if (ROT_IS_ERROR (length)) {
		if (length == FLASH_STORE_NO_DATA) {
			return 0;
		}
		else {
			return length;
		}
	}

	return 1;
}

int flash_store_contiguous_blocks_get_max_data_length (const struct flash_store *flash_store)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	return flash->state->max_size - flash->state->overhead;
}

int flash_store_contiguous_blocks_get_flash_size (const struct flash_store *flash_store)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	return flash->state->block_size * flash->blocks;
}

int flash_store_contiguous_blocks_get_num_blocks (const struct flash_store *flash_store)
{
	const struct flash_store_contiguous_blocks *flash =
		(const struct flash_store_contiguous_blocks*) flash_store;

	if (flash == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	return flash->blocks;
}

/**
 * Common API to initialize the variable state of flash store interface.
 *
 * @param store The flash storage to initialize.
 * @param data_length The minimum length of each data block.  This length must include any storage
 * overhead necessary when the data is written to flash.
 * @param overhead The amount of data that is storage overhead.  This will reduce the maximum amount
 * of data that can be stored in a data block.
 * @param extra_data The length of extra internal data that will be added to each data block.  This
 * will not be counted as part of the available data storage.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_init_state_common (
	const struct flash_store_contiguous_blocks *store, size_t data_length, size_t overhead,
	size_t extra_data)
{
	uint32_t sector_size;
	uint32_t device_size;

#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	uint32_t write_size;
#endif
	int status;

	if ((store->state == NULL) || (store->flash == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	memset (store->state, 0, sizeof (struct flash_store_contiguous_blocks_state));

	status = store->flash->get_sector_size (store->flash, &sector_size);
	if (status != 0) {
		return status;
	}

	if (FLASH_REGION_OFFSET (store->base_addr, sector_size) != 0) {
		return FLASH_STORE_STORAGE_NOT_ALIGNED;
	}

	status = store->flash->get_device_size (store->flash, &device_size);
	if (status != 0) {
		return status;
	}

	if ((store->base_addr >= device_size) || (store->decreasing && (store->base_addr == 0))) {
		return FLASH_STORE_BAD_BASE_ADDRESS;
	}

	store->state->max_size = data_length;
	store->state->overhead = overhead;

	data_length += extra_data;
	if (store->variable) {
		data_length += FLASH_STORE_HEADER_LENGTH;
	}
	if (data_length > sector_size) {
		store->state->block_size = data_length;
	}
	else {
		store->state->block_size = sector_size;
	}

	store->state->block_size = (store->state->block_size + (sector_size - 1)) &
		FLASH_REGION_MASK (sector_size);
	if (!store->decreasing) {
		if ((store->base_addr + (store->state->block_size * store->blocks)) > device_size) {
			return FLASH_STORE_INSUFFICIENT_STORAGE;
		}
	}
	else {
		if ((store->state->block_size * (store->blocks - 1)) > store->base_addr) {
			return FLASH_STORE_INSUFFICIENT_STORAGE;
		}
	}

	if (store->variable) {
		store->state->max_size = store->state->block_size - FLASH_STORE_HEADER_LENGTH - extra_data;
		if (store->state->max_size > FLASH_STORE_MAX_DATA_SIZE) {
			return FLASH_STORE_BLOCK_TOO_LARGE;
		}
	}

#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	status = store->flash->get_page_size (store->flash, &store->state->page_size);
	if (status != 0) {
		return status;
	}

	status = store->flash->minimum_write_per_page (store->flash, &write_size);
	if (status != 0) {
		return status;
	}

	if ((write_size != 1) &&
		(store->variable || (!store->variable && extra_data &&
		(FLASH_REGION_OFFSET (store->state->max_size, store->state->page_size) != 0)))) {
		/* We need to buffer full page writes at the beginning and/or end of the data. */
		store->state->page_buffer = platform_malloc (store->state->page_size);
		if (store->state->page_buffer == NULL) {
			return FLASH_STORE_NO_MEMORY;
		}
	}

	status = platform_mutex_init (&store->state->lock);
	if (status != 0) {
		platform_free (store->state->page_buffer);

		return status;
	}
#endif

	return 0;
}

/**
 * Initialize flash storage for contiguous blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param state The flash store state to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The minimum length of each data block.
 * @param decreasing Flag indicating if the storage grows down in the device address space.
 * @param variable Flag indicating if the blocks contain variable length data.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_init_storage_common (struct flash_store_contiguous_blocks *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, bool decreasing, bool variable)
{
	if ((store == NULL) || (state == NULL) || (flash == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if (block_count == 0) {
		return FLASH_STORE_NO_STORAGE;
	}

	if (data_length > FLASH_STORE_MAX_DATA_SIZE) {
		return FLASH_STORE_BLOCK_TOO_LARGE;
	}

	memset (store, 0, sizeof (struct flash_store_contiguous_blocks));

	store->base.erase = flash_store_contiguous_blocks_erase;
	store->base.erase_all = flash_store_contiguous_blocks_erase_all;
	store->base.get_data_length = flash_store_contiguous_blocks_get_data_length;
	store->base.has_data_stored = flash_store_contiguous_blocks_has_data_stored;
	store->base.get_max_data_length = flash_store_contiguous_blocks_get_max_data_length;
	store->base.get_flash_size = flash_store_contiguous_blocks_get_flash_size;
	store->base.get_num_blocks = flash_store_contiguous_blocks_get_num_blocks;

	store->base_addr = base_addr;
	store->blocks = block_count;
	store->decreasing = decreasing;
	store->variable = variable;
	store->flash = flash;
	store->state = state;

	return 0;
}

/**
 * Initialize flash storage for contiguous blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param state The flash store state to initialize.
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
static int flash_store_contiguous_blocks_init (struct flash_store_contiguous_blocks *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct hash_engine *hash,
	bool decreasing, bool variable)
{
	int status;

	status = flash_store_contiguous_blocks_init_storage_common (store, state, flash, base_addr,
		block_count, data_length, decreasing, variable);
	if (status != 0) {
		return status;
	}

	if (hash) {
		store->base.write = flash_store_contiguous_blocks_write_with_hash;
		store->base.read = flash_store_contiguous_blocks_read_with_hash;
		store->hash = hash;
	}
	else {
		store->base.write = flash_store_contiguous_blocks_write_no_hash;
		store->base.read = flash_store_contiguous_blocks_read_no_hash;
	}

	status = flash_store_contiguous_blocks_init_state (store, data_length);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Initialize flash storage for fixed sized contiguous blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param state The flash store state to initialize.
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
int flash_store_contiguous_blocks_init_fixed_storage (struct flash_store_contiguous_blocks *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct hash_engine *hash)
{
	return flash_store_contiguous_blocks_init (store, state, flash, base_addr, block_count,
		data_length, hash, false, false);
}

/**
 * Initialize flash storage for fixed sized contiguous blocks of data.  Blocks will be stored in
 * addresses decreasing from the first block.
 *
 * @param store The flash storage to initialize.
 * @param state The flash store state to initialize.
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
int flash_store_contiguous_blocks_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks *store, struct flash_store_contiguous_blocks_state *state,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t data_length,
	const struct hash_engine *hash)
{
	return flash_store_contiguous_blocks_init (store, state, flash, base_addr, block_count,
		data_length, hash, true, false);
}

/**
 * Initialize flash storage for variable sized contiguous blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param state The flash store state to initialize.
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
int flash_store_contiguous_blocks_init_variable_storage (
	struct flash_store_contiguous_blocks *store, struct flash_store_contiguous_blocks_state *state,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t min_length,
	const struct hash_engine *hash)
{
	return flash_store_contiguous_blocks_init (store, state, flash, base_addr, block_count,
		min_length, hash, false, true);
}

/**
 * Initialize flash storage for variable sized contiguous blocks of data.  Blocks will be stored in
 * addresses decreasing from the first block.
 *
 * @param store The flash storage to initialize.
 * @param state The flash store state to initialize.
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
int flash_store_contiguous_blocks_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks *store, struct flash_store_contiguous_blocks_state *state,
	const struct flash *flash, uint32_t base_addr, size_t block_count, size_t min_length,
	const struct hash_engine *hash)
{
	return flash_store_contiguous_blocks_init (store, state, flash, base_addr, block_count,
		min_length, hash, true, true);
}

/**
 * Initialize only the variable state for flash store interface.
 *
 * @param store The flash storage to initialize.
 * @param data_length The minimum length of each data block.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_init_state (const struct flash_store_contiguous_blocks *store,
	size_t data_length)
{
	int status;

	if (store == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if (store->hash) {
		status = flash_store_contiguous_blocks_init_state_common (store, data_length, 0,
			SHA256_HASH_LENGTH);
	}
	else {
		status = flash_store_contiguous_blocks_init_state_common (store, data_length, 0, 0);
	}

	return status;
}

/**
 * Release the resources used for flash block storage.
 *
 * @param store The flash storage to release.
 */
void flash_store_contiguous_blocks_release (const struct flash_store_contiguous_blocks *store)
{
#ifdef FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
	if (store) {
		platform_free (store->state->page_buffer);
		platform_mutex_free (&store->state->lock);
	}
#else
	UNUSED (store);
#endif
}

/**
 * Configure the flash storage to write a backwards-compatible header on variable length data.
 * This type of header is always accepted when reading variable length data.
 *
 * @param store The flash storage to configure.
 */
void flash_store_contiguous_blocks_use_length_only_header (
	struct flash_store_contiguous_blocks *store)
{
	if (store) {
		store->state->old_header = true;
	}
}
