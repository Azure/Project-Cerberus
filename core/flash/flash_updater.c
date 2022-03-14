// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "flash_updater.h"
#include "flash_util.h"


/**
 * Initialize a flash update manager with a configurable erase mechanism.
 *
 * @param updater The update manager to initialize.
 * @param flash The flash device where updates will be written.
 * @param base_addr The starting address for updates.
 * @param max_size The maximum number of bytes that can be written for a single update.
 * @param erase The function to use to erase the flash.
 *
 * @return 0 if the update manager was initialized successfully or an error code.
 */
static int flash_updater_init_common (struct flash_updater *updater, struct flash *flash,
	uint32_t base_addr, size_t max_size, int (*erase) (const struct flash*, uint32_t, size_t))
{
	if ((updater == NULL) || (flash == NULL)) {
		return FLASH_UPDATER_INVALID_ARGUMENT;
	}

	memset (updater, 0, sizeof (struct flash_updater));

	updater->flash = flash;
	updater->base_addr = base_addr;
	updater->max_size = max_size;
	updater->erase = erase;

	return 0;
}

/**
 * Initialize a flash update manager that will operate on erase blocks.  The base address and
 * maximum size don't need to be aligned to the block size, but erase blocks need to accounted for
 * externally.
 *
 * @param updater The update manager to initialize.
 * @param flash The flash device where updates will be written.
 * @param base_addr The starting address for updates.
 * @param max_size The maximum number of bytes that can be written for a single update.
 *
 * @return 0 if the update manager was initialized successfully or an error code.
 */
int flash_updater_init (struct flash_updater *updater, struct flash *flash, uint32_t base_addr,
	size_t max_size)
{
	return flash_updater_init_common (updater, flash, base_addr, max_size,
		flash_erase_region_and_verify);
}

/**
 * Initialize a flash update manager that will operate on erase sectors.  The base address and
 * maximum size don't need to be aligned to the sector size, but erase sectors need to accounted for
 * externally.
 *
 * @param updater The update manager to initialize.
 * @param flash The flash device where updates will be written.
 * @param base_addr The starting address for updates.
 * @param max_size The maximum number of bytes that can be written for a single update.
 *
 * @return 0 if the update manager was initialized successfully or an error code.
 */
int flash_updater_init_sector (struct flash_updater *updater, struct flash *flash,
	uint32_t base_addr, size_t max_size)
{
	return flash_updater_init_common (updater, flash, base_addr, max_size,
		flash_sector_erase_region_and_verify);
}

/**
 * Release a flash update manager.
 *
 * @param updater The update manager to release.
 */
void flash_updater_release (struct flash_updater *updater)
{

}

/**
 * Apply an offset to the flash updater manager.  The offset will shift the base address and reduce
 * the amount of space available for updates.
 *
 * @param updater The update manager to configure.
 * @param offset The offset to apply for updates.
 */
void flash_updater_apply_update_offset (struct flash_updater *updater, uint32_t offset)
{
	if (updater != NULL) {
		updater->base_addr += offset;
		updater->max_size -= offset;
	}
}

/**
 * Check to see if there enough space for an update in the defined flash region.
 *
 * @param updater The updater to query.
 * @param total_length The total length of the update.
 *
 * @return 0 if the update will fit in flash or an error code.
 */
int flash_updater_check_update_size (struct flash_updater *updater, size_t total_length)
{
	if (updater != NULL) {
		if (total_length > updater->max_size) {
			return FLASH_UPDATER_TOO_LARGE;
		}
		else {
			return 0;
		}
	}
	else {
		return FLASH_UPDATER_INVALID_ARGUMENT;
	}
}

/**
 * Prepare the flash to receive update data.
 *
 * @param updater The flash updater that will receive the update.
 * @param update_length The total expected length of the update.
 * @param erase_length The total length of the flash to erase.
 *
 * @return 0 if the flash is ready to be updated or an error code.
 */
static int flash_updater_prepare_update_flash (struct flash_updater *updater, size_t update_length,
	size_t erase_length)
{
	int status;

	if (update_length > updater->max_size) {
		return FLASH_UPDATER_TOO_LARGE;
	}

	if (erase_length) {
		status = updater->erase (updater->flash, updater->base_addr, erase_length);
		if (status != 0) {
			return status;
		}
	}

	updater->update_size = update_length;
	updater->write_offset = 0;

	return 0;
}

/**
 * Prepare the flash to receive an update.  Only the space requested for the update will be
 * guaranteed to be erased.
 *
 * @param updater The flash updater that will receive the update.
 * @param total_length The total expected length of the update.  If the length is 0, no erase will
 * be performed, but the update state will be configured to receive 0 bytes.
 *
 * @return 0 if the flash is ready to be updated or an error code.
 */
int flash_updater_prepare_for_update (struct flash_updater *updater, size_t total_length)
{
	if (updater == NULL) {
		return FLASH_UPDATER_INVALID_ARGUMENT;
	}

	return flash_updater_prepare_update_flash (updater, total_length, total_length);
}

/**
 * Prepare the flash to receive an update.  The entire flash update region will be erased.
 *
 * @param updater The flash updater that will receive the update.
 * @param total_length The total expected length of the update.
 *
 * @return 0 if the flash is ready to be updated or an error code.
 */
int flash_updater_prepare_for_update_erase_all (struct flash_updater *updater, size_t total_length)
{
	if (updater == NULL) {
		return FLASH_UPDATER_INVALID_ARGUMENT;
	}

	return flash_updater_prepare_update_flash (updater, total_length, updater->max_size);
}

/**
 * Write update data to flash.  The flash must have already been prepared for the update for this
 * data to be written correctly.  No validation of the written data will be performed.
 *
 * The data will be written starting at the next address in flash following the last successfully
 * written byte of data.  If this is the first write following preparation for an update, the data
 * will be written starting at the base address of the updater.
 *
 * @param updater The flash updater that will write the data.
 * @param data The data to write to flash.
 * @param length The amount of data to write.
 *
 * @return 0 if all of the data was written successfully or an error code.
 */
int flash_updater_write_update_data (struct flash_updater *updater, const uint8_t *data,
	size_t length)
{
	int status;

	if ((updater == NULL) || (data == NULL)) {
		return FLASH_UPDATER_INVALID_ARGUMENT;
	}

	if ((updater->write_offset + length) > updater->max_size) {
		return FLASH_UPDATER_OUT_OF_SPACE;
	}

	status = updater->flash->write (updater->flash, updater->base_addr + updater->write_offset,
		data, length);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	updater->update_size -= status;
	updater->write_offset += status;

	return (status == (int) length) ? 0 : FLASH_UPDATER_INCOMPLETE_WRITE;
}

/**
 * Get the total number of update bytes written to the flash.
 *
 * @param updater The flash updater to query.
 *
 * @return The number of bytes written.
 */
size_t flash_updater_get_bytes_written (struct flash_updater *updater)
{
	if (updater != NULL) {
		return updater->write_offset;
	}
	else {
		return 0;
	}
}

/**
 * Get the total number of bytes remaining in the expected update.
 *
 * @param updater The flash updater to query.
 *
 * @return The number of bytes remaining in the update.  If more data was received than expected,
 * this will be negative.
 */
int flash_updater_get_remaining_bytes (struct flash_updater *updater)
{
	if (updater != NULL) {
		return updater->update_size;
	}
	else {
		return 0;
	}
}
