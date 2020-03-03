// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "status/rot_status.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"
#include "flash/flash.h"
#include "logging/debug_log.h"
#include "tpm_logging.h"
#include "tpm.h"


/**
 * Internal clear TPM storage function.
 *
 * @param tpm TPM instance being utilized.
 * 
 * @return 0 if clear completed successfully or an error code.
 */
static int tpm_perform_clear (struct tpm* tpm)
{
	struct tpm_header header = {0};

	int status = flash_sector_erase_region (tpm->flash, tpm->base_addr, tpm->storage_size);
	if (status != 0) {
		return status;
	}

	memset (&header, 0, sizeof (struct tpm_header));
	header.magic = TPM_MAGIC;
	
	status = tpm->flash->write (tpm->flash, tpm->base_addr, (uint8_t*) &header, 
		sizeof (struct tpm_header));
	if (ROT_IS_ERROR (status)) {
		return status;
	}
	else if (status != sizeof (struct tpm_header)) {
		return FLASH_UTIL_INCOMPLETE_WRITE;
	}

	return 0;
}

/**
 * Clear TPM storage.
 *
 * @param observer The observer instance being notified.
 */
static void tpm_on_soft_reset (struct host_processor_observer *observer)
{
	struct tpm *tpm = (struct tpm*) observer;
	struct tpm_header header = {0};
	int status;

	if (tpm == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_CLEAR_FAILED, TPM_INVALID_ARGUMENT, 0);
		return;
	}

	status = tpm->flash->read (tpm->flash, tpm->base_addr, (uint8_t*) &header, 
		sizeof (struct tpm_header));
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_CLEAR_FAILED, status, 0);
		return;
	}

	if ((header.magic == TPM_MAGIC) && (header.clear == 0)) {
		return;
	}

	status = tpm_perform_clear (tpm);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_CLEAR_FAILED, status, 0);
		return;
	}
}

/**
 * Schedule TPM storage clear on next SoC reset.
 *
 * @param tpm The TPM to utilize.
 *
 * @return 0 if scheduled successfully or an error code.
 */
int tpm_schedule_clear (struct tpm *tpm)
{
	struct tpm_header header;
	int status;

	if (tpm == NULL) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm->flash->read (tpm->flash, tpm->base_addr, (uint8_t*) &header,
		sizeof (struct tpm_header));
	if (status != 0) {
		return status;
	}

	if (header.magic == TPM_MAGIC) {
		if (header.clear == 1) {
			return 0;
		}
	}
	else {
		memset ((uint8_t*) &header, 0, sizeof (struct tpm_header));
		header.magic = TPM_MAGIC;
	}

	header.clear = 1;

	return flash_sector_program_data (tpm->flash, tpm->base_addr, (uint8_t*) &header,
		sizeof (struct tpm_header));
}

/**
 * Increment NV counter value and update TPM storage.
 *
 * @param tpm The TPM to utilize.
 *
 * @return 0 if increment completed successfully or an error code.
 */
int tpm_increment_counter (struct tpm *tpm)
{
	struct tpm_header header;
	int status;

	if (tpm == NULL) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm->flash->read (tpm->flash, tpm->base_addr, (uint8_t*) &header,
		sizeof (struct tpm_header));
	if (status != 0) {
		return status;
	}

	if (header.magic != TPM_MAGIC) {
		memset ((uint8_t*) &header, 0, sizeof (struct tpm_header));
		header.magic = TPM_MAGIC;
	}

	++header.nv_counter;

	return flash_sector_program_data (tpm->flash, tpm->base_addr, (uint8_t*) &header,
		sizeof (struct tpm_header));
}

/**
 * Get NV counter value from TPM storage.
 *
 * @param tpm The TPM to utilize.
 * @param counter The buffer to fill with NV counter value.
 *
 * @return 0 if counter is retrieved successfully or an error code.
 */
int tpm_get_counter (struct tpm *tpm, uint64_t *counter)
{
	struct tpm_header header;
	int status;

	if ((tpm == NULL) || (counter == NULL)) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm->flash->read (tpm->flash, tpm->base_addr, (uint8_t*) &header,
		sizeof (struct tpm_header));
	if (status != 0) {
		return status;
	}

	if (header.magic != TPM_MAGIC) {
		return TPM_INVALID_STORAGE;
	}

	*counter = header.nv_counter;

	return 0;
}

/**
 * Write storage block to TPM storage.
 *
 * @param tpm The TPM to utilize.
 * @param index Storage block index
 * @param storage The buffer with storage block contents.
 * @param storage_len Size of storage buffer.
 *
 * @return 0 if storage block is written successfully or an error code.
 */
int tpm_set_storage (struct tpm *tpm, uint8_t index, uint8_t *storage, size_t storage_len)
{
	uint8_t *buffer;
	uint8_t num_segments_per_sector;
	uint8_t segment_id;
	uint8_t sector_id;
	uint32_t sector_size;
	uint32_t sector_addr;
	int status;

	if ((tpm == NULL) || (storage == NULL)) {
		return TPM_INVALID_ARGUMENT;
	}

	if (storage_len > TPM_STORAGE_SEGMENT_SIZE) {
		return TPM_INVALID_LEN;
	}

	if (index >= tpm->num_segments) {
		return TPM_OUT_OF_RANGE;
	}

	status = tpm->flash->get_sector_size (tpm->flash, &sector_size);
	if (status != 0) {
		return status;
	}

	if (storage_len > sector_size) {
		return TPM_INVALID_LEN;
	}

	num_segments_per_sector = sector_size / TPM_STORAGE_SEGMENT_SIZE;
	sector_id = index / num_segments_per_sector + 1;
	sector_addr = tpm->base_addr + sector_id * sector_size;

	if (storage_len == sector_size) {
		return flash_sector_program_data (tpm->flash, sector_addr, storage, storage_len);
	}

	buffer = platform_malloc (sector_size);
	if (buffer == NULL) {
		return TPM_NO_MEMORY;
	}

	status = tpm->flash->read (tpm->flash, sector_addr, buffer, sector_size);
	if (status != 0) {
		goto exit;
	}

	segment_id = index % num_segments_per_sector;

	memcpy (buffer + segment_id * TPM_STORAGE_SEGMENT_SIZE, storage, storage_len);

	status = flash_sector_program_data (tpm->flash, sector_addr, buffer, sector_size);
	if (status != 0) {
		goto exit;
	}

exit:
	platform_free (buffer);
	return status;
}

/**
 * Get storage block from TPM storage.
 *
 * @param tpm The TPM to utilize.
 * @param index Storage block index
 * @param storage The buffer to fill with storage block contents, buffer needs to be at least
 * 	TPM_STORAGE_SEGMENT_SIZE.
 * @param storage_len Size of storage buffer.
 *
 * @return 0 if storage block is retrieved successfully or an error code.
 */
int tpm_get_storage (struct tpm *tpm, uint8_t index, uint8_t *storage, size_t storage_len)
{
	uint32_t sector_size;
	int status;

	if ((tpm == NULL) || (storage == NULL)) {
		return TPM_INVALID_ARGUMENT;
	}

	if (storage_len < TPM_STORAGE_SEGMENT_SIZE) {
		return TPM_INVALID_LEN;
	}

	if (index >= tpm->num_segments) {
		return TPM_OUT_OF_RANGE;
	}

	status = tpm->flash->get_sector_size (tpm->flash, &sector_size);
	if (status != 0) {
		return status;
	}

	status = tpm->flash->read (tpm->flash,
		tpm->base_addr + sector_size + TPM_STORAGE_SEGMENT_SIZE * index, storage,
		TPM_STORAGE_SEGMENT_SIZE);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Initialize a TPM instance that uses persistent memory for storage.
 *
 * @param tpm The TPM to initialize.
 * @param flash The flash device used for TPM storage.
 * @param base_addr The flash starting address.
 * @param num_segments Number of storage segments to utilize.
 *
 * @return 0 if the TPM was successfully initialized or an error code.
 */
int tpm_init (struct tpm *tpm, struct flash *flash, uint32_t base_addr, uint8_t num_segments)
{
	struct tpm_header header;
	uint32_t flash_size;
	uint32_t sector_size;
	int status;

	if ((tpm == NULL) || (flash == NULL)) {
		return TPM_INVALID_ARGUMENT;
	}

	status = flash->get_device_size (flash, &flash_size);
	if (status != 0) {
		return status;
	}

	status = flash->get_sector_size (flash, &sector_size);
	if (status != 0) {
		return status;
	}

	if (FLASH_REGION_OFFSET (base_addr, sector_size) != 0) {
		return TPM_STORAGE_NOT_ALIGNED;
	}

	memset (tpm, 0, sizeof (struct tpm));
	
	tpm->flash = flash;
	tpm->base_addr = base_addr;
	tpm->num_segments = num_segments;
	tpm->storage_size = (TPM_STORAGE_SEGMENT_SIZE * num_segments) + sector_size;
	if (FLASH_REGION_OFFSET (tpm->storage_size, sector_size) != 0) {
		tpm->storage_size += sector_size - FLASH_REGION_OFFSET (tpm->storage_size, sector_size);
	}

	if ((base_addr + tpm->storage_size) > flash_size) {
		return TPM_INSUFFICIENT_STORAGE;
	}

	status = flash->read (flash, base_addr, (uint8_t*) &header, sizeof (struct tpm_header));
	if (status != 0) {
		return status;
	}

	if (header.magic != TPM_MAGIC) {
		memset ((uint8_t*) &header, 0, sizeof (struct tpm_header));
		header.magic = TPM_MAGIC;

		status = flash_sector_program_data (flash, base_addr, (uint8_t*) &header,
			sizeof (struct tpm_header));
	}
	else if (header.clear == 1) {
		status = tpm_perform_clear (tpm);
	}

	tpm->observer.on_soft_reset = tpm_on_soft_reset;

	return status;
}

/**
 * Release the resources used by TPM.
 *
 * @param tpm The TPM to release.
 */
void tpm_release (struct tpm *tpm)
{
}
