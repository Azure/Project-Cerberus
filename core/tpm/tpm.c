// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "platform.h"
#include "status/rot_status.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"
#include "flash/flash.h"
#include "logging/debug_log.h"
#include "tpm_logging.h"
#include "tpm.h"


/**
 * Initialize the TPM storage header and, optionally, clear the TPM storage.
 *
 * @param tpm TPM instance being updated.
 * @param clear Flag indicating if the TPM storage should be cleared.
 * @param write Flag indicating if the TPM header should be written.
 *
 * @return 0 if clear completed successfully or an error code.  This call cannot not fail if both
 * flags are false.
 */
static int tpm_init_header (struct tpm *tpm, bool clear, bool write)
{
	struct tpm_header *header = (struct tpm_header*) tpm->buffer;
	int id;
	int erase_status = 0;
	int status;

	if (clear) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_CLEAR_TPM, 0, 0);

		status = tpm->flash->get_num_blocks (tpm->flash);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		memset (tpm->buffer, 0xff, sizeof (tpm->buffer));
		for (id = status - 1; id > 0; id--) {
			status = tpm->flash->write (tpm->flash, id, tpm->buffer, sizeof (tpm->buffer));
			if (status != 0) {
				erase_status = status;
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_TPM,
					TPM_LOGGING_ERASE_FAILED, id, status);
			}
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_INVALID_HEADER, 0, 0);
	}

	memset (tpm->buffer, 0, sizeof (tpm->buffer));
	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	if (write) {
		status = tpm->flash->write (tpm->flash, 0, tpm->buffer, sizeof (tpm->buffer));
		if (status != 0) {
			return status;
		}
	}

	return erase_status;
}

/**
 * Read the TPM header and check if it is valid.
 *
 * @param tpm TPM instance being read.
 * @param init Flag to re-initialize a corrupt header.
 * @param write Flag to write a new header after reinitialization.
 * @param log Flag to log read errors.
 *
 * @return 0 if the header was successfully read or an error code.
 */
static int tpm_read_header (struct tpm *tpm, bool init, bool write, bool log)
{
	struct tpm_header *header;
	int status;

	status = tpm->flash->read (tpm->flash, 0, tpm->buffer, sizeof (tpm->buffer));
	if ((status == FLASH_STORE_NO_DATA) || (status == FLASH_STORE_CORRUPT_DATA)) {
		if (!init) {
			return status;
		}

		/* If the flash storage doesn't have valid data, reinitialize the header. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_NO_HEADER, status, 0);
		status = 0;
	}
	else if (ROT_IS_ERROR (status)) {
		if (log) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
				TPM_LOGGING_READ_HEADER_FAILED, status, 0);
		}
		return status;
	}
	else {
		status = 0;
	}

	header = (struct tpm_header*) tpm->buffer;
	if (header->magic != TPM_MAGIC) {
		if (init) {
			status = tpm_init_header (tpm, false, write);
		}
		else {
			status = TPM_INVALID_STORAGE;
		}
	}

	return status;
}

/**
 * Use the processor reset context to clear the TPM storage, if necessary.
 *
 * @param observer The observer instance being notified.
 */
static void tpm_on_soft_reset (struct host_processor_observer *observer)
{
	struct tpm *tpm = (struct tpm*) observer;
	struct tpm_header *header;
	int status;

	if (tpm == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_SOFT_RESET_ERROR, TPM_INVALID_ARGUMENT, 0);
		return;
	}

	status = tpm_read_header (tpm, true, true, true);
	if (status != 0) {
		return;
	}

	header = (struct tpm_header*) tpm->buffer;
	if (header->clear == 1) {
		status = tpm_init_header (tpm, true, true);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_TPM,
				TPM_LOGGING_CLEAR_FAILED, status, 0);
		}
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
	struct tpm_header *header;
	int status;

	if (tpm == NULL) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm_read_header (tpm, true, false, false);
	if (status != 0) {
		return status;
	}

	header = (struct tpm_header*) tpm->buffer;
	if (header->clear != 1) {
		header->clear = 1;
		status = tpm->flash->write (tpm->flash, 0, tpm->buffer, sizeof (tpm->buffer));
		if (status != 0) {
			return status;
		}
	}

	return 0;
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
	struct tpm_header *header;
	int status;

	if (tpm == NULL) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm_read_header (tpm, true, false, false);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	header = (struct tpm_header*) tpm->buffer;
	++header->nv_counter;

	return tpm->flash->write (tpm->flash, 0, tpm->buffer, sizeof (tpm->buffer));
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
	struct tpm_header *header;
	int status;

	if ((tpm == NULL) || (counter == NULL)) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm_read_header (tpm, false, false, false);
	if (status != 0) {
		return status;
	}

	header = (struct tpm_header*) tpm->buffer;
	*counter = header->nv_counter;

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
	if (tpm == NULL) {
		return TPM_INVALID_ARGUMENT;
	}

	return tpm->flash->write (tpm->flash, index + 1, storage, storage_len);
}

/**
 * Get storage block from TPM storage.
 *
 * @param tpm The TPM to utilize.
 * @param index Storage block index
 * @param storage The buffer to fill with storage block contents, buffer needs to be at least
 * TPM_STORAGE_SEGMENT_SIZE.
 * @param storage_len Size of storage buffer.
 * @param mask_data_error true to return a buffer of empty flash if the data in flash storage is not
 * valid.  If false, an error is returned for this case.
 *
 * @return 0 if storage block is retrieved successfully or an error code.
 */
int tpm_get_storage (struct tpm *tpm, uint8_t index, uint8_t *storage, size_t storage_len,
	bool mask_data_error)
{
	int status;

	if (tpm == NULL) {
		return TPM_INVALID_ARGUMENT;
	}

	status = tpm->flash->read (tpm->flash, index + 1, storage, storage_len);
	if (!ROT_IS_ERROR (status)) {
		status = 0;
	}
	else if (mask_data_error &&
		((status == FLASH_STORE_NO_DATA) || (status == FLASH_STORE_CORRUPT_DATA))) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_TPM,
			TPM_LOGGING_NO_SEGMENT_DATA, index, status);

		memset (storage, 0xff, storage_len);
		status = 0;
	}

	return status;
}

/**
 * Initialize a TPM storage interface that uses flash block storage.
 *
 * @param tpm The TPM storage to initialize.
 * @param flash The flash block storage used for the TPM.
 *
 * @return 0 if the TPM storage was successfully initialized or an error code.
 */
int tpm_init (struct tpm *tpm, struct flash_store *flash)
{
	struct tpm_header *header;
	int status;

	if ((tpm == NULL) || (flash == NULL)) {
		return TPM_INVALID_ARGUMENT;
	}

	status = flash->get_max_data_length (flash);
	if (ROT_IS_ERROR (status)) {
		return status;
	}
	else if (status < TPM_STORAGE_SEGMENT_SIZE) {
		return TPM_INSUFFICIENT_STORAGE;
	}

	memset (tpm, 0, sizeof (struct tpm));

	tpm->flash = flash;

	status = tpm_read_header (tpm, true, true, false);
	if (status != 0) {
		return status;
	}

	header = (struct tpm_header*) tpm->buffer;
	if (header->clear == 1) {
		status = tpm_init_header (tpm, true, true);
	}

	tpm->observer.on_soft_reset = tpm_on_soft_reset;

	return status;
}

/**
 * Release the resources used by TPM storage.
 *
 * @param tpm The TPM storage to release.
 */
void tpm_release (struct tpm *tpm)
{

}
