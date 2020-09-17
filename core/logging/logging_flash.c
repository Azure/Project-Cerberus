// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "logging_flash.h"


/**
 * Length indicator bit for a termination entry.
 */
#define	LOGGING_FLASH_TERMINATOR	(1U << 15)


/**
 * Save the entry buffer to flash.
 *
 * @param logging The log that should be saved.
 *
 * @return 0 if the data was successfully saved or an error code.
 */
static int logging_flash_save_buffer (struct logging_flash *logging)
{
	size_t write_len;
	uint8_t curr_sector_num;
	int status = 0;

	if (logging->next_write != logging->entry_buffer) {
		write_len = logging->next_write - logging->entry_buffer;
		curr_sector_num =
			(FLASH_SECTOR_BASE (logging->next_addr) - logging->base_addr) / FLASH_SECTOR_SIZE;

		if (FLASH_SECTOR_OFFSET (logging->next_addr) == 0) {
			status = spi_flash_sector_erase (logging->flash, logging->next_addr);
			if (status != 0) {
				return status;
			}

			logging->flash_used[curr_sector_num] = 0;

			if (logging->log_start == curr_sector_num) {
				int next_sector = (logging->log_start + 1) % LOGGING_FLASH_SECTORS;
				if (logging->flash_used[next_sector] != 0) {
					logging->log_start = next_sector;
				}
			}
		}

		status = spi_flash_write (logging->flash, logging->next_addr, logging->entry_buffer,
			write_len);
		if (ROT_IS_ERROR (status)) {
			return status;
		}
		else if (status != (int) write_len) {
			write_len = status;
			status = LOGGING_INCOMPLETE_FLUSH;
		}
		else {
			status = 0;
		}

		logging->next_addr += write_len;
		logging->flash_used[curr_sector_num] += write_len;

		if (status == 0) {
			if (((logging->write_remain < (int) sizeof (struct logging_entry_header)) ||
				logging->terminated) && (FLASH_SECTOR_OFFSET (logging->next_addr) != 0)) {
				logging->next_addr = FLASH_SECTOR_BASE (logging->next_addr) + FLASH_SECTOR_SIZE;
			}

			if (logging->next_addr >= (logging->base_addr + LOGGING_FLASH_AREA_LEN)) {
				logging->next_addr = logging->base_addr;
			}

			logging->next_write = logging->entry_buffer;
			logging->write_remain =
				sizeof (logging->entry_buffer) - FLASH_SECTOR_OFFSET (logging->next_addr);
			if (logging->terminated) {
				logging->flash_used[curr_sector_num] -= sizeof (struct logging_entry_header);
				logging->terminated = false;
			}
		}
		else {
			/* The write was not fully complete, so move the remaining data to be at the beginning
			 * of the buffer.  This will ensure it gets written on the next flush. */
			memmove (logging->entry_buffer, &logging->entry_buffer[write_len],
				logging->next_write - logging->entry_buffer - write_len);
			logging->next_write -= write_len;
		}
	}

	return status;
}

/**
 * Write an entry header to the entry buffer.  It assumed there is sufficient space for the header.
 *
 * @param logging The log to update.
 * @param length The length of the entry, not including the entry header.
 * @param id The entry ID.
 */
static void logging_flash_write_header (struct logging_flash *logging, uint16_t length, uint32_t id)
{
	struct logging_entry_header header;

	header.log_magic = LOGGING_MAGIC_START;
	header.length = length + sizeof (header);
	header.entry_id = id;

	memcpy (logging->next_write, (uint8_t*) &header, sizeof (header));
	logging->next_write += sizeof (header);
	logging->write_remain -= sizeof (header);
}

static int logging_flash_create_entry (struct logging *logging, uint8_t *entry, size_t length)
{
	struct logging_flash *flash_log = (struct logging_flash*) logging;
	int status;

	if ((flash_log == NULL) || (entry == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	if ((length == 0) ||
		((length + sizeof (struct logging_entry_header) > sizeof (flash_log->entry_buffer)))) {
		return LOGGING_BAD_ENTRY_LENGTH;
	}

	platform_mutex_lock (&flash_log->lock);

	if (flash_log->terminated ||
		(flash_log->write_remain < (int) (sizeof (struct logging_entry_header) + length))) {

		if (!flash_log->terminated &&
			(flash_log->write_remain >= (int) sizeof (struct logging_entry_header))) {
			logging_flash_write_header (flash_log, LOGGING_FLASH_TERMINATOR, 0);
			flash_log->terminated = true;
		}

		status = logging_flash_save_buffer (flash_log);
		if (status != 0) {
			platform_mutex_unlock (&flash_log->lock);
			return status;
		}
	}

	logging_flash_write_header (flash_log, length, flash_log->next_entry_id++);
	memcpy (flash_log->next_write, entry, length);
	flash_log->next_write += length;
	flash_log->write_remain -= length;

	platform_mutex_unlock (&flash_log->lock);

	return 0;
}

static int logging_flash_flush (struct logging *logging)
{
	struct logging_flash *flash_log = (struct logging_flash*) logging;
	int status;

	if (flash_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&flash_log->lock);
	status = logging_flash_save_buffer (flash_log);
	platform_mutex_unlock (&flash_log->lock);

	return status;
}

static int logging_flash_clear (struct logging *logging)
{
	struct logging_flash *flash_log = (struct logging_flash*) logging;
	int status;

	if (flash_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&flash_log->lock);

	status = spi_flash_block_erase (flash_log->flash, flash_log->base_addr);
	if (status != 0) {
		goto exit;
	}

	memset (flash_log->flash_used, 0, sizeof (flash_log->flash_used));
	flash_log->next_entry_id = 0;
	flash_log->log_start = 0;

	flash_log->next_addr = flash_log->base_addr;
	flash_log->next_write = flash_log->entry_buffer;
	flash_log->write_remain = sizeof (flash_log->entry_buffer);
	flash_log->terminated = false;

exit:
	platform_mutex_unlock (&flash_log->lock);
	return status;
}

static int logging_flash_get_size (struct logging *logging)
{
	struct logging_flash *flash_log = (struct logging_flash*) logging;
	int sector;
	int log_size = 0;

	if (flash_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&flash_log->lock);

	for (sector = 0; sector < LOGGING_FLASH_SECTORS; ++sector) {
		log_size += flash_log->flash_used[sector];
	}

	log_size += (flash_log->next_write - flash_log->entry_buffer);
	if (flash_log->terminated) {
		log_size -= sizeof (struct logging_entry_header);
	}

	platform_mutex_unlock (&flash_log->lock);

	return log_size;
}

static int logging_flash_read_contents (struct logging *logging, uint32_t offset, uint8_t *contents,
	size_t length)
{
	struct logging_flash *flash_log = (struct logging_flash*) logging;
	int bytes_read = 0;
	int i;
	int sectors;
	size_t read_len;
	uint32_t read_offset;
	int status;

	if ((flash_log == NULL) || (contents == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&flash_log->lock);

	i = flash_log->log_start;
	sectors = 0;

	while ((length != 0) && (sectors < LOGGING_FLASH_SECTORS) && (flash_log->flash_used[i] != 0)) {
		read_offset = (offset < flash_log->flash_used[i]) ? offset : flash_log->flash_used[i];
		read_len = (length < (flash_log->flash_used[i] - read_offset)) ?
			length : (flash_log->flash_used[i] - read_offset);

		if (read_len != 0) {
			status = spi_flash_read (flash_log->flash,
				flash_log->base_addr + (FLASH_SECTOR_SIZE * i) + read_offset, contents, read_len);
			if (status != 0) {
				platform_mutex_unlock (&flash_log->lock);
				return status;
			}
		}

		bytes_read += read_len;
		contents += read_len;
		length -= read_len;
		offset -= read_offset;

		i = (i + 1) % LOGGING_FLASH_SECTORS;
		sectors++;
	}

	/* After reading all data from flash, read buffered entries that haven't been flushed yet. */
	read_len = flash_log->next_write - flash_log->entry_buffer;
	if (flash_log->terminated) {
		read_len -= sizeof (struct logging_entry_header);
	}
	read_offset = (offset < read_len) ? offset : read_len;
	read_len = (length < (read_len - read_offset)) ? length : (read_len - read_offset);

	memcpy (contents, flash_log->entry_buffer + read_offset, read_len);
	bytes_read += read_len;

	platform_mutex_unlock (&flash_log->lock);

	return bytes_read;
}

/**
 * Initialize a log that uses flash for persistent storage.  Log entries already on flash will be
 * detected and maintained.
 *
 * The log will consume an entire flash erase block.
 *
 * @param logging The log to initialize.
 * @param flash The flash device where log entries are stored.
 * @param base_addr The starting address for log entries.  This must be aligned to the beginning of
 * an erase block.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_flash_init (struct logging_flash *logging, struct spi_flash *flash, uint32_t base_addr)
{
	int curr_sector_num;
	uint8_t *pos;
	uint8_t *end;
	uint32_t entry_id = 0;
	uint32_t prev_entry_id = 0;
	uint32_t flash_addr;
	int found_next = 0;
	int status;

	if ((logging == NULL) || (flash == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	if (FLASH_BLOCK_BASE (base_addr) != base_addr) {
		return LOGGING_STORAGE_NOT_ALIGNED;
	}

	memset (logging, 0, sizeof (struct logging_flash));

	flash_addr = base_addr;
	end = logging->entry_buffer + sizeof (logging->entry_buffer);

	for (curr_sector_num = 0; curr_sector_num < LOGGING_FLASH_SECTORS; ++curr_sector_num) {
		status = spi_flash_read (flash, base_addr + (FLASH_SECTOR_SIZE * curr_sector_num),
			logging->entry_buffer, sizeof (logging->entry_buffer));
		if (status != 0) {
			return status;
		}

		pos = logging->entry_buffer;
		while ((end - pos) >= (int) sizeof (struct logging_entry_header)) {
			struct logging_entry_header *header = (struct logging_entry_header*) pos;

			if (!LOGGING_IS_ENTRY_START (header->log_magic) ||
				(LOGGING_HEADER_FORMAT (header->log_magic) == 0xA)) {
				if (found_next == 0) {
					if (FLASH_SECTOR_OFFSET (flash_addr) == 0) {
						found_next = 1;
					}
					else {
						bool blank = true;

						while (pos != end) {
							if (*pos != 0xff) {
								blank = false;
								break;
							}

							pos++;
						}

						if (!blank) {
							flash_addr = FLASH_SECTOR_BASE (flash_addr) + FLASH_SECTOR_SIZE;
						}
						else {
							found_next = 1;
						}
					}
				}
				break;
			}
			else {
				int length = header->length & ~LOGGING_FLASH_TERMINATOR;

				if ((length > (end - pos)) ||
					(length < (int) sizeof (struct logging_entry_header))) {
					if (found_next == 0) {
						flash_addr = FLASH_SECTOR_BASE (flash_addr) + FLASH_SECTOR_SIZE;
					}
					break;
				}

				if (header->length & LOGGING_FLASH_TERMINATOR) {
					if (found_next == 0) {
						flash_addr = FLASH_SECTOR_BASE (flash_addr) + FLASH_SECTOR_SIZE;
					}
					break;
				}

				if (found_next < 2) {
					entry_id = header->entry_id + 1;

					if (prev_entry_id > entry_id) {
						entry_id = prev_entry_id;
						logging->log_start = curr_sector_num;
						found_next = 2;
					}
					else if (found_next == 0) {
						flash_addr += length;
						prev_entry_id = entry_id;
					}
				}

				logging->flash_used[curr_sector_num] += length;
				pos += length;
			}
		}

		if ((FLASH_SECTOR_SIZE - FLASH_SECTOR_OFFSET (flash_addr)) <
			sizeof (struct logging_entry_header)) {
			flash_addr = FLASH_SECTOR_BASE (flash_addr) + FLASH_SECTOR_SIZE;
		}
	}

	if (flash_addr >= (base_addr + LOGGING_FLASH_AREA_LEN)) {
		flash_addr = base_addr;
	}

	status = platform_mutex_init (&logging->lock);
	if (status != 0) {
		return status;
	}

	logging->flash = flash;
	logging->base_addr = base_addr;
	logging->next_addr = flash_addr;
	logging->next_entry_id = entry_id;
	logging->next_write = logging->entry_buffer;
	logging->write_remain = sizeof (logging->entry_buffer) - FLASH_SECTOR_OFFSET (flash_addr);

	logging->base.create_entry = logging_flash_create_entry;
	logging->base.flush = logging_flash_flush;
	logging->base.clear = logging_flash_clear;
	logging->base.get_size = logging_flash_get_size;
	logging->base.read_contents = logging_flash_read_contents;

	return 0;
}

/**
 * Release the resources used by a flash logger.  The contents on flash will remain.  Any entries
 * not already on flash will be lost.
 *
 * @param logging The log to release.
 */
void logging_flash_release (struct logging_flash *logging)
{
	if (logging) {
		platform_mutex_free (&logging->lock);
	}
}
