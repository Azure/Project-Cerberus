// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "logging_memory.h"


static int logging_memory_create_entry (struct logging *logging, uint8_t *entry, size_t length)
{
	struct logging_memory *mem_log = (struct logging_memory*) logging;
	struct logging_entry_header header;

	if ((mem_log == NULL) || (entry == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	if (length != (mem_log->entry_size - sizeof (struct logging_entry_header))) {
		return LOGGING_BAD_ENTRY_LENGTH;
	}

	platform_mutex_lock (&mem_log->lock);

	header.log_magic = LOGGING_MAGIC_START;
	header.length = sizeof (header) + length;
	header.entry_id = mem_log->next_entry_id++;

	memcpy (&mem_log->log_buffer[mem_log->log_end], (uint8_t*) &header, sizeof (header));
	mem_log->log_end += sizeof (header);

	memcpy (&mem_log->log_buffer[mem_log->log_end], entry, length);
	mem_log->log_end += length;

	if (mem_log->log_end == mem_log->log_size) {
		mem_log->log_end = 0;
	}
	if (mem_log->log_end == mem_log->log_start) {
		mem_log->log_start = mem_log->log_start + mem_log->entry_size;
		if (mem_log->log_start == mem_log->log_size) {
			mem_log->log_start = 0;
		}
	}

	platform_mutex_unlock (&mem_log->lock);

	return 0;
}

static int logging_memory_flush (struct logging *logging)
{
	return 0;
}

static int logging_memory_clear (struct logging *logging)
{
	struct logging_memory *mem_log = (struct logging_memory*) logging;

	if (mem_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&mem_log->lock);

	mem_log->log_start = 0;
	mem_log->log_end = 0;
	mem_log->next_entry_id = 0;

	platform_mutex_unlock (&mem_log->lock);

	return 0;
}

static int logging_memory_get_size (struct logging *logging)
{
	struct logging_memory *mem_log = (struct logging_memory*) logging;
	int log_size = 0;

	if (mem_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&mem_log->lock);

	if (mem_log->log_end != mem_log->log_start) {
		if (mem_log->log_end < mem_log->log_start) {
			log_size = mem_log->log_size - mem_log->entry_size;
		}
		else {
			log_size = mem_log->log_end;
		}
	}

	platform_mutex_unlock (&mem_log->lock);

	return log_size;
}

static int logging_memory_read_contents (struct logging *logging, uint32_t offset,
	uint8_t *contents, size_t length)
{
	struct logging_memory *mem_log = (struct logging_memory*) logging;
	size_t first_copy = 0;
	int bytes_read = 0;
	size_t copy_len;
	size_t copy_offset;

	platform_mutex_lock (&mem_log->lock);

	if (mem_log->log_end != mem_log->log_start) {
		if (mem_log->log_end < mem_log->log_start) {
			first_copy = mem_log->log_size - mem_log->log_start;

			copy_offset = (offset < first_copy) ? offset : first_copy;
			first_copy = (length < (first_copy - copy_offset)) ?
				length : (first_copy - copy_offset);

			memcpy (contents, &mem_log->log_buffer[mem_log->log_start + copy_offset], first_copy);
			length -= first_copy;
			offset -= copy_offset;
		}

		copy_offset = (offset < mem_log->log_end) ? offset : mem_log->log_end;
		copy_len = (length < (mem_log->log_end - copy_offset)) ?
			length : (mem_log->log_end - copy_offset);

		memcpy (&contents[first_copy], mem_log->log_buffer + copy_offset, copy_len);
		bytes_read = first_copy + copy_len;
	}

	platform_mutex_unlock (&mem_log->lock);

	return bytes_read;
}

/**
 * Initialize a log that store contents in volatile memory.
 *
 * @param logging The log to initialize.
 * @param entry_count The maximum number of entries the log should be able to hold.
 * @param entry_length The length of a single log entry.  This does not include the length of
 * standard logging overhead.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_memory_init (struct logging_memory *logging, size_t entry_count, size_t entry_length)
{
	size_t entry_size = entry_length + sizeof (struct logging_entry_header);
	size_t log_size = entry_size * (entry_count + 1);
	int status;

	if ((logging == NULL) || (entry_count == 0) || (entry_length == 0)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	memset (logging, 0, sizeof (struct logging_memory));

	logging->log_buffer = platform_malloc (log_size);
	if (logging->log_buffer == NULL) {
		return LOGGING_NO_MEMORY;
	}

	status = platform_mutex_init (&logging->lock);
	if (status != 0) {
		platform_free (logging->log_buffer);
		return status;
	}

	logging->entry_size = entry_size;
	logging->log_size = log_size;

	logging->base.create_entry = logging_memory_create_entry;
	logging->base.flush = logging_memory_flush;
	logging->base.clear = logging_memory_clear;
	logging->base.get_size = logging_memory_get_size;
	logging->base.read_contents = logging_memory_read_contents;

	return 0;
}

/**
 * Release the resources used by a log in memory.
 *
 * @param logging The log to release.
 */
void logging_memory_release (struct logging_memory *logging)
{
	if (logging) {
		platform_mutex_free (&logging->lock);
		platform_free (logging->log_buffer);
	}
}
