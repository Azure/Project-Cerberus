// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "logging_memory.h"
#include "common/buffer_util.h"
#include "common/unused.h"


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
		mem_log->is_full = true;
	}
	if (mem_log->is_full) {
		mem_log->log_start = mem_log->log_end;
	}

	platform_mutex_unlock (&mem_log->lock);

	return 0;
}

#ifndef LOGGING_DISABLE_FLUSH
static int logging_memory_flush (struct logging *logging)
{
	UNUSED (logging);

	return 0;
}
#endif

static int logging_memory_clear (struct logging *logging)
{
	struct logging_memory *mem_log = (struct logging_memory*) logging;

	if (mem_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&mem_log->lock);

	mem_log->log_start = 0;
	mem_log->log_end = 0;
	mem_log->is_full = false;

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

	if ((mem_log->log_end != mem_log->log_start) || mem_log->is_full) {
		if (mem_log->log_end == mem_log->log_start) {
			log_size = mem_log->log_size;
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
	size_t copy_offset = offset;

	platform_mutex_lock (&mem_log->lock);

	if ((mem_log->log_end != mem_log->log_start) || mem_log->is_full) {
		if (mem_log->log_end == mem_log->log_start) {
			first_copy = buffer_copy (&mem_log->log_buffer[mem_log->log_start],
				mem_log->log_size - mem_log->log_start, &copy_offset, &length, contents);
		}

		copy_len = buffer_copy (mem_log->log_buffer, mem_log->log_end, &copy_offset, &length,
			&contents[first_copy]);
		bytes_read = first_copy + copy_len;
	}

	platform_mutex_unlock (&mem_log->lock);

	return bytes_read;
}

/**
 * Initialize a log that stores contents in volatile memory.  The memory for the log will by
 * dynamically allocated to the necessary size.
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
	size_t log_size = entry_size * entry_count;
	uint8_t *log_buffer;
	int status;

	if ((logging == NULL) || (entry_count == 0) || (entry_length == 0)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	log_buffer = platform_malloc (log_size);
	if (log_buffer == NULL) {
		return LOGGING_NO_MEMORY;
	}

	status = logging_memory_init_from_buffer (logging, log_buffer, log_size, entry_length);
	if (status == 0) {
		logging->alloc_buffer = true;
	}
	else {
		platform_free (log_buffer);
	}

	return status;
}

/**
 * Initialize a log that stores contents in volatile memory.  The memory for the log will be
 * preallocated by the caller and not managed by the log instance.
 *
 * If the provided buffer is not aligned to the size of the entry, including the logging header,
 * the usable buffer will be truncated to generate this alignment.
 *
 * @param logging The log to initialize.
 * @param log_buffer The buffer to use for log entries.
 * @param log_size Length of the provided log buffer.
 * @param entry_length The length of a single log entry.  This does not include the length of
 * standard logging overhead.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_memory_init_from_buffer (struct logging_memory *logging, uint8_t *log_buffer,
	size_t log_size, size_t entry_length)
{
	size_t entry_size = entry_length + sizeof (struct logging_entry_header);

	if ((logging == NULL) || (log_buffer == NULL) | (entry_length == 0)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	if (log_size < entry_size) {
		return LOGGING_INSUFFICIENT_STORAGE;
	}

	memset (logging, 0, sizeof (struct logging_memory));

	/* Make sure the buffer is entry aligned. */
	logging->log_size = log_size - (log_size % entry_size);
	logging->log_buffer = log_buffer;
	logging->entry_size = entry_size;

	logging->base.create_entry = logging_memory_create_entry;
#ifndef LOGGING_DISABLE_FLUSH
	logging->base.flush = logging_memory_flush;
#endif
	logging->base.clear = logging_memory_clear;
	logging->base.get_size = logging_memory_get_size;
	logging->base.read_contents = logging_memory_read_contents;

	return platform_mutex_init (&logging->lock);
}

/**
 * Initialize a log that stores contents in volatile memory.  The memory for the log will already
 * exist and could contain entries.  New log entries will be appended to any existing entries.
 *
 * If the provided buffer is not aligned to the size of the entry, including the logging header,
 * the usable buffer will be truncated to generate this alignment.
 *
 * The buffer is scanned for the first entry location that does not contain a valid entry or that
 * has a discontinuity in entry IDs.  This will mark the current end of the log, and new entries
 * will be added starting at this location.  If this location contains a valid entry, it is assumed
 * that the log is full and the rest of the buffer also contains valid entries.  If this is not
 * guaranteed by the caller, reading the log could result in corrupt log entries.
 *
 * @param logging The log to initialize.
 * @param log_buffer The buffer to use for log entries.
 * @param log_size Length of the provided log buffer.
 * @param entry_length The length of a single log entry.  This does not include the length of
 * standard logging overhead.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_memory_init_append_existing (struct logging_memory *logging, uint8_t *log_buffer,
	size_t log_size, size_t entry_length)
{
	struct logging_entry_header *header = (struct logging_entry_header*) log_buffer;
	struct logging_entry_header *prev = NULL;
	int status;

	status = logging_memory_init_from_buffer (logging, log_buffer, log_size, entry_length);
	if (status != 0) {
		return status;
	}

	while (!logging->is_full && (logging->log_end != logging->log_size) &&
		LOGGING_IS_ENTRY_START (header->log_magic)) {
		if (prev && (header->entry_id != logging->next_entry_id)) {
			logging->is_full = true;
			logging->log_start = logging->log_end;
		}
		else {
			prev = header;
			logging->next_entry_id = header->entry_id + 1;
			logging->log_end += logging->entry_size;
			header = (struct logging_entry_header*) &log_buffer[logging->log_end];
		}
	}

	if (logging->log_end == logging->log_size) {
		logging->is_full = true;
		logging->log_end = 0;
	}

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

		if (logging->alloc_buffer) {
			platform_free (logging->log_buffer);
		}
	}
}
