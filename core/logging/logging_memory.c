// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "logging_memory.h"
#include "common/buffer_util.h"
#include "common/unused.h"


int logging_memory_create_entry (const struct logging *logging, uint8_t *entry, size_t length)
{
	const struct logging_memory *mem_log = (const struct logging_memory*) logging;
	struct logging_entry_header header;

	if ((mem_log == NULL) || (entry == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	if (length != (mem_log->entry_size - sizeof (struct logging_entry_header))) {
		return LOGGING_BAD_ENTRY_LENGTH;
	}

	platform_mutex_lock (&mem_log->state->lock);

	header.log_magic = LOGGING_MAGIC_START;
	header.length = sizeof (header) + length;
	header.entry_id = mem_log->state->next_entry_id++;

	memcpy (&mem_log->log_buffer[mem_log->state->log_end], (uint8_t*) &header, sizeof (header));
	mem_log->state->log_end += sizeof (header);

	memcpy (&mem_log->log_buffer[mem_log->state->log_end], entry, length);
	mem_log->state->log_end += length;

	if (mem_log->state->log_end == mem_log->log_size) {
		mem_log->state->log_end = 0;
		mem_log->state->is_full = true;
	}
	if (mem_log->state->is_full) {
		mem_log->state->log_start = mem_log->state->log_end;
	}

	platform_mutex_unlock (&mem_log->state->lock);

	return 0;
}

#ifndef LOGGING_DISABLE_FLUSH
int logging_memory_flush (const struct logging *logging)
{
	UNUSED (logging);

	return 0;
}
#endif

int logging_memory_clear (const struct logging *logging)
{
	const struct logging_memory *mem_log = (const struct logging_memory*) logging;

	if (mem_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&mem_log->state->lock);

	mem_log->state->log_start = 0;
	mem_log->state->log_end = 0;
	mem_log->state->is_full = false;
	memset (mem_log->log_buffer, 0, mem_log->log_size);

	platform_mutex_unlock (&mem_log->state->lock);

	return 0;
}

int logging_memory_get_size (const struct logging *logging)
{
	const struct logging_memory *mem_log = (const struct logging_memory*) logging;
	int log_size = 0;

	if (mem_log == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&mem_log->state->lock);

	if ((mem_log->state->log_end != mem_log->state->log_start) || mem_log->state->is_full) {
		if (mem_log->state->log_end == mem_log->state->log_start) {
			log_size = mem_log->log_size;
		}
		else {
			log_size = mem_log->state->log_end;
		}
	}

	platform_mutex_unlock (&mem_log->state->lock);

	return log_size;
}

int logging_memory_read_contents (const struct logging *logging, uint32_t offset, uint8_t *contents,
	size_t length)
{
	const struct logging_memory *mem_log = (const struct logging_memory*) logging;
	size_t first_copy = 0;
	int bytes_read = 0;
	size_t copy_len;
	size_t copy_offset = offset;

	platform_mutex_lock (&mem_log->state->lock);

	if ((mem_log->state->log_end != mem_log->state->log_start) || mem_log->state->is_full) {
		if (mem_log->state->log_end == mem_log->state->log_start) {
			first_copy = buffer_copy (&mem_log->log_buffer[mem_log->state->log_start],
				mem_log->log_size - mem_log->state->log_start, &copy_offset, &length, contents);
		}

		copy_len = buffer_copy (mem_log->log_buffer, mem_log->state->log_end, &copy_offset, &length,
			&contents[first_copy]);
		bytes_read = first_copy + copy_len;
	}

	platform_mutex_unlock (&mem_log->state->lock);

	return bytes_read;
}

/**
 * Initialize a log that stores contents in volatile memory.  The memory for the log will by
 * dynamically allocated to the necessary size.
 *
 * @param logging The log to initialize.
 * @param state Variable context for the log.  This must be uninitialized.
 * @param entry_count The maximum number of entries the log should be able to hold.
 * @param entry_length The length of a single log entry.  This does not include the length of
 * standard logging overhead.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_memory_init (struct logging_memory *logging, struct logging_memory_state *state,
	size_t entry_count, size_t entry_length)
{
	size_t entry_size = entry_length + sizeof (struct logging_entry_header);
	size_t log_size = entry_size * entry_count;
	uint8_t *log_buffer;
	int status;

	if ((logging == NULL) || (state == NULL) || (entry_count == 0) || (entry_length == 0)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	log_buffer = platform_malloc (log_size);
	if (log_buffer == NULL) {
		return LOGGING_NO_MEMORY;
	}

	status = logging_memory_init_from_buffer (logging, state, log_buffer, log_size, entry_length);
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
 * @param state Variable context for the log.  This must be uninitialized.
 * @param log_buffer The buffer to use for log entries.
 * @param log_size Length of the provided log buffer.
 * @param entry_length The length of a single log entry.  This does not include the length of
 * standard logging overhead.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_memory_init_from_buffer (struct logging_memory *logging,
	struct logging_memory_state *state, uint8_t *log_buffer, size_t log_size, size_t entry_length)
{
	size_t entry_size = entry_length + sizeof (struct logging_entry_header);

	if ((logging == NULL) || (state == NULL) || (log_buffer == NULL) | (entry_length == 0)) {
		return LOGGING_INVALID_ARGUMENT;
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

	logging->state = state;

	return logging_memory_init_state (logging);
}

/**
 * Find the location in the buffer that contains the last entry and update the log state.
 *
 * @param logging The log to scan for entries.
 */
static void logging_memory_find_last_entry (const struct logging_memory *logging)
{
	struct logging_entry_header *header = (struct logging_entry_header*) logging->log_buffer;
	struct logging_entry_header *prev = NULL;

	while (!logging->state->is_full && (logging->state->log_end != logging->log_size) &&
		LOGGING_IS_ENTRY_START (header->log_magic)) {
		if (prev && (header->entry_id != logging->state->next_entry_id)) {
			logging->state->is_full = true;
			logging->state->log_start = logging->state->log_end;
		}
		else {
			prev = header;
			logging->state->next_entry_id = header->entry_id + 1;
			logging->state->log_end += logging->entry_size;
			header = (struct logging_entry_header*) &logging->log_buffer[logging->state->log_end];
		}
	}

	if (logging->state->log_end == logging->log_size) {
		logging->state->is_full = true;
		logging->state->log_end = 0;
	}
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
 * @param state Variable context for the log.  This must be uninitialized.
 * @param log_buffer The buffer to use for log entries.
 * @param log_size Length of the provided log buffer.
 * @param entry_length The length of a single log entry.  This does not include the length of
 * standard logging overhead.
 *
 * @return 0 if the log was successfully initialized or an error code.
 */
int logging_memory_init_append_existing (struct logging_memory *logging,
	struct logging_memory_state *state, uint8_t *log_buffer, size_t log_size, size_t entry_length)
{
	int status;

	status = logging_memory_init_from_buffer (logging, state, log_buffer, log_size, entry_length);
	if (status != 0) {
		return status;
	}

	logging_memory_find_last_entry (logging);

	return 0;
}

/**
 * Initialize the variable state for log in memory and allocate the log buffer.  The rest of the log
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.  But it cannot be used with
 * a constant instance.
 *
 * The log will be initialized in the same way as logging_memory_init.
 *
 * @param logging The log instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int logging_memory_init_dynamic_state (struct logging_memory *logging)
{
	int status;

	if ((logging == NULL) || (logging->state == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	logging->log_buffer = platform_malloc (logging->log_size);
	if (logging->log_buffer == NULL) {
		return LOGGING_NO_MEMORY;
	}

	status = logging_memory_init_state (logging);
	if (status == 0) {
		logging->alloc_buffer = true;
	}
	else {
		platform_free (logging->log_buffer);
		logging->log_buffer = NULL;
	}

	return status;
}

/**
 * Initialize only the variable state for log in memory.  The rest of the log instance is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * The log will be initialized in the same way as logging_memory_init_from_buffer.
 *
 * @param logging The log instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int logging_memory_init_state (const struct logging_memory *logging)
{
	if ((logging == NULL) || (logging->state == NULL) || (logging->log_buffer == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	if (logging->log_size < logging->entry_size) {
		return LOGGING_INSUFFICIENT_STORAGE;
	}

	memset (logging->state, 0, sizeof (struct logging_memory_state));

	return platform_mutex_init (&logging->state->lock);
}

/**
 * Initialize only the variable state for log in memory.  The rest of the log instance is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * The log will be initialized in the same way as logging_memory_init_append_existing.
 *
 * @param logging The log instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int logging_memory_init_state_append_existing (const struct logging_memory *logging)
{
	int status;

	status = logging_memory_init_state (logging);
	if (status != 0) {
		return status;
	}

	logging_memory_find_last_entry (logging);

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
		platform_mutex_free (&logging->state->lock);

		if (logging->alloc_buffer) {
			platform_free (logging->log_buffer);
		}
	}
}
