// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "logging/logging_memory.h"
#include "logging/logging_memory_static.h"


TEST_SUITE_LABEL ("logging_memory");


/*******************
 * Test cases
 *******************/

static void logging_memory_test_init (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;

	TEST_START;

	status = logging_memory_init (&logging, &state, 32, 11);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, logging.base.create_entry);
#ifndef LOGGING_DISABLE_FLUSH
	CuAssertPtrNotNull (test, logging.base.flush);
#endif
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_init_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;

	TEST_START;

	status = logging_memory_init (NULL, &state, 32, 11);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init (&logging, NULL, 32, 11);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init (&logging, &state, 0, 11);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init (&logging, &state, 32, 0);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_init_from_buffer (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];

	TEST_START;

	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, logging.base.create_entry);
#ifndef LOGGING_DISABLE_FLUSH
	CuAssertPtrNotNull (test, logging.base.flush);
#endif
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_init_from_buffer_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];

	TEST_START;

	status = logging_memory_init_from_buffer (NULL, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_from_buffer (&logging, NULL, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_from_buffer (&logging, &state, NULL, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		0);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_init_from_buffer_too_small (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];

	TEST_START;

	status = logging_memory_init_from_buffer (&logging, &state, buffer, 0, entry_size);
	CuAssertIntEquals (test, LOGGING_INSUFFICIENT_STORAGE, status);

	status = logging_memory_init_from_buffer (&logging, &state, buffer, entry_size - 1, entry_size);
	CuAssertIntEquals (test, LOGGING_INSUFFICIENT_STORAGE, status);
}

static void logging_memory_test_init_append_existing (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, logging.base.create_entry);
#ifndef LOGGING_DISABLE_FLUSH
	CuAssertPtrNotNull (test, logging.base.flush);
#endif
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_init_append_existing_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	status = logging_memory_init_append_existing (NULL, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_append_existing (&logging, NULL, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_append_existing (&logging, &state, NULL, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		0);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_init_append_existing_too_small (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	status = logging_memory_init_append_existing (&logging, &state, buffer, 0, entry_size);
	CuAssertIntEquals (test, LOGGING_INSUFFICIENT_STORAGE, status);

	status = logging_memory_init_append_existing (&logging, &state, buffer, entry_size - 1,
		entry_size);
	CuAssertIntEquals (test, LOGGING_INSUFFICIENT_STORAGE, status);
}

static void logging_memory_test_dynamic_buffer_static_init (CuTest *test)
{
	struct logging_memory_state state;
	struct logging_memory logging = logging_memory_dynamic_buffer_static_init (&state, 32, 11);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, logging.base.create_entry);
#ifndef LOGGING_DISABLE_FLUSH
	CuAssertPtrNotNull (test, logging.base.flush);
#endif
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = logging_memory_init_dynamic_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_dynamic_buffer_static_init_null (CuTest *test)
{
	struct logging_memory logging = logging_memory_dynamic_buffer_static_init (NULL, 32, 11);
	int status;

	TEST_START;

	status = logging_memory_init_dynamic_state (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init_dynamic_state (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_static_init (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, logging.base.create_entry);
#ifndef LOGGING_DISABLE_FLUSH
	CuAssertPtrNotNull (test, logging.base.flush);
#endif
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_static_init_null (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	int status;

	TEST_START;

	status = logging_memory_init_state (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	logging.state = NULL;
	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	logging.state = &state;
	logging.log_buffer = NULL;
	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_static_init_buffer_too_small (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_size - 1,
		entry_size);
	int status;

	TEST_START;

	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_INSUFFICIENT_STORAGE, status);
}

static void logging_memory_test_static_init_append_existing (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	int status;

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	CuAssertPtrNotNull (test, logging.base.create_entry);
#ifndef LOGGING_DISABLE_FLUSH
	CuAssertPtrNotNull (test, logging.base.flush);
#endif
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = logging_memory_init_state_append_existing (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_static_init_append_existing_null (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	int status;

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	status = logging_memory_init_state_append_existing (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	logging.state = NULL;
	status = logging_memory_init_state_append_existing (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	logging.state = &state;
	logging.log_buffer = NULL;
	status = logging_memory_init_state_append_existing (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_static_init_append_existing_buffer_too_small (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_size - 1,
		entry_size);
	int status;

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	status = logging_memory_init_state_append_existing (&logging);
	CuAssertIntEquals (test, LOGGING_INSUFFICIENT_STORAGE, status);
}

static void logging_memory_test_release_null (CuTest *test)
{
	TEST_START;

	logging_memory_release (NULL);
}

static void logging_memory_test_get_size_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;

	TEST_START;

	status = logging_memory_init (&logging, &state, 32, 11);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_from_buffer (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (entry_data, buffer, sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_empty (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (entry_data, buffer, sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_multiple (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[3][entry_size];
	uint8_t entry_data[entry_len * 3];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < 3; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[0], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[1], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[2], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_full_log (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_log_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i != 0) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 1; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_log_wrap_from_buffer_not_entry_aligned (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t  buffer[entry_full + entry_size];
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i != 0) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	/* Beginning of the buffer has the last entry. */
	memcpy (buffer_expected, &entry_data[entry_full - entry_len], entry_len);
	memcpy (&buffer_expected[entry_len], entry_data, entry_full - entry_len);

	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 1; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_log_wrap_appending_existing_empty_not_entry_aligned (
	CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t  buffer[entry_full + entry_size];
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i != 0) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	/* Beginning of the buffer has the last entry. */
	memcpy (buffer_expected, &entry_data[entry_full - entry_len], entry_len);
	memcpy (&buffer_expected[entry_len], entry_data, entry_full - entry_len);

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 1; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_log_wrap_twice (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[(entry_count * 2) + 2][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < (entry_count * 2) + 2; i++) {
		memset (entry[i], i, entry_size);

		if (i > (entry_count + 1)) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count * 2) + 2; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_one_entry (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[3][entry_size];
	uint8_t entry_data[entry_len * 3];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	pos = entry_data;
	for (i = 0; i < 3; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	/* Initialize the buffer with a single entry. */
	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[0], entry_size);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);

	/* Append two more entries. */
	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[1], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[2], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (entry_data, buffer, sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_multiple_entries (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[6][entry_size];
	uint8_t entry_data[entry_len * 6];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	pos = entry_data;
	for (i = 0; i < 6; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	/* Initialize the buffer with multiple entries. */
	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[0], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[1], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[2], entry_size);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);

	/* Append two more entries. */
	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[3], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[4], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[5], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (entry_data, buffer, sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_full_log (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i == 0) {
			header = (struct logging_entry_header*) buffer;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;

			memcpy (&buffer[sizeof (struct logging_entry_header)], entry[i], entry_size);
		}
		else {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	memcpy (&buffer[entry_len], entry_data, entry_full - entry_len);

	/* Beginning of the buffer has the last entry. */
	memcpy (buffer_expected, &entry_data[entry_full - entry_len], entry_len);
	memcpy (&buffer_expected[entry_len], entry_data, entry_full - entry_len);

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[entry_count], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_full_log_not_entry_aligned (
	CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full + entry_size];
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer_expected));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i == 0) {
			header = (struct logging_entry_header*) buffer;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;

			memcpy (&buffer[sizeof (struct logging_entry_header)], entry[i], entry_size);
		}
		else {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	memcpy (&buffer[entry_len], entry_data, entry_full - entry_len);

	/* Beginning of the buffer has the last entry. */
	memcpy (buffer_expected, &entry_data[entry_full - entry_len], entry_len);
	memcpy (&buffer_expected[entry_len], entry_data, entry_full - entry_len);

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[entry_count], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_full_log_start_in_middle (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer_expected));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i == 0) {
			header = (struct logging_entry_header*) &buffer[entry_len * 4];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;

			memcpy (&buffer[(entry_len * 4) + sizeof (struct logging_entry_header)], entry[i],
				entry_size);
		}
		else {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	/* Put the first entry as the 5th entry, and wrap the last four entries to the beginning. */
	memcpy (&buffer[entry_len * 5], entry_data, entry_full - (entry_len * 4));
	memcpy (buffer, &entry_data[entry_len * (entry_count - 5)], entry_len * 4);

	/* Beginning of the buffer has the last entry. */
	memcpy (buffer_expected, buffer, entry_len * 4);
	memcpy (&buffer_expected[entry_len * 4], &entry_data[entry_full - entry_len], entry_len);
	memcpy (&buffer_expected[entry_len * 5], &buffer[entry_len * 5], entry_len * (entry_count - 5));

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[entry_count], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_append_existing_full_log_start_in_middle_max_entry_id (
	CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];
	uint32_t entry_id = 0xffffffff - (entry_count - 4);

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer_expected));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i == 0) {
			header = (struct logging_entry_header*) &buffer[entry_len * 10];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = entry_id++;

			memcpy (&buffer[(entry_len * 10) + sizeof (struct logging_entry_header)], entry[i],
				entry_size);
		}
		else {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = entry_id++;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	/* Put the first entry as the 5th entry, and wrap the last four entries to the beginning. */
	memcpy (&buffer[entry_len * 11], entry_data, entry_full - (entry_len * 10));
	memcpy (buffer, &entry_data[entry_len * (entry_count - 11)], entry_len * 10);

	/* Beginning of the buffer has the last entry. */
	memcpy (buffer_expected, buffer, entry_len * 10);
	memcpy (&buffer_expected[entry_len * 10], &entry_data[entry_full - entry_len], entry_len);
	memcpy (&buffer_expected[entry_len * 11], &buffer[entry_len * 11],
		entry_len * (entry_count - 11));

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[entry_count], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_dynamic_buffer_static_init (CuTest *test)
{
	struct logging_memory_state state;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	struct logging_memory logging = logging_memory_dynamic_buffer_static_init (&state, entry_count,
		entry_size);
	int status;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_dynamic_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_static_init (CuTest *test)
{
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (entry_data, buffer, sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_static_init_append_existing (CuTest *test)
{
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	uint8_t entry[3][entry_size];
	uint8_t entry_data[entry_len * 3];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	pos = entry_data;
	for (i = 0; i < 3; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	memcpy (buffer, entry_data, entry_len);

	status = logging_memory_init_state_append_existing (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[1], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[2], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (entry_data, buffer, sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;

	TEST_START;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (NULL, entry, entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.create_entry (&logging.base, NULL, entry_size);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_create_entry_bad_length (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;

	TEST_START;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size - 1);
	CuAssertIntEquals (test, LOGGING_BAD_ENTRY_LENGTH, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size + 1);
	CuAssertIntEquals (test, LOGGING_BAD_ENTRY_LENGTH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

#ifndef LOGGING_DISABLE_FLUSH
static void logging_memory_test_flush (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_flush_static_init (CuTest *test)
{
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_flush_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.flush (NULL);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}
#endif

static void logging_memory_test_read_contents_partial_read (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, entry_len * 3);
	CuAssertIntEquals (test, entry_len * 3, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_partial_read_with_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i != 0) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 1; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, entry_len * 3);
	CuAssertIntEquals (test, entry_len * 3, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_partial_read_across_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 3][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 3; i++) {
		memset (entry[i], i, entry_size);

		if (i > 2) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 3; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, entry_full - (entry_count * 3));
	CuAssertIntEquals (test, entry_full - (entry_count * 3), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_offset_read (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, entry_len * 3, output, sizeof (output));
	CuAssertIntEquals (test, entry_full - (entry_len * 3), status);

	status = testing_validate_array (&entry_data[entry_len * 3], output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_offset_read_with_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i != 0) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 1; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, entry_len * 3, output, sizeof (output));
	CuAssertIntEquals (test, entry_full - (entry_len * 3), status);

	status = testing_validate_array (&entry_data[entry_len * 3], output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_offset_across_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 3][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 3; i++) {
		memset (entry[i], i, entry_size);

		if (i > 2) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 3; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, entry_full - entry_len, output,
		sizeof (output));
	CuAssertIntEquals (test, entry_len, status);

	status = testing_validate_array (&entry_data[entry_full - entry_len], output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_offset_past_end (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[3][entry_size];
	uint8_t entry_data[entry_len * 3];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < 3; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 3; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, (entry_len * 3) + 1, output,
		sizeof (output));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_partial_read_with_offset (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count; i++) {
		memset (entry[i], i, entry_size);

		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, entry_len, output, entry_len * 3);
	CuAssertIntEquals (test, entry_len * 3, status);

	status = testing_validate_array (&entry_data[entry_len], output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_read_contents_partial_read_with_offset_across_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 5][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 5; i++) {
		memset (entry[i], i, entry_size);

		if (i > 4) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 5; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, entry_full - (entry_len * 3), output,
		entry_len);
	CuAssertIntEquals (test, entry_len, status);

	status = testing_validate_array (&entry_data[entry_full - (entry_len * 3)], output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear_from_buffer (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];
	uint8_t buffer[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0x55, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer_expected));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_from_buffer (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear_append_existing (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer_expected));

	pos = buffer;
	for (i = 0; i < entry_count ; i++) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (pos, i, entry_size);
		pos += entry_size;
	}

	status = logging_memory_init_append_existing (&logging, &state, buffer, sizeof (buffer),
		entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (buffer), status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear_log_wrap (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[entry_full];

	TEST_START;

	pos = entry_data;
	for (i = 0; i < entry_count + 1; i++) {
		memset (entry[i], i, entry_size);

		if (i != 0) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memcpy (pos, entry[i], entry_size);
			pos += entry_size;
		}
	}

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count + 1; i++) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear_add_after_clear (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];

	TEST_START;

	memset (entry, 0, sizeof (entry));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 1;
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data2), status);

	status = testing_validate_array (entry_data2, output, status);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear_static_init (CuTest *test)
{
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	const int entry_full = entry_len * entry_count;
	uint8_t buffer[entry_full];
	struct logging_memory logging = logging_memory_static_init (&state, buffer, entry_full,
		entry_size);
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	uint8_t output[entry_full];
	uint8_t buffer_expected[sizeof (buffer)];

	TEST_START;

	memset (buffer, 0x55, sizeof (buffer));
	memset (buffer_expected, 0, sizeof (buffer_expected));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (buffer_expected, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_clear_null (CuTest *test)
{
	struct logging_memory logging;
	struct logging_memory_state state;
	int status;
	const int entry_size = 11;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 32;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;

	TEST_START;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = logging_memory_init (&logging, &state, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = logging.base.clear (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	logging_memory_release (&logging);
}


TEST_SUITE_START (logging_memory);

TEST (logging_memory_test_init);
TEST (logging_memory_test_init_null);
TEST (logging_memory_test_init_from_buffer);
TEST (logging_memory_test_init_from_buffer_null);
TEST (logging_memory_test_init_from_buffer_too_small);
TEST (logging_memory_test_init_append_existing);
TEST (logging_memory_test_init_append_existing_null);
TEST (logging_memory_test_init_append_existing_too_small);
TEST (logging_memory_test_dynamic_buffer_static_init);
TEST (logging_memory_test_dynamic_buffer_static_init_null);
TEST (logging_memory_test_static_init);
TEST (logging_memory_test_static_init_null);
TEST (logging_memory_test_static_init_buffer_too_small);
TEST (logging_memory_test_static_init_append_existing);
TEST (logging_memory_test_static_init_append_existing_null);
TEST (logging_memory_test_static_init_append_existing_buffer_too_small);
TEST (logging_memory_test_release_null);
TEST (logging_memory_test_get_size_null);
TEST (logging_memory_test_create_entry);
TEST (logging_memory_test_create_entry_from_buffer);
TEST (logging_memory_test_create_entry_append_existing_empty);
TEST (logging_memory_test_create_entry_multiple);
TEST (logging_memory_test_create_entry_full_log);
TEST (logging_memory_test_create_entry_log_wrap);
TEST (logging_memory_test_create_entry_log_wrap_from_buffer_not_entry_aligned);
TEST (logging_memory_test_create_entry_log_wrap_appending_existing_empty_not_entry_aligned);
TEST (logging_memory_test_create_entry_log_wrap_twice);
TEST (logging_memory_test_create_entry_append_existing_one_entry);
TEST (logging_memory_test_create_entry_append_existing_multiple_entries);
TEST (logging_memory_test_create_entry_append_existing_full_log);
TEST (logging_memory_test_create_entry_append_existing_full_log_not_entry_aligned);
TEST (logging_memory_test_create_entry_append_existing_full_log_start_in_middle);
TEST (logging_memory_test_create_entry_append_existing_full_log_start_in_middle_max_entry_id);
TEST (logging_memory_test_create_entry_dynamic_buffer_static_init);
TEST (logging_memory_test_create_entry_static_init);
TEST (logging_memory_test_create_entry_static_init_append_existing);
TEST (logging_memory_test_create_entry_null);
TEST (logging_memory_test_create_entry_bad_length);
#ifndef LOGGING_DISABLE_FLUSH
TEST (logging_memory_test_flush);
TEST (logging_memory_test_flush_static_init);
TEST (logging_memory_test_flush_null);
#endif
TEST (logging_memory_test_read_contents_partial_read);
TEST (logging_memory_test_read_contents_partial_read_with_wrap);
TEST (logging_memory_test_read_contents_partial_read_across_wrap);
TEST (logging_memory_test_read_contents_offset_read);
TEST (logging_memory_test_read_contents_offset_read_with_wrap);
TEST (logging_memory_test_read_contents_offset_across_wrap);
TEST (logging_memory_test_read_contents_offset_past_end);
TEST (logging_memory_test_read_contents_partial_read_with_offset);
TEST (logging_memory_test_read_contents_partial_read_with_offset_across_wrap);
TEST (logging_memory_test_clear);
TEST (logging_memory_test_clear_from_buffer);
TEST (logging_memory_test_clear_append_existing);
TEST (logging_memory_test_clear_log_wrap);
TEST (logging_memory_test_clear_add_after_clear);
TEST (logging_memory_test_clear_static_init);
TEST (logging_memory_test_clear_null);

TEST_SUITE_END;
