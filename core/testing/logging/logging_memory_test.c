// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "logging/logging_memory.h"



TEST_SUITE_LABEL ("logging_memory");


/*******************
 * Test cases
 *******************/

static void logging_memory_test_init (CuTest *test)
{
	struct logging_memory logging;
	int status;

	TEST_START;

	status = logging_memory_init (&logging, 32, 11);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, logging.base.create_entry);
	CuAssertPtrNotNull (test, logging.base.flush);
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
	int status;

	TEST_START;

	status = logging_memory_init (NULL, 32, 11);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init (&logging, 0, 11);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_memory_init (&logging, 32, 0);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);
}

static void logging_memory_test_release_null (CuTest *test)
{
	TEST_START;

	logging_memory_release (NULL);
}

static void logging_memory_test_get_size_null (CuTest *test)
{
	struct logging_memory logging;
	int status;

	TEST_START;

	status = logging_memory_init (&logging, 32, 11);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

static void logging_memory_test_create_entry_multiple (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

static void logging_memory_test_create_entry_log_wrap_twice (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

static void logging_memory_test_create_entry_null (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size - 1);
	CuAssertIntEquals (test, LOGGING_BAD_ENTRY_LENGTH, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size + 1);
	CuAssertIntEquals (test, LOGGING_BAD_ENTRY_LENGTH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	logging_memory_release (&logging);
}

static void logging_memory_test_flush (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

static void logging_memory_test_read_contents_partial_read (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

static void logging_memory_test_clear_log_wrap (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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

static void logging_memory_test_clear_null (CuTest *test)
{
	struct logging_memory logging;
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

	status = logging_memory_init (&logging, entry_count, entry_size);
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
TEST (logging_memory_test_release_null);
TEST (logging_memory_test_get_size_null);
TEST (logging_memory_test_create_entry);
TEST (logging_memory_test_create_entry_multiple);
TEST (logging_memory_test_create_entry_full_log);
TEST (logging_memory_test_create_entry_null);
TEST (logging_memory_test_create_entry_bad_length);
TEST (logging_memory_test_create_entry_log_wrap);
TEST (logging_memory_test_create_entry_log_wrap_twice);
TEST (logging_memory_test_flush);
TEST (logging_memory_test_flush_null);
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
TEST (logging_memory_test_clear_log_wrap);
TEST (logging_memory_test_clear_add_after_clear);
TEST (logging_memory_test_clear_null);

TEST_SUITE_END;
