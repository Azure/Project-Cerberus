// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "logging/logging_flash.h"
#include "logging/logging_flash_static.h"
#include "testing/mock/flash/flash_master_mock.h"


TEST_SUITE_LABEL ("logging_flash");


/**
 * Header for log entries marked with 0xCA.
 */
struct logging_entry_header_ca {
	uint8_t log_magic;
	uint32_t entry_id;
} __attribute__ ((__packed__));


/*******************
 * Test cases
 *******************/

static void logging_flash_test_init_empty (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
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

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_first_sector_partial (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_first_sector_partial_different_lengths (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) &log_partial[10 + sizeof (struct logging_entry_header)];
	entry->log_magic = 0xCB;
	entry->length = 6 + sizeof (struct logging_entry_header);
	entry->entry_id = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + 6 + (2 * sizeof (struct logging_entry_header))), status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_first_sector_full_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_first_sector_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_first_sector_full_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_first_sector_full_unused_bytes_terminator_large (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_second_sector_partial_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_second_sector_partial_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_second_sector_partial_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_second_sector_partial_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_unused_bytes_terminator_large (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_overwrite_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_overwrite_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_overwrite_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_full_overwrite_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_partial_overwrite_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_partial_overwrite_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_partial_overwrite_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_all_sectors_partial_overwrite_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_ca_entry (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header_ca *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header_ca*) log_partial;
	entry->log_magic = 0xCA;
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_valid_entry_unknown_format (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 16 - 2; // Exclude 0xCA and 0xCB.
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t marker;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0, marker = 0xCC; marker != 0xCA; ++i, marker = ((marker + 1) & 0xCF)) {
		entry = (struct logging_entry_header*) &log_partial[i * entry_len];
		entry->log_magic = marker;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len * entry_count, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_no_valid_entry_markers (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	int i;
	int j;

	TEST_START;

	for (i = 0, j = 0; i < LOGGING_FLASH_SECTORS; ++i, j += 0x10) {
		if (j != 0xC0) {
			memset (log_full[i], j, FLASH_SECTOR_SIZE);
		}
		else {
			memset (log_full[i], 0xff, FLASH_SECTOR_SIZE);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_entry_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t log_partial2[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));
	memset (log_partial2, 0xff, sizeof (log_partial2));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = FLASH_SECTOR_SIZE + 1;
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) log_partial2;
	entry->log_magic = 0xCB;
	entry->length = sizeof (struct logging_entry_header) - 1;
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial2, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_partial_entry_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) &log_partial[0];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) &log_partial[1 * entry_len];
	entry->log_magic = 0xCB;
	entry->length = FLASH_SECTOR_SIZE - entry_len + 1;
	entry->entry_id = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_terminator_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t log_partial2[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));
	memset (log_partial2, 0xff, sizeof (log_partial2));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 0x8000 | (FLASH_SECTOR_SIZE + 1);
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) log_partial2;
	entry->log_magic = 0xCB;
	entry->length = 0x8000 | (sizeof (struct logging_entry_header) - 1);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial2, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_partial_terminator_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) &log_partial[0];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) &log_partial[1 * entry_len];
	entry->log_magic = 0xCB;
	entry->length = 0x8000 | (FLASH_SECTOR_SIZE - entry_len + 1);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_partial_unused_not_blank (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0x00, sizeof (log_partial));

	entry = (struct logging_entry_header*) &log_partial[0];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (NULL, &state, &flash, 0x10000);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_flash_init (&logging, NULL, &flash, 0x10000);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging_flash_init (&logging, &state, NULL, 0x10000);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_not_block_aligned (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10020);
	CuAssertIntEquals (test, LOGGING_STORAGE_NOT_ALIGNED, status);

	status = logging_flash_init (&logging, &state, &flash, 0x11000);
	CuAssertIntEquals (test, LOGGING_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void logging_flash_test_init_flash_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_empty (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	CuAssertPtrNotNull (test, logging.base.create_entry);
	CuAssertPtrNotNull (test, logging.base.flush);
	CuAssertPtrNotNull (test, logging.base.clear);
	CuAssertPtrNotNull (test, logging.base.get_size);
	CuAssertPtrNotNull (test, logging.base.read_contents);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_first_sector_partial (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_first_sector_partial_different_lengths (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) &log_partial[10 + sizeof (struct logging_entry_header)];
	entry->log_magic = 0xCB;
	entry->length = 6 + sizeof (struct logging_entry_header);
	entry->entry_id = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + 6 + (2 * sizeof (struct logging_entry_header))), status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_first_sector_full_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_first_sector_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_first_sector_full_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_first_sector_full_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_second_sector_partial_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_second_sector_partial_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_second_sector_partial_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_second_sector_partial_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_overwrite_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_overwrite_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_overwrite_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_full_overwrite_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_partial_overwrite_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_partial_overwrite_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_partial_overwrite_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_all_sectors_partial_overwrite_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < (entry_count + 1); ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_ca_entry (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header_ca *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header_ca*) log_partial;
	entry->log_magic = 0xCA;
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_valid_entry_unknown_format (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = 16 - 2; // Exclude 0xCA and 0xCB.
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t marker;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0, marker = 0xCC; marker != 0xCA; ++i, marker = ((marker + 1) & 0xCF)) {
		entry = (struct logging_entry_header*) &log_partial[i * entry_len];
		entry->log_magic = marker;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len * entry_count, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_no_valid_entry_markers (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	int i;
	int j;

	TEST_START;

	for (i = 0, j = 0; i < LOGGING_FLASH_SECTORS; ++i, j += 0x10) {
		if (j != 0xC0) {
			memset (log_full[i], j, FLASH_SECTOR_SIZE);
		}
		else {
			memset (log_full[i], 0xff, FLASH_SECTOR_SIZE);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_entry_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t log_partial2[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));
	memset (log_partial2, 0xff, sizeof (log_partial2));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = FLASH_SECTOR_SIZE + 1;
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) log_partial2;
	entry->log_magic = 0xCB;
	entry->length = sizeof (struct logging_entry_header) - 1;
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial2, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_partial_entry_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) &log_partial[0];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) &log_partial[1 * entry_len];
	entry->log_magic = 0xCB;
	entry->length = FLASH_SECTOR_SIZE - entry_len + 1;
	entry->entry_id = 1;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_terminator_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t log_partial2[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));
	memset (log_partial2, 0xff, sizeof (log_partial2));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 0x8000 | (FLASH_SECTOR_SIZE + 1);
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) log_partial2;
	entry->log_magic = 0xCB;
	entry->length = 0x8000 | (sizeof (struct logging_entry_header) - 1);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial2, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_partial_terminator_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) &log_partial[0];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = 0;

	entry = (struct logging_entry_header*) &log_partial[1 * entry_len];
	entry->log_magic = 0xCB;
	entry->length = 0x8000 | (FLASH_SECTOR_SIZE - entry_len + 1);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_partial_unused_not_blank (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0x00, sizeof (log_partial));

	entry = (struct logging_entry_header*) &log_partial[0];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	logging.state = NULL;
	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	logging.state = &state;
	logging.flash = NULL;
	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_not_block_aligned (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10020);
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_STORAGE_NOT_ALIGNED, status);

	logging.base_addr = 0x11000;
	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, LOGGING_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void logging_flash_test_static_init_flash_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void logging_flash_test_release_null (CuTest *test)
{
	TEST_START;

	logging_flash_release (NULL);
}

static void logging_flash_test_get_size_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_multiple (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[3][5] = {
		{0, 1, 2, 3, 4},
		{5, 6, 7, 8, 9},
		{10, 11, 12, 13, 14}};
	uint8_t entry_data[sizeof (entry) + (3 * sizeof (struct logging_entry_header))];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < 3; ++i, pos += sizeof (entry[0])) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = sizeof (entry[0]) + sizeof (struct logging_entry_header);
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], sizeof (entry[0]));
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[0], sizeof (entry[0]));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (sizeof (entry_data) / 3) * 1, status);

	status = logging.base.create_entry (&logging.base, entry[1], sizeof (entry[1]));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (sizeof (entry_data) / 3) * 2, status);

	status = logging.base.create_entry (&logging.base, entry[2], sizeof (entry[2]));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_multiple_different_lengths (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[3][7] = {
		{0, 1, 2, 3, 4},
		{5, 6, 7},
		{8, 9, 10, 11, 12, 13, 14}};
	const uint8_t entry_size[3] = {5, 3, 7};
	uint8_t entry_data[entry_size[0] + entry_size[1] + entry_size[2] +
		(3 * sizeof (struct logging_entry_header))];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < 3; ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_size[i] + sizeof (struct logging_entry_header);
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memcpy (pos, entry[i], entry_size[i]);
		pos += entry_size[i];
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[0], entry_size[0]);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_size[0] + sizeof (struct logging_entry_header), status);

	status = logging.base.create_entry (&logging.base, entry[1], entry_size[1]);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test,
		entry_size[0] + entry_size[1] + (sizeof (struct logging_entry_header) * 2), status);

	status = logging.base.create_entry (&logging.base, entry[2], entry_size[2]);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_sector_partial_full (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;
	int start_len = sizeof (entry) + sizeof (struct logging_entry_header);

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = start_len;
	header->entry_id = 0;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 1;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + start_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_second_sector_partial_all_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *header;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	int i;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
	}

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i++;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x11000 + entry_len, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_second_sector_partial_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *header;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
	}

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i++;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x11000 + entry_len, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_second_sector_partial_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *header;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i++;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x11000 + entry_len, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);
	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_second_sector_partial_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *header;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	int i;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i++;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x11000 + entry_len, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + (entry_len * 2), status);
	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_fill_partial_buffer_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	int start_len = entry_len;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;

	pos = entry_data;
	for (i = 0; i < entry_count - 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + 1;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count - 1; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + start_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_fill_partial_buffer_flush_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	int start_len = entry_len;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;

	pos = entry_data;
	for (i = 0; i < entry_count - 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + 1;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count - 1; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + start_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_fill_partial_buffer_flush_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[(entry_len * (entry_count - 1)) + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	int start_len = entry_len;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != (entry_count - 1)) {
			header->length = entry_len;
			header->entry_id = i + 1;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count - 1; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + start_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_fill_partial_buffer_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[(entry_len * (entry_count - 1)) + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	int start_len = entry_len;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != (entry_count - 1)) {
			header->length = entry_len;
			header->entry_id = i + 1;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count - 1; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + start_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_all_sectors_full (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_all_sectors_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_all_sectors_full_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_all_sectors_full_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_overwrite_middle (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_overwrite_middle_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_overwrite_middle_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_overwrite_middle_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_partial_overwrite_middle (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) &log_full[j];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count) + 1;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x17000 + entry_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_partial_overwrite_middle_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) &log_full[j];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count) + 1;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x17000 + entry_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_partial_overwrite_middle_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) &log_full[j];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count) + 1;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x17000 + entry_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}
static void logging_flash_test_create_entry_full_partial_overwrite_middle_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) &log_full[j];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count) + 1;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x17000 + entry_len, entry_data,
		sizeof (entry_data));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_after_partial_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_len * (entry_count / 2)];
	uint8_t entry_data2[entry_full - sizeof (entry_data)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);

		if (i == (entry_count / 2) - 1) {
			pos = entry_data2;
		}
		else {
			pos += entry_size;
		}
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count / 2; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	for (; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + sizeof (entry_data),
		entry_data2, sizeof (entry_data2));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_after_partial_flush_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_len * (entry_count / 2)];
	uint8_t entry_data2[entry_full - sizeof (entry_data)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);

		if (i == (entry_count / 2) - 1) {
			pos = entry_data2;
		}
		else {
			pos += entry_size;
		}
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count / 2; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	for (; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + sizeof (entry_data),
		entry_data2, sizeof (entry_data2));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_after_partial_flush_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_len * (entry_count / 2)];
	uint8_t entry_data2[entry_full - sizeof (entry_data) + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);

			if (i == (entry_count / 2) - 1) {
				pos = entry_data2;
			}
			else {
				pos += entry_size;
			}
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count / 2; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	for (; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + sizeof (entry_data),
		entry_data2, sizeof (entry_data2));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_after_partial_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_len * (entry_count / 2)];
	uint8_t entry_data2[entry_full - sizeof (entry_data) + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);

			if (i == (entry_count / 2) - 1) {
				pos = entry_data2;
			}
			else {
				pos += entry_size;
			}
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count / 2; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	for (; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + sizeof (entry_data),
		entry_data2, sizeof (entry_data2));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_multiple (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2) + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_full];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < (entry_count * 2); ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);

		if (i == (entry_count - 1)) {
			pos = entry_data2;
		}
		else {
			pos += entry_size;
		}
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	for (; i < (entry_count * 2); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full * 2, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x12000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x12000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_multiple_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2) + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_full];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < (entry_count * 2); ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);

		if (i == (entry_count - 1)) {
			pos = entry_data2;
		}
		else {
			pos += entry_size;
		}
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	for (; i < (entry_count * 2); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full * 2, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x12000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x12000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_multiple_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2) + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0; j < 2; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
				pos += sizeof (struct logging_entry_header);

				memset (entry[i + (j * entry_count)], i + (j * entry_count), entry_size);
				memcpy (pos, entry[i + (j * entry_count)], entry_size);

				pos += entry_size;
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}

		pos = entry_data2;
	}

	i = entry_count * 2;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	for (; i < (entry_count * 2); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full * 2, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x12000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x12000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_multiple_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2) + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0; j < 2; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) pos;
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
				pos += sizeof (struct logging_entry_header);

				memset (entry[i + (j * entry_count)], i + (j * entry_count), entry_size);
				memcpy (pos, entry[i + (j * entry_count)], entry_size);

				pos += entry_size;
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}

		pos = entry_data2;
	}

	i = entry_count * 2;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	for (; i < (entry_count * 2); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full * 2, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x12000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x12000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_wrap_to_start (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[LOGGING_FLASH_SECTORS - 1][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < (LOGGING_FLASH_SECTORS - 1); ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	j = header->entry_id + 1;
	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = j + i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = j + i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 15; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x1f000, 0, -1, FLASH_SECTOR_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x1f000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x1f000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_wrap_to_start_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[LOGGING_FLASH_SECTORS - 1][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < (LOGGING_FLASH_SECTORS - 1); ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	j = header->entry_id + 1;
	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = j + i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = j + i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 15; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x1f000, 0, -1, FLASH_SECTOR_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x1f000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x1f000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_wrap_to_start_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[LOGGING_FLASH_SECTORS - 1][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < (LOGGING_FLASH_SECTORS - 1); ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	j = (LOGGING_FLASH_SECTORS - 1) * entry_count;
	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = j + i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = j + i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 15; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x1f000, 0, -1, FLASH_SECTOR_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x1f000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x1f000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_wrap_to_start_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[LOGGING_FLASH_SECTORS - 1][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < (LOGGING_FLASH_SECTORS - 1); ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	j = (LOGGING_FLASH_SECTORS - 1) * entry_count;
	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = j + i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = j + i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 15; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x1f000, 0, -1, FLASH_SECTOR_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x1f000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x1f000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data2), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data2), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_init_with_entry_too_long (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	j = 0;
	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[j][i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
	}

	j = 1;
	header = (struct logging_entry_header*) log_full[j];
	header->log_magic = 0xCB;
	header->length = FLASH_SECTOR_SIZE + 1;
	header->entry_id = (j * entry_count);

	for (j = 2; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_init_with_entry_too_short (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	j = 0;
	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[j][i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
	}

	j = 1;
	header = (struct logging_entry_header*) log_full[j];
	header->log_magic = 0xCB;
	header->length = sizeof (struct logging_entry_header) - 1;
	header->entry_id = (j * entry_count);

	for (j = 2; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_init_with_terminator_too_long (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	j = 0;
	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[j][i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
	}

	j = 1;
	header = (struct logging_entry_header*) log_full[j];
	header->log_magic = 0xCB;
	header->length = 0x8000 | (FLASH_SECTOR_SIZE + 1);
	header->entry_id = 0;

	for (j = 2; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_init_with_terminator_too_short (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	j = 0;
	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[j][i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
	}

	j = 1;
	header = (struct logging_entry_header*) log_full[j];
	header->log_magic = 0xCB;
	header->length = 0x8000 | (sizeof (struct logging_entry_header) - 1);
	header->entry_id = 0;

	for (j = 2; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = LOGGING_FLASH_SECTORS * entry_count;
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - (entry_full * 2) + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_sector_unused_not_blank (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;
	int start_len = sizeof (entry) + sizeof (struct logging_entry_header);

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = start_len;
	header->entry_id = 0;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 1;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_sector_unused_partially_not_blank (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;
	int start_len = sizeof (entry) + sizeof (struct logging_entry_header);

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	header = (struct logging_entry_header*) log_partial;
	header->log_magic = 0xCB;
	header->length = start_len;
	header->entry_id = 0;

	log_partial[FLASH_SECTOR_SIZE - 1] = 0;

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 1;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, start_len + sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_first_sector_not_valid (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_bad[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	const int entry_len = sizeof (entry) + sizeof (struct logging_entry_header);
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_bad, 0, sizeof (log_bad));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_bad, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_static_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (NULL, entry, sizeof (entry));
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.create_entry (&logging.base, NULL, sizeof (entry));
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_bad_length (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, 0);
	CuAssertIntEquals (test, LOGGING_BAD_ENTRY_LENGTH, status);

	status = logging.base.create_entry (&logging.base, entry,
		FLASH_SECTOR_SIZE - sizeof (struct logging_entry_header) + 1);
	CuAssertIntEquals (test, LOGGING_BAD_ENTRY_LENGTH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_flush_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	int i;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	for (i = 0; i < entry_count; ++i) {
		memset (entry[i], i, entry_size);
	}

	memset (entry[i], i, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_after_incomplete_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_after_incomplete_flush_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_after_incomplete_flush_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_after_incomplete_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_no_data (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	/* Make sure the lock has been released. */
	logging.base.get_size (&logging.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_erase_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCA;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_write_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCA;
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_incomplete_write (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_incomplete_write_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_incomplete_write_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_incomplete_write_unused_bytes_terminator_large (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_after_incomplete_write (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_after_incomplete_write_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_after_incomplete_write_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_flush_after_incomplete_write_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_write (&flash_mock, 0x10000 + FLASH_PAGE_SIZE,
		&entry_data[FLASH_PAGE_SIZE], sizeof (entry_data) - FLASH_PAGE_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 10 + sizeof (struct logging_entry_header)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 10 + sizeof (struct logging_entry_header), status);

	status = testing_validate_array (log_partial, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_empty (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_buffered_entry_only (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_first_sector_full (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_full, status);

	status = testing_validate_array (log_full, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_first_sector_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_full, status);

	status = testing_validate_array (log_full, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_first_sector_full_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_full, status);

	status = testing_validate_array (log_full, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_first_sector_full_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_full, status);

	status = testing_validate_array (log_full, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_second_sector_partial (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	memcpy (expected, log_full, entry_full);
	memcpy (&expected[entry_full], log_partial, entry_len);
	expected_len = entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_second_sector_partial_usused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	memcpy (expected, log_full, entry_full);
	memcpy (&expected[entry_full], log_partial, entry_len);
	expected_len = entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_second_sector_partial_usused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	i--;
	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	memcpy (expected, log_full, entry_full);
	memcpy (&expected[entry_full], log_partial, entry_len);
	expected_len = entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_second_sector_partial_usused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));
	memset (log_partial, 0xff, sizeof (log_partial));

	for (i = 0; i < entry_count + 1; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		if (i != entry_count) {
			entry->length = entry_len;
			entry->entry_id = i;
		}
		else {
			entry->length = 0x8000 | sizeof (struct logging_entry_header);
			entry->entry_id = 0;
		}
	}

	i--;
	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = i;

	memcpy (expected, log_full, entry_full);
	memcpy (&expected[entry_full], log_partial, entry_len);
	expected_len = entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + FLASH_SECTOR_SIZE, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_overwrite (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_overwrite_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_overwrite_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_full_overwrite_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_partial_overwrite (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 7; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], log_full[i], entry_len);
	expected_len = full_size - entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 7; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[7], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x17000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_partial_overwrite_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 7; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], log_full[i], entry_len);
	expected_len = full_size - entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 7; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[7], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x17000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_partial_overwrite_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 7; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], log_full[i], entry_len);
	expected_len = full_size - entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 7; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[7], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x17000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_all_sectors_partial_overwrite_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 7; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	entry = (struct logging_entry_header*) &log_full[j];
	entry->log_magic = 0xCB;
	entry->length = entry_len;
	entry->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (7 * entry_count);

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			if (i != entry_count) {
				entry->length = entry_len;
				entry->entry_id = i + (j * entry_count);
			}
			else {
				entry->length = 0x8000 | sizeof (struct logging_entry_header);
				entry->entry_id = 0;
			}
		}
	}

	for (j = 0, i = 8; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 7; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], log_full[i], entry_len);
	expected_len = full_size - entry_full + entry_len;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + entry_len, status);

	status = 0;
	for (i = 8; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 7; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[7], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x17000, 0, -1, entry_len));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_after_erase_new_middle_sector (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	for (j = 0, i = 9; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], entry_data, sizeof (entry_data));
	expected_len = full_size - entry_full + sizeof (entry_data);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 9; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x18000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_after_erase_new_middle_sector_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	for (j = 0, i = 9; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], entry_data, sizeof (entry_data));
	expected_len = full_size - entry_full + sizeof (entry_data);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 9; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x18000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_after_erase_new_middle_sector_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	for (j = 0, i = 9; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], entry_data, sizeof (entry_data));
	expected_len = full_size - entry_full + sizeof (entry_data);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 9; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x18000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_after_erase_new_middle_sector_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + (8 * entry_count);
	memset (entry, i, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	for (j = 0, i = 9; i < LOGGING_FLASH_SECTORS; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	for (i = 0; i < 8; ++j, ++i) {
		memcpy (&expected[entry_full * j], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * j], entry_data, sizeof (entry_data));
	expected_len = full_size - entry_full + sizeof (entry_data);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x18000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x18000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full + sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 9; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}
	for (i = 0; i < 8; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x18000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_partial_read (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	expected_len = (entry_full * 2) + (entry_len * 3);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 2; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, (entry_len * 3)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, expected_len);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_partial_read_buffered_entries (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, entry_len * 3);
	CuAssertIntEquals (test, entry_len * 3, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_offset_read_in_first_sector (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	memcpy (expected, &log_full[0][entry_full - (entry_len * 3)], entry_len * 3);
	for (i = 1; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[(entry_len * 3) + (entry_full * (i - 1))], log_full[i], entry_full);
	}
	expected_len = full_size - entry_full + (entry_len * 3);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		&log_full[0][entry_full - (entry_len * 3)], entry_len * 3,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + (entry_full - (entry_len * 3)), 0, -1, entry_len * 3));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, entry_full - (entry_len * 3), output,
		sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_offset_read_in_second_sector (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	memcpy (expected, &log_full[1][entry_full - (entry_len * 3)], entry_len * 3);
	for (i = 2; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[(entry_len * 3) + (entry_full * (i - 2))], log_full[i], entry_full);
	}
	expected_len = full_size - (entry_full * 2) + (entry_len * 3);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		&log_full[1][entry_full - (entry_len * 3)], entry_len * 3,
		FLASH_EXP_READ_CMD (0x03, 0x11000 + (entry_full - (entry_len * 3)), 0, -1, entry_len * 3));

	for (i = 2; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, ((entry_full * 2) - (entry_len * 3)),
		output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_offset_read_buffered_entries (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, entry_len * 3, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data) - (entry_len * 3), status);

	status = testing_validate_array (&entry_data[entry_len * 3], output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_partial_read_with_offset (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t *pos;
	uint8_t expected[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	pos = expected;
	memcpy (pos, &log_full[1][entry_full - (entry_len * 3)], entry_len * 3);
	pos += entry_len *3;
	memcpy (pos, log_full[2], entry_full);
	pos += entry_full;
	memcpy (pos, log_full[3], entry_full);
	pos += entry_full;
	memcpy (pos, log_full[4], entry_len * 3);
	expected_len = (entry_full * 2) + (entry_len * 6);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		&log_full[1][entry_full - (entry_len * 3)], entry_len * 3,
		FLASH_EXP_READ_CMD (0x03, 0x11000 + (entry_full - (entry_len * 3)), 0, -1, entry_len * 3));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[2], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x12000, 0, -1, entry_full));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[3], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x13000, 0, -1, entry_full));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[4], FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x14000, 0, -1, entry_len * 3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, ((entry_full * 2) - (entry_len * 3)),
		output, expected_len);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_offset_past_end (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		entry = (struct logging_entry_header*) &log_full[i * entry_len];
		entry->log_magic = 0xCB;
		entry->length = entry_len;
		entry->entry_id = i;
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, entry_full + 1, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_zero (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_flash_and_buffered_entries (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_full + entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;

		memset (&log_full[(i * entry_len) + sizeof (struct logging_entry_header)], i, entry_size);
	}

	memcpy (entry_data, log_full, entry_full);
	header = (struct logging_entry_header*) &entry_data[entry_full];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;

	memset (entry, i, entry_size);
	memcpy (&entry_data[entry_full + sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_flash_and_buffered_entries_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_full + entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;

		memset (&log_full[(i * entry_len) + sizeof (struct logging_entry_header)], i, entry_size);
	}

	memcpy (entry_data, log_full, entry_full);
	header = (struct logging_entry_header*) &entry_data[entry_full];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;

	memset (entry, i, entry_size);
	memcpy (&entry_data[entry_full + sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_flash_and_buffered_entries_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_full + entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;

			memset (&log_full[(i * entry_len) + sizeof (struct logging_entry_header)], i,
				entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	memcpy (entry_data, log_full, entry_full);
	header = (struct logging_entry_header*) &entry_data[entry_full];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;

	memset (entry, i, entry_size);
	memcpy (&entry_data[entry_full + sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_flash_and_buffered_entries_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_full[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_full + entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_full, 0xff, sizeof (log_full));

	for (i = 0; i < entry_count + 1; ++i) {
		header = (struct logging_entry_header*) &log_full[i * entry_len];
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;

			memset (&log_full[(i * entry_len) + sizeof (struct logging_entry_header)], i,
				entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	memcpy (entry_data, log_full, entry_full);
	header = (struct logging_entry_header*) &entry_data[entry_full];
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = i;

	memset (entry, i, entry_size);
	memcpy (&entry_data[entry_full + sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, entry_full));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_log_with_buffered_entries (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * (LOGGING_FLASH_SECTORS + 1);
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint8_t expected[full_size];
	int expected_len;
	uint8_t output[full_size];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * i], entry_data, entry_full);
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_log_with_buffered_entries_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * (LOGGING_FLASH_SECTORS + 1);
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint8_t expected[full_size];
	int expected_len;
	uint8_t output[full_size];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * i], entry_data, entry_full);
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_log_with_buffered_entries_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * (LOGGING_FLASH_SECTORS + 1);
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint8_t expected[full_size];
	int expected_len;
	uint8_t output[full_size];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * i], entry_data, entry_full);
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_log_with_buffered_entries_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * (LOGGING_FLASH_SECTORS + 1);
	uint8_t entry[entry_count][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint8_t expected[full_size];
	int expected_len;
	uint8_t output[full_size];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i + (j * entry_count);
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	for (i = 0; i < LOGGING_FLASH_SECTORS; ++i) {
		memcpy (&expected[entry_full * i], log_full[i], entry_full);
	}
	memcpy (&expected[entry_full * i], entry_data, entry_full);
	expected_len = full_size;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size - entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, entry_full));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t expected[entry_full];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	memset (entry[i], i, entry_size);

	memcpy (expected, entry_data, entry_full);
	expected_len = entry_full;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, entry_full,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_PAGE_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t expected[entry_full];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	memset (entry[i], i, entry_size);

	memcpy (expected, entry_data, entry_full);
	expected_len = entry_full;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, entry_full,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_PAGE_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t expected[entry_full];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	memset (entry[i], i, entry_size);

	memcpy (expected, entry_data, entry_full);
	expected_len = entry_full;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, entry_full,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_PAGE_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint8_t expected[entry_full];
	int expected_len;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	memset (entry[i], i, entry_size);

	memcpy (expected, entry_data, entry_full);
	expected_len = entry_full;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, entry_full,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_PAGE_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_static_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 10 + sizeof (struct logging_entry_header)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 10 + sizeof (struct logging_entry_header), status);

	status = testing_validate_array (log_partial, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (NULL, 0, output, sizeof (output));
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.read_contents (&logging.base, 0, NULL, sizeof (output));
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_read_contents_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	struct logging_entry_header *entry;
	int i;
	int j;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			entry = (struct logging_entry_header*) &log_full[j][i * entry_len];
			entry->log_magic = 0xCB;
			entry->length = entry_len;
			entry->entry_id = i + (j * entry_count);
		}
	}

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_buffered_entry (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_flushed_entry (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t entry[] = {0, 1, 2, 3, 4};
	uint8_t entry_data[sizeof (entry) + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[sizeof (entry) + sizeof (struct logging_entry_header)];
	struct logging_entry_header *header;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data);
	header->entry_id = 0;
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = sizeof (entry_data2);
	header->entry_id = 1;
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry, sizeof (entry));

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, sizeof (entry));
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, sizeof (entry_data), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_with_entries_then_fill_buffer (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = last_entry + i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[j], i, entry_size);
		memcpy (pos, entry[j], entry_size);
		pos += entry_size;
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_with_entries_then_fill_buffer_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = last_entry + i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[j], i, entry_size);
		memcpy (pos, entry[j], entry_size);
		pos += entry_size;
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_with_entries_then_fill_buffer_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count + 1; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = last_entry + i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[j], i, entry_size);
			memcpy (pos, entry[j], entry_size);
			pos += entry_size;
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	j--;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_with_entries_then_fill_buffer_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count + 1; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = last_entry + i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[j], i, entry_size);
			memcpy (pos, entry[j], entry_size);
			pos += entry_size;
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	j--;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_after_partial_flush_then_fill_buffer (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = last_entry + i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[j], i, entry_size);
		memcpy (pos, entry[j], entry_size);
		pos += entry_size;
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_after_partial_flush_then_fill_buffer_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = last_entry + i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[j], i, entry_size);
		memcpy (pos, entry[j], entry_size);
		pos += entry_size;
	}

	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_after_partial_flush_then_fill_buffer_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count + 1; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = last_entry + i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[j], i, entry_size);
			memcpy (pos, entry[j], entry_size);
			pos += entry_size;
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	j--;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_after_partial_flush_then_fill_buffer_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[(entry_count * 2)][entry_size];
	uint8_t entry_data[entry_len * (entry_count - 1)];
	uint8_t entry_data2[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data3[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (j = 0, i = 0; i < (entry_count - 1); ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
		pos += entry_size;
	}

	pos = entry_data2;
	last_entry = header->entry_id + 1;
	for (i = 0; i < entry_count + 1; ++j, ++i) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = last_entry + i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[j], i, entry_size);
			memcpy (pos, entry[j], entry_size);
			pos += entry_size;
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	j--;
	header = (struct logging_entry_header*) entry_data3;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + i;
	memset (entry[j], i, entry_size);
	memcpy (&entry_data3[sizeof (struct logging_entry_header)], entry[j], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < (entry_count - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full - entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (; i < ((entry_count * 2) - 1); ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x11000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x11000, entry_data3,
		sizeof (entry_data3));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full + entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_overwrite (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint32_t last_entry;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
			last_entry = header->entry_id;
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry, 0, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_overwrite_unused_bytes (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint32_t last_entry;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
				(j * entry_count);
			last_entry = header->entry_id;
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			header->length = entry_len;
			header->entry_id = i + (j * entry_count);
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry, 0, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_overwrite_unused_bytes_terminator (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint32_t last_entry;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
				last_entry = header->entry_id;
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry, 0, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_overwrite_unused_bytes_terminator_large (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_full[LOGGING_FLASH_SECTORS][FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	const int full_size = entry_full * LOGGING_FLASH_SECTORS;
	uint8_t entry[entry_size];
	uint8_t entry_data[entry_len];
	struct logging_entry_header *header;
	int i;
	int j;
	uint32_t last_entry;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_full, 0xff, sizeof (log_full));

	for (j = 0; j < 8; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = (LOGGING_FLASH_SECTORS * entry_count) + i +
					(j * entry_count);
				last_entry = header->entry_id;
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	for (j = 8; j < LOGGING_FLASH_SECTORS; ++j) {
		for (i = 0; i < entry_count + 1; ++i) {
			header = (struct logging_entry_header*) &log_full[j][i * entry_len];
			header->log_magic = 0xCB;
			if (i != entry_count) {
				header->length = entry_len;
				header->entry_id = i + (j * entry_count);
			}
			else {
				header->length = 0x8000 | sizeof (struct logging_entry_header);
				header->entry_id = 0;
			}
		}
	}

	header = (struct logging_entry_header*) entry_data;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry, 0, entry_size);
	memcpy (&entry_data[sizeof (struct logging_entry_header)], entry, entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_full[i], FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, full_size, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry, entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		sizeof (entry_data));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, entry_data, sizeof (entry_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, sizeof (entry_data)));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, entry_len, status);

	status = testing_validate_array (entry_data, output, status);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_buffer_flush_after_incomplete_flush (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header);
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertIntEquals (test, 0, entry_empty);

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	last_entry = header->entry_id;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_buffer_flush_after_incomplete_flush_unused_bytes (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 1;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty < (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty != 0));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		header->length = entry_len;
		header->entry_id = i;
		pos += sizeof (struct logging_entry_header);

		memset (entry[i], i, entry_size);
		memcpy (pos, entry[i], entry_size);
	}

	last_entry = header->entry_id;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) - 2;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) sizeof (struct logging_entry_header)));
	CuAssertTrue (test, (entry_empty < (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	last_entry = entry_count - 1;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator_large (
	CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	const int entry_size = 16 - sizeof (struct logging_entry_header) + 4;
	const int entry_len = entry_size + sizeof (struct logging_entry_header);
	const int entry_count = FLASH_SECTOR_SIZE / entry_len;
	const int entry_full = entry_len * entry_count;
	const int entry_empty = FLASH_SECTOR_SIZE - entry_full;
	uint8_t entry[entry_count + 1][entry_size];
	uint8_t entry_data[entry_full + sizeof (struct logging_entry_header)];
	uint8_t entry_data2[entry_len];
	struct logging_entry_header *header;
	int i;
	uint8_t *pos;
	uint32_t last_entry;

	TEST_START;

	CuAssertTrue (test, (entry_empty >= (int) (sizeof (struct logging_entry_header) * 2)));

	memset (log_empty, 0xff, sizeof (log_empty));

	pos = entry_data;
	for (i = 0; i < entry_count + 1; ++i, pos += entry_size) {
		header = (struct logging_entry_header*) pos;
		header->log_magic = 0xCB;
		if (i != entry_count) {
			header->length = entry_len;
			header->entry_id = i;
			pos += sizeof (struct logging_entry_header);

			memset (entry[i], i, entry_size);
			memcpy (pos, entry[i], entry_size);
		}
		else {
			header->length = 0x8000 | sizeof (struct logging_entry_header);
			header->entry_id = 0;
		}
	}

	i--;
	last_entry = entry_count - 1;
	header = (struct logging_entry_header*) entry_data2;
	header->log_magic = 0xCB;
	header->length = entry_len;
	header->entry_id = last_entry + 1;
	memset (entry[i], i, entry_size);
	memcpy (&entry_data2[sizeof (struct logging_entry_header)], entry[i], entry_size);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < entry_count; ++i) {
		status = logging.base.create_entry (&logging.base, entry[i], entry_size);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data,
		FLASH_PAGE_SIZE);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, LOGGING_INCOMPLETE_FLUSH, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_full, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.create_entry (&logging.base, entry[i], entry_size);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_sector (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, entry_data2,
		sizeof (entry_data2));

	CuAssertIntEquals (test, 0, status);

	status = logging.base.flush (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, entry_len, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_static_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging = logging_flash_static_init (&state, &flash, 0x10000);
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;
	uint8_t output[LOGGING_FLASH_SECTORS * FLASH_SECTOR_SIZE];

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init_state (&logging);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.read_contents (&logging.base, 0, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}

static void logging_flash_test_clear_erase_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state flash_state;
	struct spi_flash flash;
	struct logging_flash_state state;
	struct logging_flash logging;
	int status;
	uint8_t log_empty[FLASH_SECTOR_SIZE];
	uint8_t log_partial[FLASH_SECTOR_SIZE];
	struct logging_entry_header *entry;
	int i;

	TEST_START;

	memset (log_empty, 0xff, sizeof (log_empty));
	memset (log_partial, 0xff, sizeof (log_partial));

	entry = (struct logging_entry_header*) log_partial;
	entry->log_magic = 0xCB;
	entry->length = 10 + sizeof (struct logging_entry_header);
	entry->entry_id = 0;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_state, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_partial, FLASH_SECTOR_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, FLASH_SECTOR_SIZE));

	for (i = 1; i < 16; ++i) {
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, log_empty, FLASH_SECTOR_SIZE,
			FLASH_EXP_READ_CMD (0x03, 0x10000 + (i * FLASH_SECTOR_SIZE), 0, -1, FLASH_SECTOR_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = logging_flash_init (&logging, &state, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = logging.base.clear (&logging.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = logging.base.get_size (&logging.base);
	CuAssertIntEquals (test, (10 + sizeof (struct logging_entry_header)), status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	logging_flash_release (&logging);

	spi_flash_release (&flash);
}


TEST_SUITE_START (logging_flash);

TEST (logging_flash_test_init_empty);
TEST (logging_flash_test_init_first_sector_partial);
TEST (logging_flash_test_init_first_sector_partial_different_lengths);
TEST (logging_flash_test_init_first_sector_full_all_bytes);
TEST (logging_flash_test_init_first_sector_full_unused_bytes);
TEST (logging_flash_test_init_first_sector_full_unused_bytes_terminator);
TEST (logging_flash_test_init_first_sector_full_unused_bytes_terminator_large);
TEST (logging_flash_test_init_second_sector_partial_all_bytes);
TEST (logging_flash_test_init_second_sector_partial_unused_bytes);
TEST (logging_flash_test_init_second_sector_partial_unused_bytes_terminator);
TEST (logging_flash_test_init_second_sector_partial_unused_bytes_terminator_large);
TEST (logging_flash_test_init_all_sectors_full_all_bytes);
TEST (logging_flash_test_init_all_sectors_full_unused_bytes);
TEST (logging_flash_test_init_all_sectors_full_unused_bytes_terminator);
TEST (logging_flash_test_init_all_sectors_full_unused_bytes_terminator_large);
TEST (logging_flash_test_init_all_sectors_full_overwrite_all_bytes);
TEST (logging_flash_test_init_all_sectors_full_overwrite_unused_bytes);
TEST (logging_flash_test_init_all_sectors_full_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_init_all_sectors_full_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_init_all_sectors_partial_overwrite_all_bytes);
TEST (logging_flash_test_init_all_sectors_partial_overwrite_unused_bytes);
TEST (logging_flash_test_init_all_sectors_partial_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_init_all_sectors_partial_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_init_ca_entry);
TEST (logging_flash_test_init_valid_entry_unknown_format);
TEST (logging_flash_test_init_no_valid_entry_markers);
TEST (logging_flash_test_init_entry_bad_length);
TEST (logging_flash_test_init_partial_entry_bad_length);
TEST (logging_flash_test_init_terminator_bad_length);
TEST (logging_flash_test_init_partial_terminator_bad_length);
TEST (logging_flash_test_init_partial_unused_not_blank);
TEST (logging_flash_test_init_null);
TEST (logging_flash_test_init_not_block_aligned);
TEST (logging_flash_test_init_flash_read_error);
TEST (logging_flash_test_static_init_empty);
TEST (logging_flash_test_static_init_first_sector_partial);
TEST (logging_flash_test_static_init_first_sector_partial_different_lengths);
TEST (logging_flash_test_static_init_first_sector_full_all_bytes);
TEST (logging_flash_test_static_init_first_sector_full_unused_bytes);
TEST (logging_flash_test_static_init_first_sector_full_unused_bytes_terminator);
TEST (logging_flash_test_static_init_first_sector_full_unused_bytes_terminator_large);
TEST (logging_flash_test_static_init_second_sector_partial_all_bytes);
TEST (logging_flash_test_static_init_second_sector_partial_unused_bytes);
TEST (logging_flash_test_static_init_second_sector_partial_unused_bytes_terminator);
TEST (logging_flash_test_static_init_second_sector_partial_unused_bytes_terminator_large);
TEST (logging_flash_test_static_init_all_sectors_full_all_bytes);
TEST (logging_flash_test_static_init_all_sectors_full_unused_bytes);
TEST (logging_flash_test_static_init_all_sectors_full_unused_bytes_terminator);
TEST (logging_flash_test_static_init_all_sectors_full_unused_bytes_terminator_large);
TEST (logging_flash_test_static_init_all_sectors_full_overwrite_all_bytes);
TEST (logging_flash_test_static_init_all_sectors_full_overwrite_unused_bytes);
TEST (logging_flash_test_static_init_all_sectors_full_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_static_init_all_sectors_full_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_static_init_all_sectors_partial_overwrite_all_bytes);
TEST (logging_flash_test_static_init_all_sectors_partial_overwrite_unused_bytes);
TEST (logging_flash_test_static_init_all_sectors_partial_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_static_init_all_sectors_partial_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_static_init_ca_entry);
TEST (logging_flash_test_static_init_valid_entry_unknown_format);
TEST (logging_flash_test_static_init_no_valid_entry_markers);
TEST (logging_flash_test_static_init_entry_bad_length);
TEST (logging_flash_test_static_init_partial_entry_bad_length);
TEST (logging_flash_test_static_init_terminator_bad_length);
TEST (logging_flash_test_static_init_partial_terminator_bad_length);
TEST (logging_flash_test_static_init_partial_unused_not_blank);
TEST (logging_flash_test_static_init_null);
TEST (logging_flash_test_static_init_not_block_aligned);
TEST (logging_flash_test_static_init_flash_read_error);
TEST (logging_flash_test_release_null);
TEST (logging_flash_test_get_size_null);
TEST (logging_flash_test_create_entry);
TEST (logging_flash_test_create_entry_multiple);
TEST (logging_flash_test_create_entry_multiple_different_lengths);
TEST (logging_flash_test_create_entry_full_buffer_flush);
TEST (logging_flash_test_create_entry_full_buffer_flush_unused_bytes);
TEST (logging_flash_test_create_entry_full_buffer_flush_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_full_buffer_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_sector_partial_full);
TEST (logging_flash_test_create_entry_second_sector_partial_all_bytes);
TEST (logging_flash_test_create_entry_second_sector_partial_unused_bytes);
TEST (logging_flash_test_create_entry_second_sector_partial_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_second_sector_partial_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_fill_partial_buffer_flush);
TEST (logging_flash_test_create_entry_fill_partial_buffer_flush_unused_bytes);
TEST (logging_flash_test_create_entry_fill_partial_buffer_flush_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_fill_partial_buffer_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_all_sectors_full);
TEST (logging_flash_test_create_entry_all_sectors_full_unused_bytes);
TEST (logging_flash_test_create_entry_all_sectors_full_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_all_sectors_full_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_full_overwrite_middle);
TEST (logging_flash_test_create_entry_full_overwrite_middle_unused_bytes);
TEST (logging_flash_test_create_entry_full_overwrite_middle_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_full_overwrite_middle_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_full_partial_overwrite_middle);
TEST (logging_flash_test_create_entry_full_partial_overwrite_middle_unused_bytes);
TEST (logging_flash_test_create_entry_full_partial_overwrite_middle_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_full_partial_overwrite_middle_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_full_buffer_after_partial_flush);
TEST (logging_flash_test_create_entry_full_buffer_after_partial_flush_unused_bytes);
TEST (logging_flash_test_create_entry_full_buffer_after_partial_flush_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_full_buffer_after_partial_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_full_buffer_flush_multiple);
TEST (logging_flash_test_create_entry_full_buffer_flush_multiple_unused_bytes);
TEST (logging_flash_test_create_entry_full_buffer_flush_multiple_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_full_buffer_flush_multiple_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_wrap_to_start);
TEST (logging_flash_test_create_entry_wrap_to_start_unused_bytes);
TEST (logging_flash_test_create_entry_wrap_to_start_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_wrap_to_start_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_init_with_entry_too_long);
TEST (logging_flash_test_create_entry_init_with_entry_too_short);
TEST (logging_flash_test_create_entry_init_with_terminator_too_long);
TEST (logging_flash_test_create_entry_init_with_terminator_too_short);
TEST (logging_flash_test_create_entry_sector_unused_not_blank);
TEST (logging_flash_test_create_entry_sector_unused_partially_not_blank);
TEST (logging_flash_test_create_entry_first_sector_not_valid);
TEST (logging_flash_test_create_entry_static_init);
TEST (logging_flash_test_create_entry_null);
TEST (logging_flash_test_create_entry_bad_length);
TEST (logging_flash_test_create_entry_flush_error);
TEST (logging_flash_test_create_entry_after_incomplete_flush);
TEST (logging_flash_test_create_entry_after_incomplete_flush_unused_bytes);
TEST (logging_flash_test_create_entry_after_incomplete_flush_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_after_incomplete_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush);
TEST (logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush_unused_bytes);
TEST (logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator);
TEST (logging_flash_test_create_entry_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_flush_no_data);
TEST (logging_flash_test_flush_null);
TEST (logging_flash_test_flush_erase_error);
TEST (logging_flash_test_flush_write_error);
TEST (logging_flash_test_flush_incomplete_write);
TEST (logging_flash_test_flush_incomplete_write_unused_bytes);
TEST (logging_flash_test_flush_incomplete_write_unused_bytes_terminator);
TEST (logging_flash_test_flush_incomplete_write_unused_bytes_terminator_large);
TEST (logging_flash_test_flush_after_incomplete_write);
TEST (logging_flash_test_flush_after_incomplete_write_unused_bytes);
TEST (logging_flash_test_flush_after_incomplete_write_unused_bytes_terminator);
TEST (logging_flash_test_flush_after_incomplete_write_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents);
TEST (logging_flash_test_read_contents_empty);
TEST (logging_flash_test_read_contents_buffered_entry_only);
TEST (logging_flash_test_read_contents_first_sector_full);
TEST (logging_flash_test_read_contents_first_sector_full_unused_bytes);
TEST (logging_flash_test_read_contents_first_sector_full_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_first_sector_full_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_second_sector_partial);
TEST (logging_flash_test_read_contents_second_sector_partial_usused_bytes);
TEST (logging_flash_test_read_contents_second_sector_partial_usused_bytes_terminator);
TEST (logging_flash_test_read_contents_second_sector_partial_usused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_all_sectors_full);
TEST (logging_flash_test_read_contents_all_sectors_full_unused_bytes);
TEST (logging_flash_test_read_contents_all_sectors_full_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_all_sectors_full_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_all_sectors_full_overwrite);
TEST (logging_flash_test_read_contents_all_sectors_full_overwrite_unused_bytes);
TEST (logging_flash_test_read_contents_all_sectors_full_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_all_sectors_full_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_all_sectors_partial_overwrite);
TEST (logging_flash_test_read_contents_all_sectors_partial_overwrite_unused_bytes);
TEST (logging_flash_test_read_contents_all_sectors_partial_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_all_sectors_partial_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_after_erase_new_middle_sector);
TEST (logging_flash_test_read_contents_after_erase_new_middle_sector_unused_bytes);
TEST (logging_flash_test_read_contents_after_erase_new_middle_sector_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_after_erase_new_middle_sector_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_partial_read);
TEST (logging_flash_test_read_contents_partial_read_buffered_entries);
TEST (logging_flash_test_read_contents_offset_read_in_first_sector);
TEST (logging_flash_test_read_contents_offset_read_in_second_sector);
TEST (logging_flash_test_read_contents_offset_read_buffered_entries);
TEST (logging_flash_test_read_contents_partial_read_with_offset);
TEST (logging_flash_test_read_contents_offset_past_end);
TEST (logging_flash_test_read_contents_zero);
TEST (logging_flash_test_read_contents_flash_and_buffered_entries);
TEST (logging_flash_test_read_contents_flash_and_buffered_entries_unused_bytes);
TEST (logging_flash_test_read_contents_flash_and_buffered_entries_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_flash_and_buffered_entries_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_full_log_with_buffered_entries);
TEST (logging_flash_test_read_contents_full_log_with_buffered_entries_unused_bytes);
TEST (logging_flash_test_read_contents_full_log_with_buffered_entries_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_full_log_with_buffered_entries_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush);
TEST (logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush_unused_bytes);
TEST (logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator);
TEST (logging_flash_test_read_contents_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_read_contents_static_init);
TEST (logging_flash_test_read_contents_null);
TEST (logging_flash_test_read_contents_read_error);
TEST (logging_flash_test_clear);
TEST (logging_flash_test_clear_buffered_entry);
TEST (logging_flash_test_clear_flushed_entry);
TEST (logging_flash_test_clear_with_entries_then_fill_buffer);
TEST (logging_flash_test_clear_with_entries_then_fill_buffer_unused_bytes);
TEST (logging_flash_test_clear_with_entries_then_fill_buffer_unused_bytes_terminator);
TEST (logging_flash_test_clear_with_entries_then_fill_buffer_unused_bytes_terminator_large);
TEST (logging_flash_test_clear_after_partial_flush_then_fill_buffer);
TEST (logging_flash_test_clear_after_partial_flush_then_fill_buffer_unused_bytes);
TEST (logging_flash_test_clear_after_partial_flush_then_fill_buffer_unused_bytes_terminator);
TEST (logging_flash_test_clear_after_partial_flush_then_fill_buffer_unused_bytes_terminator_large);
TEST (logging_flash_test_clear_full_overwrite);
TEST (logging_flash_test_clear_full_overwrite_unused_bytes);
TEST (logging_flash_test_clear_full_overwrite_unused_bytes_terminator);
TEST (logging_flash_test_clear_full_overwrite_unused_bytes_terminator_large);
TEST (logging_flash_test_clear_full_buffer_flush_after_incomplete_flush);
TEST (logging_flash_test_clear_full_buffer_flush_after_incomplete_flush_unused_bytes);
TEST (logging_flash_test_clear_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator);
TEST (logging_flash_test_clear_full_buffer_flush_after_incomplete_flush_unused_bytes_terminator_large);
TEST (logging_flash_test_clear_static_init);
TEST (logging_flash_test_clear_null);
TEST (logging_flash_test_clear_erase_error);

TEST_SUITE_END;
