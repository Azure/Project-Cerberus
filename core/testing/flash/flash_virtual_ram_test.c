// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "platform_io.h"
#include "testing.h"
#include "flash/flash_virtual_ram.h"
#include "flash/flash_virtual_ram_static.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("flash_virtual_ram");


/**
 * Size of the buffer that is managed by virtual flash device.
 */
#define FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE	(32 * 1024)

/**
 * Buffer that need to be managed by virtual flash interface
 */
static uint8_t flash_virtual_ram_testing_buffer[FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE];


/*******************
 * Test cases
 *******************/

static void flash_virtual_ram_test_init (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	virtual_flash.state = &state;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, virtual_flash.base.get_device_size);
	CuAssertPtrNotNull (test, virtual_flash.base.read);
	CuAssertPtrNotNull (test, virtual_flash.base.get_page_size);
	CuAssertPtrNotNull (test, virtual_flash.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, virtual_flash.base.write);
	CuAssertPtrNotNull (test, virtual_flash.base.get_sector_size);
	CuAssertPtrNotNull (test, virtual_flash.base.sector_erase);
	CuAssertPtrNotNull (test, virtual_flash.base.get_block_size);
	CuAssertPtrNotNull (test, virtual_flash.base.block_erase);
	CuAssertPtrNotNull (test, virtual_flash.base.chip_erase);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_init_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash = flash_virtual_ram_static_init (&state,
		flash_virtual_ram_testing_buffer, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, virtual_flash.base.get_device_size);
	CuAssertPtrNotNull (test, virtual_flash.base.read);
	CuAssertPtrNotNull (test, virtual_flash.base.get_page_size);
	CuAssertPtrNotNull (test, virtual_flash.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, virtual_flash.base.write);
	CuAssertPtrNotNull (test, virtual_flash.base.get_sector_size);
	CuAssertPtrNotNull (test, virtual_flash.base.sector_erase);
	CuAssertPtrNotNull (test, virtual_flash.base.get_block_size);
	CuAssertPtrNotNull (test, virtual_flash.base.block_erase);
	CuAssertPtrNotNull (test, virtual_flash.base.chip_erase);

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_init_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (NULL, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = flash_virtual_ram_init (&virtual_flash, NULL, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = flash_virtual_ram_init (&virtual_flash, &state, NULL,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer, 0);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);
}

static void flash_virtual_ram_test_release_null (CuTest *test)
{
	TEST_START;

	flash_virtual_ram_release (NULL);
}

static void flash_virtual_ram_test_get_device_size (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_device_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_device_size_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint32_t bytes;
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.get_device_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_device_size_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_device_size (NULL, &bytes);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.get_device_size (&virtual_flash.base, NULL);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);
}

static void flash_virtual_ram_test_get_page_size (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_page_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_page_size_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint32_t bytes;
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.get_page_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_page_size_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_page_size (NULL, &bytes);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.get_page_size (&virtual_flash.base, NULL);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);
}

static void flash_virtual_ram_test_get_block_size (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_block_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_block_size_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint32_t bytes;
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.get_block_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_block_size_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_block_size (NULL, &bytes);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.get_block_size (&virtual_flash.base, NULL);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);
}

static void flash_virtual_ram_test_get_sector_size (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_sector_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_sector_size_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint32_t bytes;
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.get_sector_size (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_get_sector_size_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.get_sector_size (NULL, &bytes);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.get_sector_size (&virtual_flash.base, NULL);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);
}

static void flash_virtual_ram_test_minimum_write_per_page (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.minimum_write_per_page (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_minimum_write_per_page_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint32_t bytes;
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.minimum_write_per_page (&virtual_flash.base, &bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, bytes);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_minimum_write_per_page_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint32_t bytes;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.minimum_write_per_page (NULL, &bytes);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.minimum_write_per_page (&virtual_flash.base, NULL);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);
}

static void flash_virtual_ram_test_read (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[VIRTUAL_FLASH_BLOCK_SIZE];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memcpy (flash_virtual_ram_testing_buffer, RSA_PRIVKEY_DER, (VIRTUAL_FLASH_BLOCK_SIZE * 4));

	status = virtual_flash.base.read (&virtual_flash.base, 0, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA_PRIVKEY_DER, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_not_page_aligned (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[32];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 16, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (flash_virtual_ram_testing_buffer + 16, read_data,
		sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_multiple_pages (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[VIRTUAL_FLASH_BLOCK_SIZE * 4];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 0, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (flash_virtual_ram_testing_buffer, read_data,
		sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_multiple_pages_first_page_offset (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[(VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 16, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((flash_virtual_ram_testing_buffer + 16), read_data,
		sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_multiple_pages_last_page_partial (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[(VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 0, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (flash_virtual_ram_testing_buffer, read_data,
		sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_multiple_pages_first_page_offset_last_page_partial (
	CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[(VIRTUAL_FLASH_BLOCK_SIZE * 4) - 32];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 16, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((flash_virtual_ram_testing_buffer + 16), read_data,
		sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint8_t read_data[VIRTUAL_FLASH_BLOCK_SIZE];
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.read (&virtual_flash.base, 0, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RSA_PRIVKEY_DER, read_data, sizeof (read_data));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[4];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (NULL, 0, read_data, sizeof (read_data));
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.read (&virtual_flash.base, 0, NULL, sizeof (read_data));
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.read (&virtual_flash.base, 0, NULL, sizeof (read_data));
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_out_of_range_address_equals_size (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[4];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE,
		read_data, sizeof (read_data));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_out_of_range_address_zero (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[VIRTUAL_FLASH_BLOCK_SIZE];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 0, read_data,
		(FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE + 1));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_out_of_range_address_non_zero (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[VIRTUAL_FLASH_BLOCK_SIZE];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 16, read_data,
		((FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE + 1) - 16));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_address_too_large (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[4];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 0xFFFFFFFF, read_data,
		sizeof (read_data));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_read_length_too_long (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	uint8_t read_data[4];
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.read (&virtual_flash.base, 16, read_data, 0xFFFFFFFF);
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, status);

	status = testing_validate_array (RSA_PRIVKEY_DER, flash_virtual_ram_testing_buffer,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_partial_page (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER,
		(VIRTUAL_FLASH_BLOCK_SIZE / 2));
	CuAssertIntEquals (test, (VIRTUAL_FLASH_BLOCK_SIZE / 2), status);

	status = testing_validate_array (RSA_PRIVKEY_DER, flash_virtual_ram_testing_buffer,
		(VIRTUAL_FLASH_BLOCK_SIZE / 2));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_multiple_pages (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, (VIRTUAL_FLASH_BLOCK_SIZE * 4));

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER,
		(VIRTUAL_FLASH_BLOCK_SIZE * 4));
	CuAssertIntEquals (test, (VIRTUAL_FLASH_BLOCK_SIZE * 4), status);

	status = testing_validate_array (RSA_PRIVKEY_DER, flash_virtual_ram_testing_buffer,
		(VIRTUAL_FLASH_BLOCK_SIZE * 4));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_multiple_pages_partial_last_page (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, ((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16));

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER,
		((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16));
	CuAssertIntEquals (test, ((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16), status);

	status = testing_validate_array (RSA_PRIVKEY_DER, flash_virtual_ram_testing_buffer,
		((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_partial_page_offset (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, (VIRTUAL_FLASH_BLOCK_SIZE * 2));

	status = virtual_flash.base.write (&virtual_flash.base, 1, RSA_PRIVKEY_DER,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, status);

	status = testing_validate_array (RSA_PRIVKEY_DER, (flash_virtual_ram_testing_buffer + 1),
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_multiple_pages_first_page_offset (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, (VIRTUAL_FLASH_BLOCK_SIZE * 4));

	status = virtual_flash.base.write (&virtual_flash.base, 16,	RSA_PRIVKEY_DER,
		((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16));
	CuAssertIntEquals (test, ((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16), status);

	status = testing_validate_array (RSA_PRIVKEY_DER, (flash_virtual_ram_testing_buffer + 16),
		(VIRTUAL_FLASH_BLOCK_SIZE * 4) - 16);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_multiple_pages_first_page_offset_partial_last_page (
	CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (flash_virtual_ram_testing_buffer, 0xFF, (VIRTUAL_FLASH_BLOCK_SIZE * 4));

	status = virtual_flash.base.write (&virtual_flash.base, 16, RSA_PRIVKEY_DER,
		((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 32));
	CuAssertIntEquals (test, ((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 32), status);

	status = testing_validate_array (RSA_PRIVKEY_DER, (flash_virtual_ram_testing_buffer + 16),
		((VIRTUAL_FLASH_BLOCK_SIZE * 4) - 32));
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_zero_bytes (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER, 0);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_zero_bytes_offset (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 1, RSA_PRIVKEY_DER, 0);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	int status;

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	memset (flash_virtual_ram_testing_buffer, 0xFF, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, VIRTUAL_FLASH_BLOCK_SIZE, status);

	status = testing_validate_array (RSA_PRIVKEY_DER, flash_virtual_ram_testing_buffer,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_out_of_range_address_equals_size (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE,
		RSA_PRIVKEY_DER, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_out_of_range_address_zero (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 0, RSA_PRIVKEY_DER,
		(FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE + 1));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_out_of_range_address_non_zero (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 16,	RSA_PRIVKEY_DER,
		((FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE + 1) - 16));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_address_too_large (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 0xFFFFFFFF, RSA_PRIVKEY_DER, 16);
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_length_too_long (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (&virtual_flash.base, 16, RSA_PRIVKEY_DER, 0xFFFFFFFF);
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_write_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.write (NULL, 0, RSA_PRIVKEY_DER, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	status = virtual_flash.base.write (&virtual_flash.base, 0, NULL, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_sector_erase (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint8_t test_data[VIRTUAL_FLASH_BLOCK_SIZE];

	TEST_START;

	memset (test_data, 0xFF, sizeof (test_data));
	memset (flash_virtual_ram_testing_buffer, 0x11, VIRTUAL_FLASH_BLOCK_SIZE);

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.sector_erase (&virtual_flash.base, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = memcmp ((flash_virtual_ram_testing_buffer + VIRTUAL_FLASH_BLOCK_SIZE), test_data,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_sector_erase_address_offset (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint8_t test_data[VIRTUAL_FLASH_BLOCK_SIZE];

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (test_data, 0xFF, sizeof (test_data));
	memset ((flash_virtual_ram_testing_buffer + 16), 0x11, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.sector_erase (&virtual_flash.base, 16);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (flash_virtual_ram_testing_buffer, test_data, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_sector_erase_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	int status;
	uint8_t test_data[VIRTUAL_FLASH_BLOCK_SIZE];

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	memset (test_data, 0xFF, sizeof (test_data));
	memset (flash_virtual_ram_testing_buffer, 0x11, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.sector_erase (&virtual_flash.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (flash_virtual_ram_testing_buffer, test_data, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_sector_erase_out_of_range (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.sector_erase (&virtual_flash.base,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_sector_erase_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.sector_erase (NULL, 0);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_block_erase (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint8_t test_data[VIRTUAL_FLASH_BLOCK_SIZE];

	TEST_START;

	memset (test_data, 0xFF, sizeof (test_data));
	memset (flash_virtual_ram_testing_buffer, 0x11, VIRTUAL_FLASH_BLOCK_SIZE);

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.block_erase (&virtual_flash.base, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = memcmp ((flash_virtual_ram_testing_buffer + VIRTUAL_FLASH_BLOCK_SIZE), test_data,
		VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_block_erase_address_offset (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint8_t test_data[VIRTUAL_FLASH_BLOCK_SIZE];

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	memset (test_data, 0xFF, sizeof (test_data));
	memset ((flash_virtual_ram_testing_buffer + 16), 0x11, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.block_erase (&virtual_flash.base, 16);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (flash_virtual_ram_testing_buffer, test_data, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_block_erase_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	int status;
	uint8_t test_data[VIRTUAL_FLASH_BLOCK_SIZE];

	TEST_START;

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	memset (test_data, 0xFF, sizeof (test_data));
	memset (flash_virtual_ram_testing_buffer, 0x11, VIRTUAL_FLASH_BLOCK_SIZE);

	status = virtual_flash.base.block_erase (&virtual_flash.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (flash_virtual_ram_testing_buffer, test_data, VIRTUAL_FLASH_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_block_erase_out_of_range (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.block_erase (&virtual_flash.base,
		(FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE + 1));
	CuAssertIntEquals (test, FLASH_ADDRESS_OUT_OF_RANGE, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_block_erase_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.block_erase (NULL, 0);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_chip_erase (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;
	uint8_t test_data[FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE];

	TEST_START;

	memset (test_data, 0xFF, sizeof (test_data));
	memset (flash_virtual_ram_testing_buffer, 0x11, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.chip_erase (&virtual_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (flash_virtual_ram_testing_buffer, test_data,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_chip_erase_static (CuTest *test)
{
	struct flash_virtual_ram_state state;
	struct flash_virtual_ram virtual_flash =
		flash_virtual_ram_static_init (&state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	uint8_t test_data[FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE];
	int status;

	TEST_START;

	memset (test_data, 0xFF, sizeof (test_data));
	memset (flash_virtual_ram_testing_buffer, 0x11, FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = flash_virtual_ram_init_state (&virtual_flash);
	CuAssertIntEquals (test, 0, status);

	status = virtual_flash.base.chip_erase (&virtual_flash.base);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (flash_virtual_ram_testing_buffer, test_data,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);
	CuAssertIntEquals (test, 0, status);

	flash_virtual_ram_release (&virtual_flash);
}

static void flash_virtual_ram_test_chip_erase_null (CuTest *test)
{
	struct flash_virtual_ram virtual_flash;
	struct flash_virtual_ram_state state;
	int status;

	TEST_START;

	status = flash_virtual_ram_init (&virtual_flash, &state, flash_virtual_ram_testing_buffer,
		FLASH_VIRTUAL_RAM_TESTING_BUF_SIZE);

	status = virtual_flash.base.chip_erase (NULL);
	CuAssertIntEquals (test, FLASH_INVALID_ARGUMENT, status);

	flash_virtual_ram_release (&virtual_flash);
}


// *INDENT-OFF*
TEST_SUITE_START (flash_virtual_ram);

TEST (flash_virtual_ram_test_init);
TEST (flash_virtual_ram_test_init_static);
TEST (flash_virtual_ram_test_init_null);
TEST (flash_virtual_ram_test_release_null);
TEST (flash_virtual_ram_test_get_device_size);
TEST (flash_virtual_ram_test_get_device_size_static);
TEST (flash_virtual_ram_test_get_device_size_null);
TEST (flash_virtual_ram_test_get_page_size);
TEST (flash_virtual_ram_test_get_page_size_static);
TEST (flash_virtual_ram_test_get_page_size_null);
TEST (flash_virtual_ram_test_get_block_size);
TEST (flash_virtual_ram_test_get_block_size_static);
TEST (flash_virtual_ram_test_get_block_size_null);
TEST (flash_virtual_ram_test_get_sector_size);
TEST (flash_virtual_ram_test_get_sector_size_static);
TEST (flash_virtual_ram_test_get_sector_size_null);
TEST (flash_virtual_ram_test_minimum_write_per_page);
TEST (flash_virtual_ram_test_minimum_write_per_page_static);
TEST (flash_virtual_ram_test_minimum_write_per_page_null);

// Read tests
TEST (flash_virtual_ram_test_read);
TEST (flash_virtual_ram_test_read_not_page_aligned);
TEST (flash_virtual_ram_test_read_multiple_pages);
TEST (flash_virtual_ram_test_read_multiple_pages_first_page_offset);
TEST (flash_virtual_ram_test_read_multiple_pages_last_page_partial);
TEST (flash_virtual_ram_test_read_multiple_pages_first_page_offset_last_page_partial);
TEST (flash_virtual_ram_test_read_static);
TEST (flash_virtual_ram_test_read_null);
TEST (flash_virtual_ram_test_read_out_of_range_address_equals_size);
TEST (flash_virtual_ram_test_read_out_of_range_address_zero);
TEST (flash_virtual_ram_test_read_out_of_range_address_non_zero);
TEST (flash_virtual_ram_test_read_address_too_large);
TEST (flash_virtual_ram_test_read_length_too_long);

// Write Tests
TEST (flash_virtual_ram_test_write);
TEST (flash_virtual_ram_test_write_partial_page);
TEST (flash_virtual_ram_test_write_multiple_pages);
TEST (flash_virtual_ram_test_write_multiple_pages_partial_last_page);
TEST (flash_virtual_ram_test_write_partial_page_offset);
TEST (flash_virtual_ram_test_write_multiple_pages_first_page_offset);
TEST (flash_virtual_ram_test_write_multiple_pages_first_page_offset_partial_last_page);
TEST (flash_virtual_ram_test_write_zero_bytes);
TEST (flash_virtual_ram_test_write_zero_bytes_offset);
TEST (flash_virtual_ram_test_write_static);
TEST (flash_virtual_ram_test_write_out_of_range_address_equals_size);
TEST (flash_virtual_ram_test_write_out_of_range_address_zero);
TEST (flash_virtual_ram_test_write_out_of_range_address_non_zero);
TEST (flash_virtual_ram_test_write_address_too_large);
TEST (flash_virtual_ram_test_write_length_too_long);
TEST (flash_virtual_ram_test_write_null);

// Erase tests
TEST (flash_virtual_ram_test_sector_erase);
TEST (flash_virtual_ram_test_sector_erase_address_offset);
TEST (flash_virtual_ram_test_sector_erase_static);
TEST (flash_virtual_ram_test_sector_erase_out_of_range);
TEST (flash_virtual_ram_test_sector_erase_null);
TEST (flash_virtual_ram_test_block_erase);
TEST (flash_virtual_ram_test_block_erase_address_offset);
TEST (flash_virtual_ram_test_block_erase_static);
TEST (flash_virtual_ram_test_block_erase_out_of_range);
TEST (flash_virtual_ram_test_block_erase_null);
TEST (flash_virtual_ram_test_chip_erase);
TEST (flash_virtual_ram_test_chip_erase_static);
TEST (flash_virtual_ram_test_chip_erase_null);

TEST_SUITE_END;
// *INDENT-ON*
