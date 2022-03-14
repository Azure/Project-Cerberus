// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "flash_mock.h"
#include "flash/flash_common.h"


static int flash_mock_get_device_size (const struct flash *flash, uint32_t *bytes)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_get_device_size, flash, MOCK_ARG_CALL (bytes));
}

static int flash_mock_read (const struct flash *flash, uint32_t address, uint8_t *data,
	size_t length)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_read, flash, MOCK_ARG_CALL (address), MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (length));
}

static int flash_mock_get_page_size (const struct flash *flash, uint32_t *bytes)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_get_page_size, flash, MOCK_ARG_CALL (bytes));
}

static int flash_mock_minimum_write_per_page (const struct flash *flash, uint32_t *bytes)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_minimum_write_per_page, flash, MOCK_ARG_CALL (bytes));
}

static int flash_mock_write (const struct flash *flash, uint32_t address, const uint8_t *data,
	size_t length)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_write, flash, MOCK_ARG_CALL (address),
		MOCK_ARG_CALL (data), MOCK_ARG_CALL (length));
}

static int flash_mock_get_sector_size (const struct flash *flash, uint32_t *bytes)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_get_sector_size, flash, MOCK_ARG_CALL (bytes));
}

static int flash_mock_sector_erase (const struct flash *flash, uint32_t sector_addr)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_sector_erase, flash, MOCK_ARG_CALL (sector_addr));
}

static int flash_mock_get_block_size (const struct flash *flash, uint32_t *bytes)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_get_block_size, flash, MOCK_ARG_CALL (bytes));
}

static int flash_mock_block_erase (const struct flash *flash, uint32_t block_addr)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mock_block_erase, flash, MOCK_ARG_CALL (block_addr));
}

static int flash_mock_chip_erase (const struct flash *flash)
{
	struct flash_mock *mock = (struct flash_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_mock_chip_erase, flash);
}

static int flash_mock_func_arg_count (void *func)
{
	if ((func == flash_mock_read) || (func == flash_mock_write)) {
		return 3;
	}
	else if ((func == flash_mock_get_device_size) || (func == flash_mock_get_page_size) ||
		(func == flash_mock_minimum_write_per_page) || (func == flash_mock_get_sector_size) ||
		(func == flash_mock_sector_erase) || (func == flash_mock_get_block_size) ||
		(func == flash_mock_block_erase)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* flash_mock_func_name_map (void *func)
{
	if (func == flash_mock_get_device_size) {
		return "get_device_size";
	}
	else if (func == flash_mock_read) {
		return "read";
	}
	else if (func == flash_mock_get_page_size) {
		return "get_page_size";
	}
	else if (func == flash_mock_minimum_write_per_page) {
		return "minimum_write_per_page";
	}
	else if (func == flash_mock_write) {
		return "write";
	}
	else if (func == flash_mock_get_sector_size) {
		return "get_sector_size";
	}
	else if (func == flash_mock_sector_erase) {
		return "sector_erase";
	}
	else if (func == flash_mock_get_block_size) {
		return "get_block_size";
	}
	else if (func == flash_mock_block_erase) {
		return "block_erase";
	}
	else if (func == flash_mock_chip_erase) {
		return "chip_erase";
	}
	else {
		return "unknown";
	}
}

static const char* flash_mock_arg_name_map (void *func, int arg)
{
	if (func == flash_mock_get_device_size) {
		switch (arg) {
			case 0:
				return "bytes";
		}
	}
	else if (func == flash_mock_read) {
		switch (arg) {
			case 0:
				return "address";

			case 1:
				return "data";

			case 2:
				return "length";
		}
	}
	else if (func == flash_mock_get_page_size) {
		switch (arg) {
			case 0:
				return "bytes";
		}
	}
	else if (func == flash_mock_minimum_write_per_page) {
		switch (arg) {
			case 0:
				return "bytes";
		}
	}
	else if (func == flash_mock_write) {
		switch (arg) {
			case 0:
				return "address";

			case 1:
				return "data";

			case 2:
				return "length";
		}
	}
	else if (func == flash_mock_get_sector_size) {
		switch (arg) {
			case 0:
				return "bytes";
		}
	}
	else if (func == flash_mock_sector_erase) {
		switch (arg) {
			case 0:
				return "sector_addr";
		}
	}
	else if (func == flash_mock_get_block_size) {
		switch (arg) {
			case 0:
				return "bytes";
		}
	}
	else if (func == flash_mock_block_erase) {
		switch (arg) {
			case 0:
				return "block_addr";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a flash device.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int flash_mock_init (struct flash_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct flash_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "flash");

	memset (mock->blank, 0xff, sizeof (mock->blank));

	mock->base.get_device_size = flash_mock_get_device_size;
	mock->base.read = flash_mock_read;
	mock->base.get_page_size = flash_mock_get_page_size;
	mock->base.minimum_write_per_page = flash_mock_minimum_write_per_page;
	mock->base.write = flash_mock_write;
	mock->base.get_sector_size = flash_mock_get_sector_size;
	mock->base.sector_erase = flash_mock_sector_erase;
	mock->base.get_block_size = flash_mock_get_block_size;
	mock->base.block_erase = flash_mock_block_erase;
	mock->base.chip_erase = flash_mock_chip_erase;

	mock->mock.func_arg_count = flash_mock_func_arg_count;
	mock->mock.func_name_map = flash_mock_func_name_map;
	mock->mock.arg_name_map = flash_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a flash mock.
 *
 * @param mock The mock to release.
 */
void flash_mock_release (struct flash_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int flash_mock_validate_and_release (struct flash_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		flash_mock_release (mock);
	}

	return status;
}

/**
 * Add the expectations for blank checking a region of flash.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_blank_check (struct flash_mock *mock, uint32_t start, size_t length)
{
	int status = 0;
	size_t page_len;

	while (length > 0) {
		page_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= mock_expect (&mock->mock, mock->base.read, mock, 0, MOCK_ARG (start),
			MOCK_ARG_NOT_NULL, MOCK_ARG (page_len));
		status |= mock_expect_output (&mock->mock, 1, mock->blank, sizeof (mock->blank), 2);

		length -= page_len;
		start += page_len;
	}

	return status;
}

/**
 * Set up expectations for successfully erasing blocks of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the block.
 * @param length The length of the block to erase.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash (struct flash_mock *mock, uint32_t addr, size_t length)
{
	return flash_mock_expect_erase_flash_ext (mock, addr, length, FLASH_BLOCK_SIZE);
}

/**
 * Set up expectations for successfully erasing blocks of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 * @param length The length of the block to erase.
 * @param block_size The erase block size.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_ext (struct flash_mock *mock, uint32_t addr, size_t length,
	uint32_t block_size)
{
	int status;
	size_t erase_length;

	status = mock_expect (&mock->mock, mock->base.get_block_size, mock, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&mock->mock, 0, &block_size, sizeof (block_size), -1);

	while ((status == 0) && (length > 0)) {
		erase_length = block_size - FLASH_REGION_OFFSET (addr, block_size);
		erase_length = (length > erase_length) ? erase_length : length;

		status |= mock_expect (&mock->mock, mock->base.block_erase, mock, 0, MOCK_ARG (addr));

		addr += erase_length;
		length -= erase_length;
	}

	return status;
}

/**
 * Set up expectations for successfully erasing sectors of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 * @param length The length of the block to erase.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_sector (struct flash_mock *mock, uint32_t addr, size_t length)
{
	return flash_mock_expect_erase_flash_sector_ext (mock, addr, length, FLASH_SECTOR_SIZE);
}

/**
 * Set up expectations for successfully erasing sectors of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 * @param length The length of the block to erase.
 * @param sector_size The erase sector size.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_sector_ext (struct flash_mock *mock, uint32_t addr, size_t length,
	uint32_t sector_size)
{
	int status;
	size_t erase_length;

	status = mock_expect (&mock->mock, mock->base.get_sector_size, mock, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&mock->mock, 0, &sector_size, sizeof (sector_size), -1);

	while ((status == 0) && (length > 0)) {
		erase_length = sector_size - FLASH_REGION_OFFSET (addr, sector_size);
		erase_length = (length > erase_length) ? erase_length : length;

		status |= mock_expect (&mock->mock, mock->base.sector_erase, mock, 0, MOCK_ARG (addr));

		addr += erase_length;
		length -= erase_length;
	}

	return status;
}

/**
 * Set up expectations for successfully erasing a region of flash blocks with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_verify (struct flash_mock *mock, uint32_t addr, size_t length)
{
	return flash_mock_expect_erase_flash_verify_ext (mock, addr, length, FLASH_BLOCK_SIZE);
}

/**
 * Set up expectations for successfully erasing a region of flash blocks with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 * @param block_size The erase block size.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_verify_ext (struct flash_mock *mock, uint32_t addr, size_t length,
	uint32_t block_size)
{
	int status;

	status = flash_mock_expect_erase_flash_ext (mock, addr, length, block_size);
	status |= flash_mock_expect_blank_check (mock, addr, length);

	return status;
}

/**
 * Set up expectations for successfully erasing a region of flash sectors with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_sector_verify (struct flash_mock *mock, uint32_t addr,
	size_t length)
{
	return flash_mock_expect_erase_flash_sector_verify_ext (mock, addr, length, FLASH_SECTOR_SIZE);
}

/**
 * Set up expectations for successfully erasing a region of flash sectors with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 * @param sector_size The erase sector size.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_flash_sector_verify_ext (struct flash_mock *mock, uint32_t addr,
	size_t length, uint32_t sector_size)
{
	int status;

	status = flash_mock_expect_erase_flash_sector_ext (mock, addr, length, sector_size);
	status |= flash_mock_expect_blank_check (mock, addr, length);

	return status;
}

/**
 * Set up expectations for successfully copying flash data.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param page_size The size of a flash page.
 * @param verify Flag indicating if the copy is expected to be verified.
 * @param block_check Flag indicating if the block size will be checked.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_mock_expect_copy_flash_ext (struct flash_mock *mock_dest,
	struct flash_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint32_t page_size, bool verify, bool block_check)
{
	int status = 0;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	size_t page_len;
	uint32_t offset;

	if (block_check && (mock_dest == mock_src)) {
		status = mock_expect (&mock_src->mock, mock_src->base.get_block_size, mock_src, 0,
			MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&mock_src->mock, 0, &bytes, sizeof (bytes), -1);
	}

	status |= mock_expect (&mock_dest->mock, mock_dest->base.get_page_size, mock_dest, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&mock_dest->mock, 0, &page_size, sizeof (page_size), -1);

	offset = FLASH_REGION_OFFSET (dest_addr, page_size);
	while (length > 0) {
		page_len = page_size - offset;
		page_len = (length > page_len) ? page_len : length;

		status |= mock_expect (&mock_src->mock, mock_src->base.read, mock_src, 0,
			MOCK_ARG (src_addr), MOCK_ARG_NOT_NULL, MOCK_ARG (page_len));
		status |= mock_expect_output (&mock_src->mock, 1, data, length, 2);

		status |= mock_expect (&mock_dest->mock, mock_dest->base.write, mock_dest, page_len,
			MOCK_ARG (dest_addr), MOCK_ARG_PTR_CONTAINS (data, page_len), MOCK_ARG (page_len));

		if (verify) {
			status |= mock_expect (&mock_dest->mock, mock_dest->base.read, mock_dest, 0,
				MOCK_ARG (dest_addr), MOCK_ARG_NOT_NULL, MOCK_ARG (page_len));
			status |= mock_expect_output (&mock_dest->mock, 1, data, length, 2);
		}

		length -= page_len;
		dest_addr += page_len;
		src_addr += page_len;
		data += page_len;
	}

	return status;
}

/**
 * Set up expectations for successfully copying flash data with verification.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_copy_flash_verify (struct flash_mock *mock_dest, struct flash_mock *mock_src,
	uint32_t dest_addr, uint32_t src_addr, const uint8_t *data, size_t length)
{
	return flash_mock_expect_copy_flash_ext (mock_dest, mock_src, dest_addr, src_addr, data, length,
		FLASH_PAGE_SIZE, true, true);
}

/**
 * Set up expectations for successfully copying flash data with verification.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param page_size The size of a flash page.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_copy_flash_verify_ext (struct flash_mock *mock_dest,
	struct flash_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint32_t page_size)
{
	return flash_mock_expect_copy_flash_ext (mock_dest, mock_src, dest_addr, src_addr, data, length,
		page_size, true, true);
}

/**
 * Set up expectations for successfully erasing and copying flash data with verification.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_erase_copy_verify (struct flash_mock *mock_dest, struct flash_mock *mock_src,
	uint32_t dest_addr, uint32_t src_addr, const uint8_t *data, size_t length)
{
	int status = 0;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	if (mock_dest == mock_src) {
		status = mock_expect (&mock_src->mock, mock_src->base.get_block_size, mock_src, 0,
			MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&mock_src->mock, 0, &bytes, sizeof (bytes), -1);
	}

	status |= flash_mock_expect_erase_flash_verify (mock_dest, dest_addr, length);
	status |= flash_mock_expect_copy_flash_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, FLASH_PAGE_SIZE, true, false);

	return status;
}

/**
 * Set up expectations for successfully reading chunks of flash for verification.
 *
 * @param mock The mock for the flash being verified.
 * @param start The address to start verification.
 * @param data The data that should be returned from the flash.
 * @param length The length of data being verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_verify_flash (struct flash_mock *mock, uint32_t start, const uint8_t *data,
	size_t length)
{
	return flash_mock_expect_verify_flash_and_hash (mock, NULL, start, data, length);
}

/**
 * Set up expectations for successfully reading chunks of flash for verification.  The flash chucks
 * will optionally be hashed.
 *
 * @param mock The mock for the flash being verified.
 * @param hash The mock for hashing the flash data.  Set to null to skip hash mocking.
 * @param start The address to start verification.
 * @param data The data that should be returned from the flash.
 * @param length The length of data being verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_verify_flash_and_hash (struct flash_mock *mock, struct hash_engine_mock *hash,
	uint32_t start, const uint8_t *data, size_t length)
{
	int status = 0;
	size_t read_len;

	while (length != 0) {
		read_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= mock_expect (&mock->mock, mock->base.read, mock, 0, MOCK_ARG (start),
			MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
		status |= mock_expect_output (&mock->mock, 1, data, length, 2);

		if (hash) {
			status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
				MOCK_ARG_PTR_CONTAINS (data, read_len), MOCK_ARG (read_len));
		}

		start += read_len;
		data += read_len;
		length -= read_len;
	}

	return status;
}

/**
 * Set up expectations for successfully comparing the contents of two regions of flash.
 *
 * @param mock1 The mock for the first flash being compared
 * @param start1 The address to start comparison on the first flash.
 * @param data1 The data on the first flash.
 * @param mock2 The mock for the second flash being compared.
 * @param start2 The address to start comparison on the second flash.
 * @param data2 The data on the second flash.
 * @param length The length of data being compared.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_mock_expect_verify_copy (struct flash_mock *mock1, uint32_t start1, const uint8_t *data1,
	struct flash_mock *mock2, uint32_t start2, const uint8_t *data2, size_t length)
{
	int status = 0;
	size_t page_len;

	while ((length > 0) && (status == 0)) {
		page_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= mock_expect (&mock1->mock, mock1->base.read, mock1, 0, MOCK_ARG (start1),
			MOCK_ARG_NOT_NULL, MOCK_ARG (page_len));
		status |= mock_expect_output (&mock1->mock, 1, data1, length, 2);

		status |= mock_expect (&mock2->mock, mock2->base.read, mock2, 0, MOCK_ARG (start2),
			MOCK_ARG_NOT_NULL, MOCK_ARG (page_len));
		status |= mock_expect_output (&mock2->mock, 1, data2, length, 2);

		length -= page_len;
		start1 += page_len;
		data1 += page_len;
		start2 += page_len;
		data2 += page_len;
	}

	return status;
}
