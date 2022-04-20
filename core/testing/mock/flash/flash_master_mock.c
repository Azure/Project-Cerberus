// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "flash_master_mock.h"
#include "flash/flash_common.h"


const uint8_t WIP_STATUS = 0;


static int flash_master_mock_xfer (const struct flash_master *spi, const struct flash_xfer *xfer)
{
	struct flash_master_mock *mock = (struct flash_master_mock*) spi;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_master_mock_xfer, spi, MOCK_ARG_CALL (xfer->cmd),
		MOCK_ARG_CALL (xfer->address), MOCK_ARG_CALL (xfer->dummy_bytes),
		MOCK_ARG_CALL (xfer->mode_bytes), MOCK_ARG_CALL (xfer->data), MOCK_ARG_CALL (xfer->length),
		MOCK_ARG_CALL (xfer->flags));
}

static uint32_t flash_master_mock_capabilities (const struct flash_master *spi)
{
	struct flash_master_mock *mock = (struct flash_master_mock*) spi;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_master_mock_capabilities, spi);
}

static int flash_master_mock_get_spi_clock_frequency (const struct flash_master *spi)
{
	struct flash_master_mock *mock = (struct flash_master_mock*) spi;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_master_mock_get_spi_clock_frequency, spi);
}

static int flash_master_mock_set_spi_clock_frequency (const struct flash_master *spi, uint32_t freq)
{
	struct flash_master_mock *mock = (struct flash_master_mock*) spi;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_master_mock_set_spi_clock_frequency, spi, MOCK_ARG_CALL (freq));
}

static int flash_master_mock_func_arg_count (void *func)
{
	if (func == flash_master_mock_xfer) {
		return 7;
	}
	else if (func == flash_master_mock_set_spi_clock_frequency) {
		return 1;
	}
	else {
		return 0;
	}
}

/**
 * Mock function name mapping.
 */
static const char* flash_master_mock_func_name_map (void *func)
{
	if (func == flash_master_mock_xfer) {
		return "xfer";
	}
	else if (func == flash_master_mock_capabilities) {
		return "capabilities";
	}
	else if (func == flash_master_mock_get_spi_clock_frequency) {
		return "get_spi_clock_frequency";
	}
	else if (func == flash_master_mock_set_spi_clock_frequency) {
		return "set_spi_clock_frequency";
	}
	else {
		return "unknown";
	}
}

/**
 * Mock function parameter name mapping.
 */
static const char* flash_master_mock_arg_name_map (void *func, int arg)
{
	if (func == flash_master_mock_xfer) {
		switch (arg) {
			case 0:
				return "xfer.cmd";

			case 1:
				return "xfer.address";

			case 2:
				return "xfer.dummy_bytes";

			case 3:
				return "xfer.mode_bytes";

			case 4:
				return "xfer.data";

			case 5:
				return "xfer.length";

			case 6:
				return "xfer.flags";
		}
	}
	else if (func == flash_master_mock_set_spi_clock_frequency) {
		switch (arg) {
			case 0:
				return "freq";
		}
	}

	return "unknown";
}

/**
 * Initialize a flash master mock instance.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int flash_master_mock_init (struct flash_master_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct flash_master_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "flash_master");

	memset (mock->blank, 0xff, sizeof (mock->blank));

	mock->base.xfer = flash_master_mock_xfer;
	mock->base.capabilities = flash_master_mock_capabilities;
	mock->base.get_spi_clock_frequency = flash_master_mock_get_spi_clock_frequency;
	mock->base.set_spi_clock_frequency = flash_master_mock_set_spi_clock_frequency;

	mock->mock.func_arg_count = flash_master_mock_func_arg_count;
	mock->mock.func_name_map = flash_master_mock_func_name_map;
	mock->mock.arg_name_map = flash_master_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a flash master mock instance.
 *
 * @param mock The mock to release.
 */
void flash_master_mock_release (struct flash_master_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to verify.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int flash_master_mock_validate_and_release (struct flash_master_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		flash_master_mock_release (mock);
	}

	return status;
}

/**
 * Add a mock expectation for a flash transfer that will neither send nor receive data.
 *
 * @param mock The mock to update.
 * @param return_val The value to return for the transfer.
 * @param xfer The transfer to expect.
 *
 * @return 0 if the expectation was added successfully or an error code.
 */
int flash_master_mock_expect_xfer (struct flash_master_mock *mock, intptr_t return_val,
	struct flash_xfer xfer)
{
	struct mock_expect_arg data =
		(xfer.data != (void*) -1) ? MOCK_ARG (xfer.data) : MOCK_ARG_NOT_NULL;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	return mock_expect (&mock->mock, flash_master_mock_xfer, mock, return_val, MOCK_ARG (xfer.cmd),
		MOCK_ARG (xfer.address), MOCK_ARG (xfer.dummy_bytes), MOCK_ARG (xfer.mode_bytes), data,
		MOCK_ARG (xfer.length), MOCK_ARG (xfer.flags));
}

/**
 * Add a mock expectation for a flash transfer that will send data.
 *
 * @param mock The mock to update.
 * @param return_val The value to return for the transfer.
 * @param xfer The transfer to expect.
 *
 * @return 0 if the expectation was added successfully or an error code.
 */
int flash_master_mock_expect_tx_xfer (struct flash_master_mock *mock, intptr_t return_val,
	struct flash_xfer xfer)
{
	return flash_master_mock_expect_tx_xfer_ext (mock, return_val, false, xfer);
}

/**
 * Add a mock expectation for a flash transfer that will send data.
 *
 * @param mock The mock to update.
 * @param return_val The value to return for the transfer.
 * @param is_tmp Flag to indicate if the transmit data is a temporary variable.
 * @param xfer The transfer to expect.
 *
 * @return 0 if the expectation was added successfully or an error code.
 */
int flash_master_mock_expect_tx_xfer_ext (struct flash_master_mock *mock, intptr_t return_val,
	bool is_tmp, struct flash_xfer xfer)
{
	struct mock_expect_arg data;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	if (xfer.data) {
		if (is_tmp) {
			data = MOCK_ARG_PTR_CONTAINS_TMP (xfer.data, xfer.length);
		}
		else {
			data = MOCK_ARG_PTR_CONTAINS (xfer.data, xfer.length);
		}
	}
	else {
		data = MOCK_ARG_NOT_NULL;
	}

	return mock_expect (&mock->mock, flash_master_mock_xfer, mock, return_val, MOCK_ARG (xfer.cmd),
		MOCK_ARG (xfer.address), MOCK_ARG (xfer.dummy_bytes), MOCK_ARG (xfer.mode_bytes), data,
		MOCK_ARG (xfer.length), MOCK_ARG (xfer.flags));
}

/**
 * Add a mock expectation for a flash transfer that will receive data.
 *
 * @param mock The mock to update.
 * @param return_val The value to return for the transfer.
 * @param rx_data The data to return for the transfer.
 * @param rx_length The length of the data.
 * @param xfer The transfer to expect.
 *
 * @return 0 if the expectation was added successfully or an error code.
 */
int flash_master_mock_expect_rx_xfer (struct flash_master_mock *mock, intptr_t return_val,
	const uint8_t *rx_data, size_t rx_length, struct flash_xfer xfer)
{
	return flash_master_mock_expect_rx_xfer_ext (mock, return_val, rx_data, rx_length, false, xfer);
}

/**
 * Add a mock expectation for a flash transfer that will receive data.
 *
 * @param mock The mock to update.
 * @param return_val The value to return for the transfer.
 * @param rx_data The data to return for the transfer.
 * @param rx_length The length of the data.
 * @param is_tmp Flag to indicate if the receive data is a temporary variable.
 * @param xfer The transfer to expect.
 *
 * @return 0 if the expectation was added successfully or an error code.
 */
int flash_master_mock_expect_rx_xfer_ext (struct flash_master_mock *mock, intptr_t return_val,
	const uint8_t *rx_data, size_t rx_length, bool is_tmp, struct flash_xfer xfer)
{
	struct mock_expect_arg data =
		(xfer.data != (void*) -1) ? MOCK_ARG (xfer.data) : MOCK_ARG_NOT_NULL;
	int status;

	if ((mock == NULL) || (rx_data == NULL) || (rx_length == 0)) {
		return MOCK_INVALID_ARGUMENT;
	}

	status = mock_expect (&mock->mock, flash_master_mock_xfer, mock, return_val,
		MOCK_ARG (xfer.cmd), MOCK_ARG (xfer.address), MOCK_ARG (xfer.dummy_bytes),
		MOCK_ARG (xfer.mode_bytes), data, MOCK_ARG (xfer.length), MOCK_ARG (xfer.flags));
	if (status != 0) {
		return status;
	}

	if (is_tmp) {
		return mock_expect_output_tmp (&mock->mock, 4, rx_data, rx_length, 5);
	}
	else {
		return mock_expect_output (&mock->mock, 4, rx_data, rx_length, 5);
	}
}

/**
 * Add the expectations for blank checking a region of flash.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_blank_check_ext (struct flash_master_mock *mock, uint32_t start,
	size_t length, uint8_t addr4)
{
	int status = 0;
	size_t page_len;

	while (length > 0) {
		page_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		if (!addr4) {
			status |= flash_master_mock_expect_rx_xfer (mock, 0, mock->blank, sizeof (mock->blank),
				FLASH_EXP_READ_CMD (0x03, start, 0, -1, page_len));
		}
		else {
			status |= flash_master_mock_expect_rx_xfer (mock, 0, mock->blank, sizeof (mock->blank),
				FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, start, 0, -1, page_len));
		}

		length -= page_len;
		start += page_len;
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
int flash_master_mock_expect_blank_check (struct flash_master_mock *mock, uint32_t start,
	size_t length)
{
	return flash_master_mock_expect_blank_check_ext (mock, start, length, 0);
}

/**
 * Add the expectations for blank checking a region of flash using 4-byte addresses.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_blank_check_4byte (struct flash_master_mock *mock, uint32_t start,
	size_t length)
{
	return flash_master_mock_expect_blank_check_ext (mock, start, length, 1);
}

/**
 * Add the expectations for blank checking a region of flash using explicit 4-byte address commands.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_blank_check_4byte_explicit (struct flash_master_mock *mock,
	uint32_t start, size_t length)
{
	return flash_master_mock_expect_blank_check_ext (mock, start, length, 2);
}

/**
 * Add the expectations for value checking a region of flash.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be checked.
 * @param length The length of the region.
 * @param value The static value contained in the flash.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_value_check_ext (struct flash_master_mock *mock, uint32_t start,
	size_t length, uint8_t value, uint8_t addr4)
{
	int status = 0;
	size_t page_len;
	uint8_t check[FLASH_VERIFICATION_BLOCK];

	memset (check, value, sizeof (check));

	while (length > 0) {
		page_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		if (!addr4) {
			status |= flash_master_mock_expect_rx_xfer_ext (mock, 0, check, sizeof (check), true,
				FLASH_EXP_READ_CMD (0x03, start, 0, -1, page_len));
		}
		else {
			status |= flash_master_mock_expect_rx_xfer_ext (mock, 0, check, sizeof (check), true,
				FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, start, 0, -1, page_len));
		}

		length -= page_len;
		start += page_len;
	}

	return status;
}

/**
 * Add the expectations for value checking a region of flash.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 * @param value The static value contained in the flash.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_value_check (struct flash_master_mock *mock, uint32_t start,
	size_t length, uint8_t value)
{
	return flash_master_mock_expect_value_check_ext (mock, start, length, value, 0);
}

/**
 * Add the expectations for value checking a region of flash using 4-byte addresses.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 * @param value The static value contained in the flash.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_value_check_4byte (struct flash_master_mock *mock, uint32_t start,
	size_t length, uint8_t value)
{
	return flash_master_mock_expect_value_check_ext (mock, start, length, value, 1);
}

/**
 * Add the expectations for value checking a region of flash using explicit 4-byte address commands.
 *
 * @param mock The mock to update with the expectations.
 * @param start The start of the region that will be blank checked.
 * @param length The length of the region.
 * @param value The static value contained in the flash.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_value_check_4byte_explicit (struct flash_master_mock *mock,
	uint32_t start, size_t length, uint8_t value)
{
	return flash_master_mock_expect_value_check_ext (mock, start, length, value, 2);
}

/**
 * Set up expectations for successfully erasing a block of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the block.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_erase_flash_ext (struct flash_master_mock *mock, uint32_t addr,
	uint8_t addr4)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (mock, 0, FLASH_EXP_WRITE_ENABLE);
	if (!addr4) {
		status |= flash_master_mock_expect_xfer (mock, 0, FLASH_EXP_ERASE_CMD (0xd8, addr));
	}
	else {
		status |= flash_master_mock_expect_xfer (mock, 0,
			FLASH_EXP_ERASE_4B_CMD ((addr4 == 1) ? 0xd8 : 0xdc, addr));
	}
	status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	return status;
}

/**
 * Set up expectations for successfully erasing a block of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the block.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash (struct flash_master_mock *mock, uint32_t addr)
{
	return flash_master_mock_expect_erase_flash_ext (mock, addr, 0);
}

/**
 * Set up expectations for successfully erasing a block of flash using 4-byte addresses.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the block.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_4byte (struct flash_master_mock *mock, uint32_t addr)
{
	return flash_master_mock_expect_erase_flash_ext (mock, addr, 1);
}

/**
 * Set up expectations for successfully erasing a block of flash using explicit 4-byte address
 * commands.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the block.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_4byte_explicit (struct flash_master_mock *mock,
	uint32_t addr)
{
	return flash_master_mock_expect_erase_flash_ext (mock, addr, 2);
}

/**
 * Set up expectations for successfully erasing a sector of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_erase_flash_sector_ext (struct flash_master_mock *mock,
	uint32_t addr, uint8_t addr4)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (mock, 0, FLASH_EXP_WRITE_ENABLE);
	if (!addr4) {
		status |= flash_master_mock_expect_xfer (mock, 0, FLASH_EXP_ERASE_CMD (0x20, addr));
	}
	else {
		status |= flash_master_mock_expect_xfer (mock, 0,
			FLASH_EXP_ERASE_4B_CMD ((addr4 == 1) ? 0x20 : 0x21, addr));
	}
	status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	return status;
}

/**
 * Set up expectations for successfully erasing a sector of flash.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_sector (struct flash_master_mock *mock, uint32_t addr)
{
	return flash_master_mock_expect_erase_flash_sector_ext (mock, addr, 0);
}

/**
 * Set up expectations for successfully erasing a sector of flash using 4-byte addresses.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_sector_4byte (struct flash_master_mock *mock,
	uint32_t addr)
{
	return flash_master_mock_expect_erase_flash_sector_ext (mock, addr, 1);
}

/**
 * Set up expectations for successfully erasing a sector of flash using explicit 4-byte address
 * commands.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the sector.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_sector_4byte_explicit (struct flash_master_mock *mock,
	uint32_t addr)
{
	return flash_master_mock_expect_erase_flash_sector_ext (mock, addr, 2);
}

/**
 * Set up expectations for successfully erasing a region of flash with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_erase_flash_verify_ext (struct flash_master_mock *mock,
	uint32_t addr, size_t length, uint8_t addr4)
{
	int status;

	status = flash_master_mock_expect_erase_flash_ext (mock, FLASH_BLOCK_BASE (addr), addr4);
	status |= flash_master_mock_expect_blank_check_ext (mock, addr, length, addr4);

	return status;
}

/**
 * Set up expectations for successfully erasing a region of flash with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_verify (struct flash_master_mock *mock, uint32_t addr,
	size_t length)
{
	return flash_master_mock_expect_erase_flash_verify_ext (mock, addr, length, 0);
}

/**
 * Set up expectations for successfully erasing a region of flash with a blank check using 4-byte
 * addresses.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_verify_4byte (struct flash_master_mock *mock,
	uint32_t addr, size_t length)
{
	return flash_master_mock_expect_erase_flash_verify_ext (mock, addr, length, 1);
}

/**
 * Set up expectations for successfully erasing a region of flash with a blank check using explicit
 * 4-byte address commands.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_verify_4byte_explicit (struct flash_master_mock *mock,
	uint32_t addr, size_t length)
{
	return flash_master_mock_expect_erase_flash_verify_ext (mock, addr, length, 2);
}

/**
 * Set up expectations for successfully erasing a sector of flash with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_erase_flash_sector_verify_ext (struct flash_master_mock *mock,
	uint32_t addr, size_t length, uint8_t addr4)
{
	int status;

	status = flash_master_mock_expect_erase_flash_sector_ext (mock, FLASH_SECTOR_BASE (addr),
		addr4);
	status |= flash_master_mock_expect_blank_check_ext (mock, addr, length, addr4);

	return status;
}

/**
 * Set up expectations for successfully erasing a sector of flash with a blank check.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_sector_verify (struct flash_master_mock *mock,
	uint32_t addr, size_t length)
{
	return flash_master_mock_expect_erase_flash_sector_verify_ext (mock, addr, length, 0);
}

/**
 * Set up expectations for successfully erasing a sector of flash with a blank check using 4-byte
 * addresses.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_sector_verify_4byte (struct flash_master_mock *mock,
	uint32_t addr, size_t length)
{
	return flash_master_mock_expect_erase_flash_sector_verify_ext (mock, addr, length, 1);
}

/**
 * Set up expectations for successfully erasing a sector of flash with a blank check using explicit
 * 4-byte address commands.
 *
 * @param mock The mock to update.
 * @param addr The starting address of the region.
 * @param length The length of the region.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_erase_flash_sector_verify_4byte_explicit (
	struct flash_master_mock *mock, uint32_t addr, size_t length)
{
	return flash_master_mock_expect_erase_flash_sector_verify_ext (mock, addr, length, 2);
}

/**
 * Set up expectations for successfully executing a chip erase command.
 *
 * @param mock The mock to update.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_chip_erase (struct flash_master_mock *mock)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (mock, 0, FLASH_EXP_OPCODE (0xc7));
	status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	return status;
}

/**
 * Set up expectations for successfully copying a single page of flash.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param verify Flag indicating the copy is expected to be verified.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_copy_page_ext (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify, uint8_t addr4)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (mock_src, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	if (!addr4) {
		status |= flash_master_mock_expect_rx_xfer (mock_src, 0, data, length,
			FLASH_EXP_READ_CMD (0x03, src_addr, 0, -1, length));
	}
	else {
		status |= flash_master_mock_expect_rx_xfer (mock_src, 0, data, length,
			FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, src_addr, 0, -1, length));
	}

	status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (mock_dest, 0, FLASH_EXP_WRITE_ENABLE);
	if (!addr4) {
		status |= flash_master_mock_expect_tx_xfer (mock_dest, 0,
			FLASH_EXP_WRITE_CMD (0x02, dest_addr, 0, data, length));
	}
	else {
		status |= flash_master_mock_expect_tx_xfer (mock_dest, 0,
			FLASH_EXP_WRITE_4B_CMD ((addr4 == 1) ? 0x02 : 0x12, dest_addr, 0, data, length));
	}
	status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	if (verify) {
		status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		if (!addr4) {
			status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, data, length,
				FLASH_EXP_READ_CMD (0x03, dest_addr, 0, -1, length));
		}
		else {
			status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, data, length,
				FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, dest_addr, 0, -1, length));
		}
	}

	return status;
}

/**
 * Set up expectations for successfully copying a single page of flash.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param verify Flag indicating the copy is expected to be verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_copy_page (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify)
{
	return flash_master_mock_expect_copy_page_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, verify, 0);
}

/**
 * Set up expectations for successfully copying a single page of flash using 4-byte addresses.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param verify Flag indicating the copy is expected to be verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_copy_page_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify)
{
	return flash_master_mock_expect_copy_page_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, verify, 1);
}

/**
 * Set up expectations for successfully copying a single page of flash using explicit 4-byte address
 * commands.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param verify Flag indicating the copy is expected to be verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_copy_page_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify)
{
	return flash_master_mock_expect_copy_page_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, verify, 2);
}

/**
 * Set up expectations for successfully copying a single page of flash with verification.
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
int flash_master_mock_expect_copy_page_verify (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	return flash_master_mock_expect_copy_page (mock_dest, mock_src, dest_addr, src_addr, data,
		length, 1);
}

/**
 * Set up expectations for successfully copying a single page of flash with verification using
 * 4-byte addresses.
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
int flash_master_mock_expect_copy_page_verify_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	return flash_master_mock_expect_copy_page_4byte (mock_dest, mock_src, dest_addr, src_addr, data,
		length, 1);
}

/**
 * Set up expectations for successfully copying a single page of flash with verification using
 * explicit 4-byte address commands.
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
int flash_master_mock_expect_copy_page_verify_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	return flash_master_mock_expect_copy_page_4byte_explicit (mock_dest, mock_src, dest_addr,
		src_addr, data, length, 1);
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
 * @param verify Flag indicating if the copy is expected to be verified.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_copy_flash_ext (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify, uint8_t addr4)
{
	int status = 0;
	size_t page_len;

	while (length > 0) {
		page_len = (length > FLASH_PAGE_SIZE) ? FLASH_PAGE_SIZE : length;

		status |= flash_master_mock_expect_copy_page_ext (mock_dest, mock_src, dest_addr, src_addr,
			data, page_len, verify, addr4);

		length -= page_len;
		dest_addr += page_len;
		src_addr += page_len;
		data += page_len;
	}

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
 * @param verify Flag indicating if the copy is expected to be verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_copy_flash (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify)
{
	return flash_master_mock_expect_copy_flash_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, verify, 0);
}

/**
 * Set up expectations for successfully copying flash data using 4-byte addresses.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param verify Flag indicating if the copy is expected to be verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_copy_flash_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify)
{
	return flash_master_mock_expect_copy_flash_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, verify, 1);
}

/**
 * Set up expectations for successfully copying flash data using explicit 4-byte address commands.
 *
 * @param mock_dest The mock for the destination flash.
 * @param mock_src The mock for the source flash.
 * @param dest_addr The destination address.
 * @param src_addr The source address.
 * @param data The data that will be copied.
 * @param length The length of the data.
 * @param verify Flag indicating if the copy is expected to be verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_copy_flash_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify)
{
	return flash_master_mock_expect_copy_flash_ext (mock_dest, mock_src, dest_addr, src_addr, data,
		length, verify, 2);
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
int flash_master_mock_expect_copy_flash_verify (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	return flash_master_mock_expect_copy_flash (mock_dest, mock_src, dest_addr, src_addr, data,
		length, 1);
}

/**
 * Set up expectations for successfully copying flash data with verification using 4-byte addresses.
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
int flash_master_mock_expect_copy_flash_verify_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	return flash_master_mock_expect_copy_flash_4byte (mock_dest, mock_src, dest_addr, src_addr,
		data, length, 1);
}

/**
 * Set up expectations for successfully copying flash data with verification using explicit 4-byte
 * address commands.
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
int flash_master_mock_expect_copy_flash_verify_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	return flash_master_mock_expect_copy_flash_4byte_explicit (mock_dest, mock_src, dest_addr,
		src_addr, data, length, 1);
}

/**
 * Set up expectations for successfully reading chunks of flash for verification.
 *
 * @param mock The mock for the flash being verified.
 * @param start The address to start verification.
 * @param data The data that should be returned from the flash.
 * @param length The length of data being verified.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_verify_flash_ext (struct flash_master_mock *mock,
	uint32_t start, const uint8_t *data, size_t length, uint8_t addr4)
{
	int status = 0;
	size_t read_len;

	while (length != 0) {
		read_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		if (!addr4) {
			status |= flash_master_mock_expect_rx_xfer (mock, 0, data, length,
				FLASH_EXP_READ_CMD (0x03, start, 0, -1, read_len));
		}
		else {
			status |= flash_master_mock_expect_rx_xfer (mock, 0, data, length,
				FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, start, 0, -1, read_len));
		}

		start += read_len;
		data += read_len;
		length -= read_len;
	}

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
int flash_master_mock_expect_verify_flash (struct flash_master_mock *mock, uint32_t start,
	const uint8_t *data, size_t length)
{
	return flash_master_mock_expect_verify_flash_ext (mock, start, data, length, 0);
}

/**
 * Set up expectations for successfully reading chunks of flash for verification using 4-byte
 * addresses.
 *
 * @param mock The mock for the flash being verified.
 * @param start The address to start verification.
 * @param data The data that should be returned from the flash.
 * @param length The length of data being verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_verify_flash_4byte (struct flash_master_mock *mock, uint32_t start,
	const uint8_t *data, size_t length)
{
	return flash_master_mock_expect_verify_flash_ext (mock, start, data, length, 1);
}

/**
 * Set up expectations for successfully reading chunks of flash for verification using explicit
 * 4-byte address commands.
 *
 * @param mock The mock for the flash being verified.
 * @param start The address to start verification.
 * @param data The data that should be returned from the flash.
 * @param length The length of data being verified.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_verify_flash_4byte_explicit (struct flash_master_mock *mock,
	uint32_t start, const uint8_t *data, size_t length)
{
	return flash_master_mock_expect_verify_flash_ext (mock, start, data, length, 2);
}

/**
 * Set up expectations for successfully programming data to a flash device.
 *
 * @param flash The mock for the flash.
 * @param address The address to start writing to.
 * @param data The data to write.
 * @param length The length of the data.
 * @param is_tmp Flag to indicate if the transmit data is a temporary variable.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_write_ext (struct flash_master_mock *flash, uint32_t address,
	const uint8_t *data, size_t length, bool is_tmp, uint8_t addr4)
{
	uint32_t page = FLASH_PAGE_BASE (address);
	uint32_t next = page + FLASH_PAGE_SIZE;
	uint32_t end;
	size_t remaining = length;
	size_t txn_size;
	int status;
	int idx;


	status = flash_master_mock_expect_rx_xfer (flash, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	for (idx = 0; remaining > 0; ++idx) {
		end = address + remaining;

		if (page != FLASH_PAGE_BASE (end)) {
			txn_size = next - address;
		}
		else {
			txn_size = remaining;
		}

		status |= flash_master_mock_expect_xfer (flash, 0, FLASH_EXP_WRITE_ENABLE);

		if (!addr4) {
			status |= flash_master_mock_expect_tx_xfer_ext (flash, 0, is_tmp,
				FLASH_EXP_WRITE_CMD (0x02, address, 0, data, txn_size));
		}
		else {
			status |= flash_master_mock_expect_tx_xfer_ext (flash, 0, is_tmp,
				FLASH_EXP_WRITE_4B_CMD ((addr4 == 1) ? 0x02 : 0x12, address, 0, data, txn_size));
		}

		status |= flash_master_mock_expect_rx_xfer (flash, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);

		remaining -= txn_size;
		page = next;
		address = next;
		next += FLASH_PAGE_SIZE;
		if (data) {
			data += txn_size;
		}
	}

	return status;
}

/**
 * Set up expectations for successfully programming data to a flash device.
 *
 * @param flash The mock for the flash.
 * @param address The address to start writing to.
 * @param data The data to write.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_write (struct flash_master_mock *flash, uint32_t address,
	const uint8_t *data, size_t length)
{
	return flash_master_mock_expect_write_ext (flash, address, data, length, false, 0);
}

/**
 * Set up expectations for successfully programming data to a flash device using 4-byte addresses.
 *
 * @param flash The mock for the flash.
 * @param address The address to start writing to.
 * @param data The data to write.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_write_4byte (struct flash_master_mock *flash, uint32_t address,
	const uint8_t *data, size_t length)
{
	return flash_master_mock_expect_write_ext (flash, address, data, length, false, 1);
}

/**
 * Set up expectations for successfully programming data to a flash device using explicit 4-byte
 * address commands.
 *
 * @param flash The mock for the flash.
 * @param address The address to start writing to.
 * @param data The data to write.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_write_4byte_explicit (struct flash_master_mock *flash,
	uint32_t address, const uint8_t *data, size_t length)
{
	return flash_master_mock_expect_write_ext (flash, address, data, length, false, 2);
}

/**
 * Add the expectations for comparing two regions of flash.
 *
 * @param mock_src The mock to update with the expectations for sourcing data.
 * @param mock_check The mock to update with the expectations for checking data.
 * @param start The start of the region of the expected data.
 * @param data The data in the sourced region.
 * @param start_check The start of the region to check.
 * @param data_check The data in the checked region.  If this is null, the source data will be used.
 * @param length The length of the region.
 * @param addr4 Type of of 4-byte addressing to use:  0 = None, 1 = 4-byte, 2 = explicit 4-byte
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
static int flash_master_mock_expect_verify_copy_ext (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t start, const uint8_t *data, uint32_t start_check,
	const uint8_t *data_check, size_t length, uint8_t addr4)
{
	int status = 0;
	size_t page_len;

	if (data_check == NULL) {
		data_check = data;
	}

	while (length > 0) {
		page_len = (length > FLASH_VERIFICATION_BLOCK) ? FLASH_VERIFICATION_BLOCK : length;

		status |= flash_master_mock_expect_rx_xfer (mock_src, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		if (!addr4) {
			status |= flash_master_mock_expect_rx_xfer_ext (mock_src, 0, data, page_len, true,
				FLASH_EXP_READ_CMD (0x03, start, 0, -1, page_len));
		}
		else {
			status |= flash_master_mock_expect_rx_xfer_ext (mock_src, 0, data, page_len, true,
				FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, start, 0, -1, page_len));
		}

		status |= flash_master_mock_expect_rx_xfer (mock_check, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		if (!addr4) {
			status |= flash_master_mock_expect_rx_xfer_ext (mock_check, 0, data_check, page_len,
				true, FLASH_EXP_READ_CMD (0x03, start_check, 0, -1, page_len));
		}
		else {
			status |= flash_master_mock_expect_rx_xfer_ext (mock_check, 0, data_check, page_len,
				true,
				FLASH_EXP_READ_4B_CMD ((addr4 == 1) ? 0x03 : 0x13, start_check, 0, -1, page_len));
		}

		if (memcmp (data, data_check, page_len) == 0) {
			length -= page_len;
			start += page_len;
			data += page_len;
			start_check += page_len;
			data_check += page_len;
		}
		else {
			length = 0;
		}
	}

	return status;
}

/**
 * Set up expectations for comparing the data in two regions of flash.
 *
 * @param mock_src The mock for the flash that contains the expected data.
 * @param mock_check The mock for the flash that will be checked.
 * @param src_addr The start address of the expected data.
 * @param check_addr The start address of the data to check.
 * @param data The expected data.
 * @param check_data Optionally, the data on the flash to check.  If null, the expected data will be
 * used.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_verify_copy (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t src_addr, uint32_t check_addr,
	const uint8_t *data, const uint8_t *check_data, size_t length)
{
	return flash_master_mock_expect_verify_copy_ext (mock_src, mock_check, src_addr, data,
		check_addr, check_data, length, 0);
}

/**
 * Set up expectations for comparing the data in two regions of flash using 4-byte addresses.
 *
 * @param mock_src The mock for the flash that contains the expected data.
 * @param mock_check The mock for the flash that will be checked.
 * @param src_addr The start address of the expected data.
 * @param check_addr The start address of the data to check.
 * @param data The expected data.
 * @param check_data Optionally, the data on the flash to check.  If null, the expected data will be
 * used.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_verify_copy_4byte (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t src_addr, uint32_t check_addr,
	const uint8_t *data, const uint8_t *check_data, size_t length)
{
	return flash_master_mock_expect_verify_copy_ext (mock_src, mock_check, src_addr, data,
		check_addr, check_data, length, 1);
}

/**
 * Set up expectations for comparing the data in two regions of flash using explicit 4-byte address
 * commands.
 *
 * @param mock_src The mock for the flash that contains the expected data.
 * @param mock_check The mock for the flash that will be checked.
 * @param src_addr The start address of the expected data.
 * @param check_addr The start address of the data to check.
 * @param data The expected data.
 * @param check_data Optionally, the data on the flash to check.  If null, the expected data will be
 * used.
 * @param length The length of the data.
 *
 * @return 0 if the expectations were added successfully or non-zero if not.
 */
int flash_master_mock_expect_verify_copy_4byte_explicit (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t src_addr, uint32_t check_addr,
	const uint8_t *data, const uint8_t *check_data, size_t length)
{
	return flash_master_mock_expect_verify_copy_ext (mock_src, mock_check, src_addr, data,
		check_addr, check_data, length, 2);
}
