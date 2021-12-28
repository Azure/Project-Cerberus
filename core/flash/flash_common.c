// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "flash_common.h"


/**
 * Convert flash command address bytes (big endian) to an integer address.
 *
 * @param buf The buffer containing the address bytes.
 * @param addr_bytes The number of address bytes in the command.
 *
 * @return The integer address or an error code if the parameters are not valid.  Use ROT_IS_ERROR
 * to check the return value.
 */
uint32_t flash_address_to_int (const uint8_t *buf, uint8_t addr_bytes)
{
	if (buf == NULL) {
		return FLASH_COMMON_INVALID_ARGUMENT;
	}

	switch (addr_bytes) {
		case 3:
			return (((int) buf[0] << 16) | ((int) buf[1] << 8) | (buf[2]));

		case 4:
			return (((int) buf[0] << 24) | ((int) buf[1] << 16) | ((int) buf[2] << 8) | (buf[3]));

		default:
			return FLASH_COMMON_INVALID_ARGUMENT;
	}
}

/**
 * Convert an integer address to flash command bytes.  The converted address will be stored big
 * endian.
 *
 * @param address The flash address to convert.
 * @param addr_bytes The number of address bytes to populate.
 * @param buf The buffer that will hold the converted bytes.
 *
 * @return 0 if the conversion was successful or an error code if the parameters are not valid.
 */
int flash_int_to_address (uint32_t address, uint8_t addr_bytes, uint8_t *buf)
{
	if (buf == NULL) {
		return FLASH_COMMON_INVALID_ARGUMENT;
	}

	switch (addr_bytes) {
		case 3:
			buf[0] = address >> 16;
			buf[1] = address >> 8;
			buf[2] = address;
			break;

		case 4:
			buf[0] = address >> 24;
			buf[1] = address >> 16;
			buf[2] = address >> 8;
			buf[3] = address;
			break;

		default:
			return FLASH_COMMON_INVALID_ARGUMENT;
	}

	return 0;
}
