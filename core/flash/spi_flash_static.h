// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FLASH_STATIC_H_
#define SPI_FLASH_STATIC_H_

#include "flash/spi_flash.h"


/* Internal functions declared to allow for static initialization. */
int spi_flash_get_size_read_only (const struct flash *flash, uint32_t *bytes);
int spi_flash_write_read_only (const struct flash *flash, uint32_t address, const uint8_t *data,
	size_t length);
int spi_flash_erase_read_only (const struct flash *flash, uint32_t addr);
int spi_flash_chip_erase_read_only (const struct flash *flash);


/**
 * Constant initializer for the SPI flash API.
 */
#define	SPI_FLASH_API_INIT  { \
		.get_device_size = (int (*) (const struct flash*, uint32_t*)) spi_flash_get_device_size, \
		.read = (int (*) (const struct flash*, uint32_t, uint8_t*, size_t)) spi_flash_read, \
		.get_page_size = (int (*) (const struct flash*, uint32_t*)) spi_flash_get_page_size, \
		.minimum_write_per_page = \
			(int (*) (const struct flash*, uint32_t*)) spi_flash_minimum_write_per_page, \
		.write = \
			(int (*) (const struct flash*, uint32_t, const uint8_t*, size_t)) spi_flash_write, \
		.get_sector_size = (int (*) (const struct flash*, uint32_t*)) spi_flash_get_sector_size, \
		.sector_erase = (int (*) (const struct flash*, uint32_t)) spi_flash_sector_erase, \
		.get_block_size = (int (*) (const struct flash*, uint32_t*)) spi_flash_get_block_size, \
		.block_erase = (int (*) (const struct flash*, uint32_t)) spi_flash_block_erase, \
		.chip_erase = (int (*) (const struct flash*)) spi_flash_chip_erase \
	}

/**
 * Constant initializer for the SPI flash API that will only be allowed to read from the device.
 * All other API calls will return an error.
 *
 * This does not block the interface from being used to write to flash by calling spi_flash_*
 * functions directly.  This only disables it through the abstracted API.
 */
#define	SPI_FLASH_READ_ONLY_API_INIT  { \
		.get_device_size = (int (*) (const struct flash*, uint32_t*)) spi_flash_get_device_size, \
		.read = (int (*) (const struct flash*, uint32_t, uint8_t*, size_t)) spi_flash_read, \
		.get_page_size = spi_flash_get_size_read_only, \
		.minimum_write_per_page = spi_flash_get_size_read_only, \
		.write = spi_flash_write_read_only, \
		.get_sector_size = spi_flash_get_size_read_only, \
		.sector_erase = spi_flash_erase_read_only, \
		.get_block_size = spi_flash_get_size_read_only, \
		.block_erase = spi_flash_erase_read_only, \
		.chip_erase = spi_flash_chip_erase_read_only \
	}


/**
 * Initialize a static instance of a SPI flash device interface.
 *
 * There is no validation done on the arguments.
 *
 * @param api The API implementation that should be used.
 * @param state_ptr Variable context for the flash interface.
 * @param spi_ptr The SPI master connected to the flash.
 */
#define	spi_flash_static_init(api, state_ptr, spi_ptr)	{ \
		.base = api, \
		.state = state_ptr, \
		.spi = spi_ptr, \
	}


#endif /* SPI_FLASH_STATIC_H_ */
