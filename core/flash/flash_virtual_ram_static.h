// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_VIRTUAL_RAM_STATIC_H_
#define FLASH_VIRTUAL_RAM_STATIC_H_

#include "flash_virtual_ram.h"


/* Internal functions declared to allow for static initialization. */
int flash_virtual_ram_get_device_size (const struct flash *virtual_ram, uint32_t *bytes);
int flash_virtual_ram_read (const struct flash *virtual_ram, uint32_t address, uint8_t *data,
	size_t length);
int flash_virtual_ram_get_block_size (const struct flash *virtual_ram, uint32_t *bytes);
int flash_virtual_ram_write (const struct flash *virtual_ram, uint32_t address,	const uint8_t *data,
	size_t length);
int flash_virtual_ram_block_erase (const struct flash *virtual_ram, uint32_t address);
int flash_virtual_ram_chip_erase (const struct flash *virtual_ram);

/**
 * Constant initializer for the virtual flash APIs.
 */
#define	FLASH_VIRTUAL_RAM_API_INIT  { \
		.get_device_size = flash_virtual_ram_get_device_size, \
		.read = flash_virtual_ram_read, \
		.get_page_size = flash_virtual_ram_get_block_size, \
		.minimum_write_per_page = flash_virtual_ram_get_block_size, \
		.write = flash_virtual_ram_write, \
		.get_sector_size = flash_virtual_ram_get_block_size, \
		.sector_erase = flash_virtual_ram_block_erase, \
		.get_block_size = flash_virtual_ram_get_block_size, \
		.block_erase = flash_virtual_ram_block_erase, \
		.chip_erase = flash_virtual_ram_chip_erase \
	}

/**
 * Initialize a static instance of a virtual ram device.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the virtual flash interface.
 * @param buf_ptr pointer to the buffer that is managed by the device.
 * @param buf_size Maximum size of the buffer.
 */
#define	flash_virtual_ram_static_init(state_ptr, buf_ptr, buf_size) { \
		.base = FLASH_VIRTUAL_RAM_API_INIT, \
		.state = state_ptr, \
		.buffer = buf_ptr, \
		.size = buf_size, \
	}


#endif	/* FLASH_STORE_AGGREGATOR_STATIC_H_*/
