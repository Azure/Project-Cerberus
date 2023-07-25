// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "flash_virtual_ram.h"


int flash_virtual_ram_get_device_size (const struct flash *virtual_flash, uint32_t *bytes)
{
	const struct flash_virtual_ram *ram = (const struct flash_virtual_ram*) virtual_flash;

	if ((ram == NULL) || (bytes == NULL)) {
		return FLASH_INVALID_ARGUMENT;
	}

	*bytes = ram->size;

	return 0;
}

int flash_virtual_ram_read (const struct flash *virtual_flash, uint32_t address, uint8_t *data,
	size_t length)
{
	struct flash_virtual_ram *ram = (struct flash_virtual_ram*) virtual_flash;

	if ((ram == NULL) || (data == NULL)) {
		return FLASH_INVALID_ARGUMENT;
	}

	if ((address >= ram->size) || (length > (ram->size - address))) {
		return FLASH_ADDRESS_OUT_OF_RANGE;
	}

	platform_mutex_lock (&ram->state->lock);

	memcpy (data, (ram->buffer + address), length);

	platform_mutex_unlock (&ram->state->lock);

	return 0;
}

int flash_virtual_ram_get_block_size (const struct flash *virtual_flash, uint32_t *bytes)
{
	if ((virtual_flash == NULL) || (bytes == NULL)) {
		return FLASH_INVALID_ARGUMENT;
	}

	*bytes = VIRTUAL_FLASH_BLOCK_SIZE;

	return 0;
}

int flash_virtual_ram_write (const struct flash *virtual_flash, uint32_t address,
	const uint8_t *data, size_t length)
{
	const struct flash_virtual_ram *ram = (const struct flash_virtual_ram*) virtual_flash;

	if ((ram == NULL) || (data == NULL)) {
		return FLASH_INVALID_ARGUMENT;
	}

	if ((address >= ram->size) || (length > (ram->size - address))) {
		return FLASH_ADDRESS_OUT_OF_RANGE;
	}

	platform_mutex_lock (&ram->state->lock);

	memcpy ((ram->buffer + address), data, length);

	platform_mutex_unlock (&ram->state->lock);

	return length;
}

int flash_virtual_ram_block_erase (const struct flash *virtual_flash, uint32_t address)
{
	const struct flash_virtual_ram *ram = (const struct flash_virtual_ram*) virtual_flash;

	if (ram == NULL) {
		return FLASH_INVALID_ARGUMENT;
	}

	if (address >= ram->size) {
		return FLASH_ADDRESS_OUT_OF_RANGE;
	}

	address = FLASH_REGION_BASE (address, VIRTUAL_FLASH_BLOCK_SIZE);

	platform_mutex_lock (&ram->state->lock);

	memset ((ram->buffer + address), 0xFF, VIRTUAL_FLASH_BLOCK_SIZE);

	platform_mutex_unlock (&ram->state->lock);

	return 0;
}

int flash_virtual_ram_chip_erase (const struct flash *virtual_flash)
{
	const struct flash_virtual_ram *ram = (const struct flash_virtual_ram*) virtual_flash;

	if (ram == NULL) {
		return FLASH_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ram->state->lock);

	memset (ram->buffer, 0xFF, ram->size);

	platform_mutex_unlock (&ram->state->lock);

	return 0;
}

/**
 * Initialize the virtual flash device using a RAM buffer for the data storage.
 *
 * @param virtual_flash The device instance to initialize.
 * @param state_ptr Variable context for the virtual flash interface.
 * @param buf_ptr pointer to the buffer that is managed by the device.
 * @param size Maximum size of the buffer.
 *
 * @return 0 if the device was successfully initialized or an error code.
 */
int flash_virtual_ram_init (struct flash_virtual_ram *virtual_flash,
	struct flash_virtual_ram_state *state_ptr, uint8_t *buf_ptr, size_t size)
{
	if (virtual_flash == NULL) {
		return FLASH_INVALID_ARGUMENT;
	}

	memset (virtual_flash, 0, sizeof (struct flash_virtual_ram));

	virtual_flash->base.get_device_size = flash_virtual_ram_get_device_size;
	virtual_flash->base.read = flash_virtual_ram_read;
	virtual_flash->base.get_page_size = flash_virtual_ram_get_block_size;
	virtual_flash->base.minimum_write_per_page = flash_virtual_ram_get_block_size;
	virtual_flash->base.write = flash_virtual_ram_write;
	virtual_flash->base.get_sector_size = flash_virtual_ram_get_block_size;
	virtual_flash->base.sector_erase = flash_virtual_ram_block_erase;
	virtual_flash->base.get_block_size = flash_virtual_ram_get_block_size;
	virtual_flash->base.block_erase = flash_virtual_ram_block_erase;
	virtual_flash->base.chip_erase = flash_virtual_ram_chip_erase;

	virtual_flash->buffer = buf_ptr;
	virtual_flash->size = size;
	virtual_flash->state = state_ptr;

	return flash_virtual_ram_init_state (virtual_flash);
}

/**
 * Initialize only the variable state for an virtual flash interface.  The rest of the interface is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param virtual_flash The virtual flash instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int flash_virtual_ram_init_state (struct flash_virtual_ram *virtual_flash)
{
	if ((virtual_flash == NULL) || (virtual_flash->state == NULL) ||
		(virtual_flash->buffer == NULL) || (virtual_flash->size == 0)) {
		return FLASH_INVALID_ARGUMENT;
	}

	memset (virtual_flash->state, 0, sizeof (struct flash_virtual_ram_state));

	return platform_mutex_init (&virtual_flash->state->lock);
}

/**
 * Release the resources used by the virtual ram instance.
 *
 * @param virtual_flash The virtual flash instance to release.
 */
void flash_virtual_ram_release (struct flash_virtual_ram *virtual_flash)
{
	if (virtual_flash) {
		platform_mutex_free (&virtual_flash->state->lock);
	}
}
