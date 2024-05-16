// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_VIRTUAL_RAM_H_
#define FLASH_VIRTUAL_RAM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "flash.h"
#include "platform_api.h"
#include "status/rot_status.h"


/**
 * Block size of the virtual flash instance.
 */
#define	VIRTUAL_FLASH_BLOCK_SIZE		256

/**
 * Variable context for a virtual flash instance.
 */
struct flash_virtual_ram_state {
	platform_mutex lock;	/**< Lock to synchronize access to the hardware. */
};

/**
 * Defines a flash implementation that uses a RAM buffer as a virtual flash device. This can be
 * used in the same way as any other flash device, but the data is volatile.
 */
struct flash_virtual_ram {
	struct flash base;						/**< Base flash API. */
	struct flash_virtual_ram_state *state;	/**< Variable context for the virtual  instance. */
	uint8_t *buffer;						/**< Pointer to the memory buffer of virtual device. */
	size_t size;							/**< Size in bytes. */
};


int flash_virtual_ram_init (struct flash_virtual_ram *virtual_flash,
	struct flash_virtual_ram_state *state_ptr, uint8_t *buf_ptr, size_t size);
int flash_virtual_ram_init_state (struct flash_virtual_ram *virtual_ram);
void flash_virtual_ram_release (struct flash_virtual_ram *virtual_ram);


#endif	/* FLASH_VIRTUAL_RAM */
