// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_FLASH_H
#define PCD_FLASH_H

#include <stdint.h>
#include "pcd.h"
#include "manifest/manifest_flash.h"
#include "flash/flash.h"


/**
 * Defines a PCD that is stored in flash memory.
 */
struct pcd_flash {
	struct pcd base;							/**< The base PCD instance. */
	struct manifest_flash base_flash;			/**< The base PCD flash instance. */
};


int pcd_flash_init (struct pcd_flash *pcd, struct flash *flash, struct hash_engine *hash, 
	uint32_t base_addr, uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id);
void pcd_flash_release (struct pcd_flash *pcd);


#endif //PCD_FLASH_H
