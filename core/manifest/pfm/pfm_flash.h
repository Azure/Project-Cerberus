// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_FLASH_H
#define PFM_FLASH_H

#include <stdint.h>
#include "pfm.h"
#include "pfm_format.h"
#include "manifest/manifest_flash.h"
#include "flash/flash.h"


/**
 * Defines a PFM that is stored in flash memory.
 */
struct pfm_flash {
	struct pfm base;							/**< The base PFM instance. */
	struct manifest_flash base_flash;			/**< The base PFM flash instance. */
	struct pfm_flash_device_element flash_dev;	/**< Flash device element for the PFM. */
	int flash_dev_format;						/**< Format of the flash device element. */
};


int pfm_flash_init (struct pfm_flash *pfm, struct flash *flash, struct hash_engine *hash,
	uint32_t base_addr, uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id);
void pfm_flash_release (struct pfm_flash *pfm);


#endif //PFM_FLASH_H
