// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_FLASH_H
#define CFM_FLASH_H

#include <stdint.h>
#include "cfm.h"
#include "manifest/manifest_flash.h"
#include "flash/flash.h"


/**
 * Defines a CFM that is stored in flash memory.
 */
struct cfm_flash {
	struct cfm base;							/**< The base CFM instance. */
	struct manifest_flash base_flash;			/**< The base CFM flash instance. */
};


int cfm_flash_init (struct cfm_flash *cfm, struct flash *flash, struct hash_engine *hash,
	uint32_t base_addr, uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id);
void cfm_flash_release (struct cfm_flash *cfm);


#endif //CFM_FLASH_H
