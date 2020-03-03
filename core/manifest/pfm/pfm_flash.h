// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_FLASH_H
#define PFM_FLASH_H

#include <stdint.h>
#include "pfm.h"
#include "manifest/manifest_flash.h"
#include "flash/spi_flash.h"


/**
 * Defines a PFM that is stored in flash memory.
 */
struct pfm_flash {
	struct pfm base;							/**< The base PFM instance. */
	struct manifest_flash base_flash;			/**< The base PFM flash instance. */
};


int pfm_flash_init (struct pfm_flash *pfm, struct spi_flash *flash, uint32_t base_addr);
void pfm_flash_release (struct pfm_flash *pfm);

uint32_t pfm_flash_get_addr (struct pfm_flash *pfm);
struct spi_flash* pfm_flash_get_flash (struct pfm_flash *pfm);


#endif //PFM_FLASH_H
