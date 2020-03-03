// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_FLASH_H
#define CFM_FLASH_H

#include <stdint.h>
#include "cfm.h"
#include "manifest/manifest_flash.h"
#include "flash/spi_flash.h"


/**
 * Defines a CFM that is stored in flash memory.
 */
struct cfm_flash {
	struct cfm base;							/**< The base CFM instance. */
	struct manifest_flash base_flash;			/**< The base CFM flash instance. */
};


int cfm_flash_init (struct cfm_flash *cfm, struct spi_flash *flash, uint32_t base_addr);
void cfm_flash_release (struct cfm_flash *cfm);

uint32_t cfm_flash_get_addr (struct cfm_flash *cfm);
struct spi_flash* cfm_flash_get_flash (struct cfm_flash *cfm);


#endif //CFM_FLASH_H
