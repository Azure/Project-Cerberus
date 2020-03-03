// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_FLASH_H
#define PCD_FLASH_H

#include <stdint.h>
#include "pcd.h"
#include "manifest/manifest_flash.h"
#include "flash/spi_flash.h"


/**
 * Defines a PCD that is stored in flash memory.
 */
struct pcd_flash {
	struct pcd base;							/**< The base PCD instance. */
	struct manifest_flash base_flash;			/**< The base PCD flash instance. */
};


int pcd_flash_init (struct pcd_flash *pcd, struct spi_flash *flash, uint32_t base_addr);
void pcd_flash_release (struct pcd_flash *pcd);

uint32_t pcd_flash_get_addr (struct pcd_flash *pcd);
struct spi_flash* pcd_flash_get_flash (struct pcd_flash *pcd);


#endif //PCD_FLASH_H
