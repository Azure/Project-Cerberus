// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_H_
#define HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_H_

#include "host_flash_manager_single.h"


/**
 * Manager for protected flash devices for a single host processor with a single flash
 * configuration.  There are two flash devices available, though only one is accessible at a time.
 */
struct host_flash_manager_single_with_backup {
	struct host_flash_manager_single base;	/**< Base flash manager interface. */
	const struct spi_flash *flash_cs1;		/**< The flash device connected to CS1. */
};


int host_flash_manager_single_with_backup_init (
	struct host_flash_manager_single_with_backup *manager, const struct spi_flash *cs0,
	const struct spi_flash *cs1, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler);
int host_flash_manager_single_with_backup_init_with_managed_flash_initialization (
	struct host_flash_manager_single_with_backup *manager, const struct spi_flash *cs0,
	const struct spi_flash *cs1, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler,
	const struct host_flash_initialization *flash_init);
void host_flash_manager_single_with_backup_release (
	const struct host_flash_manager_single_with_backup *manager);


#endif	/* HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_H_ */
