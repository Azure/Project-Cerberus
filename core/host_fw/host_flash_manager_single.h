// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_SINGLE_H_
#define HOST_FLASH_MANAGER_SINGLE_H_

#include "host_flash_manager.h"
#include "host_state_manager.h"
#include "spi_filter/flash_mfg_filter_handler.h"


/**
 * Manager for protected flash devices for a single host processor with a single flash
 * configuration.
 */
struct host_flash_manager_single {
	struct host_flash_manager base;					/**< Base flash manager interface. */
	struct spi_flash *flash;						/**< The host flash device. */
	struct host_state_manager *host_state;			/**< State information for the host using the flash. */
	struct spi_filter_interface *filter;			/**< The SPI filter connected to the flash devices. */
	struct flash_mfg_filter_handler *mfg_handler;	/**< The filter handler for flash device types. */
	struct host_flash_initialization *flash_init;	/**< Host flash initialization manager. */
};


int host_flash_manager_single_init (struct host_flash_manager_single *manager,
	struct spi_flash *flash, struct host_state_manager *host_state,
	struct spi_filter_interface *filter, struct flash_mfg_filter_handler *mfg_handler);
int host_flash_manager_single_init_with_managed_flash_initialization (
	struct host_flash_manager_single *manager, struct spi_flash *flash,
	struct host_state_manager *host_state, struct spi_filter_interface *filter,
	struct flash_mfg_filter_handler *mfg_handler, struct host_flash_initialization *flash_init);
void host_flash_manager_single_release (struct host_flash_manager_single *manager);


#endif /* HOST_FLASH_MANAGER_SINGLE_H_ */
