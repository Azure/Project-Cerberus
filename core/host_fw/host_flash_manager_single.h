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
	struct host_flash_manager base;						/**< Base flash manager interface. */
	const struct spi_flash *flash;						/**< The host flash device. */
	const struct host_state_manager *host_state;		/**< State information for the host using the flash. */
	const struct spi_filter_interface *filter;			/**< The SPI filter connected to the flash devices. */
	const struct flash_mfg_filter_handler *mfg_handler;	/**< The filter handler for flash device types. */
	const struct host_flash_initialization *flash_init;	/**< Host flash initialization manager. */
};


int host_flash_manager_single_init (struct host_flash_manager_single *manager,
	const struct spi_flash *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler);
int host_flash_manager_single_init_with_managed_flash_initialization (
	struct host_flash_manager_single *manager, const struct spi_flash *flash,
	const struct host_state_manager *host_state, const struct spi_filter_interface *filter,
	const struct flash_mfg_filter_handler *mfg_handler,
	const struct host_flash_initialization *flash_init);
void host_flash_manager_single_release (const struct host_flash_manager_single *manager);

/* Internal functions for use by derived types. */
int host_flash_manager_single_init_no_api (struct host_flash_manager_single *manager,
	const struct spi_flash *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler);

int host_flash_manager_single_validate_read_only_flash (const struct host_flash_manager *manager,
	const struct pfm *pfm, const struct pfm *good_pfm, const struct hash_engine *hash,
	const struct rsa_engine *rsa, bool full_validation,
	struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_validate_read_write_flash (const struct host_flash_manager *manager,
	const struct pfm *pfm, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_get_flash_read_write_regions (
	const struct host_flash_manager *manager, const struct pfm *pfm, bool rw_flash,
	struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_restore_flash_read_write_regions (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_set_flash_for_host_access (const struct host_flash_manager *manager,
	const struct host_control *control);
int host_flash_manager_single_host_has_flash_access (const struct host_flash_manager *manager,
	const struct host_control *control);

int host_flash_manager_single_config_spi_filter_flash_devices_with_mode (
	const struct host_flash_manager_single *single, spi_filter_flash_mode mode);
int host_flash_manager_single_swap_flash_devices_with_mode (
	const struct host_flash_manager_single *single, const struct pfm_manager *used_pending,
	spi_filter_flash_mode mode);
int host_flash_manager_single_initialize_flash_protection_for_mode (
	const struct host_flash_manager_single *single, spi_filter_flash_mode mode);


#endif	/* HOST_FLASH_MANAGER_SINGLE_H_ */
