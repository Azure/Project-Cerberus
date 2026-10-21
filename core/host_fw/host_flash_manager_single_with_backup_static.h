// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_STATIC_H_
#define HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_STATIC_H_

#include "host_flash_manager_single_static.h"
#include "host_flash_manager_single_with_backup.h"


/* Internal functions declared to allow for static initialization. */
const struct spi_flash* host_flash_manager_single_with_backup_get_read_only_flash (
	const struct host_flash_manager *manager);
const struct spi_flash* host_flash_manager_single_with_backup_get_read_write_flash (
	const struct host_flash_manager *manager);


bool host_flash_manager_single_with_backup_has_two_flash_devices (
	const struct host_flash_manager *manager);
int host_flash_manager_single_with_backup_config_spi_filter_flash_type (
	const struct host_flash_manager *manager);
int host_flash_manager_single_with_backup_config_spi_filter_flash_devices (
	const struct host_flash_manager *manager);
int host_flash_manager_single_with_backup_swap_flash_devices (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw,
	const struct pfm_manager *used_pending);
int host_flash_manager_single_with_backup_initialize_flash_protection (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_with_backup_set_flash_for_rot_access (
	const struct host_flash_manager *manager, const struct host_control *control);
int host_flash_manager_single_with_backup_reset_flash (const struct host_flash_manager *manager);


/**
 * Constant initializer for the flash manager API.
 */
#define	HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_API_INIT  { \
		.has_two_flash_devices = host_flash_manager_single_with_backup_has_two_flash_devices, \
		.get_read_only_flash = host_flash_manager_single_with_backup_get_read_only_flash, \
		.get_read_write_flash = host_flash_manager_single_with_backup_get_read_write_flash, \
		.validate_read_only_flash = host_flash_manager_single_validate_read_only_flash, \
		.validate_read_write_flash = host_flash_manager_single_validate_read_write_flash, \
		.get_flash_read_write_regions = host_flash_manager_single_get_flash_read_write_regions, \
		.free_read_write_regions = host_flash_manager_free_read_write_regions, \
		.config_spi_filter_flash_type = \
			host_flash_manager_single_with_backup_config_spi_filter_flash_type, \
		.config_spi_filter_flash_devices = \
			host_flash_manager_single_with_backup_config_spi_filter_flash_devices, \
		.swap_flash_devices = host_flash_manager_single_with_backup_swap_flash_devices, \
		.initialize_flash_protection = \
			host_flash_manager_single_with_backup_initialize_flash_protection, \
		.restore_flash_read_write_regions = \
			host_flash_manager_single_restore_flash_read_write_regions, \
		.set_flash_for_rot_access = \
			host_flash_manager_single_with_backup_set_flash_for_rot_access, \
		.set_flash_for_host_access = host_flash_manager_single_set_flash_for_host_access, \
		.host_has_flash_access = host_flash_manager_single_host_has_flash_access, \
		.reset_flash = host_flash_manager_single_with_backup_reset_flash, \
	}


/**
 * Initialize a static instance of the manager for two host flash devices where only a single flash
 * is accessible at any time.
 *
 * There is no validation done on the arguments.
 *
 * @param cs0_ptr The flash device connected to chip select 0.
 * @param cs1_ptr The flash device connected to chip select 1.
 * @param host_state_ptr The manager for host state information.
 * @param filter_ptr The SPI filter for the protected flash.
 * @param mfg_handler_ptr The SPI filter handler for configuring the flash device manufacturer.
 */
#define	host_flash_manager_single_with_backup_static_init(cs0_ptr, cs1_ptr, host_state_ptr, \
	filter_ptr, mfg_handler_ptr)	{ \
		.base = host_flash_manager_single_static_init_internal (\
			HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_API_INIT, cs0_ptr, host_state_ptr, filter_ptr, \
			mfg_handler_ptr, NULL), \
		.flash_cs1 = cs1_ptr, \
	}

/**
 * Initialize a static instance of the manager for two host flash devices where only a single flash
 * is accessible at any time.  The interface to the flash device may be uninitialized, but an
 * initialization manager is provided to ensure it gets initialized prior to use.
 *
 * There is no validation done on the arguments.
 *
 * @param cs0_ptr The flash device connected to chip select 0.
 * @param cs1_ptr The flash device connected to chip select 1.
 * @param host_state_ptr The manager for host state information.
 * @param filter_ptr The SPI filter for the protected flash.
 * @param mfg_handler_ptr The SPI filter handler for configuring the flash device manufacturer.
 * @param flash_init_ptr The initialization manager for SPI flash interfaces.
 */
#define	host_flash_manager_single_with_backup_static_init_with_managed_flash_initialization( \
	cs0_ptr, cs1_ptr, host_state_ptr, filter_ptr, mfg_handler_ptr, flash_init_ptr)	{ \
		.base = host_flash_manager_single_static_init_internal (\
			HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_API_INIT, cs0_ptr, host_state_ptr, filter_ptr, \
			mfg_handler_ptr, flash_init_ptr), \
		.flash_cs1 = cs1_ptr, \
	}


#endif	/* HOST_FLASH_MANAGER_SINGLE_WITH_BACKUP_STATIC_H_ */
