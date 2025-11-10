// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_SINGLE_STATIC_H_
#define HOST_FLASH_MANAGER_SINGLE_STATIC_H_

#include "host_flash_manager_single.h"


/* Internal functions declared to allow for static initialization. */
const struct spi_flash* host_flash_manager_single_get_read_only_flash (
	const struct host_flash_manager *manager);
const struct spi_flash* host_flash_manager_single_get_read_write_flash (
	const struct host_flash_manager *manager);


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
int host_flash_manager_single_config_spi_filter_flash_type (
	const struct host_flash_manager *manager);
int host_flash_manager_single_config_spi_filter_flash_devices (
	const struct host_flash_manager *manager);
int host_flash_manager_single_swap_flash_devices (const struct host_flash_manager *manager,
	const struct host_flash_manager_rw_regions *host_rw, const struct pfm_manager *used_pending);
int host_flash_manager_single_initialize_flash_protection (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_restore_flash_read_write_regions (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw);
int host_flash_manager_single_set_flash_for_rot_access (const struct host_flash_manager *manager,
	const struct host_control *control);
int host_flash_manager_single_set_flash_for_host_access (const struct host_flash_manager *manager,
	const struct host_control *control);
int host_flash_manager_single_host_has_flash_access (const struct host_flash_manager *manager,
	const struct host_control *control);
int host_flash_manager_single_reset_flash (const struct host_flash_manager *manager);


/**
 * Constant initializer for the flash manager API.
 */
#define	HOST_FLASH_MANAGER_SINGLE_API_INIT  { \
		.get_read_only_flash = host_flash_manager_single_get_read_only_flash, \
		.get_read_write_flash = host_flash_manager_single_get_read_write_flash, \
		.validate_read_only_flash = host_flash_manager_single_validate_read_only_flash, \
		.validate_read_write_flash = host_flash_manager_single_validate_read_write_flash, \
		.get_flash_read_write_regions = host_flash_manager_single_get_flash_read_write_regions, \
		.free_read_write_regions = host_flash_manager_free_read_write_regions, \
		.config_spi_filter_flash_type = host_flash_manager_single_config_spi_filter_flash_type, \
		.config_spi_filter_flash_devices = \
			host_flash_manager_single_config_spi_filter_flash_devices, \
		.swap_flash_devices = host_flash_manager_single_swap_flash_devices, \
		.initialize_flash_protection = host_flash_manager_single_initialize_flash_protection, \
		.restore_flash_read_write_regions = \
			host_flash_manager_single_restore_flash_read_write_regions, \
		.set_flash_for_rot_access = host_flash_manager_single_set_flash_for_rot_access, \
		.set_flash_for_host_access = host_flash_manager_single_set_flash_for_host_access, \
		.host_has_flash_access = host_flash_manager_single_host_has_flash_access, \
		.reset_flash = host_flash_manager_single_reset_flash, \
	}


/**
 * Initialize a static instance of the manager for a single host flash device.
 *
 * There is no validation done on the arguments.
 *
 * @param flash_ptr The host flash device.
 * @param host_state_ptr The manager for host state information.
 * @param filter_ptr The SPI filter for the protected flash.
 * @param mfg_handler_ptr The SPI filter handler for configuring the flash device manufacturer.
 */
#define	host_flash_manager_single_static_init(flash_ptr, host_state_ptr, filter_ptr, \
	mfg_handler_ptr)	{ \
		.base = HOST_FLASH_MANAGER_SINGLE_API_INIT, \
		.flash = flash_ptr, \
		.host_state = host_state_ptr, \
		.filter = filter_ptr, \
		.mfg_handler = mfg_handler_ptr, \
		.flash_init = NULL, \
	}

/**
 * Initialize a static instance of the manager for a single host flash device.  The interface to the
 * flash device may be uninitialized, but an initialization manager is provided to ensure it gets
 * initialized prior to use.
 *
 * There is no validation done on the arguments.
 *
 * @param flash_ptr The host flash device.
 * @param host_state_ptr The manager for host state information.
 * @param filter_ptr The SPI filter for the protected flash.
 * @param mfg_handler_ptr The SPI filter handler for configuring the flash device manufacturer.
 * @param flash_init_ptr The initialization manager for SPI flash interfaces.
 */
#define	host_flash_manager_single_static_init_with_managed_flash_initialization(flash_ptr, \
	host_state_ptr, filter_ptr, mfg_handler_ptr, flash_init_ptr)	{ \
		.base = HOST_FLASH_MANAGER_SINGLE_API_INIT, \
		.flash = flash_ptr, \
		.host_state = host_state_ptr, \
		.filter = filter_ptr, \
		.mfg_handler = mfg_handler_ptr, \
		.flash_init = flash_init_ptr, \
	}


#endif	/* HOST_FLASH_MANAGER_SINGLE_STATIC_H_ */
