// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_flash_manager_single_with_backup.h"
#include "common/unused.h"

#include "host_flash_manager_single_static.h"


/**
 * Determine the filter mode to use for single flash access based on the current RO flash setting.
 *
 * @param single The flash manager to query.
 *
 * @return The SPI filter mode to use.
 */
static spi_filter_flash_mode host_flash_manager_single_with_backup_get_filter_mode (
	const struct host_flash_manager_single_with_backup *single)
{
	if (host_state_manager_get_read_only_flash (single->base.host_state) == SPI_FILTER_CS_0) {
		return SPI_FILTER_FLASH_SINGLE_CS0;
	}
	else {
		return SPI_FILTER_FLASH_SINGLE_CS1;
	}
}

bool host_flash_manager_single_with_backup_has_two_flash_devices (
	const struct host_flash_manager *manager)
{
	UNUSED (manager);

	return true;
}

const struct spi_flash* host_flash_manager_single_with_backup_get_read_only_flash (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	if (single == NULL) {
		return NULL;
	}

	if (host_state_manager_get_read_only_flash (single->base.host_state) == SPI_FILTER_CS_0) {
		return single->base.flash;
	}
	else {
		return single->flash_cs1;
	}
}

const struct spi_flash* host_flash_manager_single_with_backup_get_read_write_flash (
	const struct host_flash_manager *manager)
{
	if (manager == NULL) {
		return NULL;
	}

	return manager->get_read_only_flash (manager);
}

int host_flash_manager_single_with_backup_config_spi_filter_flash_type (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_config_spi_filter_flash_type (single->base.flash, single->flash_cs1,
		single->base.filter, single->base.mfg_handler);
}

int host_flash_manager_single_with_backup_config_spi_filter_flash_devices (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_single_config_spi_filter_flash_devices_with_mode (&single->base,
		host_flash_manager_single_with_backup_get_filter_mode (single));
}

int host_flash_manager_single_with_backup_swap_flash_devices (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw,
	const struct pfm_manager *used_pending)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	UNUSED (host_rw);

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_single_swap_flash_devices_with_mode (&single->base, used_pending,
		host_flash_manager_single_with_backup_get_filter_mode (single));
}

int host_flash_manager_single_with_backup_initialize_flash_protection (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	if ((single == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_single_initialize_flash_protection_for_mode (&single->base, host_rw,
		host_flash_manager_single_with_backup_get_filter_mode (single));
}

int host_flash_manager_single_with_backup_set_flash_for_rot_access (
	const struct host_flash_manager *manager, const struct host_control *control)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_rot_access (control, single->base.filter,
		single->base.flash, single->flash_cs1, single->base.flash_init);
}

int host_flash_manager_single_with_backup_reset_flash (const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single_with_backup *single =
		(const struct host_flash_manager_single_with_backup*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_reset_flash (single->base.flash, single->flash_cs1);
}

/**
 * Initialize the manager for two host flash devices where only a single flash is accessible at any
 * time.
 *
 * @param manager The flash manager to initialize.
 * @param cs0 The flash device connected to chip select 0.
 * @param cs1 The flash device connected to chip select 1.
 * @param host_state The manager for host state information.
 * @param filter The SPI filter for the protected flash.
 * @param mfg_handler The SPI filter handler for configuring the flash device manufacturer.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int host_flash_manager_single_with_backup_init (
	struct host_flash_manager_single_with_backup *manager, const struct spi_flash *cs0,
	const struct spi_flash *cs1, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler)
{
	int status;

	if (cs1 == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = host_flash_manager_single_init_no_api (&manager->base, cs0, host_state, filter,
		mfg_handler);
	if (status == 0) {
		manager->base.base.has_two_flash_devices =
			host_flash_manager_single_with_backup_has_two_flash_devices;
		manager->base.base.get_read_only_flash =
			host_flash_manager_single_with_backup_get_read_only_flash;
		manager->base.base.get_read_write_flash =
			host_flash_manager_single_with_backup_get_read_write_flash;
		manager->base.base.validate_read_only_flash =
			host_flash_manager_single_validate_read_only_flash;
		manager->base.base.validate_read_write_flash =
			host_flash_manager_single_validate_read_write_flash;
		manager->base.base.get_flash_read_write_regions =
			host_flash_manager_single_get_flash_read_write_regions;
		manager->base.base.free_read_write_regions = host_flash_manager_free_read_write_regions;
		manager->base.base.config_spi_filter_flash_type =
			host_flash_manager_single_with_backup_config_spi_filter_flash_type;
		manager->base.base.config_spi_filter_flash_devices =
			host_flash_manager_single_with_backup_config_spi_filter_flash_devices;
		manager->base.base.swap_flash_devices =
			host_flash_manager_single_with_backup_swap_flash_devices;
		manager->base.base.initialize_flash_protection =
			host_flash_manager_single_with_backup_initialize_flash_protection;
		manager->base.base.restore_flash_read_write_regions =
			host_flash_manager_single_restore_flash_read_write_regions;
		manager->base.base.set_flash_for_rot_access =
			host_flash_manager_single_with_backup_set_flash_for_rot_access;
		manager->base.base.set_flash_for_host_access =
			host_flash_manager_single_set_flash_for_host_access;
		manager->base.base.host_has_flash_access = host_flash_manager_single_host_has_flash_access;
		manager->base.base.reset_flash = host_flash_manager_single_with_backup_reset_flash;

		manager->flash_cs1 = cs1;
	}

	return status;
}

/**
 * Initialize the manager for two host flash devices where only a single flash is accessible at any
 * time.  The interface to the flash device may be uninitialized, but an initialization manager is
 * provided to ensure it gets initialized prior to use.
 *
 * @param manager The flash manager to initialize.
 * @param cs0 The flash device connected to chip select 0.
 * @param cs1 The flash device connected to chip select 1.
 * @param host_state The manager for host state information.
 * @param filter The SPI filter for the protected flash.
 * @param mfg_handler The SPI filter handler for configuring the flash device manufacturer.
 * @param flash_init The initialization manager for SPI flash interfaces.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int host_flash_manager_single_with_backup_init_with_managed_flash_initialization (
	struct host_flash_manager_single_with_backup *manager, const struct spi_flash *cs0,
	const struct spi_flash *cs1, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler,
	const struct host_flash_initialization *flash_init)
{
	int status;

	if (flash_init == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = host_flash_manager_single_with_backup_init (manager, cs0, cs1, host_state, filter,
		mfg_handler);
	if (status != 0) {
		return status;
	}

	manager->base.flash_init = flash_init;

	return 0;
}

/**
 * Release the resources used for single host flash management with two physical flash devices.
 *
 * @param manager The manager to release.
 */
void host_flash_manager_single_with_backup_release (
	const struct host_flash_manager_single_with_backup *manager)
{
	if (manager != NULL) {
		host_flash_manager_single_release (&manager->base);
	}
}
