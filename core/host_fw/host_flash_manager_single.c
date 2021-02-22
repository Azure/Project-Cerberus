// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_flash_manager_single.h"


static struct spi_flash* host_flash_manager_single_get_read_only_flash (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return NULL;
	}

	return single->flash;
}

static struct spi_flash* host_flash_manager_single_get_read_write_flash (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return NULL;
	}

	return single->flash;
}

static int host_flash_manager_single_validate_read_only_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct pfm *good_pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	bool full_validation, struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;
	int status;

	if ((single == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	if (good_pfm && !full_validation) {
		status = host_flash_manager_validate_pfm (pfm, good_pfm, hash, rsa, single->flash, host_rw);
	}
	else {
		status = host_flash_manager_validate_flash (pfm, hash, rsa, full_validation, single->flash,
			host_rw);
	}

	return status;
}

static int host_flash_manager_single_validate_read_write_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if ((single == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_validate_flash (pfm, hash, rsa, true, single->flash, host_rw);
}

static int host_flash_manager_single_get_flash_read_write_regions (
	struct host_flash_manager *manager, struct pfm *pfm, bool rw_flash,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if ((single == NULL) || (pfm == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_get_flash_read_write_regions (single->flash, pfm, host_rw);
}

static int host_flash_manager_single_config_spi_filter_flash_type (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_config_spi_filter_flash_type (single->flash, NULL, single->filter,
		single->mfg_handler);
}

static int host_flash_manager_single_config_spi_filter_flash_devices (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;
	int status;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = single->filter->allow_all_single_flash_writes (single->filter, true);
	if (status != 0) {
		return status;
	}

	return single->filter->set_filter_mode (single->filter, SPI_FILTER_FLASH_SINGLE_CS0);
}

static int host_flash_manager_single_swap_flash_devices (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw, struct pfm_manager *used_pending)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;
	int status;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Clear the dirty bit in the SPI filter. */
	status = single->filter->clear_flash_dirty_state (single->filter);
	if (status != 0) {
		return status;
	}

	/* Ensure proper configuration of the SPI filter. */
	status = single->filter->allow_all_single_flash_writes (single->filter, true);
	if (status != 0) {
		return status;
	}

	status = single->filter->set_filter_mode (single->filter, SPI_FILTER_FLASH_SINGLE_CS0);

	/* Save the current flash configuration. */
	if (status == 0) {
		state_manager_block_non_volatile_state_storage (&single->host_state->base, true);

		host_state_manager_save_inactive_dirty (single->host_state, false);

		if (used_pending) {
			used_pending->base.activate_pending_manifest (&used_pending->base);
		}

		state_manager_block_non_volatile_state_storage (&single->host_state->base, false);
	}

	return status;
}

static int host_flash_manager_single_initialize_flash_protection (
	struct host_flash_manager *manager, struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;
	int status;
	int addr_4byte;

	if ((single == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Protection is being initialized, so the flash can't be dirty yet. */
	status = single->filter->clear_flash_dirty_state (single->filter);
	if (status != 0) {
		return status;
	}

	host_state_manager_save_inactive_dirty (single->host_state, false);

	/* Make sure the SPI filter address mode matches the mode of the physical devices.
	 *
	 * If the device address mode is fixed, this was already configured during initial filter setup
	 * and doesn't need to be done again. */
	if (!spi_flash_is_address_mode_fixed (single->flash)) {
		addr_4byte = spi_flash_is_4byte_address_mode (single->flash);

		status = single->filter->set_addr_byte_mode (single->filter,
			(addr_4byte == 1) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3);
		if (status != 0) {
			return status;
		}
	}

	/* Turn on the SPI filter. */
	status = single->filter->allow_all_single_flash_writes (single->filter, true);
	if (status != 0) {
		return status;
	}

	return single->filter->set_filter_mode (single->filter, SPI_FILTER_FLASH_SINGLE_CS0);
}

static int host_flash_manager_single_restore_flash_read_write_regions (
	struct host_flash_manager *manager, struct host_flash_manager_rw_regions *host_rw)
{
	if ((manager == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return HOST_FLASH_MGR_UNSUPPORTED_OPERATION;
}

static int host_flash_manager_single_set_flash_for_rot_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_rot_access (control, single->filter, single->flash,
		NULL, single->flash_init);
}

static int host_flash_manager_single_set_flash_for_host_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_host_access (control, single->filter);
}

static int host_flash_manager_single_host_has_flash_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_single *single = (struct host_flash_manager_single*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_host_has_flash_access (control, single->filter);
}

/**
 * Initialize the manager for a single host flash device.
 *
 * @param manager The flash manager to initialize.
 * @param flash The host flash device.
 * @param host_state The manager for host state information.
 * @param filter The SPI filter for the protected flash.
 * @param mfg_handler The SPI filter handler for configuring the flash device manufacturer.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int host_flash_manager_single_init (struct host_flash_manager_single *manager,
	struct spi_flash *flash, struct host_state_manager *host_state,
	struct spi_filter_interface *filter, struct flash_mfg_filter_handler *mfg_handler)
{
	if ((manager == NULL) || (flash == NULL) || (host_state == NULL) || (filter == NULL) ||
		(mfg_handler == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct host_flash_manager_single));

	manager->base.get_read_only_flash = host_flash_manager_single_get_read_only_flash;
	manager->base.get_read_write_flash = host_flash_manager_single_get_read_write_flash;
	manager->base.validate_read_only_flash = host_flash_manager_single_validate_read_only_flash;
	manager->base.validate_read_write_flash = host_flash_manager_single_validate_read_write_flash;
	manager->base.get_flash_read_write_regions =
		host_flash_manager_single_get_flash_read_write_regions;
	manager->base.free_read_write_regions = host_flash_manager_free_read_write_regions;
	manager->base.config_spi_filter_flash_type =
		host_flash_manager_single_config_spi_filter_flash_type;
	manager->base.config_spi_filter_flash_devices =
		host_flash_manager_single_config_spi_filter_flash_devices;
	manager->base.swap_flash_devices = host_flash_manager_single_swap_flash_devices;
	manager->base.initialize_flash_protection =
		host_flash_manager_single_initialize_flash_protection;
	manager->base.restore_flash_read_write_regions =
		host_flash_manager_single_restore_flash_read_write_regions;
	manager->base.set_flash_for_rot_access = host_flash_manager_single_set_flash_for_rot_access;
	manager->base.set_flash_for_host_access = host_flash_manager_single_set_flash_for_host_access;
	manager->base.host_has_flash_access = host_flash_manager_single_host_has_flash_access;

	manager->flash = flash;
	manager->host_state = host_state;
	manager->filter = filter;
	manager->mfg_handler = mfg_handler;

	return 0;
}

/**
 * Initialize the manager for a single host flash device.  The interface to the flash device may be
 * uninitialized, but an initialization manager is provided to ensure it gets initialized prior to
 * use.
 *
 * @param manager The flash manager to initialize.
 * @param flash The host flash device.
 * @param host_state The manager for host state information.
 * @param filter The SPI filter for the protected flash.
 * @param mfg_handler The SPI filter handler for configuring the flash device manufacturer.
 * @param flash_init The initialization manager for SPI flash interfaces.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int host_flash_manager_single_init_with_managed_flash_initialization (
	struct host_flash_manager_single *manager, struct spi_flash *flash,
	struct host_state_manager *host_state, struct spi_filter_interface *filter,
	struct flash_mfg_filter_handler *mfg_handler, struct host_flash_initialization *flash_init)
{
	int status;

	if (flash_init == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = host_flash_manager_single_init (manager, flash, host_state, filter, mfg_handler);
	if (status != 0) {
		return status;
	}

	manager->flash_init = flash_init;

	return 0;
}

/**
 * Release the resources used for single host flash management.
 *
 * @param manager The manager to release.
 */
void host_flash_manager_single_release (struct host_flash_manager_single *manager)
{

}
