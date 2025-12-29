// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_flash_manager_single.h"
#include "common/unused.h"


bool host_flash_manager_single_has_two_flash_devices (const struct host_flash_manager *manager)
{
	UNUSED (manager);

	return false;
}

const struct spi_flash* host_flash_manager_single_get_read_only_flash (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return NULL;
	}

	return single->flash;
}

const struct spi_flash* host_flash_manager_single_get_read_write_flash (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return NULL;
	}

	return single->flash;
}

int host_flash_manager_single_validate_read_only_flash (const struct host_flash_manager *manager,
	const struct pfm *pfm, const struct pfm *good_pfm, const struct hash_engine *hash,
	const struct rsa_engine *rsa, bool full_validation,
	struct host_flash_manager_rw_regions *host_rw)
{
	int status;

	if ((manager == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) ||
		(host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	if (good_pfm && !full_validation) {
		status = host_flash_manager_validate_pfm (pfm, good_pfm, hash, rsa,
			manager->get_read_only_flash (manager), host_rw);
	}
	else {
		status = host_flash_manager_validate_flash (pfm, hash, rsa, full_validation,
			manager->get_read_only_flash (manager), host_rw);
	}

	return status;
}

int host_flash_manager_single_validate_read_write_flash (const struct host_flash_manager *manager,
	const struct pfm *pfm, const struct hash_engine *hash, const struct rsa_engine *rsa,
	struct host_flash_manager_rw_regions *host_rw)
{
	if ((manager == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) ||
		(host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_validate_flash (pfm, hash, rsa, true,
		manager->get_read_write_flash (manager), host_rw);
}

int host_flash_manager_single_get_flash_read_write_regions (
	const struct host_flash_manager *manager, const struct pfm *pfm, bool rw_flash,
	struct host_flash_manager_rw_regions *host_rw)
{
	UNUSED (rw_flash);

	if ((manager == NULL) || (pfm == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_get_flash_read_write_regions (manager->get_read_only_flash (manager),
		pfm, host_rw);
}

int host_flash_manager_single_config_spi_filter_flash_type (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_config_spi_filter_flash_type (single->flash, NULL, single->filter,
		single->mfg_handler);
}

/**
 * Configure the SPI filter for single flash mode using the specified filter configuration.
 *
 * No parameter validation is performed.
 *
 * @param single Manager for the flash to configure.
 * @param mode The SPI filter to use for host flash.
 *
 * @return 0 if the filter configuration was set successfully or an error code.
 */
int host_flash_manager_single_config_spi_filter_flash_devices_with_mode (
	const struct host_flash_manager_single *single, spi_filter_flash_mode mode)
{
	int status;

	status = single->filter->allow_all_single_flash_writes (single->filter, true);
	if (status != 0) {
		return status;
	}

	return single->filter->set_filter_mode (single->filter, mode);
}

int host_flash_manager_single_config_spi_filter_flash_devices (
	const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* There is only a single flash, so any other RO flash configuration is not valid. */
	host_state_manager_save_read_only_flash_nv_config (single->host_state, SPI_FILTER_CS_0);
	host_state_manager_clear_read_only_flash_override (single->host_state);

	return host_flash_manager_single_config_spi_filter_flash_devices_with_mode (single,
		SPI_FILTER_FLASH_SINGLE_CS0);
}

/**
 * Mark the flash as verified.  Since this is single flash, nothing is actually swapped.
 *
 * No parameter validation is performed.
 *
 * @param single The flash manager for host flash that was verified.
 * @param used_pending If a pending PFM was used to authenticate the device being made
 * read-only, activate the PFM as part of the device swap.  Make this null if no pending PFM
 * should be activated.
 * @param mode The SPI filter mode to use for the read-only flash.
 *
 * @return 0 if the flash state was updated successfully or an error code.
 */
int host_flash_manager_single_swap_flash_devices_with_mode (
	const struct host_flash_manager_single *single, const struct pfm_manager *used_pending,
	spi_filter_flash_mode mode)
{
	int status;

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

	status = single->filter->set_filter_mode (single->filter, mode);

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

int host_flash_manager_single_swap_flash_devices (const struct host_flash_manager *manager,
	const struct host_flash_manager_rw_regions *host_rw, const struct pfm_manager *used_pending)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	UNUSED (host_rw);

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* There is only a single flash, so any other RO flash configuration is not valid. */
	host_state_manager_save_read_only_flash_nv_config (single->host_state, SPI_FILTER_CS_0);
	host_state_manager_clear_read_only_flash_override (single->host_state);

	return host_flash_manager_single_swap_flash_devices_with_mode (single, used_pending,
		SPI_FILTER_FLASH_SINGLE_CS0);
}

/**
 * Configure the system for first-time flash protection using single flash mode.  Which chip select
 * is accessible is specified by the provided SPI filter mode setting.
 *
 * No parameter validation is performed.
 *
 * @param manager Manager for the flash protection to initialize.
 * @param host_rw The list of read/write images in the protected image.
 * @param mode The SPI filter mode to use.
 *
 * @return 0 if flash protection was initialized successfully or an error code.
 */
int host_flash_manager_single_initialize_flash_protection_for_mode (
	const struct host_flash_manager_single *single,
	const struct host_flash_manager_rw_regions *host_rw, spi_filter_flash_mode mode)
{
	const struct spi_flash *flash = single->base.get_read_only_flash (&single->base);
	int status;
	int addr_4byte;

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
	if (!spi_flash_is_address_mode_fixed (flash)) {
		addr_4byte = spi_flash_is_4byte_address_mode (flash);

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

	return single->filter->set_filter_mode (single->filter, mode);
}

int host_flash_manager_single_initialize_flash_protection (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if ((single == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* There is only a single flash, so any other RO flash configuration is not valid. */
	host_state_manager_save_read_only_flash_nv_config (single->host_state, SPI_FILTER_CS_0);
	host_state_manager_clear_read_only_flash_override (single->host_state);

	return host_flash_manager_single_initialize_flash_protection_for_mode (single, host_rw,
		SPI_FILTER_FLASH_SINGLE_CS0);
}

int host_flash_manager_single_restore_flash_read_write_regions (
	const struct host_flash_manager *manager, const struct host_flash_manager_rw_regions *host_rw)
{
	if ((manager == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return HOST_FLASH_MGR_UNSUPPORTED_OPERATION;
}

int host_flash_manager_single_set_flash_for_rot_access (const struct host_flash_manager *manager,
	const struct host_control *control)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_rot_access (control, single->filter, single->flash,
		NULL, single->flash_init);
}

int host_flash_manager_single_set_flash_for_host_access (const struct host_flash_manager *manager,
	const struct host_control *control)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_host_access (control, single->filter);
}

int host_flash_manager_single_host_has_flash_access (const struct host_flash_manager *manager,
	const struct host_control *control)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if ((single == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_host_has_flash_access (control, single->filter);
}

int host_flash_manager_single_reset_flash (const struct host_flash_manager *manager)
{
	const struct host_flash_manager_single *single =
		(const struct host_flash_manager_single*) manager;

	if (single == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_reset_flash (single->flash, NULL);
}

/**
 * Initialize the manager for a single host flash device without initializing the flash manager API.
 *
 * @param manager The flash manager to initialize.
 * @param flash The host flash device.
 * @param host_state The manager for host state information.
 * @param filter The SPI filter for the protected flash.
 * @param mfg_handler The SPI filter handler for configuring the flash device manufacturer.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int host_flash_manager_single_init_no_api (struct host_flash_manager_single *manager,
	const struct spi_flash *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler)
{
	if ((manager == NULL) || (flash == NULL) || (host_state == NULL) || (filter == NULL) ||
		(mfg_handler == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct host_flash_manager_single));

	manager->flash = flash;
	manager->host_state = host_state;
	manager->filter = filter;
	manager->mfg_handler = mfg_handler;

	return 0;
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
	const struct spi_flash *flash, const struct host_state_manager *host_state,
	const struct spi_filter_interface *filter, const struct flash_mfg_filter_handler *mfg_handler)
{
	int status;

	status = host_flash_manager_single_init_no_api (manager, flash, host_state, filter,
		mfg_handler);
	if (status == 0) {
		manager->base.has_two_flash_devices = host_flash_manager_single_has_two_flash_devices;
		manager->base.get_read_only_flash = host_flash_manager_single_get_read_only_flash;
		manager->base.get_read_write_flash = host_flash_manager_single_get_read_write_flash;
		manager->base.validate_read_only_flash = host_flash_manager_single_validate_read_only_flash;
		manager->base.validate_read_write_flash =
			host_flash_manager_single_validate_read_write_flash;
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
		manager->base.set_flash_for_host_access =
			host_flash_manager_single_set_flash_for_host_access;
		manager->base.host_has_flash_access = host_flash_manager_single_host_has_flash_access;
		manager->base.reset_flash = host_flash_manager_single_reset_flash;
	}

	return status;
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
	struct host_flash_manager_single *manager, const struct spi_flash *flash,
	const struct host_state_manager *host_state, const struct spi_filter_interface *filter,
	const struct flash_mfg_filter_handler *mfg_handler,
	const struct host_flash_initialization *flash_init)
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
void host_flash_manager_single_release (const struct host_flash_manager_single *manager)
{
	UNUSED (manager);
}
