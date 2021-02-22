// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_flash_manager_dual.h"
#include "host_fw_util.h"


static struct spi_flash* host_flash_manager_dual_get_read_only_flash (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;

	if (dual == NULL) {
		return NULL;
	}

	if (host_state_manager_get_read_only_flash (dual->host_state) == SPI_FILTER_CS_0) {
		return dual->flash_cs0;
	}
	else {
		return dual->flash_cs1;
	}
}

static struct spi_flash* host_flash_manager_dual_get_read_write_flash (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;

	if (dual == NULL) {
		return NULL;
	}

	if (host_state_manager_get_read_only_flash (dual->host_state) == SPI_FILTER_CS_0) {
		return dual->flash_cs1;
	}
	else {
		return dual->flash_cs0;
	}
}

static int host_flash_manager_dual_validate_read_only_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct pfm *good_pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	bool full_validation, struct host_flash_manager_rw_regions *host_rw)
{
	int status;

	if ((manager == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) ||
		(host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	if (good_pfm && !full_validation) {
		status = host_flash_manager_validate_pfm (pfm, good_pfm, hash, rsa,
			host_flash_manager_dual_get_read_only_flash (manager), host_rw);
	}
	else {
		status = host_flash_manager_validate_flash (pfm, hash, rsa, full_validation,
			host_flash_manager_dual_get_read_only_flash (manager), host_rw);
	}

	return status;
}

static int host_flash_manager_dual_validate_read_write_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	struct host_flash_manager_rw_regions *host_rw)
{
	if ((manager == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) ||
		(host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_validate_flash (pfm, hash, rsa, true,
		host_flash_manager_dual_get_read_write_flash (manager), host_rw);
}

static int host_flash_manager_dual_get_flash_read_write_regions (struct host_flash_manager *manager,
	struct pfm *pfm, bool rw_flash, struct host_flash_manager_rw_regions *host_rw)
{
	if ((manager == NULL) || (pfm == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_get_flash_read_write_regions (
		(rw_flash) ?
			host_flash_manager_dual_get_read_write_flash (manager) :
			host_flash_manager_dual_get_read_only_flash (manager),
		pfm, host_rw);
}

static int host_flash_manager_dual_config_spi_filter_flash_type (struct host_flash_manager *manager)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;

	if (dual == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_config_spi_filter_flash_type (dual->flash_cs0, dual->flash_cs1,
		dual->filter, dual->mfg_handler);
}

static int host_flash_manager_dual_config_spi_filter_flash_devices (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;
	spi_filter_cs ro;

	if (dual == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	ro = host_state_manager_get_read_only_flash (dual->host_state);
	return dual->filter->set_ro_cs (dual->filter, ro);
}

/**
 * Copy the read/write data regions from one flash to another.
 *
 * @param manager The flash manager to use for the data migration.
 * @param from The flash device to copy from.
 * @param writable The list of read/write regions that should be migrated.
 *
 * @return 0 if the data migration was successful or an error code.
 */
static int host_flash_manager_dual_migrate_rw_data (struct host_flash_manager_dual *manager,
	spi_filter_cs from, struct host_flash_manager_rw_regions *host_rw)
{
	int status;

	if (from == SPI_FILTER_CS_0) {
		status = host_fw_migrate_read_write_data_multiple_fw (manager->flash_cs1, host_rw->writable,
			host_rw->count, manager->flash_cs0, NULL, 0);
	}
	else {
		status = host_fw_migrate_read_write_data_multiple_fw (manager->flash_cs0, host_rw->writable,
			host_rw->count, manager->flash_cs1, NULL, 0);
	}

	return status;
}

static int host_flash_manager_dual_swap_flash_devices (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw, struct pfm_manager *used_pending)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;
	spi_filter_cs rw;
	int status;

	if (dual == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Clear the dirty bit in the SPI filter. */
	status = dual->filter->clear_flash_dirty_state (dual->filter);
	if (status != 0) {
		return status;
	}

	/* Configure the SPI filter to switch the read and write flashes. */
	rw = (host_state_manager_get_read_only_flash (dual->host_state) == SPI_FILTER_CS_0) ?
		SPI_FILTER_CS_1 : SPI_FILTER_CS_0;
	status = dual->filter->set_ro_cs (dual->filter, rw);
	if (status != 0) {
		return status;
	}

	/* Migrate the R/W data to the new write flash. */
	if (host_rw) {
		status = host_flash_manager_dual_migrate_rw_data (dual, rw, host_rw);
	}

	/* Save the current flash configuration. */
	if (status == 0) {
		state_manager_block_non_volatile_state_storage (&dual->host_state->base, true);

		host_state_manager_save_read_only_flash (dual->host_state, rw);
		host_state_manager_save_inactive_dirty (dual->host_state, false);

		if (used_pending) {
			used_pending->base.activate_pending_manifest (&used_pending->base);
		}

		state_manager_block_non_volatile_state_storage (&dual->host_state->base, false);
	}

	return status;
}

static int host_flash_manager_dual_initialize_flash_protection (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;
	spi_filter_cs ro;
	struct spi_flash *ro_flash;
	struct spi_flash *rw_flash;
	int status;
	int addr_4byte;

	if ((dual == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Make sure both flash devices are running with the same address mode. */
	ro_flash = host_flash_manager_dual_get_read_only_flash (manager);
	rw_flash = host_flash_manager_dual_get_read_write_flash (manager);

	addr_4byte = spi_flash_is_4byte_address_mode (ro_flash);
	if (ROT_IS_ERROR (addr_4byte)) {
		return addr_4byte;
	}

	if (addr_4byte != spi_flash_is_4byte_address_mode (rw_flash)) {
		status = spi_flash_enable_4byte_address_mode (rw_flash, addr_4byte);
		if (status != 0) {
			return status;
		}
	}

	/* Make the R/W data available on the R/W flash device. */
	ro = host_state_manager_get_read_only_flash (dual->host_state);

	status = host_flash_manager_dual_migrate_rw_data (dual, ro, host_rw);
	if (status != 0) {
		return status;
	}

	/* Protection is being initialized, so the R/W flash can't be dirty yet. */
	status = dual->filter->clear_flash_dirty_state (dual->filter);
	if (status != 0) {
		return status;
	}

	host_state_manager_save_inactive_dirty (dual->host_state, false);

	/* Make sure the SPI filter address mode matches the mode of the physical devices.
	 *
	 * If the device address mode is fixed, this was already configured during initial filter setup
	 * and doesn't need to be done again. */
	if (!spi_flash_is_address_mode_fixed (ro_flash)) {
		status = dual->filter->set_addr_byte_mode (dual->filter,
			(addr_4byte == 1) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3);
		if (status != 0) {
			return status;
		}
	}

	/* Turn on the SPI filter. */
	status = dual->filter->set_filter_mode (dual->filter, SPI_FILTER_FLASH_DUAL);
	if (status != 0) {
		return status;
	}

	return dual->filter->set_ro_cs (dual->filter, ro);
}

static int host_flash_manager_dual_restore_flash_read_write_regions (
	struct host_flash_manager *manager, struct host_flash_manager_rw_regions *host_rw)
{
	if ((manager == NULL) || (host_rw == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_fw_restore_read_write_data_multiple_fw (
		host_flash_manager_dual_get_read_write_flash (manager),
		host_flash_manager_dual_get_read_only_flash (manager), host_rw->writable, host_rw->count);
}

static int host_flash_manager_dual_set_flash_for_rot_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;

	if ((dual == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_rot_access (control, dual->filter, dual->flash_cs0,
		dual->flash_cs1, dual->flash_init);
}

static int host_flash_manager_dual_set_flash_for_host_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;

	if ((dual == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_set_flash_for_host_access (control, dual->filter);
}

static int host_flash_manager_dual_host_has_flash_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_dual *dual = (struct host_flash_manager_dual*) manager;

	if ((dual == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_host_has_flash_access (control, dual->filter);
}

/**
 * Initialize the manager for dual host flash devices.
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
int host_flash_manager_dual_init (struct host_flash_manager_dual *manager, struct spi_flash *cs0,
	struct spi_flash *cs1, struct host_state_manager *host_state,
	struct spi_filter_interface *filter, struct flash_mfg_filter_handler *mfg_handler)
{
	if ((manager == NULL) || (cs0 == NULL) || (cs1 == NULL) || (host_state == NULL) ||
		(filter == NULL) || (mfg_handler == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct host_flash_manager_dual));

	manager->base.get_read_only_flash = host_flash_manager_dual_get_read_only_flash;
	manager->base.get_read_write_flash = host_flash_manager_dual_get_read_write_flash;
	manager->base.validate_read_only_flash = host_flash_manager_dual_validate_read_only_flash;
	manager->base.validate_read_write_flash = host_flash_manager_dual_validate_read_write_flash;
	manager->base.get_flash_read_write_regions =
		host_flash_manager_dual_get_flash_read_write_regions;
	manager->base.free_read_write_regions = host_flash_manager_free_read_write_regions;
	manager->base.config_spi_filter_flash_type =
		host_flash_manager_dual_config_spi_filter_flash_type;
	manager->base.config_spi_filter_flash_devices =
		host_flash_manager_dual_config_spi_filter_flash_devices;
	manager->base.swap_flash_devices = host_flash_manager_dual_swap_flash_devices;
	manager->base.initialize_flash_protection = host_flash_manager_dual_initialize_flash_protection;
	manager->base.restore_flash_read_write_regions =
		host_flash_manager_dual_restore_flash_read_write_regions;
	manager->base.set_flash_for_rot_access = host_flash_manager_dual_set_flash_for_rot_access;
	manager->base.set_flash_for_host_access = host_flash_manager_dual_set_flash_for_host_access;
	manager->base.host_has_flash_access = host_flash_manager_dual_host_has_flash_access;

	manager->flash_cs0 = cs0;
	manager->flash_cs1 = cs1;
	manager->host_state = host_state;
	manager->filter = filter;
	manager->mfg_handler = mfg_handler;

	return 0;
}

/**
 * Initialize the manager for dual host flash devices.  The interfaces to the flash devices may be
 * uninitialized, but an initialization manager is provided to ensure they get initialized prior to
 * use.
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
int host_flash_manager_dual_init_with_managed_flash_initialization (
	struct host_flash_manager_dual *manager, struct spi_flash *cs0, struct spi_flash *cs1,
	struct host_state_manager *host_state, struct spi_filter_interface *filter,
	struct flash_mfg_filter_handler *mfg_handler, struct host_flash_initialization *flash_init)
{
	int status;

	if (flash_init == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = host_flash_manager_dual_init (manager, cs0, cs1, host_state, filter, mfg_handler);
	if (status != 0) {
		return status;
	}

	manager->flash_init = flash_init;

	return 0;
}

/**
 * Release the resources used for dual host flash management.
 *
 * @param manager The manager to release.
 */
void host_flash_manager_dual_release (struct host_flash_manager_dual *manager)
{

}
