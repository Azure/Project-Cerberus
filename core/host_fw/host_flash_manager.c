// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_flash_manager.h"
#include "host_fw_util.h"
#include "host_state_manager.h"


static struct spi_flash* host_flash_manager_get_read_only_flash (struct host_flash_manager *manager)
{
	if (manager == NULL) {
		return NULL;
	}

	if (host_state_manager_get_read_only_flash (manager->host_state) == SPI_FILTER_CS_0) {
		return manager->flash_cs0;
	}
	else {
		return manager->flash_cs1;
	}
}

static struct spi_flash* host_flash_manager_get_read_write_flash (
	struct host_flash_manager *manager)
{
	if (manager == NULL) {
		return NULL;
	}

	if (host_state_manager_get_read_only_flash (manager->host_state) == SPI_FILTER_CS_0) {
		return manager->flash_cs1;
	}
	else {
		return manager->flash_cs0;
	}
}

/**
 * Find the entry in the PFM for the firmware version stored on flash.
 *
 * @param manager THe manager for the flash to inspect.
 * @param pfm The PFM to check the flash contents against.
 * @param rw_flash Flag indicating if the read/write flash should be checked.
 * @param versions Output for the list of supported versions in the PFM.
 * @param version Output for the version entry that matches the flash contents.
 *
 * @return 0 if a match was found in the PFM or an error code.
 */
static int host_flash_manager_find_flash_version (struct host_flash_manager *manager,
	struct pfm *pfm, bool rw_flash, struct pfm_firmware_versions *versions,
	const struct pfm_firmware_version **version)
{
	int status;

	status = pfm->get_supported_versions (pfm, NULL, versions);
	if (status != 0) {
		return status;
	}

	if (rw_flash) {
		status = host_fw_determine_version (host_flash_manager_get_read_write_flash (manager),
			versions, version);
	}
	else {
		status = host_fw_determine_version (host_flash_manager_get_read_only_flash (manager),
			versions, version);
	}

	if (status != 0) {
		pfm->free_fw_versions (pfm, versions);
	}

	return status;
}

/**
 * Get the information from a PFM entry for the image on flash.
 *
 * @param pfm The PFM to query for image information.
 * @param flash The flash containing the image.
 * @param offset An offset to apply to version addresses when matching the PFM entry.
 * @param versions Output for the list of supported versions in the PFM.
 * @param version Output for the version entry for the image on flash.
 * @param fw_images Output for the list of images specified for the version.
 * @param writable Output for the list of read/write regions for the version.  This can be null if
 * this information is not needed.
 *
 * @return 0 if the entry information was successfully queried or an error code.
 */
static int host_flash_manager_get_image_entry (struct pfm *pfm, struct spi_flash *flash,
	uint32_t offset, struct pfm_firmware_versions *versions,
	const struct pfm_firmware_version **version, struct pfm_image_list *fw_images,
	struct pfm_read_write_regions *writable)
{
	int status;

	status = pfm->get_supported_versions (pfm, NULL, versions);
	if (status != 0) {
		return status;
	}

	status = host_fw_determine_offset_version (flash, offset, versions, version);
	if (status != 0) {
		goto free_versions;
	}

	status = pfm->get_firmware_images (pfm, NULL, (*version)->fw_version_id, fw_images);
	if (status != 0) {
		goto free_versions;
	}

	if (writable) {
		status = pfm->get_read_write_regions (pfm, NULL, (*version)->fw_version_id, writable);
		if (status != 0) {
			goto free_images;
		}
	}

	return 0;

free_images:
	pfm->free_firmware_images (pfm, fw_images);
free_versions:
	pfm->free_fw_versions (pfm, versions);
	return status;
}

/**
 * Validate the image on a flash device.
 *
 * @param pfm The PFM to use for validation.
 * @param hash The hash to use for image validation.
 * @param rsa The RSA engine to use for signature verification.
 * @param full_validation Flag to control level of flash validation.
 * @param flash The flash device to validate.
 * @param writable Output for the read/write regions of the validated flash.  This will only be
 * valid if the flash is successfully validated.  This can be null if full_validation is false.
 *
 * @return 0 if the validation was successful or an error code.
 */
int host_flash_manager_validate_flash (struct pfm *pfm, struct hash_engine *hash,
	struct rsa_engine *rsa, bool full_validation, struct spi_flash *flash,
	struct pfm_read_write_regions *writable)
{
	return host_flash_manager_validate_offset_flash (pfm, hash, rsa, full_validation, flash, 0,
		writable);
}

/**
 * Validate the image on a flash device.
 *
 * @param pfm The PFM to use for validation.
 * @param hash The hash to use for image validation.
 * @param rsa The RSA engine to use for signature verification.
 * @param full_validation Flag to control level of flash validation.
 * @param flash The flash device to validate.
 * @param offset An offset in flash for images that will be validated.  Ignored if full_validation
 * is set.
 * @param writable Output for the read/write regions of the validated flash.  This will only be
 * valid if the flash is successfully validated.  This can be null if full_validation is false.
 *
 * @return 0 if the validation was successful or an error code.
 */
int host_flash_manager_validate_offset_flash (struct pfm *pfm, struct hash_engine *hash,
	struct rsa_engine *rsa, bool full_validation, struct spi_flash *flash, uint32_t offset,
	struct pfm_read_write_regions *writable)
{
	struct pfm_firmware_versions versions;
	const struct pfm_firmware_version *version;
	struct pfm_image_list fw_images;
	int status;

	status = host_flash_manager_get_image_entry (pfm, flash, offset, &versions, &version,
		&fw_images, writable);
	if (status != 0) {
		return status;
	}

	if (full_validation) {
		status = host_fw_full_flash_verification (flash, &fw_images, writable, version->blank_byte,
			hash, rsa);
	}
	else {
		status = host_fw_verify_offset_images (flash, &fw_images, offset, hash, rsa);
	}

	if ((status != 0) && writable) {
		pfm->free_read_write_regions (pfm, writable);
	}

	pfm->free_firmware_images (pfm, &fw_images);
	pfm->free_fw_versions (pfm, &versions);
	return status;
}

/**
 * Validate a PFM against the image on flash using a different PFM that is known to validate that
 * image.
 *
 * @param pfm The PFM to use for validation.
 * @param good_pfm The PFM that is known to be good for the flash image.
 * @param hash The hash to use for image validation.
 * @param rsa The RSA engine to use for signature verification.
 * @param flash The flash device to validate.
 * @param writable Output for the read/write regions of the validated flash.  This will only be
 * valid if the flash is successfully validated.  This can be null.
 *
 * @return 0 if the validation was successful or an error code.
 */
int host_flash_manager_validate_pfm (struct pfm *pfm, struct pfm *good_pfm,
	struct hash_engine *hash, struct rsa_engine *rsa, struct spi_flash *flash,
	struct pfm_read_write_regions *writable)
{
	struct pfm_firmware_versions versions;
	const struct pfm_firmware_version *version;
	struct pfm_image_list fw_images;
	struct pfm_image_list fw_images_good;
	int status;

	status = host_flash_manager_get_image_entry (pfm, flash, 0, &versions, &version, &fw_images,
		writable);
	if (status != 0) {
		return status;
	}

	status = good_pfm->get_firmware_images (good_pfm, NULL, version->fw_version_id,
		&fw_images_good);
	if (status == 0) {
		status = host_fw_are_images_different (&fw_images, &fw_images_good);

		good_pfm->free_firmware_images (good_pfm, &fw_images_good);
	}

	if (status != 0) {
		status = host_fw_verify_images (flash, &fw_images, hash, rsa);
	}

	if ((status != 0) && writable) {
		pfm->free_read_write_regions (pfm, writable);
	}

	pfm->free_firmware_images (pfm, &fw_images);
	pfm->free_fw_versions (pfm, &versions);
	return status;
}

static int host_flash_manager_validate_read_only_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct pfm *good_pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	bool full_validation, struct pfm_read_write_regions *writable)
{
	int status;

	if ((manager == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) ||
		(writable == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	if (good_pfm && !full_validation) {
		status = host_flash_manager_validate_pfm (pfm, good_pfm, hash, rsa,
			host_flash_manager_get_read_only_flash (manager), writable);
	}
	else {
		status = host_flash_manager_validate_flash (pfm, hash, rsa, full_validation,
			host_flash_manager_get_read_only_flash (manager), writable);
	}

	return status;
}

static int host_flash_manager_validate_read_write_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	struct pfm_read_write_regions *writable)
{
	if ((manager == NULL) || (pfm == NULL) || (hash == NULL) || (rsa == NULL) ||
		(writable == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	return host_flash_manager_validate_flash (pfm, hash, rsa, true,
		host_flash_manager_get_read_write_flash (manager), writable);
}

static int host_flash_manager_get_flash_read_write_regions (struct host_flash_manager *manager,
	struct pfm *pfm, bool rw_flash, struct pfm_read_write_regions *writable)
{
	struct pfm_firmware_versions versions;
	const struct pfm_firmware_version *version;
	int status;

	if ((manager == NULL) || (pfm == NULL) || (writable == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = host_flash_manager_find_flash_version (manager, pfm, rw_flash, &versions, &version);
	if (status != 0) {
		return status;
	}

	status = pfm->get_read_write_regions (pfm, NULL, version->fw_version_id, writable);

	pfm->free_fw_versions (pfm, &versions);
	return status;
}

/**
 * Ensure both flash devices are operating in the same address mode.
 *
 * @param manager The manager for the flash devices to configure.
 * @param mode Output indicating the current address mode of both devices.
 *
 * @return 0 if the address mode was configured successfully or an error code.
 */
static int host_flash_manager_flash_address_mode (struct host_flash_manager *manager,
	spi_filter_address_mode *mode)
{
	int addr_4byte;
	int status;

	addr_4byte = spi_flash_is_4byte_address_mode (manager->flash_cs0);
	if (addr_4byte != spi_flash_is_4byte_address_mode (manager->flash_cs1)) {
		status = spi_flash_enable_4byte_address_mode (manager->flash_cs1, addr_4byte);
		if (status != 0) {
			if (status == SPI_FLASH_UNSUPPORTED_ADDR_MODE) {
				status = HOST_FLASH_MGR_MISMATCH_ADDR_MODE;
			}

			return status;
		}
	}

	*mode = (addr_4byte) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3;
	return 0;
}

/**
 * Detect the address mode properties of the flash devices.
 *
 * @param manager The manager for the flash to query.
 * @param wen_required Output indicating if write enable is required to switch address modes.
 * @param fixed_addr Output indicating if the device address mode is fixed.
 * @param mode Output indicating the current address mode of the device.
 * @param reset_mode Output indicating the default address mode on device reset.
 *
 * @return 0 if the address mode properties were successfully detected or an error code.
 */
static int host_flash_manager_detect_flash_address_mode_properties (
	struct host_flash_manager *manager, bool *wen_required, bool *fixed_addr,
	spi_filter_address_mode *mode, spi_filter_address_mode *reset_mode)
{
	int req_write_en[2];
	int reset_addr[2];
	int status;

	req_write_en[0] = spi_flash_address_mode_requires_write_enable (manager->flash_cs0);
	req_write_en[1] = spi_flash_address_mode_requires_write_enable (manager->flash_cs1);
	if (req_write_en[0] != req_write_en[1]) {
		return HOST_FLASH_MGR_MISMATCH_ADDR_MODE;
	}

	if (req_write_en[0] == SPI_FLASH_ADDR_MODE_FIXED) {
		*wen_required = false;
		*fixed_addr = true;
	}
	else {
		*wen_required = req_write_en[0];
		*fixed_addr = false;
	}

	status = host_flash_manager_flash_address_mode (manager, mode);
	if (status != 0) {
		return status;
	}

	reset_addr[0] = spi_flash_is_4byte_address_mode_on_reset (manager->flash_cs0);
	if ((reset_addr[0] != 0) && (reset_addr[0] != 1)) {
		return reset_addr[0];
	}

	reset_addr[1] = spi_flash_is_4byte_address_mode_on_reset (manager->flash_cs1);
	if ((reset_addr[1] != 0) && (reset_addr[1] != 1)) {
		return reset_addr[1];
	}

	if (reset_addr[0] != reset_addr[1]) {
		return HOST_FLASH_MGR_MISMATCH_ADDR_MODE;
	}

	*reset_mode = (reset_addr[0] == 1) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3;
	return 0;
}

static int host_flash_manager_config_spi_filter_flash_type (struct host_flash_manager *manager)
{
	uint8_t vendor[2];
	uint16_t device[2];
	uint32_t bytes[2];
	bool req_write_en;
	bool fixed;
	spi_filter_address_mode mode;
	spi_filter_address_mode reset_mode;
	int status;

	if (manager == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Validate and configure the type of devices being used. */
	status = spi_flash_get_device_id (manager->flash_cs0, &vendor[0], &device[0]);
	if (status != 0) {
		return status;
	}

	status = spi_flash_get_device_id (manager->flash_cs1, &vendor[1], &device[1]);
	if (status != 0) {
		return status;
	}

	if (vendor[0] != vendor[1]) {
		return HOST_FLASH_MGR_MISMATCH_VENDOR;
	}
	else if (device[0] != device[1]) {
		return HOST_FLASH_MGR_MISMATCH_DEVICE;
	}

	status = manager->mfg_handler->set_flash_manufacturer (manager->mfg_handler, vendor[0],
		device[0]);
	if (status != 0) {
		return status;
	}

	/* Validate and configure the flash device capacity. */
	spi_flash_get_device_size (manager->flash_cs0, &bytes[0]);
	spi_flash_get_device_size (manager->flash_cs1, &bytes[1]);
	if (bytes[0] != bytes[1]) {
		return HOST_FLASH_MGR_MISMATCH_SIZES;
	}

	status = manager->filter->set_flash_size (manager->filter, bytes[0]);
	if ((status != 0) && (status != SPI_FILTER_UNSUPPORTED_OPERATION)) {
		return status;
	}

	/* Validate and configure the address byte mode of the devices. */
	status = host_flash_manager_detect_flash_address_mode_properties (manager, &req_write_en,
		&fixed, &mode, &reset_mode);
	if (status != 0) {
		return status;
	}

	if (!fixed) {
		status = manager->filter->set_addr_byte_mode (manager->filter, mode);
	}
	else {
		status = manager->filter->set_fixed_addr_byte_mode (manager->filter, mode);
	}
	if (status != 0) {
		return status;
	}

	status = manager->filter->require_addr_byte_mode_write_enable (manager->filter, req_write_en);
	if ((status != 0) && (status != SPI_FILTER_UNSUPPORTED_OPERATION)) {
		return status;
	}

	status = manager->filter->set_reset_addr_byte_mode (manager->filter, reset_mode);
	if (status == SPI_FILTER_UNSUPPORTED_OPERATION) {
		status = 0;
	}

	return status;
}

static int host_flash_manager_config_spi_filter_flash_devices (struct host_flash_manager *manager)
{
	spi_filter_cs ro;

	if (manager == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	ro = host_state_manager_get_read_only_flash (manager->host_state);
	return manager->filter->set_ro_cs (manager->filter, ro);
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
static int host_flash_manager_migrate_rw_data (struct host_flash_manager *manager,
	spi_filter_cs from, struct pfm_read_write_regions *writable)
{
	int status;

	if (from == SPI_FILTER_CS_0) {
		status = host_fw_migrate_read_write_data (manager->flash_cs1, writable,
			manager->flash_cs0, NULL);
	}
	else {
		status = host_fw_migrate_read_write_data (manager->flash_cs0, writable,
			manager->flash_cs1, NULL);
	}

	return status;
}

static int host_flash_manager_swap_flash_devices (struct host_flash_manager *manager,
	struct pfm_read_write_regions *writable, struct pfm_manager *used_pending)
{
	spi_filter_cs rw;
	int status;

	if (manager == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Clear the dirty bit in the SPI filter. */
	status = manager->filter->clear_flash_dirty_state (manager->filter);
	if (status != 0) {
		return status;
	}

	/* Configure the SPI filter to switch the read and write flashes. */
	rw = (host_state_manager_get_read_only_flash (manager->host_state) == SPI_FILTER_CS_0) ?
		SPI_FILTER_CS_1 : SPI_FILTER_CS_0;
	status = manager->filter->set_ro_cs (manager->filter, rw);
	if (status != 0) {
		return status;
	}

	/* Migrate the R/W data to the new write flash. */
	if (writable) {
		status = host_flash_manager_migrate_rw_data (manager, rw, writable);
	}

	/* Save the current flash configuration. */
	if (status == 0) {
		state_manager_block_non_volatile_state_storage (manager->host_state, true);

		host_state_manager_save_read_only_flash (manager->host_state, rw);
		host_state_manager_save_inactive_dirty (manager->host_state, false);

		if (used_pending) {
			used_pending->base.activate_pending_manifest (&used_pending->base);
		}

		state_manager_block_non_volatile_state_storage (manager->host_state, false);
	}

	return status;
}

static int host_flash_manager_initialize_flash_protection (struct host_flash_manager *manager,
	struct pfm_read_write_regions *writable)
{
	spi_filter_cs ro;
	struct spi_flash *ro_flash;
	struct spi_flash *rw_flash;
	int status;
	int addr_4byte;

	if ((manager == NULL) || (writable == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	/* Make sure both flash devices are running with the same address mode. */
	ro_flash = host_flash_manager_get_read_only_flash (manager);
	rw_flash = host_flash_manager_get_read_write_flash (manager);

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
	ro = host_state_manager_get_read_only_flash (manager->host_state);

	status = host_flash_manager_migrate_rw_data (manager, ro, writable);
	if (status != 0) {
		return status;
	}

	/* Protection is being initialized, so the R/W flash can't be dirty yet. */
	status = manager->filter->clear_flash_dirty_state (manager->filter);
	if (status != 0) {
		return status;
	}

	host_state_manager_save_inactive_dirty (manager->host_state, false);

	/* Make sure the SPI filter address mode matches the mode of the physical devices.
	 *
	 * If the device address mode is fixed, this was already configured during initial filter setup
	 * and doesn't need to be done again. */
	if (!spi_flash_is_address_mode_fixed (ro_flash)) {
		status = manager->filter->set_addr_byte_mode (manager->filter,
			(addr_4byte == 1) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3);
		if (status != 0) {
			return status;
		}
	}

	/* Turn on the SPI filter. */
	status = manager->filter->set_bypass_mode (manager->filter, SPI_FILTER_OPERATE);
	if (status != 0) {
		return status;
	}

	return manager->filter->set_ro_cs (manager->filter, ro);
}

/**
 * Configure a single SPI flash device and the driver to allow the RoT access to the device.
 *
 * @param flash The flash device to configure.
 *
 * @return 0 if the device was configured successfully or an error code.
 */
int host_flash_manager_configure_flash_for_rot_access (struct spi_flash *flash)
{
	uint8_t vendor;
	int status;

	status = spi_flash_get_device_id (flash, &vendor, NULL);
	if (status != 0) {
		return status;
	}

	if ((vendor == 0xff) || (vendor == 0x00)) {
		return HOST_FLASH_MGR_INVALID_VENDOR;
	}

	/* We don't know what state the flash device is in at this point, so make sure there is no
	 * write in progress before we try to use it. */
	status = spi_flash_wait_for_write (flash, 10000);
	if (status != 0) {
		return status;
	}

	status = spi_flash_clear_block_protect (flash);
	if (status != 0) {
		return status;
	}

	if (spi_flash_is_quad_spi_enabled (flash) != 1) {
		status = spi_flash_enable_quad_spi (flash, true);
		if (status != 0) {
			return status;
		}
	}

	/* Detect the address mode of the device so we know how to talk with it. */
	status = spi_flash_detect_4byte_address_mode (flash);
	if (status != 0) {
		return status;
	}

	return 0;
}

static int host_flash_manager_set_flash_for_rot_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct spi_flash *flash;
	int i;
	int status;

	if ((manager == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = manager->filter->enable_filter (manager->filter, false);
	if (status != 0) {
		return status;
	}

	status = control->enable_processor_flash_access (control, false);
	if (status != 0) {
		return status;
	}

	if (manager->flash_init) {
		status = host_flash_initialization_initialize_flash (manager->flash_init);
		if (status != 0) {
			return status;
		}
	}

	flash = manager->flash_cs0;
	for (i = 0; i < 2; i++) {
		status = host_flash_manager_configure_flash_for_rot_access (flash);
		if (status != 0) {
			return status;
		}

		flash = manager->flash_cs1;
	}

	return 0;
}

static int host_flash_manager_set_flash_for_host_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	int status;

	if ((manager == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = control->enable_processor_flash_access (control, true);
	if (status != 0) {
		return status;
	}

	return manager->filter->enable_filter (manager->filter, true);
}

static int host_flash_manager_host_has_flash_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	bool enabled;
	int status;

	if ((manager == NULL) || (control == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = manager->filter->get_filter_enabled (manager->filter, &enabled);
	if (status != 0) {
		return status;
	}

	status = control->processor_has_flash_access (control);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if ((status == 0) || !enabled) {
		return 0;
	}

	return 1;
}

/**
 * Initialize the manager for host flash devices.
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
int host_flash_manager_init (struct host_flash_manager *manager, struct spi_flash *cs0,
	struct spi_flash *cs1, struct state_manager *host_state, struct spi_filter_interface *filter,
	struct flash_mfg_filter_handler *mfg_handler)
{
	if ((manager == NULL) || (cs0 == NULL) || (cs1 == NULL) || (host_state == NULL) ||
		(filter == NULL) || (mfg_handler == NULL)) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct host_flash_manager));

	manager->get_read_only_flash = host_flash_manager_get_read_only_flash;
	manager->get_read_write_flash = host_flash_manager_get_read_write_flash;
	manager->validate_read_only_flash = host_flash_manager_validate_read_only_flash;
	manager->validate_read_write_flash = host_flash_manager_validate_read_write_flash;
	manager->get_flash_read_write_regions = host_flash_manager_get_flash_read_write_regions;
	manager->config_spi_filter_flash_type = host_flash_manager_config_spi_filter_flash_type;
	manager->config_spi_filter_flash_devices = host_flash_manager_config_spi_filter_flash_devices;
	manager->swap_flash_devices = host_flash_manager_swap_flash_devices;
	manager->initialize_flash_protection = host_flash_manager_initialize_flash_protection;
	manager->set_flash_for_rot_access = host_flash_manager_set_flash_for_rot_access;
	manager->set_flash_for_host_access = host_flash_manager_set_flash_for_host_access;
	manager->host_has_flash_access = host_flash_manager_host_has_flash_access;

	manager->flash_cs0 = cs0;
	manager->flash_cs1 = cs1;
	manager->host_state = host_state;
	manager->filter = filter;
	manager->mfg_handler = mfg_handler;

	return 0;
}

/**
 * Initialize the manager for host flash devices.  The interfaces to the flash devices may be
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
int host_flash_manager_init_with_managed_flash_initialization (struct host_flash_manager *manager,
	struct spi_flash *cs0, struct spi_flash *cs1, struct state_manager *host_state,
	struct spi_filter_interface *filter, struct flash_mfg_filter_handler *mfg_handler,
	struct host_flash_initialization *flash_init)
{
	int status;

	if (flash_init == NULL) {
		return HOST_FLASH_MGR_INVALID_ARGUMENT;
	}

	status = host_flash_manager_init (manager, cs0, cs1, host_state, filter, mfg_handler);
	if (status != 0) {
		return status;
	}

	manager->flash_init = flash_init;

	return 0;
}

/**
 * Release the resources used by host flash management.
 *
 * @param manager The manager to release.
 */
void host_flash_manager_release (struct host_flash_manager *manager)
{

}
