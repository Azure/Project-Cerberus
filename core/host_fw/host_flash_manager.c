// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_flash_manager.h"
#include "host_fw_util.h"


/**
 * Get the information from a PFM entry for the image on flash.
 *
 * @param pfm The PFM to query for image information.
 * @param flash The flash containing the image.
 * @param offset An offset to apply to version addresses when matching the PFM entry.
 * @param fw_id Identifier for the firmware type to query in the PFM.
 * @param versions Output for the list of supported versions in the PFM.
 * @param version Output for the version entry for the image on flash.
 * @param fw_images Output for the list of images specified for the version.
 * @param writable Output for the list of read/write regions for the version.  This can be null if
 * this information is not needed.
 *
 * @return 0 if the entry information was successfully queried or an error code.
 */
int host_flash_manager_get_image_entry (struct pfm *pfm, struct spi_flash *flash, uint32_t offset,
	const char *fw_id, struct pfm_firmware_versions *versions,
	const struct pfm_firmware_version **version, struct pfm_image_list *fw_images,
	struct pfm_read_write_regions *writable)
{
	int status;

	status = pfm->get_supported_versions (pfm, fw_id, versions);
	if (status != 0) {
		return status;
	}

	status = host_fw_determine_offset_version (flash, offset, versions, version);
	if (status != 0) {
		goto free_versions;
	}

	status = pfm->get_firmware_images (pfm, fw_id, (*version)->fw_version_id, fw_images);
	if (status != 0) {
		goto free_versions;
	}

	if (writable) {
		status = pfm->get_read_write_regions (pfm, fw_id, (*version)->fw_version_id, writable);
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
 * Get the list of firmware components expected on flash and initialize containers for PFM entries.
 *
 * @param pfm The PFM to query for firmware information.
 * @param host_fw Output for the list of host firmware.
 * @param host_img Output for the container of host firmware images.  Null if not necessary.
 * @param host_rw Output for the container of host read/write regions.  Null if not necessary.
 *
 * @return 0 if the operation was successful or an error code.
 */
int host_flash_manager_get_firmware_types (struct pfm *pfm, struct pfm_firmware *host_fw,
	struct host_flash_manager_images *host_img, struct host_flash_manager_rw_regions *host_rw)
{
	int status;

	status = pfm->get_firmware (pfm, host_fw);
	if (status != 0) {
		return status;
	}

	if (host_img) {
		host_img->pfm = pfm;
		host_img->count = 0;
		host_img->fw_images = platform_calloc (host_fw->count, sizeof (struct pfm_image_list));
		if (host_img->fw_images == NULL) {
			goto free_firmware;
		}
	}

	if (host_rw) {
		host_rw->pfm = pfm;
		host_rw->count = 0;
		host_rw->writable = platform_calloc (host_fw->count,
			sizeof (struct pfm_read_write_regions));
		if (host_rw->writable == NULL) {
			goto free_img;
		}
	}

	return 0;

free_img:
	platform_free (host_img->fw_images);
free_firmware:
	pfm->free_firmware (pfm, host_fw);
	return HOST_FLASH_MGR_NO_MEMORY;
}

void host_flash_manager_free_read_write_regions (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw)
{
	size_t i;

	if (host_rw && host_rw->pfm) {
		if (host_rw->writable) {
			for (i = 0; i < host_rw->count; i++) {
				host_rw->pfm->free_read_write_regions (host_rw->pfm, &host_rw->writable[i]);
			}

			platform_free (host_rw->writable);
		}

		memset (host_rw, 0, sizeof (*host_rw));
	}
}

/**
 * Free a list of authenticated firmware images on flash.
 *
 * @param host_img The list to free.
 */
void host_flash_manager_free_images (struct host_flash_manager_images *host_img)
{
	size_t i;

	if (host_img->fw_images) {
		for (i = 0; i < host_img->count; i++) {
			host_img->pfm->free_firmware_images (host_img->pfm, &host_img->fw_images[i]);
		}

		platform_free (host_img->fw_images);
	}
}

/**
 * Validate the image on a flash device.
 *
 * @param pfm The PFM to use for validation.
 * @param hash The hash to use for image validation.
 * @param rsa The RSA engine to use for signature verification.
 * @param full_validation Flag to control level of flash validation.
 * @param flash The flash device to validate.
 * @param host_rw Output for the read/write regions of the validated flash.  This will only be
 * valid if the flash is successfully validated.  This can be null if full_validation is false.
 *
 * @return 0 if the validation was successful or an error code.
 */
int host_flash_manager_validate_flash (struct pfm *pfm, struct hash_engine *hash,
	struct rsa_engine *rsa, bool full_validation, struct spi_flash *flash,
	struct host_flash_manager_rw_regions *host_rw)
{
	return host_flash_manager_validate_offset_flash (pfm, hash, rsa, full_validation, flash, 0,
		host_rw);
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
 * @param host_rw Output for the read/write regions of the validated flash.  This will only be
 * valid if the flash is successfully validated.  This can be null if full_validation is false.
 *
 * @return 0 if the validation was successful or an error code.
 */
int host_flash_manager_validate_offset_flash (struct pfm *pfm, struct hash_engine *hash,
	struct rsa_engine *rsa, bool full_validation, struct spi_flash *flash, uint32_t offset,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct pfm_firmware host_fw;
	struct pfm_firmware_versions versions;
	const struct pfm_firmware_version *version;
	struct host_flash_manager_images host_img;
	size_t i;
	int status;

	status = host_flash_manager_get_firmware_types (pfm, &host_fw, &host_img, host_rw);
	if (status != 0) {
		return status;
	}

	for (i = 0; i < host_fw.count; i++) {
		status = host_flash_manager_get_image_entry (pfm, flash, offset, host_fw.ids[i], &versions,
			&version, &host_img.fw_images[i], (host_rw) ? &host_rw->writable[i] : NULL);
		if (status != 0) {
			goto free_host;
		}

		host_img.count++;
		if (host_rw) {
			host_rw->count++;
		}

		pfm->free_fw_versions (pfm, &versions);
	}

	if (full_validation) {
		status = host_fw_full_flash_verification_multiple_fw (flash, host_img.fw_images,
			host_rw->writable, host_fw.count, version->blank_byte, hash, rsa);
	}
	else {
		status = host_fw_verify_offset_images_multiple_fw (flash, host_img.fw_images,
			host_img.count, offset, hash, rsa);
	}

free_host:
	if ((status != 0) && host_rw) {
		host_flash_manager_free_read_write_regions (NULL, host_rw);
	}

	host_flash_manager_free_images (&host_img);
	pfm->free_firmware (pfm, &host_fw);
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
 * @param host_rw Output for the read/write regions of the validated flash.  This will only be
 * valid if the flash is successfully validated.  This can be null.
 *
 * @return 0 if the validation was successful or an error code.
 */
int host_flash_manager_validate_pfm (struct pfm *pfm, struct pfm *good_pfm,
	struct hash_engine *hash, struct rsa_engine *rsa, struct spi_flash *flash,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct pfm_firmware host_fw;
	struct pfm_firmware_versions versions;
	const struct pfm_firmware_version *version;
	struct host_flash_manager_images host_img;
	struct pfm_image_list fw_images_good;
	size_t i;
	int status;
	int match_status = 0;

	status = host_flash_manager_get_firmware_types (pfm, &host_fw, &host_img, host_rw);
	if (status != 0) {
		return status;
	}

	for (i = 0; i <host_fw.count; i++) {
		status = host_flash_manager_get_image_entry (pfm, flash, 0, host_fw.ids[i], &versions,
			&version, &host_img.fw_images[i], (host_rw) ? &host_rw->writable[i] : NULL);
		if (status != 0) {
			goto free_host;
		}

		host_img.count++;
		if (host_rw) {
			host_rw->count++;
		}

		if (match_status == 0) {
			match_status = good_pfm->get_firmware_images (good_pfm, host_fw.ids[i],
				version->fw_version_id, &fw_images_good);
			if (match_status == 0) {
				match_status = host_fw_are_images_different (&host_img.fw_images[i],
					&fw_images_good);

				good_pfm->free_firmware_images (good_pfm, &fw_images_good);
			}
		}

		pfm->free_fw_versions (pfm, &versions);
	}

	if (match_status != 0) {
		status = host_fw_verify_images_multiple_fw (flash, host_img.fw_images, host_img.count, hash,
			rsa);
	}

free_host:
	if ((status != 0) && host_rw) {
		host_flash_manager_free_read_write_regions (NULL, host_rw);
	}

	host_flash_manager_free_images (&host_img);
	pfm->free_firmware (pfm, &host_fw);
	return status;
}

/**
 * Find the entry in the PFM for the firmware version stored on flash.
 *
 * @param flash The flash to inspect.
 * @param pfm The PFM to check the flash contents against.
 * @param fw_id Identifier for the firmware type to query in the PFM.
 * @param versions Output for the list of supported versions in the PFM.
 * @param version Output for the version entry that matches the flash contents.
 *
 * @return 0 if a match was found in the PFM or an error code.
 */
static int host_flash_manager_find_flash_version (struct spi_flash *flash, struct pfm *pfm,
	const char *fw_id, struct pfm_firmware_versions *versions,
	const struct pfm_firmware_version **version)
{
	int status;

	status = pfm->get_supported_versions (pfm, fw_id, versions);
	if (status != 0) {
		return status;
	}

	status = host_fw_determine_version (flash, versions, version);
	if (status != 0) {
		pfm->free_fw_versions (pfm, versions);
	}

	return status;
}

/**
 * Determine the the read/write regions for the host firmware on flash.
 *
 * @param flash The flash containing the firmware.
 * @param pfm The PFM to use to determine R/W regions.
 * @param host_rw Output for the firmware read/write regions.
 *
 * @return 0 if the regions were successfully determined or an error code.
 */
int host_flash_manager_get_flash_read_write_regions (struct spi_flash *flash, struct pfm *pfm,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct pfm_firmware host_fw;
	struct pfm_firmware_versions versions;
	const struct pfm_firmware_version *version;
	size_t i;
	int status;

	status = host_flash_manager_get_firmware_types (pfm, &host_fw, NULL, host_rw);
	if (status != 0) {
		return status;
	}

	for (i = 0; i < host_fw.count; i++, host_rw->count++) {
		status = host_flash_manager_find_flash_version (flash, pfm, host_fw.ids[i], &versions,
			&version);
		if (status != 0) {
			goto free_rw;
		}

		status = pfm->get_read_write_regions (pfm, host_fw.ids[i], version->fw_version_id,
			&host_rw->writable[i]);
		pfm->free_fw_versions (pfm, &versions);
		if (status != 0) {
			goto free_rw;
		}
	}

free_rw:
	if (status != 0) {
		host_flash_manager_free_read_write_regions (NULL, host_rw);
	}

	pfm->free_firmware (pfm, &host_fw);
	return status;
}

/**
 * Ensure both flash devices are operating in the same address mode.
 *
 * @param cs0 The flash device connected to CS0.
 * @param cs1 The flash device connected to CS1.  Null if there is only a single flash device.
 * @param mode Output indicating the current address mode of both devices.
 *
 * @return 0 if the address mode was configured successfully or an error code.
 */
static int host_flash_manager_flash_address_mode (struct spi_flash *cs0, struct spi_flash *cs1,
	spi_filter_address_mode *mode)
{
	int addr_4byte;
	int status;

	addr_4byte = spi_flash_is_4byte_address_mode (cs0);

	if (cs1) {
		if (addr_4byte != spi_flash_is_4byte_address_mode (cs1)) {
			status = spi_flash_enable_4byte_address_mode (cs1, addr_4byte);
			if (status != 0) {
				if (status == SPI_FLASH_UNSUPPORTED_ADDR_MODE) {
					status = HOST_FLASH_MGR_MISMATCH_ADDR_MODE;
				}

				return status;
			}
		}
	}

	*mode = (addr_4byte) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3;
	return 0;
}

/**
 * Detect the address mode properties of the flash devices.
 *
 * @param cs0 The flash device connected to CS0.
 * @param cs1 The flash device connected to CS1.  Null if there is only a single flash device.
 * @param wen_required Output indicating if write enable is required to switch address modes.
 * @param fixed_addr Output indicating if the device address mode is fixed.
 * @param mode Output indicating the current address mode of the device.
 * @param reset_mode Output indicating the default address mode on device reset.
 *
 * @return 0 if the address mode properties were successfully detected or an error code.
 */
static int host_flash_manager_detect_flash_address_mode_properties (struct spi_flash *cs0,
	struct spi_flash *cs1, bool *wen_required, bool *fixed_addr, spi_filter_address_mode *mode,
	spi_filter_address_mode *reset_mode)
{
	int req_write_en[2];
	int reset_addr[2];
	int status;

	req_write_en[0] = spi_flash_address_mode_requires_write_enable (cs0);
	if (cs1) {
		req_write_en[1] = spi_flash_address_mode_requires_write_enable (cs1);
		if (req_write_en[0] != req_write_en[1]) {
			return HOST_FLASH_MGR_MISMATCH_ADDR_MODE;
		}
	}

	if (req_write_en[0] == SPI_FLASH_ADDR_MODE_FIXED) {
		*wen_required = false;
		*fixed_addr = true;
	}
	else {
		*wen_required = req_write_en[0];
		*fixed_addr = false;
	}

	status = host_flash_manager_flash_address_mode (cs0, cs1, mode);
	if (status != 0) {
		return status;
	}

	reset_addr[0] = spi_flash_is_4byte_address_mode_on_reset (cs0);
	if ((reset_addr[0] != 0) && (reset_addr[0] != 1)) {
		return reset_addr[0];
	}

	if (cs1) {
		reset_addr[1] = spi_flash_is_4byte_address_mode_on_reset (cs1);
		if ((reset_addr[1] != 0) && (reset_addr[1] != 1)) {
			return reset_addr[1];
		}

		if (reset_addr[0] != reset_addr[1]) {
			return HOST_FLASH_MGR_MISMATCH_ADDR_MODE;
		}
	}

	*reset_mode = (reset_addr[0] == 1) ? SPI_FILTER_ADDRESS_MODE_4 : SPI_FILTER_ADDRESS_MODE_3;
	return 0;
}

/**
 * Detect the flash device properties and configure the SPI filter to match.  If there are two flash
 * devices, they must match exactly or an error will be generated.
 *
 * @param cs0 The flash device connected to CS0.
 * @param cs1 The flash device connected to CS1.  Null if there is only a single flash device.
 * @param filter The SPI filter to configure.
 * @param mfg_handler Handler for configuring flash manufacturer details into the filter.
 *
 * @return 0 if the flash is supported and the filter was configured successfully or an error code.
 */
int host_flash_manager_config_spi_filter_flash_type (struct spi_flash *cs0, struct spi_flash *cs1,
	struct spi_filter_interface *filter, struct flash_mfg_filter_handler *mfg_handler)
{
	uint8_t vendor[2];
	uint16_t device[2];
	uint32_t bytes[2];
	bool req_write_en;
	bool fixed;
	spi_filter_address_mode mode;
	spi_filter_address_mode reset_mode;
	int status;

	/* Validate and configure the type of devices being used. */
	status = spi_flash_get_device_id (cs0, &vendor[0], &device[0]);
	if (status != 0) {
		return status;
	}

	if (cs1) {
		status = spi_flash_get_device_id (cs1, &vendor[1], &device[1]);
		if (status != 0) {
			return status;
		}

		if (vendor[0] != vendor[1]) {
			return HOST_FLASH_MGR_MISMATCH_VENDOR;
		}
		else if (device[0] != device[1]) {
			return HOST_FLASH_MGR_MISMATCH_DEVICE;
		}
	}

	status = mfg_handler->set_flash_manufacturer (mfg_handler, vendor[0],
		device[0]);
	if (status != 0) {
		return status;
	}

	/* Validate and configure the flash device capacity. */
	spi_flash_get_device_size (cs0, &bytes[0]);
	if (cs1) {
		spi_flash_get_device_size (cs1, &bytes[1]);
		if (bytes[0] != bytes[1]) {
			return HOST_FLASH_MGR_MISMATCH_SIZES;
		}
	}

	status = filter->set_flash_size (filter, bytes[0]);
	if ((status != 0) && (status != SPI_FILTER_UNSUPPORTED_OPERATION)) {
		return status;
	}

	/* Validate and configure the address byte mode of the devices. */
	status = host_flash_manager_detect_flash_address_mode_properties (cs0, cs1, &req_write_en,
		&fixed, &mode, &reset_mode);
	if (status != 0) {
		return status;
	}

	if (!fixed) {
		status = filter->set_addr_byte_mode (filter, mode);
	}
	else {
		status = filter->set_fixed_addr_byte_mode (filter, mode);
	}
	if (status != 0) {
		return status;
	}

	status = filter->require_addr_byte_mode_write_enable (filter, req_write_en);
	if ((status != 0) && (status != SPI_FILTER_UNSUPPORTED_OPERATION)) {
		return status;
	}

	status = filter->set_reset_addr_byte_mode (filter, reset_mode);
	if (status == SPI_FILTER_UNSUPPORTED_OPERATION) {
		status = 0;
	}

	return status;
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

/**
 * Enable RoT access to the protected flash devices.
 *
 * @param control The interface for hardware controls for flash access.
 * @param filter The SPI filter connected to the flash devices.
 * @param cs0 Flash device connected to CS0.
 * @param cs1 Flash device connected to CS1.  Null if there is only a single flash device.
 * @param flash_init Initialization handler for the protected flash devices.  Null to skip
 * initialization.
 *
 * @return 0 if RoT flash access has been enabled or an error code.
 */
int host_flash_manager_set_flash_for_rot_access (struct host_control *control,
	struct spi_filter_interface *filter, struct spi_flash *cs0, struct spi_flash *cs1,
	struct host_flash_initialization *flash_init)
{
	struct spi_flash *flash;
	int i;
	int status;

	status = filter->enable_filter (filter, false);
	if (status != 0) {
		return status;
	}

	status = control->enable_processor_flash_access (control, false);
	if (status != 0) {
		return status;
	}

	if (flash_init) {
		status = host_flash_initialization_initialize_flash (flash_init);
		if (status != 0) {
			return status;
		}
	}

	flash = cs0;
	for (i = 0; i < 2; i++) {
		if (flash) {
			status = host_flash_manager_configure_flash_for_rot_access (flash);
			if (status != 0) {
				return status;
			}
		}

		flash = cs1;
	}

	return 0;
}

/**
 * Enable host access to the protected flash devices.
 *
 * @param control The interface for hardware controls for flash access.
 * @param filter The SPI filter connected to the flash devices.
 *
 * @return 0 if host flash access has been enabled or an error code.
 */
int host_flash_manager_set_flash_for_host_access (struct host_control *control,
	struct spi_filter_interface *filter)
{
	int status;

	status = control->enable_processor_flash_access (control, true);
	if (status != 0) {
		return status;
	}

	return filter->enable_filter (filter, true);
}

/**
 * Determine if the host has access to the protected flash devices.
 *
 * @param control The interface for hardware controls for flash access.
 * @param filter The SPI filter connected to the flash devices.
 *
 * @return 0 if the host doesn't if access, 1 if it does, or an error code.
 */
int host_flash_manager_host_has_flash_access (struct host_control *control,
	struct spi_filter_interface *filter)
{
	bool enabled;
	int status;

	status = filter->get_filter_enabled (filter, &enabled);
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
