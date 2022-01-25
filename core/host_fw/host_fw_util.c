// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "host_fw_util.h"
#include "flash/flash_util.h"


/**
 * Search a list of host firmware version identifiers to find the longest string.
 *
 * @param list The list of versions to search.
 *
 * @return The length of the longest identifier.
 */
static int host_fw_find_longest_version_id (const struct pfm_firmware_versions *list)
{
	size_t i;
	int max = 0;
	int len;

	if (list != NULL) {
		for (i = 0; i < list->count; i++) {
			len = strlen (list->versions[i].fw_version_id);
			if (len > max) {
				max = len;
			}
		}
	}

	return max;
}

/**
 * Determine the version of the host firmware image stored on flash.  In order for the version to be
 * recognized, it must be present in the list of firmware versions from the PFM.
 *
 * @param flash The flash device that contains the host firmware.
 * @param allowed The list of allowed versions to use when inspecting the flash.
 * @param version A pointer that will be updated to reference the version information for the
 * matched version.  This will be a pointer to the entry within the versions list.
 *
 * @return 0 if the firmware version was found or an error code.
 */
int host_fw_determine_version (struct spi_flash *flash, const struct pfm_firmware_versions *allowed,
	const struct pfm_firmware_version **version)
{
	return host_fw_determine_offset_version (flash, 0, allowed, version);
}

/**
 * Determine the version of the host firmware image stored on flash.  In order for the version to be
 * recognized, it must be present in the list of firmware versions from the PFM.
 *
 * All version ID addresses specified in the PFM will be offset by a fixed amount.
 *
 * @param flash The flash device that contains the host firmware.
 * @param offset The offset to apply to version addresses.
 * @param allowed The list of allowed versions to use when inspecting the flash.
 * @param version A pointer that will be updated to reference the version information for the
 * matched version.  This will be a pointer to the entry within the versions list.
 *
 * @return 0 if the firmware version was found or an error code.
 */
int host_fw_determine_offset_version (struct spi_flash *flash, uint32_t offset,
	const struct pfm_firmware_versions *allowed, const struct pfm_firmware_version **version)
{
	char *fw_version;
	size_t version_len;
	size_t current_len;
	int status;
	int i;
	int prev = -1;

	if ((flash == NULL) || (allowed == NULL) || (version == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	if ((allowed->count == 0) || (allowed->versions == NULL)) {
		return HOST_FW_UTIL_UNSUPPORTED_VERSION;
	}

	fw_version = platform_malloc (host_fw_find_longest_version_id (allowed));
	if (fw_version == NULL) {
		return HOST_FW_UTIL_NO_MEMORY;
	}

	*version = NULL;
	i = allowed->count - 1;
	while (!(*version) && (i >= 0)) {
		current_len = strlen (allowed->versions[i].fw_version_id);

		if ((prev < 0) ||
			((allowed->versions[i].version_addr) != (allowed->versions[prev].version_addr))) {
			/* We need to read a fresh version ID from the flash. */
			version_len = current_len;
			status = spi_flash_read (flash, allowed->versions[i].version_addr + offset,
				(uint8_t*) fw_version, version_len);
			if (status != 0) {
				goto exit;
			}

			if (strncmp (allowed->versions[i].fw_version_id, fw_version, version_len) == 0) {
				*version = &allowed->versions[i];
				status = 0;
			}
		}
		else {
			int extra = current_len - version_len;

			if (extra < 0) {
				/* Our current ID is shorter than the cached one, so only compare against the length
				 * of the current ID. */
				if (strncmp (allowed->versions[i].fw_version_id, fw_version,
					version_len + extra) == 0) {
					*version = &allowed->versions[i];
					status = 0;
				}
			}
			else {
				/* The current ID is at least as long at the cached one.  Check the parts we
				 * already have to see if it matches at all. */
				if (strncmp (allowed->versions[i].fw_version_id, fw_version, version_len) == 0) {
					if (extra != 0) {
						/* Get more data to finish the version check, but don't read the data we
						 * already have. */
						status = spi_flash_read (flash,
							allowed->versions[i].version_addr + offset + version_len,
							(uint8_t*) (fw_version + version_len), extra);
						if (status != 0) {
							goto exit;
						}

						if (strncmp (allowed->versions[i].fw_version_id + version_len,
							fw_version + version_len, extra) == 0) {
							*version = &allowed->versions[i];
							status = 0;
						}

						version_len = current_len;
					}
					else {
						*version = &allowed->versions[i];
						status = 0;
					}
				}
			}
		}

		prev = i;
		i--;
	}

	if (*version == NULL) {
		status = HOST_FW_UTIL_UNSUPPORTED_VERSION;
	}

exit:
	platform_free (fw_version);
	return status;
}

/**
 * Find the next flash region based on the starting address of the region.
 *
 * @param last_addr The flash address to start looking for the next region.
 * @param regions The list of defined flash regions.
 * @param count The number of regions defined in the list.
 *
 * @return The region description for the next defined flash region or null if there are no more
 * defined regions.
 */
static const struct flash_region* host_fw_find_next_region (uint32_t last_addr,
	const struct flash_region *regions, size_t count)
{
	const struct flash_region *next = NULL;
	size_t i;

	for (i = 0; i < count; i++) {
		if (regions[i].start_addr >= last_addr) {
			if (regions[i].start_addr == last_addr) {
				return &regions[i];
			}

			if (!next || (regions[i].start_addr < next->start_addr)) {
				next = &regions[i];
			}
		}
	}

	return next;
}

/**
 * Determine if two lists of regions are different.  Ordering of the regions in the list doesn't
 * matter.
 *
 * @param region1 The first list of defined regions.
 * @param count1 The number of regions in the first list.
 * @param region2 The second list of defined regions.
 * @param count2 The number of regions in the second list.
 *
 * @return true if the region lists are different or false if they are the same.
 */
static bool host_fw_are_regions_different (const struct flash_region *region1, size_t count1,
	const struct flash_region *region2, size_t count2)
{
	uint32_t last_addr;
	const struct flash_region *pos1;
	const struct flash_region *pos2;

	if (count1 != count2) {
		return true;
	}

	last_addr = 0;
	pos1 = host_fw_find_next_region (last_addr, region1, count1);
	while (pos1) {
		pos2 = host_fw_find_next_region (last_addr, region2, count2);
		if (!pos2) {
			return true;
		}

		if (pos1->start_addr != pos2->start_addr) {
			return true;
		}
		if (pos1->length != pos2->length) {
			return true;
		}

		last_addr = pos1->start_addr + pos1->length;
		pos1 = host_fw_find_next_region (last_addr, region1, count1);
	}

	return false;
}

/**
 * Determine if the lists of signed images are different.
 *
 * @param img_list1 The first list of signed images.
 * @param img_list2 The second list of signed images.
 *
 * @return true if the images lists are different or false if they are the identical.
 */
bool host_fw_are_images_different (const struct pfm_image_list *img_list1,
	const struct pfm_image_list *img_list2)
{
	size_t i;

	if ((img_list1 == NULL) || (img_list2 == NULL)) {
		if ((img_list1 == NULL) && (img_list2 == NULL)) {
			return false;
		}

		return true;
	}

	if (img_list1->count != img_list2->count) {
		return true;
	}

	if ((img_list1->images_sig && img_list2->images_hash) ||
		(img_list1->images_hash && img_list2->images_sig)) {
		return true;
	}

	for (i = 0; i < img_list1->count; i++) {
		if (img_list1->images_sig) {
			if (!rsa_same_public_key (&img_list1->images_sig[i].key,
				&img_list2->images_sig[i].key)) {
				return true;
			}

			if ((img_list1->images_sig[i].sig_length != img_list2->images_sig[i].sig_length) ||
				(img_list1->images_sig[i].always_validate !=
					img_list2->images_sig[i].always_validate)) {
				return true;
			}

			if (memcmp (img_list1->images_sig[i].signature, img_list2->images_sig[i].signature,
				img_list1->images_sig->sig_length) != 0) {
				return true;
			}

			if (host_fw_are_regions_different (img_list1->images_sig[i].regions,
				img_list1->images_sig[i].count, img_list2->images_sig[i].regions,
				img_list2->images_sig[i].count)) {
				return true;
			}
		}
		else {
			if ((img_list1->images_hash[i].hash_length != img_list2->images_hash[i].hash_length) ||
				(img_list1->images_hash[i].hash_type != img_list2->images_hash[i].hash_type) ||
				(img_list1->images_hash[i].always_validate !=
					img_list2->images_hash[i].always_validate)) {
				return true;
			}

			if (memcmp (img_list1->images_hash[i].hash, img_list2->images_hash[i].hash,
				img_list1->images_hash->hash_length) != 0) {
				return true;
			}

			if (host_fw_are_regions_different (img_list1->images_hash[i].regions,
				img_list1->images_hash[i].count, img_list2->images_hash[i].regions,
				img_list2->images_hash[i].count)) {
				return true;
			}
		}
	}

	return false;
}

/**
 * Verify that images on the flash are valid.  All image addresses specified in the PFM will be
 * offset by a fixed amount.
 *
 * @param flash The flash that contains the images to validate.
 * @param img_list The list of images to validate.
 * @param validate_all Override the image validation flag and validate all images in the list.
 * @param offset The offset to apply to image addresses.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if all images that should be validated are good or an error code.
 */
static int host_fw_verify_images_on_flash (struct spi_flash *flash,
	const struct pfm_image_list *img_list, bool validate_all, uint32_t offset,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	size_t i;
	int status = 0;

	for (i = 0; i < img_list->count; i++) {
		if (img_list->images_sig) {
			if (validate_all || img_list->images_sig[i].always_validate) {
				status = flash_verify_noncontiguous_contents_at_offset (&flash->base, offset,
					img_list->images_sig[i].regions, img_list->images_sig[i].count, hash,
					HASH_TYPE_SHA256, rsa, img_list->images_sig[i].signature,
					img_list->images_sig[i].sig_length, &img_list->images_sig[i].key, NULL, 0);
				if (status != 0) {
					return status;
				}
			}
		}
		else if (validate_all || img_list->images_hash[i].always_validate) {
			uint8_t img_hash[SHA512_HASH_LENGTH];

			status = flash_hash_noncontiguous_contents_at_offset (&flash->base, offset,
				img_list->images_hash[i].regions, img_list->images_hash[i].count, hash,
				img_list->images_hash[i].hash_type, img_hash, sizeof (img_hash));
			if (status != 0) {
				return status;
			}

			if (memcmp (img_list->images_hash[i].hash, img_hash,
				img_list->images_hash[i].hash_length) != 0) {
				return HOST_FW_UTIL_BAD_IMAGE_HASH;
			}
		}
	}

	return status;
}

/**
 * Verify that images on the flash are valid.  Only images flagged for validation will be checked.
 *
 * @param flash The flash that contains the images to validate.
 * @param img_list The list of images to validate.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if all images that should be validated are good or an error code.
 */
int host_fw_verify_images (struct spi_flash *flash, const struct pfm_image_list *img_list,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	return host_fw_verify_offset_images_multiple_fw (flash, img_list, 1, 0, hash, rsa);
}

/**
 * Verify that images on the flash are valid.  Only images flagged for validation will be checked.
 *
 * All image addresses specified in the PFM will be offset by a fixed amount.
 *
 * @param flash The flash that contains the images to validate.
 * @param img_list The list of images to validate.
 * @param offset The offset to apply to image addresses.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if all images that should be validated are good or an error code.
 */
int host_fw_verify_offset_images (struct spi_flash *flash, const struct pfm_image_list *img_list,
	uint32_t offset, struct hash_engine *hash, struct rsa_engine *rsa)
{
	return host_fw_verify_offset_images_multiple_fw (flash, img_list, 1, offset, hash, rsa);
}

/**
 * Verify that images from multiple different firmware components on the flash are valid.  Only
 * images flagged for validation will be checked.
 *
 * @param flash The flash that contains the images to validate.
 * @param img_list An array of firmware images that should be validated.
 * @param fw_count The number of firmware components in the list.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if all images that should be validated are good or an error code.
 */
int host_fw_verify_images_multiple_fw (struct spi_flash *flash,
	const struct pfm_image_list *img_list, size_t fw_count, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	return host_fw_verify_offset_images_multiple_fw (flash, img_list, fw_count, 0, hash, rsa);
}

/**
 * Verify that images from multiple different firmware components on the flash are valid.  Only
 * images flagged for validation will be checked.
 *
 * All image addresses specified in the PFM will be offset by a fixed amount.
 *
 * @param flash The flash that contains the images to validate.
 * @param img_list An array of firmware images that should be validated.
 * @param fw_count The number of firmware components in the list.
 * @param offset The offset to apply to image addresses.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if all images that should be validated are good or an error code.
 */
int host_fw_verify_offset_images_multiple_fw (struct spi_flash *flash,
	const struct pfm_image_list *img_list, size_t fw_count, uint32_t offset,
	struct hash_engine *hash, struct rsa_engine *rsa)
{
	size_t i;
	int status;

	if ((flash == NULL) || (img_list == NULL) || (hash == NULL) || (rsa == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	for (i = 0; i < fw_count; i++) {
		status = host_fw_verify_images_on_flash (flash, &img_list[i], false, offset, hash, rsa);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Find the next flash region defined to be part of a firmware image.
 *
 * @param last_addr The flash address to start looking for the next region.
 * @param img_list The list of firmware images in flash.
 * @param fw_count The number of image instances.
 *
 * @return The region description for the next defined image region or null if there are no more
 * defined regions.
 */
static const struct flash_region* host_fw_find_next_img_region (uint32_t last_addr,
	const struct pfm_image_list *img_list, size_t fw_count)
{
	const struct flash_region *next = NULL;
	const struct flash_region *img_next;
	size_t i;
	size_t j;

	for (i = 0; i < fw_count; i++) {
		for (j = 0; j < img_list[i].count; j++) {
			if (img_list[i].images_sig) {
				img_next = host_fw_find_next_region (last_addr, img_list[i].images_sig[j].regions,
					img_list[i].images_sig[j].count);
			}
			else {
				img_next = host_fw_find_next_region (last_addr, img_list[i].images_hash[j].regions,
					img_list[i].images_hash[j].count);
			}

			if (img_next) {
				if (img_next->start_addr == last_addr) {
					return img_next;
				}
				else if (!next || (img_next->start_addr < next->start_addr)) {
					next = img_next;
				}
			}
		}
	}

	return next;
}

/**
 * Find the next read/write region defined in the flash.
 *
 * @param last_addr The flash address to start looking for the next region.
 * @param writable The list of read/write regions in flash.
 * @param fw_count The number of read/write region instances.
 *
 * @return The region description for the next defined read/write region or null if there are no
 * more defined regions.
 */
static const struct flash_region* host_fw_find_next_rw_region (uint32_t last_addr,
	const struct pfm_read_write_regions *writable, size_t fw_count)
{
	const struct flash_region *next = NULL;
	const struct flash_region *rw_next;
	size_t i;

	for (i = 0; i < fw_count; i++) {
		rw_next = host_fw_find_next_region (last_addr, writable[i].regions, writable[i].count);

		if (rw_next) {
			if (rw_next->start_addr == last_addr) {
				return rw_next;
			}
			else if (!next || (rw_next->start_addr < next->start_addr)) {
				next = rw_next;
			}
		}
	}

	return next;
}

/**
 * Find the next used region of flash.
 *
 * @param last_addr The flash address to start looking for the next region.
 * @param img_list The list of images in the flash.
 * @param writable The list of read/write regions in the flash.
 * @param fw_count The number of different firmware instances.
 *
 * @return The region description for the next used region or null if there are no more used
 * regions.
 */
static const struct flash_region* host_fw_find_next_flash_region (uint32_t last_addr,
	const struct pfm_image_list *img_list, const struct pfm_read_write_regions *writable,
	size_t fw_count)
{
	const struct flash_region *next;
	const struct flash_region *rw_next;

	next = host_fw_find_next_img_region (last_addr, img_list, fw_count);
	if (next && (next->start_addr == last_addr)) {
		return next;
	}

	rw_next = host_fw_find_next_rw_region (last_addr, writable, fw_count);
	if (rw_next) {
		if (!next || (rw_next->start_addr == last_addr)) {
			next = rw_next;
		}
		else if (rw_next->start_addr < next->start_addr) {
			next = rw_next;
		}
	}

	return next;
}

/**
 * Verify that the entire flash contents are good.  All images will be verified and unused regions
 * of read-only flash will be verified to be empty.
 *
 * @param flash The flash that should be validated.
 * @param img_list The list of images contained in the flash.
 * @param writable The list of writable regions of flash.
 * @param unused_byte The byte value to check for in unused flash regions.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if the flash contents are good or an error code.
 */
int host_fw_full_flash_verification (struct spi_flash *flash, const struct pfm_image_list *img_list,
	const struct pfm_read_write_regions *writable, uint8_t unused_byte, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	return host_fw_full_flash_verification_multiple_fw (flash, img_list, writable, 1,
		unused_byte, hash, rsa);
}

/**
 * Verify that the entire flash contents are good.  All images will be verified and unused regions
 * of read-only flash will be verified to be empty.
 *
 * The flash contains multiple, independent firmware components.
 *
 * @param flash The flash that should be validated.
 * @param img_list The list of images contained in the flash.
 * @param writable The list of writable regions of flash.
 * @param img_list An array of firmware images that should be validated.
 * @param writable An array of writable regions for each firmware component.
 * @param fw_count The number of firmware components in the list.  Both arrays of firmware
 * information must be the same length.
 * @param unused_byte The byte value to check for in unused flash regions.
 * @param hash The hashing engine to use for validation.
 * @param rsa The RSA engine to use for signature checking.
 *
 * @return 0 if the flash contents are good or an error code.
 */
int host_fw_full_flash_verification_multiple_fw (struct spi_flash *flash,
	const struct pfm_image_list *img_list, const struct pfm_read_write_regions *writable,
	size_t fw_count, uint8_t unused_byte, struct hash_engine *hash, struct rsa_engine *rsa)
{
	const struct flash_region *pos;
	uint32_t flash_size;
	uint32_t last_addr;
	int status;
	size_t i;

	if ((flash == NULL) || (img_list == NULL) || (writable == NULL) || (hash == NULL) ||
		(rsa == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	status = spi_flash_get_device_size (flash, &flash_size);
	if (status != 0) {
		return status;
	}

	for (i = 0; i < fw_count; i++) {
		status = host_fw_verify_images_on_flash (flash, &img_list[i], true, 0, hash, rsa);
		if (status != 0) {
			return status;
		}
	}

	last_addr = 0;
	pos = host_fw_find_next_flash_region (last_addr, img_list, writable, fw_count);
	while (pos) {
		status = flash_value_check (&flash->base, last_addr, pos->start_addr - last_addr,
			unused_byte);
		if (status != 0) {
			return status;
		}

		last_addr = pos->start_addr + pos->length;
		pos = host_fw_find_next_flash_region (last_addr, img_list, writable, fw_count);
	}

	return flash_value_check (&flash->base, last_addr, flash_size - last_addr, unused_byte);
}

/**
 * Determine if the defined regions for read/write data are different between different PFM entries.
 *
 * @param rw1 The first list of read/write regions.
 * @param rw2 The second list of read/write regions.
 *
 * @return true if the defined regions are different or false if they are the same.
 */
bool host_fw_are_read_write_regions_different (const struct pfm_read_write_regions *rw1,
	const struct pfm_read_write_regions *rw2)
{
	if ((rw1 == NULL) || (rw2 == NULL)) {
		if ((rw1 == NULL) && (rw2 == NULL)) {
			return false;
		}

		return true;
	}

	return host_fw_are_regions_different (rw1->regions, rw1->count, rw2->regions, rw2->count);
}

/**
 * Migrate the read/write data from one flash device to another.  The migration will only happen if
 * the read/write regions defined for the two flash devices are exactly the same.  Any change in
 * defined read/write regions will cause the migration to fail.  It is possible to bypass this error
 * checking and force the migration, if that behavior is necessary.
 *
 * The read/write regions of the destination flash are always erased, even if the migration can't
 * happen.  This ensures blank data on the destination read/write regions instead of allowing
 * data previously in that location to persist.
 *
 * @param dest The flash device that will receive the read/write data.
 * @param dest_writable The read/write regions defined on the destination flash.
 * @param src The flash device that contains the read/write data to migrate.
 * @param src_writable The read/write regions that should be migrated.  This can be null to force
 * the migration with no compatibility checking.
 *
 * @return 0 if the data migration was successful or an error code.  If the data regions are not
 * compatible for migration, one of the following errors will be returned:
 * 		- HOST_FW_UTIL_DIFF_REGION_COUNT
 * 		- HOST_FW_UTIL_DIFF_REGION_ADDR
 * 		- HOST_FW_UTIL_DIFF_REGION_SIZE
 */
int host_fw_migrate_read_write_data (struct spi_flash *dest,
	const struct pfm_read_write_regions *dest_writable, struct spi_flash *src,
	const struct pfm_read_write_regions *src_writable)
{
	uint32_t last_addr;
	const struct flash_region *dest_pos;
	const struct flash_region *src_pos;
	int status;
	int migrate_fail = 0;

	if ((dest == NULL) || (dest_writable == NULL) || (src == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	if (src_writable && (src_writable->count != dest_writable->count)) {
		migrate_fail = HOST_FW_UTIL_DIFF_REGION_COUNT;
	}

	last_addr = 0;
	dest_pos = host_fw_find_next_rw_region (last_addr, dest_writable, 1);
	while (dest_pos) {
		status = flash_erase_region_and_verify (&dest->base, dest_pos->start_addr,
			dest_pos->length);
		if (status != 0) {
			return status;
		}

		if (src_writable && !migrate_fail) {
			src_pos = host_fw_find_next_rw_region (last_addr, src_writable, 1);
			if (src_pos) {
				if (dest_pos->start_addr != src_pos->start_addr) {
					migrate_fail = HOST_FW_UTIL_DIFF_REGION_ADDR;
				}
				else if (dest_pos->length != src_pos->length) {
					migrate_fail = HOST_FW_UTIL_DIFF_REGION_SIZE;
				}
			}
		}

		last_addr = dest_pos->start_addr + dest_pos->length;
		dest_pos = host_fw_find_next_rw_region (last_addr, dest_writable, 1);
	}

	if (migrate_fail) {
		return migrate_fail;
	}

	last_addr = 0;
	dest_pos = host_fw_find_next_rw_region (last_addr, dest_writable, 1);
	while (dest_pos) {
		status = flash_copy_ext_to_blank_and_verify (&dest->base, dest_pos->start_addr, &src->base,
			dest_pos->start_addr, dest_pos->length);
		if (status != 0) {
			return status;
		}

		last_addr = dest_pos->start_addr + dest_pos->length;
		dest_pos = host_fw_find_next_rw_region (last_addr, dest_writable, 1);
	}

	return 0;
}

/**
 * Migrate the read/write data from one flash device to another.  The migration will only happen if
 * the read/write regions defined for the two flash devices are exactly the same.  Any change in
 * defined read/write regions will cause the migration to fail.  It is possible to bypass this error
 * checking and force the migration, if that behavior is necessary.
 *
 * The flash contains multiple firmware components with defined read/write regions.  Comparison for
 * migration compatiblity will be done for each individual firmware component.
 *
 * The read/write regions of the destination flash are always erased, even if the migration can't
 * happen.  This ensures blank data on the destination read/write regions instead of allowing
 * data previously in that location to persist.
 *
 * @param dest The flash device that will receive the read/write data.
 * @param dest_writable The read/write regions defined on the destination flash.
 * @param dest_count The number of firmware components in the destination list.
 * @param src The flash device that contains the read/write data to migrate.
 * @param src_writable The read/write regions that should be migrated.  This can be null to force
 * the migration with no compatibility checking.
 * @param src_count The number of firmware components in the source list.
 *
 * @return 0 if the data migration was successful or an error code.  If the data regions are not
 * compatible for migration, one of the following errors will be returned:
 * 		- HOST_FW_UTIL_DIFF_REGION_COUNT
 * 		- HOST_FW_UTIL_DIFF_REGION_ADDR
 * 		- HOST_FW_UTIL_DIFF_REGION_SIZE
 * 		- HOST_FW_UTIL_DIFF_FW_COUNT
 */
int host_fw_migrate_read_write_data_multiple_fw (struct spi_flash *dest,
	const struct pfm_read_write_regions *dest_writable, size_t dest_count, struct spi_flash *src,
	const struct pfm_read_write_regions *src_writable, size_t src_count)
{
	size_t i;
	int status;
	int migrate_fail = 0;

	if ((dest == NULL) || (dest_writable == NULL) || (src == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	if (src_writable && (dest_count != src_count)) {
		return HOST_FW_UTIL_DIFF_FW_COUNT;
	}

	for (i = 0; i < dest_count; i++) {
		status = host_fw_migrate_read_write_data (dest, &dest_writable[i], src,
			(src_writable) ? &src_writable[i] : NULL);
		if (status != 0) {
			if ((status == HOST_FW_UTIL_DIFF_REGION_COUNT) ||
				(status == HOST_FW_UTIL_DIFF_REGION_ADDR) ||
				(status == HOST_FW_UTIL_DIFF_REGION_SIZE)) {
				migrate_fail = status;
			}
			else {
				return status;
			}
		}
	}

	return migrate_fail;
}

/**
 * Restore the firmware images in a flash device from the contents of a different device.  No
 * verification will be performed on the restored device.
 *
 * @param restore The flash device that should be restored.
 * @param from The device to restore from.
 * @param img_list The list of firmware images in the good flash device.
 * @param writable The list of read/write regions in the good flash device.
 *
 * @return 0 if the bad flash was restored to a good state or an error code.
 */
int host_fw_restore_flash_device (struct spi_flash *restore, struct spi_flash *from,
	const struct pfm_image_list *img_list, const struct pfm_read_write_regions *writable)
{
	uint32_t flash_size;
	uint32_t last_addr;
	const struct flash_region *pos;
	const struct flash_region *img_data;
	size_t img_count;
	int status;
	size_t i;
	size_t j;

	if ((restore == NULL) || (from == NULL) || (img_list == NULL) || (writable == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	status = spi_flash_get_device_size (restore, &flash_size);
	if (status != 0) {
		return status;
	}

	/* TODO: Flash operations should include a verify step.  At least for program. */

	/* Erase all read-only regions. */
	last_addr = 0;
	pos = host_fw_find_next_rw_region (last_addr, writable, 1);
	while (pos) {
		status = flash_erase_region (&restore->base, last_addr, pos->start_addr - last_addr);
		if (status != 0) {
			return status;
		}

		last_addr = pos->start_addr + pos->length;
		pos = host_fw_find_next_rw_region (last_addr, writable, 1);
	}

	status = flash_erase_region (&restore->base, last_addr, flash_size - last_addr);
	if (status != 0) {
		return status;
	}

	/* Copy firmware images. */
	for (i = 0; i < img_list->count; i++) {
		if (img_list->images_sig) {
			img_data = img_list->images_sig[i].regions;
			img_count = img_list->images_sig[i].count;
		}
		else {
			img_data = img_list->images_hash[i].regions;
			img_count = img_list->images_hash[i].count;
		}

		for (j = 0; j < img_count; j++) {
			status = flash_copy_ext_to_blank (&restore->base, img_data[j].start_addr, &from->base,
				img_data[j].start_addr, img_data[j].length);
			if (status != 0) {
				return status;
			}
		}
	}

	return 0;
}

/**
 * Restore the read/write data in a flash device.  Based on the configuration of each region, the
 * destination flash will either be left unchanged, completely erased, or copied from a different
 * flash device.
 *
 * @param restore The flash device that should be restored.
 * @param from The device to restore data from.  If this is null, regions that are configured to be
 * copied will instead remain unchanged.
 * @param writable The list of read/write regions to restore.
 *
 * @return 0 if all regions were restored successfully or an error code.
 */
int host_fw_restore_read_write_data (struct spi_flash *restore, struct spi_flash *from,
	const struct pfm_read_write_regions *writable)
{
	size_t i;
	int status;

	if ((restore == NULL) || (writable == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	for (i = 0; i < writable->count; i++) {
		switch (writable->properties[i].on_failure) {
			case PFM_RW_ERASE:
				status = flash_erase_region_and_verify (&restore->base,
					writable->regions[i].start_addr, writable->regions[i].length);
				if (status != 0) {
					return status;
				}
				break;

			case PFM_RW_RESTORE:
				if (from != NULL) {
					status = flash_copy_ext_and_verify (&restore->base,
						writable->regions[i].start_addr, &from->base,
						writable->regions[i].start_addr, writable->regions[i].length);
					if (status != 0) {
						return status;
					}
				}
				break;

			default:
				break;
		}
	}

	return 0;
}

/**
 * Restore the read/write data in a flash device.  Based on the configuration of each region, the
 * destination flash will either be left unchanged, completely erased, or copied from a different
 * flash device.
 *
 * Read/write data from multiple firmware components will be restored.
 *
 * @param restore The flash device that should be restored.
 * @param from The device to restore data from.  If this is null, regions that are configured to be
 * copied will instead remain unchanged.
 * @param writable An array of read/write regions to restore.
 * @param fw_count The number of firmware components in the list.
 *
 * @return 0 if all regions were restored successfully or an error code.
 */
int host_fw_restore_read_write_data_multiple_fw (struct spi_flash *restore, struct spi_flash *from,
	const struct pfm_read_write_regions *writable, size_t fw_count)
{
	size_t i;
	int status;

	if ((restore == NULL) || (writable == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	for (i = 0; i < fw_count; i++) {
		status = host_fw_restore_read_write_data (restore, from, &writable[i]);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Configure the SPI filter with the read/write region definitions from a PFM entry.
 *
 * @param filter The SPI filter to configure.
 * @param writable The defined read/write regions to configure in the filter.
 *
 * @return 0 if the SPI filter was successfully configured or an error code.
 */
int host_fw_config_spi_filter_read_write_regions (struct spi_filter_interface *filter,
	const struct pfm_read_write_regions *writable)
{
	size_t i;
	int status;

	if ((filter == NULL) || (writable == NULL)) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	status = filter->clear_filter_rw_regions (filter);
	if (status != 0) {
		return status;
	}

	for (i = 0; i < writable->count; i++) {
		status = filter->set_filter_rw_region (filter, i + 1, writable->regions[i].start_addr,
			writable->regions[i].start_addr + writable->regions[i].length);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Configure the SPI filter with the read/write region definitions from the PFM.  The read/write
 * regions from multiple different firmware components will be inspected to generate the fewest
 * number of contiguous regions for the filter.
 *
 * @param filter The SPI filter to configure.
 * @param writable An array of read/write regions defined for all firmware components.
 * @param fw_count The number of firmware components in the list.
 *
 * @return 0 if the SPI filter was successfully configured or an error code.
 */
int host_fw_config_spi_filter_read_write_regions_multiple_fw (struct spi_filter_interface *filter,
	const struct pfm_read_write_regions *writable, size_t fw_count)
{
	uint8_t region_id = 0;
	uint32_t last_addr = 0;
	const struct flash_region *next = NULL;
	const struct flash_region *prev = NULL;
	size_t total_len;
	int status;

	if ((filter == NULL) || ((writable == NULL) && (fw_count != 0))) {
		return HOST_FW_UTIL_INVALID_ARGUMENT;
	}

	status = filter->clear_filter_rw_regions (filter);
	if (status != 0) {
		return status;
	}

	do {
		if (!prev) {
			prev = next;
		}
		next = host_fw_find_next_rw_region (last_addr, writable, fw_count);

		if (prev) {
			if (next && (next->start_addr == last_addr)) {
				/* The next region is contiguous with the previous one. */
				total_len += next->length;
				last_addr += next->length;
			}
			else {
				/* Found the end of a R/W region. */
				status = filter->set_filter_rw_region (filter, ++region_id, prev->start_addr,
					prev->start_addr + total_len);
				if (status != 0) {
					return status;
				}

				prev = NULL;
				if (next) {
					total_len = next->length;
					last_addr = next->start_addr + next->length;
				}
			}
		}
		else if (next) {
			total_len = next->length;
			last_addr = next->start_addr + next->length;
		}
	} while (prev || next);

	return 0;
}
