// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "flash/flash_util.h"
#include "manifest/manifest_flash.h"
#include "pfm_format.h"
#include "pfm_flash.h"


static int pfm_flash_verify (struct manifest *pfm, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	struct manifest_header header;
	struct pfm_allowable_firmware_header fw_section;
	struct pfm_key_manifest_header key_section;
	struct pfm_platform_header platform_section;
	uint32_t next_addr;
	int status;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	status = manifest_flash_verify (&pfm_flash->base_flash, hash, verification, hash_out,
		hash_length);
	if (status != 0) {
		return status;
	}

	/* Check the contents of the PFM to make sure they make sense.
	 *
	 * TODO: Drill deeper into the PFM structure to verify lengths for the contents of each
	 * section. */
	status = spi_flash_read (pfm_flash->base_flash.flash, pfm_flash->base_flash.addr,
		(uint8_t*) &header, sizeof (header));
	if (status != 0) {
		return status;
	}

	next_addr = pfm_flash->base_flash.addr + sizeof (header);
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &fw_section,
		sizeof (fw_section));
	if (status != 0) {
		return status;
	}

	next_addr += fw_section.length;
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &key_section,
		sizeof (key_section));
	if (status != 0) {
		return status;
	}

	next_addr += key_section.length;
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &platform_section,
		sizeof (platform_section));
	if (status != 0) {
		return status;
	}

	if (header.length != (sizeof (header) + fw_section.length + key_section.length +
		platform_section.length + header.sig_length)) {
		return MANIFEST_MALFORMED;
	}

	return 0;
}

static int pfm_flash_get_id (struct manifest *pfm, uint32_t *id)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&pfm_flash->base_flash, id);
}

static int pfm_flash_get_hash (struct manifest *pfm, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_hash (&pfm_flash->base_flash, hash, hash_out, hash_length);
}

static int pfm_flash_get_signature (struct manifest *pfm, uint8_t *signature, size_t length)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_signature (&pfm_flash->base_flash, signature, length);
}

static int pfm_flash_get_platform_id (struct manifest *pfm, char **id)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	struct manifest_header header;
	struct pfm_allowable_firmware_header fw_section;
	struct pfm_key_manifest_header key_section;
	struct pfm_platform_header platform_section;
	uint32_t next_addr;
	int status;

	if (id == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	*id = NULL;
	if (pfm == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	status = spi_flash_read (pfm_flash->base_flash.flash, pfm_flash->base_flash.addr,
		(uint8_t*) &header, sizeof (header));
	if (status != 0) {
		return status;
	}

	if (header.magic != PFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	next_addr = pfm_flash->base_flash.addr + sizeof (struct manifest_header);
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &fw_section,
		sizeof (fw_section));
	if (status != 0) {
		return status;
	}

	next_addr += fw_section.length;
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &key_section,
		sizeof (key_section));
	if (status != 0) {
		return status;
	}

	next_addr += key_section.length;
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &platform_section,
		sizeof (platform_section));
	if (status != 0) {
		return status;
	}

	*id = platform_malloc (platform_section.id_length + 1);
	if (*id == NULL) {
		return PFM_NO_MEMORY;
	}

	next_addr += sizeof (struct pfm_platform_header);
	status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) *id,
		platform_section.id_length);
	if (status != 0) {
		platform_free (*id);
		*id = NULL;

		return status;
	}

	(*id)[platform_section.id_length] = '\0';
	return 0;
}

static int pfm_flash_get_supported_versions (struct pfm *pfm, struct pfm_firmware_versions *fw)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	struct manifest_header header;
	struct pfm_allowable_firmware_header fw_section;
	struct pfm_firmware_header fw_header;
	struct pfm_firmware_version *version_list;
	int i;
	uint32_t next_addr;
	int status;

	if ((pfm_flash == NULL) || (fw == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	status = spi_flash_read (pfm_flash->base_flash.flash, pfm_flash->base_flash.addr,
		(uint8_t*) &header, sizeof (header));
	if (status != 0) {
		return status;
	}

	if (header.magic != PFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	status = spi_flash_read (pfm_flash->base_flash.flash,
		pfm_flash->base_flash.addr + sizeof (struct manifest_header), (uint8_t*) &fw_section,
		sizeof (fw_section));
	if (status != 0) {
		return status;
	}

	if (fw_section.fw_count == 0) {
		memset (fw, 0, sizeof (*fw));
		return 0;
	}

	version_list = platform_calloc (fw_section.fw_count, sizeof (struct pfm_firmware_version));
	if (version_list == NULL) {
		return PFM_NO_MEMORY;
	}

	next_addr = pfm_flash->base_flash.addr + sizeof (struct manifest_header) +
		sizeof (struct pfm_allowable_firmware_header);
	for (i = 0; i < fw_section.fw_count; i++) {
		status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &fw_header,
			sizeof (fw_header));
		if (status != 0) {
			goto exit_error;
		}

		version_list[i].fw_version_id = platform_malloc (fw_header.version_length + 1);
		if (version_list[i].fw_version_id == NULL) {
			status = PFM_NO_MEMORY;
			goto exit_error;
		}

		status = spi_flash_read (pfm_flash->base_flash.flash,
			next_addr + sizeof (struct pfm_firmware_header),
			(uint8_t*) version_list[i].fw_version_id, fw_header.version_length);
		if (status != 0) {
			goto exit_error;
		}

		((char*) version_list[i].fw_version_id)[fw_header.version_length] = '\0';
		version_list[i].version_addr = fw_header.version_addr;
		version_list[i].blank_byte = fw_header.blank_byte;

		next_addr += fw_header.length;
	}

	fw->versions = version_list;
	fw->count = fw_section.fw_count;

	return 0;

exit_error:
	for (i = 0; i < fw_section.fw_count; i++) {
		platform_free ((void*) version_list[i].fw_version_id);
	}
	platform_free (version_list);

	return status;
}

static void pfm_flash_free_fw_versions (struct pfm *pfm, struct pfm_firmware_versions *fw)
{
	size_t i;

	if ((fw != NULL) && (fw->versions != NULL)) {
		for (i = 0; i < fw->count; i++) {
			platform_free ((void*) fw->versions[i].fw_version_id);
		}

		platform_free ((void*) fw->versions);
	}
}

/**
 * Find the version entry in the PFM that matches the expected version identifier.
 *
 * @param pfm The PFM instance to search.
 * @param version The version identifier to find.
 * @param fw_header The output buffer for the firmware header of the matching version.
 * @param fw_addr This will be updated with the address offset of the matching firmware header.
 * @param manifest_addr This will be updated with the address offset of the key manifest in the PFM.
 * This can be NULL to not return this information.
 *
 * @return 0 if a matching entry was found or an error code.
 */
static int pfm_flash_find_version_entry (struct manifest_flash *pfm, const char *version,
	struct pfm_firmware_header *fw_header, uint32_t *fw_addr, uint32_t *manifest_addr)
{
	struct manifest_header header;
	struct pfm_allowable_firmware_header fw_section;
	char *check;
	size_t check_len;
	int i;
	int status;
	uint8_t found;

	check_len = strlen (version);
	if (check_len == 0) {
		return PFM_INVALID_ARGUMENT;
	}

	*fw_addr = pfm->addr;
	status = spi_flash_read (pfm->flash, *fw_addr, (uint8_t*) &header, sizeof (header));
	if (status != 0) {
		return status;
	}

	if (header.magic != PFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	*fw_addr += sizeof (struct manifest_header);
	status = spi_flash_read (pfm->flash, *fw_addr, (uint8_t*) &fw_section, sizeof (fw_section));
	if (status != 0) {
		return status;
	}

	if (manifest_addr != NULL) {
		*manifest_addr = *fw_addr + fw_section.length;
	}

	check = platform_malloc (check_len + 1);
	if (check == NULL) {
		return PFM_NO_MEMORY;
	}

	i = 0;
	found = 0;
	*fw_addr += sizeof (struct pfm_allowable_firmware_header);
	while (!found && (i < fw_section.fw_count)) {
		status = spi_flash_read (pfm->flash, *fw_addr, (uint8_t*) fw_header, sizeof (*fw_header));
		if (status != 0) {
			goto check_free;
		}

		if (fw_header->version_length == check_len) {
			status = spi_flash_read (pfm->flash, *fw_addr + sizeof (struct pfm_firmware_header),
				(uint8_t*) check, fw_header->version_length);
			if (status != 0) {
				goto check_free;
			}

			check[fw_header->version_length] = '\0';
			if (strcmp (version, check) == 0) {
				found = 1;
			}
		}

		if (!found) {
			*fw_addr += fw_header->length;
			i++;
		}
	}

	platform_free (check);
	if (!found) {
		return PFM_UNSUPPORTED_VERSION;
	}

	return 0;

check_free:
	platform_free (check);
	return status;
}

/**
 * Read a flash region definition from flash.
 *
 * @param pfm The PFM instance to read.
 * @param addr The address of the region definition in flash.
 * @param region The region information that will be updated from flash.
 *
 * @return 0 if the region was read successfully or an error code.
 */
static int pfm_flash_read_region (struct manifest_flash *pfm, uint32_t addr,
	struct flash_region *region)
{
	struct pfm_flash_region rw_region;
	int status;

	status = spi_flash_read (pfm->flash, addr, (uint8_t*) &rw_region, sizeof (rw_region));
	if (status != 0) {
		return status;
	}

	region->start_addr = rw_region.start_addr;
	region->length = (rw_region.end_addr - rw_region.start_addr) + 1;

	return 0;
}

/**
 * Read multiple flash region definitions from flash.
 *
 * @param pfm The PFM instance to read.
 * @param count The number of regions to read.
 * @param region_list The list of regions to populate with data from flash.
 * @param addr The starting address to read from.  This will be updated with the address after the
 * last read region definition.
 *
 * @return 0 if the flash regions were read successfully or an error code.
 */
static int pfm_flash_read_multiple_regions (struct manifest_flash *pfm, size_t count,
	struct flash_region *region_list, uint32_t *addr)
{
	size_t i;
	int status;

	for (i = 0; i < count; i++) {
		status = pfm_flash_read_region (pfm, *addr, &region_list[i]);
		if (status != 0) {
			return status;
		}

		*addr += sizeof (struct pfm_flash_region);
	}

	return 0;
}

static int pfm_flash_get_read_write_regions (struct pfm *pfm, const char *version,
	struct pfm_read_write_regions *writable)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	struct pfm_firmware_header fw_header;
	struct flash_region *region_list;
	uint32_t next_addr;
	int status;

	if ((pfm == NULL) || (version == NULL) || (writable == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	status = pfm_flash_find_version_entry (&pfm_flash->base_flash, version, &fw_header, &next_addr,
		NULL);
	if (status != 0) {
		return status;
	}

	region_list = platform_calloc (fw_header.rw_count, sizeof (struct flash_region));
	if (region_list == NULL) {
		return PFM_NO_MEMORY;
	}

	next_addr += sizeof (struct pfm_firmware_header) + fw_header.version_length;
	if ((fw_header.version_length % 4) != 0) {
		next_addr += (4 - (fw_header.version_length % 4));
	}

	status = pfm_flash_read_multiple_regions (&pfm_flash->base_flash, fw_header.rw_count,
		region_list, &next_addr);
	if (status != 0) {
		platform_free (region_list);
		return status;
	}

	writable->regions = region_list;
	writable->count = fw_header.rw_count;

	return 0;
}

static void pfm_flash_free_read_write_regions (struct pfm *pfm,
	struct pfm_read_write_regions *writable)
{
	if (writable != NULL) {
		platform_free ((void*) writable->regions);
	}
}

static int pfm_flash_get_firmware_images (struct pfm *pfm, const char *version,
	struct pfm_image_list *img_list)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	struct pfm_firmware_header fw_header;
	struct pfm_image_header img_header;
	struct pfm_key_manifest_header key_section;
	struct pfm_public_key_header key_header;
	struct rsa_public_key key;
	struct pfm_image_signature *images;
	struct flash_region *region_list = NULL;
	uint32_t next_addr;
	uint32_t key_addr;
	int status;
	int i;
	int j;
	int matched;

	if ((pfm_flash == NULL) || (version == NULL) || (img_list == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	status = pfm_flash_find_version_entry (&pfm_flash->base_flash, version, &fw_header, &next_addr,
		&key_addr);
	if (status != 0) {
		return status;
	}

	images = platform_calloc (fw_header.img_count, sizeof (struct pfm_image_signature));
	if (images == NULL) {
		return PFM_NO_MEMORY;
	}

	next_addr += sizeof (struct pfm_firmware_header) + fw_header.version_length +
		(sizeof (struct pfm_flash_region) * fw_header.rw_count);
	if ((fw_header.version_length % 4) != 0) {
		next_addr += 4 - (fw_header.version_length % 4);
	}

	for (i = 0; i < fw_header.img_count; i++) {
		status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &img_header,
			sizeof (img_header));
		if (status != 0) {
			goto exit;
		}

		region_list = platform_calloc (img_header.region_count, sizeof (struct flash_region));
		if (region_list == NULL) {
			status = PFM_NO_MEMORY;
			goto exit;
		}

		images[i].regions = region_list;
		images[i].count = img_header.region_count;
		images[i].always_validate = !!(img_header.flags & PFM_IMAGE_MUST_VALIDATE);
		images[i].sig_length = img_header.sig_length;
		images[i].key.mod_length = (0xffU << 24) | img_header.key_id;

		next_addr += sizeof (struct pfm_image_header);
		status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, images[i].signature,
			img_header.sig_length);
		if (status != 0) {
			goto exit;
		}

		next_addr += img_header.sig_length;
		status = pfm_flash_read_multiple_regions (&pfm_flash->base_flash, img_header.region_count,
			region_list, &next_addr);
		if (status != 0) {
			goto exit;
		}
	}

	status = spi_flash_read (pfm_flash->base_flash.flash, key_addr, (uint8_t*) &key_section,
		sizeof (key_section));
	if (status != 0) {
		goto exit;
	}

	i = 0;
	matched = 0;
	next_addr = key_addr + sizeof (struct pfm_key_manifest_header);
	while ((i < key_section.key_count) && (matched < fw_header.img_count)) {
		status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, (uint8_t*) &key_header,
			sizeof (key_header));
		if (status != 0) {
			goto exit;
		}

		next_addr += sizeof (struct pfm_public_key_header);
		status = spi_flash_read (pfm_flash->base_flash.flash, next_addr, key.modulus,
			key_header.key_length);
		if (status != 0) {
			goto exit;
		}

		key.exponent = key_header.key_exponent;
		key.mod_length = key_header.key_length;

		for (j = 0; j < fw_header.img_count; j++) {
			if (((images[j].key.mod_length >> 24) & 0xff) == 0xff) {
				if ((images[j].key.mod_length & 0xff) == key_header.id) {
					images[j].key = key;
					matched++;
				}
			}
		}

		i++;
		next_addr += key_header.key_length;
	}

	if (matched < fw_header.img_count) {
		status = PFM_UNKNOWN_KEY_ID;
		goto exit;
	}

	img_list->images = images;
	img_list->count = fw_header.img_count;

	return 0;

exit:
	for (i = 0; i < fw_header.img_count; i++) {
		platform_free ((void*) images[i].regions);
	}
	platform_free (images);
	return status;
}

static void pfm_flash_free_firmware_images (struct pfm *pfm, struct pfm_image_list *img_list)
{
	size_t i;

	if ((img_list != NULL) && (img_list->images != NULL)) {
		for (i = 0; i < img_list->count; i++) {
			platform_free ((void*) img_list->images[i].regions);
		}

		platform_free ((void*) img_list->images);
	}
}

/**
 * Initialize the interface to a PFM residing in flash memory.
 *
 * @param pfm The PFM instance to initialize.
 * @param flash The flash device that contains the PFM.
 * @param base_addr The starting address of the PFM storage location.
 *
 * @return 0 if the PFM instance was initialized successfully or an error code.
 */
int pfm_flash_init (struct pfm_flash *pfm, struct spi_flash *flash, uint32_t base_addr)
{
	int status;

	if ((pfm == NULL) || (flash == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	memset (pfm, 0, sizeof (struct pfm_flash));

	status = manifest_flash_init (&pfm->base_flash, flash, base_addr, PFM_MAGIC_NUM);
	if (status != 0) {
		return status;
	}

	pfm->base.base.verify = pfm_flash_verify;
	pfm->base.base.get_id = pfm_flash_get_id;
	pfm->base.base.get_hash = pfm_flash_get_hash;
	pfm->base.base.get_signature = pfm_flash_get_signature;
	pfm->base.base.get_platform_id = pfm_flash_get_platform_id;

	pfm->base.get_supported_versions = pfm_flash_get_supported_versions;
	pfm->base.free_fw_versions = pfm_flash_free_fw_versions;
	pfm->base.get_read_write_regions = pfm_flash_get_read_write_regions;
	pfm->base.free_read_write_regions = pfm_flash_free_read_write_regions;
	pfm->base.get_firmware_images = pfm_flash_get_firmware_images;
	pfm->base.free_firmware_images = pfm_flash_free_firmware_images;

	return 0;
}

/**
 * Release the resources used by the PFM interface.
 *
 * @param pfm The PFM instance to release.
 */
void pfm_flash_release (struct pfm_flash *pfm)
{

}

/**
 * Get the starting flash address of the PFM.
 *
 * @param pfm The PFM to query.
 *
 * @return The PFM flash address.
 */
uint32_t pfm_flash_get_addr (struct pfm_flash *pfm)
{
	if (pfm) {
		return pfm->base_flash.addr;
	}
	else {
		return 0;
	}
}

/**
 * Get the flash device that is used to store the PFM.
 *
 * @param pfm The PFM to query.
 *
 * @return The flash device for the PFM.
 */
struct spi_flash* pfm_flash_get_flash (struct pfm_flash *pfm)
{
	if (pfm) {
		return pfm->base_flash.flash;
	}
	else {
		return NULL;
	}
}
