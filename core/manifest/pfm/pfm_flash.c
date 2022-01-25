// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "pfm_flash.h"
#include "pfm_format.h"
#include "flash/flash_util.h"
#include "manifest/manifest_flash.h"
#include "common/buffer_util.h"


/**
 * Static array indicating the manifest contains no firmware identifiers.
 */
static const char *NO_FW_IDS[] = {NULL};


static int pfm_flash_verify (struct manifest *pfm, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	int status;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	status = manifest_flash_verify (&pfm_flash->base_flash, hash, verification, hash_out,
		hash_length);
	if (status != 0) {
		return status;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		struct pfm_allowable_firmware_header fw_section;
		struct pfm_key_manifest_header key_section;
		struct pfm_platform_header platform_section;
		uint32_t next_addr;

		/* Check the contents of the PFM to make sure they make sense. */
		next_addr = pfm_flash->base_flash.addr + sizeof (struct manifest_header);
		status = pfm_flash->base_flash.flash->read (pfm_flash->base_flash.flash, next_addr,
			(uint8_t*) &fw_section, sizeof (fw_section));
		if (status != 0) {
			goto error;
		}

		next_addr += fw_section.length;
		status = pfm_flash->base_flash.flash->read (pfm_flash->base_flash.flash, next_addr,
			(uint8_t*) &key_section, sizeof (key_section));
		if (status != 0) {
			goto error;
		}

		next_addr += key_section.length;
		status = pfm_flash->base_flash.flash->read (pfm_flash->base_flash.flash, next_addr,
			(uint8_t*) &platform_section, sizeof (platform_section));
		if (status != 0) {
			goto error;
		}

		if (platform_section.id_length > pfm_flash->base_flash.max_platform_id) {
			status = MANIFEST_PLAT_ID_BUFFER_TOO_SMALL;
			goto error;
		}

		if (pfm_flash->base_flash.header.length !=
			(sizeof (struct manifest_header) + fw_section.length + key_section.length +
				platform_section.length + pfm_flash->base_flash.header.sig_length)) {
			status = MANIFEST_MALFORMED;
			goto error;
		}

		next_addr += sizeof (struct pfm_platform_header);
		status = pfm_flash->base_flash.flash->read (pfm_flash->base_flash.flash, next_addr,
			(uint8_t*) pfm_flash->base_flash.platform_id, platform_section.id_length);
		if (status != 0) {
			goto error;
		}

		pfm_flash->base_flash.platform_id[platform_section.id_length] = '\0';
	}
	else {
		uint8_t format;
		uint8_t *element = (uint8_t*) &pfm_flash->flash_dev;

		status = manifest_flash_read_element_data (&pfm_flash->base_flash, hash, PFM_FLASH_DEVICE,
			0, MANIFEST_NO_PARENT, 0, NULL, &format, NULL, &element, sizeof (pfm_flash->flash_dev));
		if (ROT_IS_ERROR (status) && (status != MANIFEST_ELEMENT_NOT_FOUND)) {
			goto error;
		}

		if ((size_t) status < sizeof (pfm_flash->flash_dev)) {
			status = PFM_MALFORMED_FLASH_DEV_ELEMENT;
			goto error;
		}

		if (status != MANIFEST_ELEMENT_NOT_FOUND) {
			pfm_flash->flash_dev_format = format;
		}
		else {
			pfm_flash->flash_dev_format = -1;
		}
	}

	return 0;

error:
	pfm_flash->base_flash.manifest_valid = false;
	return status;
}

static int pfm_flash_get_id (struct manifest *pfm, uint32_t *id)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&pfm_flash->base_flash, id);
}

static int pfm_flash_get_platform_id (struct manifest *pfm, char **id, size_t length)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_platform_id (&pfm_flash->base_flash, id, length);
}

static void pfm_flash_free_platform_id (struct manifest *manifest, char *id)
{
	/* Don't need to do anything.  Manifest allocated buffers use the internal static buffer. */
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

static int pfm_flash_is_empty (struct manifest *pfm)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	int status;

	if (pfm_flash == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	if (!pfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		uint8_t check;

		status = pfm_flash->base.buffer_supported_versions (&pfm_flash->base, NULL, 0, 1, &check);
		if ((status == 0) || (status == 1)) {
			status = !status;
		}
	}
	else {
		status = (pfm_flash->flash_dev_format < 0) || (pfm_flash->flash_dev.fw_count == 0);
	}

	return status;
}

static void pfm_flash_free_firmware (struct pfm *pfm, struct pfm_firmware *fw)
{
	size_t i;

	if ((fw != NULL) && (fw->ids != NULL) && (fw->ids != NO_FW_IDS)) {
		for (i = 0; i < fw->count; i++) {
			platform_free ((void*) fw->ids[i]);
		}

		platform_free (fw->ids);

		memset (fw, 0, sizeof (*fw));
	}
}

/**
 * Get the list of firmware components in a v1 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param fw Output for the the list of firmware.
 *
 * @return Always succeeds and returns 0.
 */
static int pfm_flash_get_firmware_v1 (struct pfm_flash *pfm, struct pfm_firmware *fw)
{
	fw->ids = NO_FW_IDS;
	fw->count = 1;

	return 0;
}

/**
 * Read the next firmware element in a v2 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param entry On input, the entry to start searching.  On output, the entry that was read.
 * @param fw_element Output for the firmware element data.
 *
 * @return 0 if the element was successfully read or an error code.
 */
static int pfm_flash_read_firmware_element_v2 (struct pfm_flash *pfm, uint8_t *entry,
	struct pfm_firmware_element *fw_element)
{
	uint8_t *element = (uint8_t*) fw_element;
	int id_pad;
	int status;

	status = manifest_flash_read_element_data (&pfm->base_flash, pfm->base_flash.hash,
		PFM_FIRMWARE, *entry, MANIFEST_NO_PARENT, 0, entry, NULL, NULL, &element,
		sizeof (*fw_element));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if ((size_t) status < (sizeof (*fw_element) - sizeof (fw_element->id))) {
		return PFM_MALFORMED_FIRMWARE_ELEMENT;
	}

	id_pad = fw_element->id_length % 4;
	if (id_pad != 0) {
		id_pad = 4 - id_pad;
	}

	if ((size_t) status <
		((sizeof (*fw_element) - sizeof (fw_element->id)) + fw_element->id_length + id_pad)) {
		return PFM_MALFORMED_FIRMWARE_ELEMENT;
	}

	return 0;
}

/**
 * Get the list of firmware components in a v2 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param fw Output for the list of firmware.
 *
 * @return 0 if the list was generated successfully or an error code.
 */
static int pfm_flash_get_firmware_v2 (struct pfm_flash *pfm, struct pfm_firmware *fw)
{
	struct pfm_firmware_element fw_element;
	uint8_t last = 0;
	size_t i;
	int status;

	if ((pfm->flash_dev_format >= 0) && (pfm->flash_dev.fw_count != 0)) {
		fw->count = pfm->flash_dev.fw_count;
		fw->ids = platform_calloc (fw->count, sizeof (char*));
		if (fw->ids == NULL) {
			return PFM_NO_MEMORY;
		}

		for (i = 0; i < fw->count; i++, last++) {
			status = pfm_flash_read_firmware_element_v2 (pfm, &last, &fw_element);
			if (status != 0) {
				goto error;
			}

			fw_element.id[fw_element.id_length] = '\0';
			fw->ids[i] = strdup ((char*) fw_element.id);
			if (fw->ids[i] == NULL) {
				status = PFM_NO_MEMORY;
				goto error;
			}
		}
	}
	else {
		memset (fw, 0, sizeof (*fw));
	}

	return 0;

error:
	pfm_flash_free_firmware (&pfm->base, fw);
	return status;
}

static int pfm_flash_get_firmware (struct pfm *pfm, struct pfm_firmware *fw)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if ((pfm_flash == NULL) || (fw == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	if (!pfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		return pfm_flash_get_firmware_v1 (pfm_flash, fw);
	}
	else {
		return pfm_flash_get_firmware_v2 (pfm_flash, fw);
	}
}

static void pfm_flash_free_fw_versions (struct pfm *pfm, struct pfm_firmware_versions *ver_list)
{
	size_t i;

	if ((ver_list != NULL) && (ver_list->versions != NULL)) {
		for (i = 0; i < ver_list->count; i++) {
			platform_free ((void*) ver_list->versions[i].fw_version_id);
		}

		platform_free ((void*) ver_list->versions);

		memset (ver_list, 0, sizeof (*ver_list));
	}
}

/**
 * Get the list of supported firmware versions from a v1 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param ver_list Output for the list of supported firmware versions.  Null to buffer the output.
 * @param offset Offset to start buffering version strings.
 * @param length Maximum length of version strings to buffer.
 * @param ver_out Output for buffering the list of versions.  Not used if allocating a list.
 * @param bytes Output for the number of bytes that were buffered.
 *
 * @return 0 if the version list was successfully generated or an error code.
 */
static int pfm_flash_get_supported_versions_v1 (struct pfm_flash *pfm,
	struct pfm_firmware_versions *ver_list, size_t offset, size_t length, uint8_t *ver_out,
	int *bytes)
{
	struct manifest_header header;
	struct pfm_allowable_firmware_header fw_section;
	struct pfm_firmware_header fw_header;
	struct pfm_firmware_version *version_list = NULL;
	uint8_t version_str[MANIFEST_MAX_STRING];
	int i;
	uint32_t next_addr;
	int status;

	status = pfm->base_flash.flash->read (pfm->base_flash.flash, pfm->base_flash.addr,
		(uint8_t*) &header, sizeof (header));
	if (status != 0) {
		return status;
	}

	if (header.magic != PFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	status = pfm->base_flash.flash->read (pfm->base_flash.flash,
		pfm->base_flash.addr + sizeof (struct manifest_header), (uint8_t*) &fw_section,
		sizeof (fw_section));
	if (status != 0) {
		return status;
	}

	if (fw_section.fw_count == 0) {
		if (ver_list) {
			memset (ver_list, 0, sizeof (*ver_list));
		}
		return 0;
	}

	if (ver_list) {
		version_list = platform_calloc (fw_section.fw_count, sizeof (struct pfm_firmware_version));
		if (version_list == NULL) {
			return PFM_NO_MEMORY;
		}

		ver_list->versions = version_list;
		ver_list->count = fw_section.fw_count;
	}

	next_addr = pfm->base_flash.addr + sizeof (struct manifest_header) +
		sizeof (struct pfm_allowable_firmware_header);
	i = 0;
	while ((i < fw_section.fw_count) && (length > 0)) {
		status = pfm->base_flash.flash->read (pfm->base_flash.flash, next_addr,
			(uint8_t*) &fw_header, sizeof (fw_header));
		if (status != 0) {
			goto error;
		}

		status = pfm->base_flash.flash->read (pfm->base_flash.flash,
			next_addr + sizeof (struct pfm_firmware_header), version_str, fw_header.version_length);
		if (status != 0) {
			goto error;
		}

		version_str[fw_header.version_length] = '\0';

		if (ver_list) {
			version_list[i].version_addr = fw_header.version_addr;
			version_list[i].blank_byte = fw_header.blank_byte;
			version_list[i].fw_version_id = strdup ((char*) version_str);
			if (version_list[i].fw_version_id == NULL) {
				status = PFM_NO_MEMORY;
				goto error;
			}
		}
		else {
			*bytes += buffer_copy (version_str, fw_header.version_length + 1, &offset, &length,
				&ver_out[*bytes]);
		}

		next_addr += fw_header.length;
		i++;
	}

	return 0;

error:
	pfm_flash_free_fw_versions (&pfm->base, ver_list);
	return status;
}

/**
 * Find the firmware element for the specified ID.  The PFM must be in v2 format.
 *
 * @param pfm The PFM to query.
 * @param fw The firmware ID to find.  This can be null to return the first firmware element.
 * @param fw_element Output for the firmware element data.
 * @param entry Output for the entry index following the matching firmware element.
 *
 * @return 0 if the firmware element was found or an error code.
 */
static int pfm_flash_find_firmware_element_v2 (struct pfm_flash *pfm, const char *fw,
	struct pfm_firmware_element *fw_element, uint8_t *entry)
{
	int status;

	*entry = 0;
	do {
		status = pfm_flash_read_firmware_element_v2 (pfm, entry, fw_element);
		if (status != 0) {
			if (status == MANIFEST_ELEMENT_NOT_FOUND) {
				return PFM_UNKNOWN_FIRMWARE;
			}
			else {
				return status;
			}
		}

		(*entry)++;
		fw_element->id[fw_element->id_length] = '\0';
	} while ((fw != NULL) && (strcmp (fw, (char*) fw_element->id) != 0));

	return 0;
}

/**
 * Read the next firmware version element in a v2 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param entry On input, the entry to start searching.  On output, the entry that was read.
 * @param ver_element Output for the firmware version element data.
 * @param element_len Optional output for the amount of element data read.
 *
 * @return 0 if the element was successfully read or an error code.
 */
static int pfm_flash_read_firmware_version_element_v2 (struct pfm_flash *pfm, uint8_t *entry,
	struct pfm_firmware_version_element *ver_element, size_t *element_len)
{
	uint8_t *element = (uint8_t*) ver_element;
	size_t ver_len;
	int ver_pad;
	int status;

	status = manifest_flash_read_element_data (&pfm->base_flash, pfm->base_flash.hash,
		PFM_FIRMWARE_VERSION, *entry, PFM_FIRMWARE, 0, entry, NULL, &ver_len, &element,
		sizeof (*ver_element));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if ((size_t) status < (sizeof (*ver_element) - (sizeof (ver_element->version)))) {
		return PFM_MALFORMED_FW_VER_ELEMENT;
	}

	ver_pad = ver_element->version_length % 4;
	if (ver_pad != 0) {
		ver_pad = 4 - ver_pad;
	}

	if (ver_len <
		((sizeof (*ver_element) - sizeof (ver_element->version)) + ver_element->version_length +
			ver_pad + (sizeof (struct pfm_fw_version_element_rw_region) * ver_element->rw_count))) {
		return PFM_MALFORMED_FW_VER_ELEMENT;
	}

	if (element_len) {
		*element_len = status;
	}
	return 0;
}

/**
 * Get the list of supported firmware versions from a v2 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param fw The firmware ID to query.  This can be null to default to the first firmware ID.
 * @param ver_list Output for the list of supported firmware versions.  Null to buffer the output.
 * @param offset Offset to start buffering version strings.  Updated on output.
 * @param length Maximum length of version strings to buffer.  Updated on output.
 * @param ver_out Output for buffering the list of versions.  Not used if allocating a list.
 * @param bytes Output for the number of bytes that were buffered.
 *
 * @return 0 if the version list was successfully generated or an error code.
 */
static int pfm_flash_get_supported_versions_v2 (struct pfm_flash *pfm, const char *fw,
	struct pfm_firmware_versions *ver_list, size_t *offset, size_t *length, uint8_t *ver_out,
	int *bytes)
{
	union {
		struct pfm_firmware_element fw_element;
		struct pfm_firmware_version_element ver_element;
	} buffer;
	struct pfm_firmware_version *version_list = NULL;
	uint8_t entry;
	int i;
	int count;
	int status;

	if ((pfm->flash_dev_format < 0) || (pfm->flash_dev.fw_count == 0)) {
		if (fw == NULL) {
			if (ver_list) {
				memset (ver_list, 0, sizeof (*ver_list));
			}
			return 0;
		}
		else {
			return PFM_UNKNOWN_FIRMWARE;
		}
	}

	status = pfm_flash_find_firmware_element_v2 (pfm, fw, &buffer.fw_element, &entry);
	if (status != 0) {
		return status;
	}

	if (buffer.fw_element.version_count == 0) {
		if (ver_list) {
			memset (ver_list, 0, sizeof (*ver_list));
		}
		return 0;
	}

	count = buffer.fw_element.version_count;
	if (ver_list) {
		ver_list->count = count;
		version_list = platform_calloc (ver_list->count, sizeof (struct pfm_firmware_version));
		if (version_list == NULL) {
			return PFM_NO_MEMORY;
		}

		ver_list->versions = version_list;
	}

	i = 0;
	while ((i < count) && ((length == NULL) || (*length > 0))) {
		status = pfm_flash_read_firmware_version_element_v2 (pfm, &entry, &buffer.ver_element,
			NULL);
		if (status != 0) {
			goto error;
		}

		buffer.ver_element.version[buffer.ver_element.version_length] = '\0';

		if (ver_list) {
			version_list[i].blank_byte = pfm->flash_dev.blank_byte;
			version_list[i].version_addr = buffer.ver_element.version_addr;
			version_list[i].fw_version_id = strdup ((char*) buffer.ver_element.version);
			if (version_list[i].fw_version_id == NULL) {
				status = PFM_NO_MEMORY;
				goto error;
			}
		}
		else {
			*bytes += buffer_copy (buffer.ver_element.version,
				buffer.ver_element.version_length + 1, offset, length, &ver_out[*bytes]);
		}

		i++;
		entry++;
	}

	return 0;

error:
	pfm_flash_free_fw_versions (&pfm->base, ver_list);
	return status;
}

static int pfm_flash_get_supported_versions (struct pfm *pfm, const char *fw,
	struct pfm_firmware_versions *ver_list)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if ((pfm_flash == NULL) || (ver_list == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	if (!pfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		return pfm_flash_get_supported_versions_v1 (pfm_flash, ver_list, 0, 1, NULL, NULL);
	}
	else {
		return pfm_flash_get_supported_versions_v2 (pfm_flash, fw, ver_list, NULL, NULL, NULL,
			NULL);
	}
}

static int pfm_flash_buffer_supported_versions (struct pfm *pfm, const char *fw, size_t offset,
	size_t length, uint8_t *ver_list)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;
	struct pfm_firmware fw_list;
	int bytes = 0;
	int status = 0;
	size_t i;

	if ((pfm_flash == NULL) || (ver_list == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	if (!pfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		if (fw != NULL) {
			return PFM_UNKNOWN_FIRMWARE;
		}

		status = pfm_flash_get_supported_versions_v1 (pfm_flash, NULL, offset, length, ver_list,
			&bytes);
	}
	else {
		if (fw == NULL) {
			status = pfm_flash_get_firmware_v2 (pfm_flash, &fw_list);
			if (status != 0) {
				return status;
			}

			i = 0;
			while ((i < fw_list.count) && (length > 0) && (status == 0)) {
				bytes += buffer_copy ((const uint8_t*) fw_list.ids[i], strlen (fw_list.ids[i]) + 1,
					&offset, &length, &ver_list[bytes]);

				if (length > 0) {
					status = pfm_flash_get_supported_versions_v2 (pfm_flash, fw_list.ids[i], NULL,
						&offset, &length, ver_list, &bytes);
				}

				i++;
			}

			pfm_flash_free_firmware (pfm, &fw_list);
		}
		else {
			status = pfm_flash_get_supported_versions_v2 (pfm_flash, fw, NULL, &offset, &length,
				ver_list, &bytes);
		}
	}

	return (status == 0) ? bytes : status;
}

/**
 * Find the version entry in the PFM that matches the expected version identifier.  The PFM must be
 * in v1 format.
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
static int pfm_flash_find_version_entry_v1 (struct manifest_flash *pfm, const char *version,
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
	status = pfm->flash->read (pfm->flash, *fw_addr, (uint8_t*) &header, sizeof (header));
	if (status != 0) {
		return status;
	}

	if (header.magic != PFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	*fw_addr += sizeof (struct manifest_header);
	status = pfm->flash->read (pfm->flash, *fw_addr, (uint8_t*) &fw_section, sizeof (fw_section));
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
		status = pfm->flash->read (pfm->flash, *fw_addr, (uint8_t*) fw_header, sizeof (*fw_header));
		if (status != 0) {
			goto error;
		}

		if (fw_header->version_length == check_len) {
			status = pfm->flash->read (pfm->flash, *fw_addr + sizeof (struct pfm_firmware_header),
				(uint8_t*) check, fw_header->version_length);
			if (status != 0) {
				goto error;
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

error:
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
static int pfm_flash_read_region_v1 (struct manifest_flash *pfm, uint32_t addr,
	struct flash_region *region)
{
	struct pfm_flash_region rw_region;
	int status;

	status = pfm->flash->read (pfm->flash, addr, (uint8_t*) &rw_region, sizeof (rw_region));
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
static int pfm_flash_read_multiple_regions_v1 (struct manifest_flash *pfm, size_t count,
	struct flash_region *region_list, uint32_t *addr)
{
	size_t i;
	int status;

	for (i = 0; i < count; i++) {
		status = pfm_flash_read_region_v1 (pfm, *addr, &region_list[i]);
		if (status != 0) {
			return status;
		}

		*addr += sizeof (struct pfm_flash_region);
	}

	return 0;
}

static void pfm_flash_free_read_write_regions (struct pfm *pfm,
	struct pfm_read_write_regions *writable)
{
	if (writable != NULL) {
		platform_free ((void*) writable->regions);
		platform_free ((void*) writable->properties);

		memset (writable, 0, sizeof (*writable));
	}
}

/**
 * Get the list of read/write regions for a firmware version from a v1 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param version The firmware version to query.
 * @param writable Output for the list of read/write regions.
 *
 * @return 0 if the list was successfully generated or an error code.
 */
static int pfm_flash_get_read_write_regions_v1 (struct pfm_flash *pfm, const char *version,
	struct pfm_read_write_regions *writable)
{
	struct pfm_firmware_header fw_header;
	struct flash_region *region_list;
	uint32_t next_addr;
	int status;

	status = pfm_flash_find_version_entry_v1 (&pfm->base_flash, version, &fw_header, &next_addr,
		NULL);
	if (status != 0) {
		return status;
	}

	region_list = platform_calloc (fw_header.rw_count, sizeof (struct flash_region));
	if (region_list == NULL) {
		return PFM_NO_MEMORY;
	}

	writable->regions = region_list;
	writable->count = fw_header.rw_count;
	writable->properties = platform_calloc (fw_header.rw_count, sizeof (struct pfm_read_write));
	if (writable->properties == NULL) {
		status = PFM_NO_MEMORY;
		goto error;
	}

	next_addr += sizeof (struct pfm_firmware_header) + fw_header.version_length;
	if ((fw_header.version_length % 4) != 0) {
		next_addr += (4 - (fw_header.version_length % 4));
	}

	status = pfm_flash_read_multiple_regions_v1 (&pfm->base_flash, fw_header.rw_count, region_list,
		&next_addr);
	if (status != 0) {
		goto error;
	}

	return 0;

error:
	pfm_flash_free_read_write_regions (&pfm->base, writable);
	return status;
}

/**
 * Find the firmware version element for the specified ID.  The PFM must be in v2 format.
 *
 * @param pfm The PFM to query.
 * @param version The version ID to find.
 * @param entry On input, the entry index to start searching.  On output, the entry index for the
 * firmware version element.
 * @param ver_element Output for the firmware version element data.
 * @param element_len Optional output for the amount of element data read.
 *
 * @return 0 if the firmware version element was found or an error code.
 */
static int pfm_flash_find_firmware_version_element_v2 (struct pfm_flash *pfm, const char *version,
	uint8_t *entry, struct pfm_firmware_version_element *ver_element, size_t *element_len)
{
	uint8_t temp;
	int status;

	do {
		status = pfm_flash_read_firmware_version_element_v2 (pfm, entry, ver_element, element_len);
		if (status != 0) {
			if (status == MANIFEST_CHILD_NOT_FOUND) {
				return PFM_UNSUPPORTED_VERSION;
			}
			else {
				return status;
			}
		}

		(*entry)++;
		temp = ver_element->version[ver_element->version_length];
		ver_element->version[ver_element->version_length] = '\0';
	} while (strcmp (version, (char*) ver_element->version) != 0);

	/* Restore the modified byte to ensure the original data is returned in the buffer. */
	ver_element->version[ver_element->version_length] = temp;
	(*entry)--;

	return 0;
}

/**
 * Get the list of read/write regions for a firmware version from a v2 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param fw The firmware ID to query.  This can be null to default to the first firmware ID.
 * @param version The firmware version to query.
 * @param writable Output for the list of read/write regions.
 *
 * @return 0 if the list was successfully generated or an error code.
 */
static int pfm_flash_get_read_write_regions_v2 (struct pfm_flash *pfm, const char *fw,
	const char *version, struct pfm_read_write_regions *writable)
{
	union {
		struct pfm_firmware_element fw_element;
		struct pfm_firmware_version_element ver_element;
	} buffer;
	struct pfm_fw_version_element_rw_region *rw_region;
	struct flash_region *region_list;
	struct pfm_read_write *prop_list;
	uint8_t *element;
	uint8_t entry;
	size_t i;
	int version_pad;
	int rw_len;
	uint32_t offset;
	int status;

	if ((pfm->flash_dev_format < 0) || (pfm->flash_dev.fw_count == 0)) {
		return PFM_UNKNOWN_FIRMWARE;
	}

	status = pfm_flash_find_firmware_element_v2 (pfm, fw, &buffer.fw_element, &entry);
	if (status != 0) {
		return status;
	}

	status = pfm_flash_find_firmware_version_element_v2 (pfm, version, &entry, &buffer.ver_element,
		NULL);
	if (status != 0) {
		return status;
	}

	if (buffer.ver_element.rw_count == 0) {
		memset (writable, 0, sizeof (*writable));
		return 0;
	}

	rw_len = buffer.ver_element.rw_count * sizeof (struct pfm_fw_version_element_rw_region);
	if (rw_len > MANIFEST_MAX_STRING) {
		/* We do not have enough buffer available to read all R/W region information in a single
		 * read.  We could loop through reading one buffer's worth at a time, but this is overly
		 * complicated and unnecessary.  That many R/W regions is unrealistic and doesn't need to be
		 * supported. */
		return PFM_READ_WRITE_UNSUPPORTED;
	}

	version_pad = buffer.ver_element.version_length % 4;
	if (version_pad != 0) {
		version_pad = 4 - version_pad;
	}

	if ((MANIFEST_MAX_STRING - (buffer.ver_element.version_length + version_pad)) < rw_len) {
		/* The R/W region definitions are not contained within the first element read.  Reuse the
		 * version buffer to read the element again, starting at the R/W regions. */
		element = buffer.ver_element.version;
		offset = (sizeof (buffer.ver_element) - sizeof (buffer.ver_element.version)) +
			buffer.ver_element.version_length + version_pad;

		status = manifest_flash_read_element_data (&pfm->base_flash, pfm->base_flash.hash,
			PFM_FIRMWARE_VERSION, entry, PFM_FIRMWARE, offset, NULL, NULL, NULL, &element,
			sizeof (buffer.ver_element.version));
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		buffer.ver_element.version_length = 0;
		version_pad = 0;
	}

	writable->count = buffer.ver_element.rw_count;
	writable->regions = platform_calloc (writable->count, sizeof (struct flash_region));
	if (writable->regions == NULL) {
		return PFM_NO_MEMORY;
	}

	writable->properties = platform_calloc (writable->count, sizeof (struct pfm_read_write));
	if (writable->properties == NULL) {
		status = PFM_NO_MEMORY;
		goto error;
	}

	region_list = (struct flash_region*) writable->regions;
	prop_list = (struct pfm_read_write*) writable->properties;
	rw_region = (struct pfm_fw_version_element_rw_region*)
		&buffer.ver_element.version[buffer.ver_element.version_length + version_pad];

	for (i = 0; i < writable->count; i++) {
		if (rw_region[i].region.end_addr <= rw_region[i].region.start_addr) {
			status = PFM_MALFORMED_FW_VER_ELEMENT;
			goto error;
		}

		region_list[i].start_addr = rw_region[i].region.start_addr;
		region_list[i].length = (rw_region[i].region.end_addr - rw_region[i].region.start_addr) + 1;
		prop_list[i].on_failure = pfm_get_rw_operation_on_failure (&rw_region[i]);
	}

	return 0;

error:
	pfm_flash_free_read_write_regions (&pfm->base, writable);
	return status;
}

static int pfm_flash_get_read_write_regions (struct pfm *pfm, const char *fw, const char *version,
	struct pfm_read_write_regions *writable)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if ((pfm_flash == NULL) || (version == NULL) || (writable == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	if (!pfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		return pfm_flash_get_read_write_regions_v1 (pfm_flash, version, writable);
	}
	else {
		return pfm_flash_get_read_write_regions_v2 (pfm_flash, fw, version, writable);
	}
}

static void pfm_flash_free_firmware_images (struct pfm *pfm, struct pfm_image_list *img_list)
{
	size_t i;

	if (img_list != NULL) {
		if (img_list->images_sig != NULL) {
			for (i = 0; i < img_list->count; i++) {
				platform_free ((void*) img_list->images_sig[i].regions);
			}

			platform_free ((void*) img_list->images_sig);
		}

		if (img_list->images_hash != NULL) {
			for (i = 0; i < img_list->count; i++) {
				platform_free ((void*) img_list->images_hash[i].regions);
			}

			platform_free ((void*) img_list->images_hash);
		}

		memset (img_list, 0, sizeof (*img_list));
	}
}

/**
 * Get the list of signed images for a version of firmware from a v1 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param version The firmware version to query.
 * @param img_list Output for the list of signed images.
 *
 * @return 0 if the list was successfully generated or an error code.
 */
static int pfm_flash_get_firmware_images_v1 (struct pfm_flash *pfm, const char *version,
	struct pfm_image_list *img_list)
{
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

	status = pfm_flash_find_version_entry_v1 (&pfm->base_flash, version, &fw_header, &next_addr,
		&key_addr);
	if (status != 0) {
		return status;
	}

	images = platform_calloc (fw_header.img_count, sizeof (struct pfm_image_signature));
	if (images == NULL) {
		return PFM_NO_MEMORY;
	}

	img_list->images_hash = NULL;
	img_list->images_sig = images;
	img_list->count = fw_header.img_count;

	next_addr += sizeof (struct pfm_firmware_header) + fw_header.version_length +
		(sizeof (struct pfm_flash_region) * fw_header.rw_count);
	if ((fw_header.version_length % 4) != 0) {
		next_addr += 4 - (fw_header.version_length % 4);
	}

	for (i = 0; i < fw_header.img_count; i++) {
		status = pfm->base_flash.flash->read (pfm->base_flash.flash, next_addr,
			(uint8_t*) &img_header, sizeof (img_header));
		if (status != 0) {
			goto error;
		}

		if (img_header.sig_length > sizeof (images[i].signature)) {
			status = PFM_FW_IMAGE_UNSUPPORTED;
			goto error;
		}

		region_list = platform_calloc (img_header.region_count, sizeof (struct flash_region));
		if (region_list == NULL) {
			status = PFM_NO_MEMORY;
			goto error;
		}

		images[i].regions = region_list;
		images[i].count = img_header.region_count;
		images[i].always_validate = !!(img_header.flags & PFM_IMAGE_MUST_VALIDATE);
		images[i].sig_length = img_header.sig_length;
		images[i].key.mod_length = (0xffU << 24) | img_header.key_id;

		next_addr += sizeof (struct pfm_image_header);
		status = pfm->base_flash.flash->read (pfm->base_flash.flash, next_addr, images[i].signature,
			img_header.sig_length);
		if (status != 0) {
			goto error;
		}

		next_addr += img_header.sig_length;
		status = pfm_flash_read_multiple_regions_v1 (&pfm->base_flash, img_header.region_count,
			region_list, &next_addr);
		if (status != 0) {
			goto error;
		}
	}

	status = pfm->base_flash.flash->read (pfm->base_flash.flash, key_addr, (uint8_t*) &key_section,
		sizeof (key_section));
	if (status != 0) {
		goto error;
	}

	i = 0;
	matched = 0;
	next_addr = key_addr + sizeof (struct pfm_key_manifest_header);
	while ((i < key_section.key_count) && (matched < fw_header.img_count)) {
		status = pfm->base_flash.flash->read (pfm->base_flash.flash, next_addr,
			(uint8_t*) &key_header, sizeof (key_header));
		if (status != 0) {
			goto error;
		}

		if (key_header.key_length > sizeof (key.modulus)) {
			status = PFM_KEY_UNSUPPORTED;
			goto error;
		}

		next_addr += sizeof (struct pfm_public_key_header);
		status = pfm->base_flash.flash->read (pfm->base_flash.flash, next_addr, key.modulus,
			key_header.key_length);
		if (status != 0) {
			goto error;
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
		goto error;
	}

	return 0;

error:
	pfm_flash_free_firmware_images (&pfm->base, img_list);
	return status;
}

/**
 * Determine the total length of a image definition within a firmware version element.
 *
 * @param img The image header.
 *
 * @return The total length of the image description.
 */
static uint32_t pfm_flash_get_image_length_v2 (struct pfm_fw_version_element_image *img)
{
	uint32_t length = sizeof (*img) + (sizeof (struct pfm_flash_region) * img->region_count);

	switch (img->hash_type) {
		case MANIFEST_HASH_SHA256:
			length += SHA256_HASH_LENGTH;
			break;

		case MANIFEST_HASH_SHA384:
			length += SHA384_HASH_LENGTH;
			break;

		case MANIFEST_HASH_SHA512:
			length += SHA512_HASH_LENGTH;
			break;
	}

	return length;
}

/**
 * Get the list of signed images for a version of firmware from a v2 formatted PFM.
 *
 * @param pfm The PFM to query.
 * @param fw The firmware ID to query.  This can be null to default to the first firmware ID.
 * @param version The firmware version to query.
 * @param img_list Output for the list of signed images.
 *
 * @return 0 if the list was successfully generated or an error code.
 */
static int pfm_flash_get_firmware_images_v2 (struct pfm_flash *pfm, const char *fw,
	const char *version, struct pfm_image_list *img_list)
{
	union {
		struct pfm_firmware_element fw_element;
		struct pfm_firmware_version_element ver_element;
	} buffer;
	struct pfm_fw_version_element_image *img;
	struct pfm_flash_region *img_regions;
	struct pfm_image_hash *images;
	struct flash_region *region_list;
	uint8_t *element;
	uint8_t entry;
	size_t element_len;
	int version_pad;
	uint32_t offset;
	uint32_t buf_offset;
	size_t img_len;
	size_t i;
	size_t j;
	int status;

	if ((pfm->flash_dev_format < 0) || (pfm->flash_dev.fw_count == 0)) {
		return PFM_UNKNOWN_FIRMWARE;
	}

	status = pfm_flash_find_firmware_element_v2 (pfm, fw, &buffer.fw_element, &entry);
	if (status != 0) {
		return status;
	}

	status = pfm_flash_find_firmware_version_element_v2 (pfm, version, &entry, &buffer.ver_element,
		&element_len);
	if (status != 0) {
		return status;
	}

	img_list->count = buffer.ver_element.img_count;
	img_list->images_sig = NULL;
	img_list->images_hash = platform_calloc (img_list->count, sizeof (struct pfm_image_hash));
	if (img_list->images_hash == NULL) {
		return PFM_NO_MEMORY;
	}

	version_pad = buffer.ver_element.version_length % 4;
	if (version_pad != 0) {
		version_pad = 4 - version_pad;
	}
	offset = (sizeof (buffer.ver_element) - sizeof (buffer.ver_element.version)) +
		buffer.ver_element.version_length + version_pad +
		(sizeof (struct pfm_fw_version_element_rw_region) * buffer.ver_element.rw_count);

	buf_offset = offset - (sizeof (buffer.ver_element) - sizeof (buffer.ver_element.version));
	element_len -= (sizeof (buffer.ver_element) - sizeof (buffer.ver_element.version));

	for (i = 0; i < img_list->count; i++) {
		img = (struct pfm_fw_version_element_image*) &buffer.ver_element.version[buf_offset];

		if (buf_offset >= sizeof (buffer.ver_element.version)) {
			img = NULL;
		}
		else if ((buf_offset + pfm_flash_get_image_length_v2 (img)) >
			sizeof (buffer.ver_element.version)) {
			img = NULL;
		}

		if (img == NULL) {
			/* The complete image definition does not reside in memory.  We may have part of the
			 * image information or none of it.  Either way, use the version buffer to read the
			 * element again starting at the beginning of the image information. */
			element = buffer.ver_element.version;
			status = manifest_flash_read_element_data (&pfm->base_flash, pfm->base_flash.hash,
				PFM_FIRMWARE_VERSION, entry, PFM_FIRMWARE, offset, NULL, NULL, NULL, &element,
				sizeof (buffer.ver_element.version));
			if (ROT_IS_ERROR (status)) {
				goto error;
			}

			element_len = status;
			buf_offset = 0;
			img = (struct pfm_fw_version_element_image*) buffer.ver_element.version;
		}

		if ((element_len - buf_offset) < sizeof (struct pfm_fw_version_element_image)) {
			status = PFM_MALFORMED_FW_VER_ELEMENT;
			goto error;
		}

		if (img->region_count == 0) {
			status = PFM_FW_IMAGE_UNSUPPORTED;
			goto error;
		}

		img_len = pfm_flash_get_image_length_v2 (img);
		if (img_len > sizeof (buffer.ver_element.version)) {
			/* We cannot read the entire image information in a single read, so we cannot support
			 * this image.  Handling larger image definitions would greatly complicate processing
			 * for very little gain.  An image that needs to be defined with that many regions would
			 * be an extremely rare case.  If it does happen, it can be worked around by adding more
			 * image definitions with separate hashes instead of using many regions and a single
			 * hash. */
			status = PFM_FW_IMAGE_UNSUPPORTED;
			goto error;
		}

		if ((element_len - buf_offset) < img_len) {
			status = PFM_MALFORMED_FW_VER_ELEMENT;
			goto error;
		}

		buf_offset += sizeof (struct pfm_fw_version_element_image);

		images = (struct pfm_image_hash*) img_list->images_hash;
		images[i].count = img->region_count;
		images[i].regions = platform_calloc (images[i].count, sizeof (struct flash_region));
		if (images[i].regions == NULL) {
			status = PFM_NO_MEMORY;
			goto error;
		}

		region_list = (struct flash_region*) images[i].regions;

		switch (img->hash_type) {
			case MANIFEST_HASH_SHA256:
				images[i].hash_type = HASH_TYPE_SHA256;
				images[i].hash_length = SHA256_HASH_LENGTH;
				break;

			case MANIFEST_HASH_SHA384:
				images[i].hash_type = HASH_TYPE_SHA384;
				images[i].hash_length = SHA384_HASH_LENGTH;
				break;

			case MANIFEST_HASH_SHA512:
				images[i].hash_type = HASH_TYPE_SHA512;
				images[i].hash_length = SHA512_HASH_LENGTH;
				break;

			default:
				status = PFM_UNKNOWN_HASH_TYPE;
				goto error;
		}

		memcpy (images[i].hash, &buffer.ver_element.version[buf_offset], images[i].hash_length);
		images[i].always_validate = img->flags & PFM_IMAGE_MUST_VALIDATE;
		buf_offset += images[i].hash_length;

		img_regions = (struct pfm_flash_region*) &buffer.ver_element.version[buf_offset];

		for (j = 0; j < images[i].count; j++) {
			if (img_regions[j].end_addr <= img_regions[j].start_addr) {
				status = PFM_MALFORMED_FW_VER_ELEMENT;
				goto error;
			}

			region_list[j].start_addr = img_regions[j].start_addr;
			region_list[j].length = (img_regions[j].end_addr - img_regions[j].start_addr) + 1;
		}

		buf_offset += (sizeof (struct pfm_flash_region) * images[i].count);
		offset += img_len;
	}

	return 0;

error:
	pfm_flash_free_firmware_images (&pfm->base, img_list);
	return status;
}

static int pfm_flash_get_firmware_images (struct pfm *pfm, const char *fw, const char *version,
	struct pfm_image_list *img_list)
{
	struct pfm_flash *pfm_flash = (struct pfm_flash*) pfm;

	if ((pfm_flash == NULL) || (version == NULL) || (img_list == NULL)) {
		return PFM_INVALID_ARGUMENT;
	}

	if (!pfm_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (pfm_flash->base_flash.header.magic == PFM_MAGIC_NUM) {
		return pfm_flash_get_firmware_images_v1 (pfm_flash, version, img_list);
	}
	else {
		return pfm_flash_get_firmware_images_v2 (pfm_flash, fw, version, img_list);
	}
}

/**
 * Initialize the interface to a PFM residing in flash memory.
 *
 * @param pfm The PFM instance to initialize.
 * @param flash The flash device that contains the PFM.
 * @param hash A hash engine to use for validating run-time access to PFM information.  If it is
 * possible for any PFM information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe.  There is no internal synchronization around the hashing operations.
 * @param base_addr The starting address of the PFM storage location.
 * @param signature_cache Buffer to hold the manifest signature.
 * @param max_signature The maximum supported length for a manifest signature.
 * @param platform_id_cache Buffer to hold the manifest platform ID.
 * @param max_platform_id The maximum platform ID length supported, including the NULL terminator.
 *
 * @return 0 if the PFM instance was initialized successfully or an error code.
 */
int pfm_flash_init (struct pfm_flash *pfm, struct flash *flash, struct hash_engine *hash,
	uint32_t base_addr, uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id)
{
	int status;

	if (pfm == NULL) {
		return PFM_INVALID_ARGUMENT;
	}

	memset (pfm, 0, sizeof (struct pfm_flash));

	status = manifest_flash_v2_init (&pfm->base_flash, flash, hash, base_addr, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, signature_cache, max_signature, platform_id_cache, max_platform_id);
	if (status != 0) {
		return status;
	}

	pfm->base.base.verify = pfm_flash_verify;
	pfm->base.base.get_id = pfm_flash_get_id;
	pfm->base.base.get_platform_id = pfm_flash_get_platform_id;
	pfm->base.base.free_platform_id = pfm_flash_free_platform_id;
	pfm->base.base.get_hash = pfm_flash_get_hash;
	pfm->base.base.get_signature = pfm_flash_get_signature;
	pfm->base.base.is_empty = pfm_flash_is_empty;

	pfm->base.get_firmware = pfm_flash_get_firmware;
	pfm->base.free_firmware = pfm_flash_free_firmware;
	pfm->base.get_supported_versions = pfm_flash_get_supported_versions;
	pfm->base.free_fw_versions = pfm_flash_free_fw_versions;
	pfm->base.buffer_supported_versions = pfm_flash_buffer_supported_versions;
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
	if (pfm != NULL) {
		manifest_flash_release (&pfm->base_flash);
	}
}
