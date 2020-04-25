// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "cfm_flash.h"
#include "cfm_format.h"
#include "flash/flash_util.h"
#include "manifest/manifest_flash.h"


static int cfm_flash_verify (struct manifest *cfm, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_verify (&cfm_flash->base_flash, hash, verification, hash_out,
		hash_length);
}

static int cfm_flash_get_id (struct manifest *cfm, uint32_t *id)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&cfm_flash->base_flash, id);
}

static int cfm_flash_get_platform_id (struct manifest *cfm, char **id)
{
	char *curr_id = NULL;
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if ((cfm_flash == NULL) || (id == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	curr_id = platform_malloc (2);
	if (curr_id == NULL) {
		return CFM_NO_MEMORY;
	}

	/* This is a just place holder as CFM currently do not include platform ID.  It should be
	 * updated to return actual platform_id once CFM header is updated to include platform ID.
	 */
	strcpy (curr_id, "");

	*id = curr_id;

	return 0;
}

static int cfm_flash_get_hash (struct manifest *cfm, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_hash (&cfm_flash->base_flash, hash, hash_out, hash_length);
}

static int cfm_flash_get_signature (struct manifest *cfm, uint8_t *signature, size_t length)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;

	if (cfm_flash == NULL) {
		return CFM_INVALID_ARGUMENT;
	}

	return manifest_flash_get_signature (&cfm_flash->base_flash, signature, length);
}

static int cfm_flash_get_supported_component_ids (struct cfm *cfm,
	struct cfm_component_ids *id_list)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct manifest_header header;
	struct cfm_components_header components_header;
	struct cfm_component_header component_header;
	uint32_t *ids;
	uint32_t next_addr;
	int i;
	int status;

	if ((cfm_flash == NULL) || (id_list == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	memset (id_list, 0, sizeof (struct cfm_component_ids));

	status = spi_flash_read (cfm_flash->base_flash.flash, cfm_flash->base_flash.addr,
		(uint8_t*) &header, sizeof (header));

	if (status != 0) {
		return status;
	}

	if (header.magic != CFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	status = spi_flash_read (cfm_flash->base_flash.flash,
		cfm_flash->base_flash.addr + sizeof (header), (uint8_t*) &components_header,
		sizeof (components_header));

	if (status != 0) {
		return status;
	}

	ids = platform_calloc (components_header.components_count, sizeof (uint32_t));

	if (ids == NULL) {
		return CFM_NO_MEMORY;
	}

	next_addr = cfm_flash->base_flash.addr + sizeof (header) + sizeof (components_header);

	for (i = 0; i < components_header.components_count; ++i, next_addr += component_header.length) {
		status = spi_flash_read (cfm_flash->base_flash.flash, next_addr,
			(uint8_t*) &component_header, sizeof (component_header));

		if (status != 0) {
			platform_free (ids);
			return status;
		}

		ids[i] = component_header.component_id;
	}

	id_list->ids = ids;
	id_list->count = components_header.components_count;

	return 0;
}

static void cfm_flash_free_component_ids (struct cfm *cfm, struct cfm_component_ids *id_list)
{
	if (id_list != NULL) {
		platform_free ((void*) id_list->ids);
	}
}

/**
 * Create a list of component FW signed images from CFM stored in flash
 *
 * @param cfm_flash The flash instance containing CFM.
 * @param addr Pointer to current CFM offset in flash, to be updated with offset post processing
 * @param fw The output buffer for the component signed images list.
 *
 * @return 0 if the processing completed successfully or an error code.
 */
static int cfm_flash_process_signed_img (struct manifest_flash *cfm_flash, uint32_t *addr,
	struct cfm_component_signed_img *img)
{
	uint8_t *digest = NULL;
	struct cfm_img_header img_header;
	int status;

	status = spi_flash_read (cfm_flash->flash, *addr, (uint8_t*) &img_header,
		sizeof (img_header));

	if (status != 0) {
		return status;
	}

	digest = platform_calloc (img_header.digest_length, sizeof (uint8_t));

	if (digest == NULL) {
		return CFM_NO_MEMORY;
	}

	*addr += sizeof (img_header);

	status = spi_flash_read (cfm_flash->flash, *addr, (uint8_t*) digest, img_header.digest_length);

	if (status != 0) {
		platform_free (digest);
		return status;
	}

	*addr += img_header.digest_length;

	img->failure_action = img_header.flags;
	img->digest_length = img_header.digest_length;
	img->digest = digest;

	return 0;
}

/**
 * Create a list of component FW from CFM stored in flash
 *
 * @param cfm_flash The flash instance containing CFM.
 * @param addr Pointer to current CFM offset in flash, to be updated with offset post processing
 * @param fw The output buffer for the component FW list.
 *
 * @return 0 if the processing completed successfully or an error code.
 */
static int cfm_flash_process_fw (struct manifest_flash *cfm_flash, uint32_t *addr,
	struct cfm_component_firmware *fw)
{
	struct cfm_fw_header fw_header;
	struct cfm_component_signed_img *imgs = NULL;
	char *fw_version_id = NULL;
	uint8_t alignment_len;
	int i_img;
	int status;

	status = spi_flash_read (cfm_flash->flash, *addr, (uint8_t*) &fw_header, sizeof (fw_header));

	if (status != 0) {
		return status;
	}

	fw_version_id = platform_calloc (fw_header.version_length + 1, sizeof (char));

	if (fw_version_id == NULL) {
		status = CFM_NO_MEMORY;
		goto cleanup;
	}

	imgs = platform_calloc (fw_header.img_count, sizeof (struct cfm_component_signed_img));

	if (imgs == NULL) {
		status = CFM_NO_MEMORY;
		goto cleanup;
	}

	*addr += sizeof (fw_header);

	status = spi_flash_read (cfm_flash->flash, *addr, (uint8_t*) fw_version_id,
		fw_header.version_length);

	if (status != 0) {
		goto cleanup;
	}

	fw_version_id[fw_header.version_length] = '\0';

	alignment_len = fw_header.version_length  % 4;
    alignment_len = (alignment_len == 0) ? 0 : (4 - alignment_len);

	*addr += fw_header.version_length + alignment_len;

	for (i_img = 0; i_img < fw_header.img_count; ++i_img) {
		status = cfm_flash_process_signed_img (cfm_flash, addr, &imgs[i_img]);

		if (status != 0) {
			goto cleanup;
		}
	}

	fw->version_length = fw_header.version_length;
	fw->fw_version_id = fw_version_id;
	fw->img_count = fw_header.img_count;
	fw->imgs = imgs;

	return 0;

cleanup:
	platform_free (fw_version_id);
	platform_free (imgs);

	return status;
}

static int cfm_flash_get_component (struct cfm *cfm, uint32_t component_id,
	struct cfm_component *component)
{
	struct cfm_flash *cfm_flash = (struct cfm_flash*) cfm;
	struct manifest_header manifest_header;
	struct cfm_components_header components_header;
	struct cfm_component_header component_header;
	struct cfm_component_firmware *fw = NULL;
	uint32_t addr;
	int i_component, i_fw, i_fw_free, i_img_free;
	int status;

	if ((cfm_flash == NULL) || (component == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	memset (component, 0, sizeof (struct cfm_component));

	addr = cfm_flash->base_flash.addr;

	status = spi_flash_read (cfm_flash->base_flash.flash, addr, (uint8_t*) &manifest_header,
		sizeof (manifest_header));
	if (status != 0) {
		return status;
	}

	if (manifest_header.magic != CFM_MAGIC_NUM) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	addr += sizeof (manifest_header);

	status = spi_flash_read (cfm_flash->base_flash.flash, addr, (uint8_t*) &components_header,
		sizeof (components_header));
	if (status != 0) {
		return status;
	}

	addr += sizeof (components_header);

	for (i_component = 0; i_component < components_header.components_count; ++i_component) {
		status = spi_flash_read (cfm_flash->base_flash.flash, addr, (uint8_t*) &component_header,
			sizeof (component_header));
		if (status != 0) {
			return status;
		}

		if (component_header.component_id == component_id) {
			fw = platform_calloc (component_header.fw_count,
				sizeof (struct cfm_component_firmware));
			if (fw == NULL) {
				return CFM_NO_MEMORY;
			}

			addr += sizeof (sizeof (struct cfm_component_header));

			for (i_fw = 0; i_fw < component_header.fw_count; ++i_fw) {
				status = cfm_flash_process_fw (&cfm_flash->base_flash, &addr, &fw[i_fw]);

				if (status != 0) {
					for (i_fw_free = 0; i_fw_free < i_fw; ++i_fw_free) {
						platform_free ((void*) fw[i_fw_free].fw_version_id);

						if (fw[i_fw_free].imgs != NULL) {
							for (i_img_free = 0; i_img_free < fw[i_fw_free].img_count;
								++i_img_free) {
								platform_free ((void*) fw[i_fw_free].imgs[i_img_free].digest);
							}

							platform_free (fw[i_fw_free].imgs);
						}
					}

					platform_free (fw);
					return status;
				}
			}

			component->component_id = component_header.component_id;
			component->fw = fw;
			component->fw_count = component_header.fw_count;

			return 0;
		}
		else {
			addr += component_header.length;
		}
	}

	return CFM_UNKNOWN_COMPONENT;
}

static void cfm_flash_free_component (struct cfm *cfm, struct cfm_component *component)
{
	int i_fw, i_img;

	if ((component != NULL) && component->fw != NULL) {
		for (i_fw = 0; i_fw < component->fw_count; ++i_fw) {
			platform_free ((void*) component->fw[i_fw].fw_version_id);

			if (component->fw[i_fw].imgs != NULL) {
				for (i_img = 0; i_img < component->fw[i_fw].img_count; ++i_img) {
					platform_free ((void*) component->fw[i_fw].imgs[i_img].digest);
				}

				platform_free (component->fw[i_fw].imgs);
			}
		}

		platform_free (component->fw);
	}
}

/**
 * Initialize the interface to a CFM residing in flash memory.
 *
 * @param cfm The CFM instance to initialize.
 * @param flash The flash device that contains the CFM.
 * @param base_addr The starting address of the CFM storage location.
 *
 * @return 0 if the CFM instance was initialized successfully or an error code.
 */
int cfm_flash_init (struct cfm_flash *cfm, struct spi_flash *flash, uint32_t base_addr)
{
	int status;

	if ((cfm == NULL) || (flash == NULL)) {
		return CFM_INVALID_ARGUMENT;
	}

	memset (cfm, 0, sizeof (struct cfm_flash));

	status = manifest_flash_init (&cfm->base_flash, flash, base_addr, CFM_MAGIC_NUM);
	if (status != 0) {
		return status;
	}

	cfm->base.base.verify = cfm_flash_verify;
	cfm->base.base.get_id = cfm_flash_get_id;
	cfm->base.base.get_platform_id = cfm_flash_get_platform_id;
	cfm->base.base.get_hash = cfm_flash_get_hash;
	cfm->base.base.get_signature = cfm_flash_get_signature;

	cfm->base.get_supported_component_ids = cfm_flash_get_supported_component_ids;
	cfm->base.free_component_ids = cfm_flash_free_component_ids;
	cfm->base.get_component = cfm_flash_get_component;
	cfm->base.free_component = cfm_flash_free_component;

	return 0;
}

/**
 * Release the resources used by the CFM interface.
 *
 * @param cfm The CFM instance to release.
 */
void cfm_flash_release (struct cfm_flash *cfm)
{

}

/**
 * Get the starting flash address of the CFM.
 *
 * @param cfm The CFM to query.
 *
 * @return The CFM flash address.
 */
uint32_t cfm_flash_get_addr (struct cfm_flash *cfm)
{
	if (cfm) {
		return cfm->base_flash.addr;
	}
	else {
		return 0;
	}
}

/**
 * Get the flash device that is used to store the CFM.
 *
 * @param cfm The CFM to query.
 *
 * @return The flash device for the CFM.
 */
struct spi_flash* cfm_flash_get_flash (struct cfm_flash *cfm)
{
	if (cfm) {
		return cfm->base_flash.flash;
	}
	else {
		return NULL;
	}
}
