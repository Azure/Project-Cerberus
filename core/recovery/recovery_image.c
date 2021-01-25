// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "recovery_image.h"
#include "recovery_image_header.h"
#include "recovery_image_section_header.h"
#include "platform.h"
#include "flash/flash_util.h"
#include "crypto/ecc.h"
#include "cmd_interface/cerberus_protocol.h"


/**
 * Match the recovery image platform ID if there is an active PFM to ensure hardware compatibility.
 *
 * @param pfm The PFM manager to use for verification.
 * @param header The recovery image header data.
 *
 * @return 0 if the the platform IDs match or an error code.
 */
static int recovery_image_check_platform_id (struct pfm_manager *pfm,
	struct recovery_image_header *header)
{
	struct pfm *manifest;
	char *pfm_id= NULL;
	char *img_id;
	int status;

	manifest = pfm->get_active_pfm (pfm);
	if (manifest == NULL) {
		return 0;
	}

	status = manifest->base.get_platform_id (&manifest->base, &pfm_id, 0);
	if (status != 0) {
		goto err_free_pfm;
	}

	status = recovery_image_header_get_platform_id (header, &img_id);
	if (status != 0) {
		goto err_free_id;
	}

	if (strcmp (pfm_id, img_id) != 0) {
		status = RECOVERY_IMAGE_INCOMPATIBLE;
	}

err_free_id:
	manifest->base.free_platform_id (&manifest->base, pfm_id);
err_free_pfm:
	pfm->free_pfm (pfm, manifest);

	return status;
}

static int recovery_image_verify (struct recovery_image *image, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length,
	struct pfm_manager *pfm)
{
	uint8_t *signature;
	size_t img_len;
	size_t section_len;
	size_t sig_len;
	struct recovery_image_section_header section_header;
	int header_len;
	int rem_len;
	uint32_t next_addr;
	uint32_t host_addr;
	uint32_t min_host_addr = 0;
	struct recovery_image_header header;
	int status;

	if ((image == NULL) || (hash == NULL) || (verification == NULL) || (pfm == NULL)) {
		return RECOVERY_IMAGE_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_length < SHA256_HASH_LENGTH)) {
        return RECOVERY_IMAGE_HASH_BUFFER_TOO_SMALL;
	}

	image->cache_valid = false;

	status = recovery_image_header_init (&header, image->flash, image->addr);
	if (status != 0) {
		return status;
	}

	recovery_image_header_get_signature_length (&header, &sig_len);
	signature = platform_malloc (sig_len);
	if (signature == NULL) {
		status = RECOVERY_IMAGE_NO_MEMORY;
		goto free_header;
	}

	recovery_image_header_get_image_length (&header, &img_len);
	status = image->flash->read (image->flash,
		image->addr + img_len - sig_len, signature, sig_len);
	if (status != 0) {
		goto free_signature;
	}

	status = flash_contents_verification (image->flash, image->addr,
		img_len - sig_len, hash, HASH_TYPE_SHA256, verification, signature, sig_len,
		image->hash_cache, sizeof (image->hash_cache));

	if ((status == 0) || (status == RSA_ENGINE_BAD_SIGNATURE) ||
		(status == ECC_ENGINE_BAD_SIGNATURE)) {
		image->cache_valid = true;
		if (hash_out) {
			memcpy (hash_out, image->hash_cache, sizeof (image->hash_cache));
		}
	}

	if (status != 0) {
		goto free_signature;
	}

	status = recovery_image_check_platform_id (pfm, &header);
	if (status != 0) {
		goto free_signature;
	}

	/* Check the contents of the recovery image to make sure it makes sense. */
	header_len = image_header_get_length (&header.base);
	rem_len = img_len - header_len - sig_len;
	if (rem_len <= 0) {
		status = RECOVERY_IMAGE_MALFORMED;
		goto free_signature;
	}

	next_addr = image->addr + header_len;
	while (rem_len > 0) {
		status = recovery_image_section_header_init (&section_header, image->flash,
			next_addr);
		if (status != 0) {
			status = RECOVERY_IMAGE_MALFORMED;
			goto free_signature;
		}

		recovery_image_section_header_get_host_write_addr (&section_header, &host_addr);
		if (host_addr < min_host_addr) {
			status = RECOVERY_IMAGE_INVALID_SECTION_ADDRESS;
			recovery_image_section_header_release (&section_header);
			goto free_signature;
		}

		header_len = image_header_get_length (&section_header.base);
		recovery_image_section_header_get_section_image_length (&section_header, &section_len);
		recovery_image_section_header_release (&section_header);

		min_host_addr = host_addr + section_len;
		rem_len -= (header_len + section_len);
		next_addr += (header_len + section_len);
	}

	if (rem_len < 0) {
		status = RECOVERY_IMAGE_MALFORMED;
	}

free_signature:
	platform_free (signature);
free_header:
	recovery_image_header_release (&header);

	return status;
}

static int recovery_image_get_hash (struct recovery_image *image, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct recovery_image_header header;
	size_t image_len;
	size_t sig_len;
	int status;

	if ((image == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return RECOVERY_IMAGE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return RECOVERY_IMAGE_HASH_BUFFER_TOO_SMALL;
	}

	if (image->cache_valid) {
		memcpy (hash_out, image->hash_cache, SHA256_HASH_LENGTH);
	}
	else {
		status = recovery_image_header_init (&header, image->flash, image->addr);
		if (status != 0) {
			return status;
		}

		recovery_image_header_get_image_length (&header, &image_len);
		recovery_image_header_get_signature_length (&header, &sig_len);
		recovery_image_header_release (&header);

		status = flash_hash_contents (image->flash, image->addr,
			image_len - sig_len, hash, HASH_TYPE_SHA256, hash_out, hash_length);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

static int recovery_image_get_version (struct recovery_image *image, char *version, size_t len)
{
	struct recovery_image_header header;
	char *id;
	int status;

	if ((image == NULL) || (version == NULL)) {
		return RECOVERY_IMAGE_INVALID_ARGUMENT;
	}

	if (len < CERBERUS_PROTOCOL_FW_VERSION_LEN) {
		return RECOVERY_IMAGE_ID_BUFFER_TOO_SMALL;
	}

	status = recovery_image_header_init (&header, image->flash, image->addr);
	if (status != 0) {
		return status;
	}

	recovery_image_header_get_version_id (&header, &id);
	strncpy (version, id, CERBERUS_PROTOCOL_FW_VERSION_LEN);

	recovery_image_header_release (&header);

	return status;
}

static int recovery_image_apply_to_flash (struct recovery_image *image, struct spi_flash *flash)
{
	struct recovery_image_header header;
	struct recovery_image_section_header section_header;
	size_t image_len;
	size_t header_len;
	size_t sig_len;
	int rem_len;
	uint32_t next_img_addr;
	uint32_t host_addr;
	size_t section_hdr_len;
	size_t section_img_len;
	int status;

	if ((image == NULL) || (flash == NULL)) {
		return RECOVERY_IMAGE_INVALID_ARGUMENT;
	}

	status = recovery_image_header_init (&header, image->flash, image->addr);
	if (status != 0) {
		return status;
	}

	recovery_image_header_get_length (&header, &header_len);
	recovery_image_header_get_image_length (&header, &image_len);
	recovery_image_header_get_signature_length (&header, &sig_len);
	recovery_image_header_release (&header);

	rem_len = image_len - header_len - sig_len;
	next_img_addr = image->addr + header_len;

	while (rem_len > 0) {
		status = recovery_image_section_header_init (&section_header, image->flash, next_img_addr);
		if (status != 0) {
			return status;
		}

		recovery_image_section_header_get_host_write_addr (&section_header, &host_addr);
		recovery_image_section_header_get_length (&section_header, &section_hdr_len);
		recovery_image_section_header_get_section_image_length (&section_header, &section_img_len);
		recovery_image_section_header_release (&section_header);

		status = flash_copy_ext_to_blank_and_verify (&flash->base, host_addr, image->flash,
			next_img_addr + section_hdr_len, section_img_len);
		if (status != 0) {
			return status;
		}

		rem_len -= (section_hdr_len + section_img_len);
		next_img_addr += (section_hdr_len + section_img_len);
	}

	if (rem_len < 0) {
		status = RECOVERY_IMAGE_MALFORMED;
	}

	return status;
}

/**
 * Initialize the recovery image region.
 *
 * @param image The recovery image to initialize.
 * @param flash The flash device that contains the recovery image.
 * @param base_addr The starting address in flash of the recovery image.
 *
 * @return 0 if the recovery image was successfully initialized or an error code.
 */
int recovery_image_init (struct recovery_image *image, struct flash *flash, uint32_t base_addr)
{
	if ((image == NULL) || (flash == NULL)) {
		return RECOVERY_IMAGE_INVALID_ARGUMENT;
	}

	memset (image, 0, sizeof (struct recovery_image));

	image->verify = recovery_image_verify;
	image->get_hash = recovery_image_get_hash;
	image->get_version = recovery_image_get_version;
	image->apply_to_flash = recovery_image_apply_to_flash;

	image->flash = flash;
	image->addr = base_addr;

	return 0;
}

/**
 * Release the resources used by the recovery image.
 *
 * @param image The recovery image to release.
 */
void recovery_image_release (struct recovery_image *image)
{

}
