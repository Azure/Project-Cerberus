// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "manifest_flash.h"
#include "manifest.h"
#include "flash/flash_util.h"
#include "flash/flash_common.h"
#include "crypto/ecc.h"


/**
 * Initialize the common handling for manifests store on flash.
 *
 * @param manifest The manifest to initialize.
 * @param flash The flash device that contains the manifest.
 * @param base_addr The starting address in flash of the manifest.
 * @param magic_num The magic number that identifies the manifest.
 *
 * @return 0 if the manifest was initialized successfully or an error code.
 */
int manifest_flash_init (struct manifest_flash *manifest, struct spi_flash *flash,
	uint32_t base_addr, uint16_t magic_num)
{
	if (FLASH_BLOCK_OFFSET (base_addr) != 0) {
		return MANIFEST_STORAGE_NOT_ALIGNED;
	}

	manifest->flash = flash;
	manifest->addr = base_addr;
	manifest->magic_num = magic_num;
	manifest->cache_valid = false;

	return 0;
}

/**
 * Read the manifest header and run validity checking on the contents:
 * - Check the magic number.
 * - Verify that signature length is valid relative to the total length.
 *
 * @param manifest The manifest for the header to read.
 * @param header Output for the header data.
 *
 * @return 0 if the header was successfully read and checked or an error code.
 */
int manifest_flash_read_header (struct manifest_flash *manifest, struct manifest_header *header)
{
	int status;

	if ((manifest == NULL) || (header == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	status = spi_flash_read (manifest->flash, manifest->addr, (uint8_t*) header, sizeof (*header));
	if (status != 0) {
		return status;
	}

	if (header->magic != manifest->magic_num) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	if (header->sig_length > (header->length - sizeof (struct manifest_header))) {
		return MANIFEST_BAD_LENGTH;
	}

	return 0;
}

/**
 * Verify if the manifest is valid.
 *
 * @param manifest The manifest that will be verified.
 * @param hash The hash engine to use for validation.
 * @param verification The module to use for signature verification.
 * @param hash_out Optional buffer to hold the manifest hash calculated during verification.  The
 * hash output will be valid even if the signature verification fails.  This can be set to null to
 * not save the hash value.
 * @param hash_length Length of hash output buffer.
 *
 * @return 0 if the manifest is valid or an error code.
 */
int manifest_flash_verify (struct manifest_flash *manifest, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct manifest_header header;
	uint8_t *signature;
	int status;

	if ((manifest == NULL) || (hash == NULL) || (verification == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_length < SHA256_HASH_LENGTH)) {
		return MANIFEST_HASH_BUFFER_TOO_SMALL;
	}

	manifest->cache_valid = false;

	status = manifest_flash_read_header (manifest, &header);
	if (status != 0) {
		return status;
	}

	signature = platform_malloc (header.sig_length);
	if (signature == NULL) {
		return MANIFEST_NO_MEMORY;
	}

	status = spi_flash_read (manifest->flash, manifest->addr + header.length - header.sig_length,
		signature, header.sig_length);
	if (status != 0) {
		goto exit;
	}

	status = flash_contents_verification (&manifest->flash->base, manifest->addr,
		header.length - header.sig_length, hash, HASH_TYPE_SHA256, verification, signature,
		header.sig_length, manifest->hash_cache, sizeof (manifest->hash_cache));

	if ((status == 0) || (status == RSA_ENGINE_BAD_SIGNATURE) ||
		(status == ECC_ENGINE_BAD_SIGNATURE)) {
		manifest->cache_valid = true;
		if (hash_out) {
			memcpy (hash_out, manifest->hash_cache, SHA256_HASH_LENGTH);
		}
	}

exit:
	platform_free (signature);
	return status;
}

/**
 * Get the ID of the manifest.
 *
 * @param manifest The manifest to query.
 * @param id The buffer to hold the manifest ID.
 *
 * @return 0 if the ID was successfully retrieved or an error code.
 */
int manifest_flash_get_id (struct manifest_flash *manifest, uint32_t *id)
{
	struct manifest_header header;
	int status;

	if ((manifest == NULL) || (id == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	status = spi_flash_read (manifest->flash, manifest->addr, (uint8_t*) &header, sizeof (header));

	if (status == 0) {
		if (header.magic == manifest->magic_num) {
			*id = header.id;
		}
		else {
			status = MANIFEST_BAD_MAGIC_NUMBER;
		}
	}

	return status;
}

/**
 * Get the hash for the manifest.  The hash will be the hash last calculated for manifest
 * verification.  If no verification has been previously performed or there was an error during the
 * last verification, the hash will be calculated from flash.
 *
 * @param manifest The manifest to hash.
 * @param hash The hash engine to use to calculate the hash.
 * @param hash_out Output buffer for the manifest hash.
 * @param hash_length Length of the hash output buffer.
 *
 * @return 0 if the hash was successfully retrieved or an error code.
 */
int manifest_flash_get_hash (struct manifest_flash *manifest, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct manifest_header header;
	int status;

	if ((manifest == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return MANIFEST_HASH_BUFFER_TOO_SMALL;
	}

	if (manifest->cache_valid) {
		memcpy (hash_out, manifest->hash_cache, SHA256_HASH_LENGTH);
	}
	else {
		status = manifest_flash_read_header (manifest, &header);
		if (status != 0) {
			return status;
		}

		status = flash_hash_contents (&manifest->flash->base, manifest->addr,
			header.length - header.sig_length, hash, HASH_TYPE_SHA256, hash_out, hash_length);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Get the signature for the manifest.
 *
 * @param manifest The manifest to query.
 * @param signature Output buffer for the manifest signature.
 * @param length Length of the signature output buffer.
 *
 * @return 0 if the signature was successfully retrieved or an error code.
 */
int manifest_flash_get_signature (struct manifest_flash *manifest, uint8_t *signature,
	size_t length)
{
	struct manifest_header header;
	int status;

	if ((manifest == NULL) || (signature == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	status = manifest_flash_read_header (manifest, &header);
	if (status != 0) {
		return status;
	}

	if (length < header.sig_length) {
		return MANIFEST_SIG_BUFFER_TOO_SMALL;
	}

	status = spi_flash_read (manifest->flash, manifest->addr + header.length - header.sig_length,
		signature, header.sig_length);
	if (status != 0) {
		return status;
	}

	return header.sig_length;
}
