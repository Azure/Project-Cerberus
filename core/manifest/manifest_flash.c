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
#include "crypto/rsa.h"
#include "common/common_math.h"


/**
 * Initialize the common handling for manifests stored on flash.  Only version 1 style manifests
 * will be supported.
 *
 * @param manifest The manifest to initialize.
 * @param flash The flash device that contains the manifest.
 * @param base_addr The starting address in flash of the manifest.
 * @param magic_num The magic number that identifies the manifest.
 *
 * @return 0 if the manifest was initialized successfully or an error code.
 */
int manifest_flash_init (struct manifest_flash *manifest, struct flash *flash, uint32_t base_addr,
	uint16_t magic_num)
{
	return manifest_flash_v2_init (manifest, flash, NULL, base_addr, magic_num,
		MANIFEST_NOT_SUPPORTED, NULL, 0, NULL, 0);
}

/**
 * Initialize the common handling for manifests stored on flash.  Both version 1 and version 2 style
 * manifests will be supported.
 *
 * @param manifest The manifest to initialize.
 * @param flash The flash device that contains the manifest.
 * @param hash A hash engine to use for validating run-time access of manifest elements.
 * @param base_addr The starting address in flash of the manifest.
 * @param magic_num_v1 The magic number that identifies version 1 of the manifest.
 * @param magic_num_v2 The magic number that identifies version 2 of the manifest.
 * @param signature_cache Buffer to hold the manifest signature.
 * @param max_signature The maximum supported length for a manifest signature.
 * @param platform_id_cache Buffer to hold the manifest platform ID.
 * @param max_platform_id The maximum platform ID length supported, including the NULL terminator.
 *
 * @return 0 if the manifest was initialized successfully or an error code.
 */
int manifest_flash_v2_init (struct manifest_flash *manifest, struct flash *flash,
	struct hash_engine *hash, uint32_t base_addr, uint16_t magic_num_v1, uint16_t magic_num_v2,
	uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id)
{
	uint32_t block;
	int status;

	if ((manifest == NULL) || (flash == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if ((magic_num_v2 != MANIFEST_NOT_SUPPORTED) &&
		((hash == NULL) || (platform_id_cache == NULL) || (signature_cache == NULL))) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	status = flash->get_block_size (flash, &block);
	if (status != 0) {
		return status;
	}

	if (FLASH_REGION_OFFSET (base_addr, block) != 0) {
		return MANIFEST_STORAGE_NOT_ALIGNED;
	}

	memset (manifest, 0, sizeof (struct manifest_flash));

	if (signature_cache == NULL) {
		/* This can only be true if v2 manifests are not supported. */
		max_signature = RSA_KEY_LENGTH_2K;
		signature_cache = platform_malloc (max_signature);
		if (signature_cache == NULL) {
			return MANIFEST_NO_MEMORY;
		}

		manifest->free_signature = true;
	}

	manifest->flash = flash;
	manifest->hash = hash;
	manifest->addr = base_addr;
	manifest->magic_num_v1 = magic_num_v1;
	manifest->magic_num_v2 = magic_num_v2;
	manifest->signature = signature_cache;
	manifest->max_signature = max_signature;
	manifest->platform_id = (char*) platform_id_cache;
	manifest->max_platform_id = max_platform_id - 1;
	manifest->cache_valid = false;

	return 0;
}

/**
 * Release the common manifest components.
 *
 * @param manifest The manifest to release.
 */
void manifest_flash_release (struct manifest_flash *manifest)
{
	if (manifest && manifest->free_signature) {
		platform_free (manifest->signature);
	}
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

	status = manifest->flash->read (manifest->flash, manifest->addr, (uint8_t*) header,
		sizeof (*header));
	if (status != 0) {
		return status;
	}

	if ((header->magic == MANIFEST_NOT_SUPPORTED) ||
		((header->magic != manifest->magic_num_v1) && (header->magic != manifest->magic_num_v2))) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	if (header->sig_length > (header->length - sizeof (struct manifest_header))) {
		return MANIFEST_BAD_LENGTH;
	}

	return 0;
}

/**
 * Validate the signature on a version 1 manifest.
 *
 * @param manifest The manifest that will be verified.
 * @param hash The hash engine to use for validation.
 * @param verification The module to use for signature verification.
 * @param sig_hash The type of hash used to generate the signature.
 * @param hash_out Optional output buffer for the manifest hash.
 *
 * @return 0 if the manifest is valid or an error code.
 */
static int manifest_flash_verify_v1 (struct manifest_flash *manifest, struct hash_engine *hash,
	struct signature_verification *verification, enum hash_type sig_hash, uint8_t *hash_out)
{
	int status;

	status = flash_contents_verification (manifest->flash, manifest->addr,
		manifest->header.length - manifest->header.sig_length, hash, sig_hash, verification,
		manifest->signature, manifest->header.sig_length, manifest->hash_cache,
		sizeof (manifest->hash_cache));

	if ((status == 0) || (status == RSA_ENGINE_BAD_SIGNATURE) ||
		(status == ECC_ENGINE_BAD_SIGNATURE)) {
		manifest->cache_valid = true;
		if (hash_out) {
			memcpy (hash_out, manifest->hash_cache, manifest->hash_length);
		}
	}

	return status;
}

/**
 * Validate the signature on a version 2 manifest.
 *
 * @param manifest The manifest that will be verified.
 * @param hash The hash engine to use for validation.
 * @param verification The module to use for signature verification.
 * @param sig_hash The type of hash used to generate the signature.
 * @param hash_out Optional output buffer for the manifest hash.
 *
 * @return 0 if the manifest is valid or an error code.
 */
static int manifest_flash_verify_v2 (struct manifest_flash *manifest, struct hash_engine *hash,
	struct signature_verification *verification, enum hash_type sig_hash, uint8_t *hash_out)
{
	struct manifest_toc_entry entry;
	struct manifest_platform_id plat_id_header;
	uint32_t next_addr;
	uint32_t toc_end;
	uint32_t sig_addr = manifest->addr + manifest->header.length - manifest->header.sig_length;
	int i;
	int status;

	/* Hash the header data that has already been read in. */
	status = hash_start_new_hash (hash, sig_hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, (uint8_t*) &manifest->header, sizeof (manifest->header));
	if (status != 0) {
		goto error;
	}

	/* Read and hash the table of contents header. */
	next_addr = manifest->addr + sizeof (manifest->header);
	status = manifest->flash->read (manifest->flash, next_addr, (uint8_t*) &manifest->toc_header,
		sizeof (manifest->toc_header));
	if (status != 0) {
		goto error;
	}

	switch (manifest->toc_header.hash_type) {
		case MANIFEST_HASH_SHA256:
			manifest->toc_hash_type = HASH_TYPE_SHA256;
			manifest->toc_hash_length = SHA256_HASH_LENGTH;
			break;

		case MANIFEST_HASH_SHA384:
			manifest->toc_hash_type = HASH_TYPE_SHA384;
			manifest->toc_hash_length = SHA384_HASH_LENGTH;
			break;

		case MANIFEST_HASH_SHA512:
			manifest->toc_hash_type = HASH_TYPE_SHA512;
			manifest->toc_hash_length = SHA512_HASH_LENGTH;
			break;

		default:
			status = MANIFEST_TOC_UNKNOWN_HASH_TYPE;
			goto error;
	}

	status = hash->update (hash, (uint8_t*) &manifest->toc_header, sizeof (manifest->toc_header));
	if (status != 0) {
		goto error;
	}

	/* Find the platform ID element, hashing each entry as it is read in. */
	next_addr += sizeof (manifest->toc_header);
	i = 0;
	do {
		status = manifest->flash->read (manifest->flash, next_addr, (uint8_t*) &entry,
			sizeof (entry));
		if (status != 0) {
			goto error;
		}

		status = hash->update (hash, (uint8_t*) &entry, sizeof (entry));
		if (status != 0) {
			goto error;
		}

		next_addr += sizeof (entry);
		i++;
	} while ((entry.type_id != MANIFEST_PLATFORM_ID) && (i < manifest->toc_header.entry_count));

	if (entry.type_id != MANIFEST_PLATFORM_ID) {
		status = MANIFEST_NO_PLATFORM_ID;
		goto error;
	}

	/* Hash the flash contents for the rest of the table of contents. */
	toc_end = manifest->addr + sizeof (manifest->header) + sizeof (manifest->toc_header) +
		(manifest->toc_header.entry_count * sizeof (entry)) +
		(manifest->toc_header.hash_count * manifest->toc_hash_length);
	status = flash_hash_update_contents (manifest->flash, next_addr, toc_end - next_addr, hash);
	if (status != 0) {
		goto error;
	}

	/* Read and hash the table of contents hash. */
	next_addr = toc_end;
	status = manifest->flash->read (manifest->flash, next_addr, manifest->toc_hash,
		manifest->toc_hash_length);
	if (status != 0) {
		goto error;
	}

	status = hash->update (hash, manifest->toc_hash, manifest->toc_hash_length);
	if (status != 0) {
		goto error;
	}

	/* Hash the flash contents until the platform ID element. */
	next_addr += manifest->toc_hash_length;
	status = flash_hash_update_contents (manifest->flash, next_addr,
		manifest->addr + entry.offset - next_addr, hash);
	if (status != 0) {
		goto error;
	}

	/* Read and hash the platform ID element header. */
	next_addr = manifest->addr + entry.offset;
	status = manifest->flash->read (manifest->flash, next_addr, (uint8_t*) &plat_id_header,
		sizeof (plat_id_header));
	if (status != 0) {
		goto error;
	}

	if (plat_id_header.id_length > manifest->max_platform_id) {
		status = MANIFEST_PLAT_ID_BUFFER_TOO_SMALL;
		goto error;
	}

	status = hash->update (hash, (uint8_t*) &plat_id_header, sizeof (plat_id_header));
	if (status != 0) {
		goto error;
	}

	/* Read and hash the platform ID string. */
	next_addr += sizeof (plat_id_header);
	status = manifest->flash->read (manifest->flash, next_addr, (uint8_t*) manifest->platform_id,
		plat_id_header.id_length);
	if (status != 0) {
		goto error;
	}

	manifest->platform_id[plat_id_header.id_length] = '\0';
	status = hash->update (hash, (uint8_t*) manifest->platform_id, plat_id_header.id_length);
	if (status != 0) {
		goto error;
	}

	/* Hash the remaining manifest flash contents. */
	next_addr += plat_id_header.id_length;
	status = flash_hash_update_contents (manifest->flash, next_addr, sig_addr - next_addr, hash);
	if (status != 0) {
		goto error;
	}

	/* Verify the signature of the overall manifest data. */
	status = hash->finish (hash, manifest->hash_cache, sizeof (manifest->hash_cache));
	if (status != 0) {
		goto error;
	}

	manifest->cache_valid = true;
	if (hash_out) {
		memcpy (hash_out, manifest->hash_cache, manifest->hash_length);
	}

	return verification->verify_signature (verification, manifest->hash_cache,
		manifest->hash_length, manifest->signature, manifest->header.sig_length);

error:
	hash->cancel (hash);
	return status;
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
	enum hash_type sig_hash;
	int status;

	if ((manifest == NULL) || (hash == NULL) || (verification == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_length < SHA256_HASH_LENGTH)) {
		return MANIFEST_HASH_BUFFER_TOO_SMALL;
	}

	manifest->manifest_valid = false;
	manifest->cache_valid = false;
	if (hash_out != NULL) {
		/* Clear the output hash buffer to indicate no hash was calculated. */
		memset (hash_out, 0, hash_length);
	}

	status = manifest_flash_read_header (manifest, &manifest->header);
	if (status != 0) {
		return status;
	}

	if (manifest->header.sig_length > manifest->max_signature) {
		return MANIFEST_SIG_BUFFER_TOO_SMALL;
	}

	switch (manifest_get_hash_type (manifest->header.sig_type)) {
		case MANIFEST_HASH_SHA256:
			sig_hash = HASH_TYPE_SHA256;
			manifest->hash_length = SHA256_HASH_LENGTH;
			break;

		case MANIFEST_HASH_SHA384:
			sig_hash = HASH_TYPE_SHA384;
			manifest->hash_length = SHA384_HASH_LENGTH;
			break;

		case MANIFEST_HASH_SHA512:
			sig_hash = HASH_TYPE_SHA512;
			manifest->hash_length = SHA512_HASH_LENGTH;
			break;

		default:
			return MANIFEST_SIG_UNKNOWN_HASH_TYPE;
	}

	if (hash_out != NULL) {
		if (hash_length < manifest->hash_length) {
			return MANIFEST_HASH_BUFFER_TOO_SMALL;
		}
	}

	status = manifest->flash->read (manifest->flash,
		manifest->addr + manifest->header.length - manifest->header.sig_length, manifest->signature,
		manifest->header.sig_length);
	if (status != 0) {
		return status;
	}

	if (manifest->header.magic == manifest->magic_num_v1) {
		status = manifest_flash_verify_v1 (manifest, hash, verification, sig_hash, hash_out);
	}
	else {
		status = manifest_flash_verify_v2 (manifest, hash, verification, sig_hash, hash_out);
	}

	if (status == 0) {
		manifest->manifest_valid = true;
	}
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
	int status = 0;

	if ((manifest == NULL) || (id == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (manifest->manifest_valid) {
		*id = manifest->header.id;
	}
	else {
		status = MANIFEST_NO_MANIFEST;
	}

	return status;
}

/**
 * Get the platform identifier from the manifest.
 *
 * @param manifest The manifest to query.
 * @param id Pointer to the output buffer for the platform identifier.  The buffer pointer
 * cannot be null, but if the buffer itself is null, the output will directly reference the internal
 * static buffer holding the platform identifier.
 * @param length Length of the output buffer if the buffer is static (i.e. not null).  This argument
 * is ignored when using dynamic allocation.
 *
 * @return 0 if the platform ID was retrieved successfully or an error code.
 */
int manifest_flash_get_platform_id (struct manifest_flash *manifest, char **id, size_t length)
{
	if ((manifest == NULL) || (id == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (*id != NULL) {
		strncpy (*id, manifest->platform_id, length);
		if ((*id)[length - 1] != '\0') {
			return MANIFEST_PLAT_ID_BUFFER_TOO_SMALL;
		}
	}
	else {
		*id = manifest->platform_id;
	}

	return 0;
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
 * @return Length of the hash if it was calculated successfully or an error code.  Use
 * ROT_IS_ERROR to check the return value.
 */
int manifest_flash_get_hash (struct manifest_flash *manifest, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct manifest_header header;
	enum hash_type sig_hash;
	int status;

	if ((manifest == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return MANIFEST_HASH_BUFFER_TOO_SMALL;
	}

	if (manifest->cache_valid) {
		if (hash_length < manifest->hash_length) {
			return MANIFEST_HASH_BUFFER_TOO_SMALL;
		}

		memcpy (hash_out, manifest->hash_cache, manifest->hash_length);
	}
	else {
		status = manifest_flash_read_header (manifest, &header);
		if (status != 0) {
			return status;
		}

		switch (manifest_get_hash_type (header.sig_type)) {
			case MANIFEST_HASH_SHA256:
				sig_hash = HASH_TYPE_SHA256;
				manifest->hash_length = SHA256_HASH_LENGTH;
				break;

			case MANIFEST_HASH_SHA384:
				sig_hash = HASH_TYPE_SHA384;
				manifest->hash_length = SHA384_HASH_LENGTH;
				break;

			case MANIFEST_HASH_SHA512:
				sig_hash = HASH_TYPE_SHA512;
				manifest->hash_length = SHA512_HASH_LENGTH;
				break;

			default:
				return MANIFEST_SIG_UNKNOWN_HASH_TYPE;
		}

		if (hash_length < manifest->hash_length) {
			return MANIFEST_HASH_BUFFER_TOO_SMALL;
		}

		status = flash_hash_contents (manifest->flash, manifest->addr,
			header.length - header.sig_length, hash, sig_hash, hash_out, hash_length);
		if (status != 0) {
			return status;
		}
	}

	return manifest->hash_length;
}

/**
 * Get the signature for the manifest.
 *
 * @param manifest The manifest to query.
 * @param signature Output buffer for the manifest signature.
 * @param length Length of the signature output buffer.
 *
 * @return Length of the signature if it was successfully retrieved or an error code.  Use
 * ROT_IS_ERROR to check the return value.
 */
int manifest_flash_get_signature (struct manifest_flash *manifest, uint8_t *signature,
	size_t length)
{
	if ((manifest == NULL) || (signature == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (manifest->manifest_valid) {
		if (length < manifest->header.sig_length) {
			return MANIFEST_SIG_BUFFER_TOO_SMALL;
		}

		memcpy (signature, manifest->signature, manifest->header.sig_length);
		return manifest->header.sig_length;
	}
	else {
		struct manifest_header header;
		int status;

		status = manifest_flash_read_header (manifest, &header);
		if (status != 0) {
			return status;
		}

		if (length < header.sig_length) {
			return MANIFEST_SIG_BUFFER_TOO_SMALL;
		}

		status = manifest->flash->read (manifest->flash,
			manifest->addr + header.length - header.sig_length, signature, header.sig_length);
		if (status != 0) {
			return status;
		}

		return header.sig_length;
	}
}

/**
 * Find the first element of a specified type in the manifest and read the element data.
 * Everything about the operation will be validated, as appropriate.  This includes table of
 * contents and entry data hashing.
 *
 * @param manifest The manifest to read.
 * @param hash The hash engine to use for element validation.
 * @param type Identifier for the type of element to find.
 * @param start Index of the table of contents entry to start searching for the element.
 * @param parent_type Identifier for the type of the parent element.  If the element has no parent,
 * MANIFEST_NO_PARENT must be provided.
 * @param read_offset Offset into the element data to start reading.  The entire element is still
 * validated, but the buffer will only contain element data starting starting at the offset.
 * @param found Optional output indicating which TOC entry was used for the element.
 * @param format Optional output for the format version of the element data.
 * @param total_len Optional output for the total length of the element data.
 * @param element Optional pointer to the output buffer for the element data.  If the output buffer
 * is null, a buffer will by dynamically allocated to fit the entire element.  This buffer must be
 * freed by the caller.  If the pointer is null, no element data will be read.
 * @param length Length of the element output buffer, if the buffer is not null.  If the actual
 * element data is longer than the specified length, only the specified length will be read back and
 * no error is generated.  This parameter is ignored when the output buffer is dynamically
 * allocated.
 *
 * @return The amount of element data read or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int manifest_flash_read_element_data (struct manifest_flash *manifest, struct hash_engine *hash,
	uint8_t type, int start, uint8_t parent_type, uint32_t read_offset, uint8_t *found,
	uint8_t *format, size_t *total_len, uint8_t **element, size_t length)
{
	struct manifest_toc_entry entry;
	uint8_t entry_hash[SHA512_HASH_LENGTH];
	uint8_t validate_hash[SHA512_HASH_LENGTH];
	uint32_t entry_addr;
	uint32_t hash_addr;
	uint32_t toc_end;
	int i;
	int status;

	if ((manifest == NULL) || (hash == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (start >= manifest->toc_header.entry_count) {
		return (parent_type == MANIFEST_NO_PARENT) ?
			MANIFEST_ELEMENT_NOT_FOUND : MANIFEST_CHILD_NOT_FOUND;
	}

	entry_addr =
		manifest->addr + sizeof (struct manifest_header) + sizeof (struct manifest_toc_header);
	hash_addr = entry_addr + (sizeof (entry) * manifest->toc_header.entry_count);
	toc_end = hash_addr + (manifest->toc_hash_length * manifest->toc_header.hash_count);

	/* Start hashing to verify the TOC contents. */
	status = hash_start_new_hash (hash, manifest->toc_hash_type);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, (uint8_t*) &manifest->toc_header, sizeof (manifest->toc_header));
	if (status != 0) {
		goto error;
	}

	/* Hash the TOC data before the first entry that will be read. */
	status = flash_hash_update_contents (manifest->flash, entry_addr, sizeof (entry) * start, hash);
	if (status != 0) {
		goto error;
	}

	/* Find the TOC entry for the requested element. */
	entry_addr += sizeof (entry) * start;
	i = start;
	do {
		status = manifest->flash->read (manifest->flash, entry_addr, (uint8_t*) &entry,
			sizeof (entry));
		if (status != 0) {
			goto error;
		}

		/* As soon as we see an element that is not a child, we fail because we have left the
		 * context of the expected parent. */
		if ((parent_type != MANIFEST_NO_PARENT) && (entry.parent == MANIFEST_NO_PARENT)) {
			status = MANIFEST_CHILD_NOT_FOUND;
			goto error;
		}

		status = hash->update (hash, (uint8_t*) &entry, sizeof (entry));
		if (status != 0) {
			goto error;
		}

		i++;
		entry_addr += sizeof (entry);
	} while ((entry.type_id != type) && (i < manifest->toc_header.entry_count));

	if (entry.type_id != type) {
		status = (parent_type == MANIFEST_NO_PARENT) ?
			MANIFEST_ELEMENT_NOT_FOUND : MANIFEST_CHILD_NOT_FOUND;
		goto error;
	}

	if (entry.hash_id < manifest->toc_header.hash_count) {
		/* Find the address of the entry hash. */
		hash_addr += (manifest->toc_hash_length * entry.hash_id);

		/* Hash the unneeded TOC data until the entry hash. */
		status = flash_hash_update_contents (manifest->flash, entry_addr, hash_addr - entry_addr,
			hash);
		if (status != 0) {
			goto error;
		}

		/* Read the entry hash for element validation. */
		status = manifest->flash->read (manifest->flash, hash_addr, entry_hash,
			manifest->toc_hash_length);
		if (status != 0) {
			goto error;
		}

		status = hash->update (hash, entry_hash, manifest->toc_hash_length);
		if (status != 0) {
			goto error;
		}

		/* Hash the remaining TOC data. */
		hash_addr += manifest->toc_hash_length;
		status = flash_hash_update_contents (manifest->flash, hash_addr, toc_end - hash_addr, hash);
		if (status != 0) {
			goto error;
		}
	}
	else {
		status = flash_hash_update_contents (manifest->flash, entry_addr, toc_end - entry_addr,
			hash);
		if (status != 0) {
			goto error;
		}
	}

	/*  Validate the TOC. */
	status = hash->finish (hash, validate_hash, sizeof (validate_hash));
	if (status != 0) {
		goto error;
	}

	if (memcmp (validate_hash, manifest->toc_hash, manifest->toc_hash_length) != 0) {
		return MANIFEST_TOC_INVALID;
	}

	/* Read the element data. */
	if ((entry.parent != MANIFEST_NO_PARENT) && (entry.parent != parent_type)) {
		return MANIFEST_WRONG_PARENT;
	}

	if (found) {
		*found = i - 1;
	}
	if (format) {
		*format = entry.format;
	}
	if (total_len) {
		*total_len = entry.length;
	}
	if ((element == NULL) || (read_offset >= entry.length)) {
		length = 0;
	}
	else if (*element == NULL) {
		/* This value doesn't matter.  It's just set to pass the check for reading element data. */
		length = 1;
	}

	if (length != 0) {
		entry.length -= read_offset;
		if (*element == NULL) {
			*element = platform_malloc (entry.length);
			if (*element == NULL) {
				return MANIFEST_NO_MEMORY;
			}

			length = entry.length;
		}

		if (entry.hash_id < manifest->toc_header.hash_count) {
			/* Hash the element data to validate the contents. */
			status = hash_start_new_hash (hash, manifest->toc_hash_type);
			if (status != 0) {
				return status;
			}

			status = flash_hash_update_contents (manifest->flash, manifest->addr + entry.offset,
				read_offset, hash);
			if (status != 0) {
				goto error;
			}
		}

		entry.offset += read_offset;
		length = min (length, entry.length);
		status = manifest->flash->read (manifest->flash, manifest->addr + entry.offset, *element,
			length);
		if (status != 0) {
			goto error;
		}

		if (entry.hash_id < manifest->toc_header.hash_count) {
			status = hash->update (hash, *element, length);
			if (status != 0) {
				goto error;
			}

			if (length < entry.length) {
				status = flash_hash_update_contents (manifest->flash,
					manifest->addr + entry.offset + length, entry.length - length, hash);
				if (status != 0) {
					goto error;
				}
			}

			status = hash->finish (hash, validate_hash, sizeof (validate_hash));
			if (status != 0) {
				goto error;
			}

			if (memcmp (validate_hash, entry_hash, manifest->toc_hash_length) != 0) {
				return MANIFEST_ELEMENT_INVALID;
			}
		}
	}

	return length;

error:
	hash->cancel (hash);
	return status;
}

/**
 * Find the number of direct child elements of specified type of requested element.  If element has
 * nested children, they are not counted.
 *
 * @param manifest The manifest to read.
 * @param hash The hash engine to use for element validation.
 * @param entry Starting table of contents entry to start processing.
 * @param type Type of requested parent element.
 * @param parent_type Type of parent to requested parent element.
 * @param child_type Type of child element to get count of.
 * @param child_len Optional output buffer with total length of child elements.
 *
 * @return The number of child elements found or an error code.  Use ROT_IS_ERROR to check the
 * return value.
 */
int manifest_flash_get_num_child_elements (struct manifest_flash *manifest,
	struct hash_engine *hash, int entry, uint8_t type, uint8_t parent_type, uint8_t child_type,
	size_t *child_len)
{
	uint8_t validate_hash[SHA512_HASH_LENGTH];
	struct manifest_toc_entry toc_entry;
	uint32_t entry_addr;
	uint32_t hash_addr;
	int child_count = 0;
	int status;

	if ((manifest == NULL) || (hash == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (child_len != NULL) {
		*child_len = 0;
	}

	if (entry >= manifest->toc_header.entry_count) {
		return 0;
	}

	entry_addr = manifest->addr + sizeof (struct manifest_header) +
		sizeof (struct manifest_toc_header);
	hash_addr = entry_addr + ((sizeof (struct manifest_toc_entry) + manifest->toc_hash_length) *
		manifest->toc_header.entry_count);

	/* Start hashing to verify the TOC contents. */
	status = hash_start_new_hash (hash, manifest->toc_hash_type);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, (uint8_t*) &manifest->toc_header,
		sizeof (struct manifest_toc_header));
	if (status != 0) {
		goto error;
	}

	/* Hash the TOC data before the first entry that will be read. */
	status = flash_hash_update_contents (manifest->flash, entry_addr,
		sizeof (struct manifest_toc_entry) * entry, hash);
	if (status != 0) {
		goto error;
	}

	entry_addr += (sizeof (struct manifest_toc_entry) * entry);

	for (; entry < manifest->toc_header.entry_count;
		++entry, entry_addr += sizeof (struct manifest_toc_entry)) {
		status = manifest->flash->read (manifest->flash, entry_addr, (uint8_t*) &toc_entry,
			sizeof (struct manifest_toc_entry));
		if (status != 0) {
			goto error;
		}

		status = hash->update (hash, (uint8_t*) &toc_entry, sizeof (struct manifest_toc_entry));
		if (status != 0) {
			goto error;
		}

		if ((toc_entry.parent == parent_type) || (toc_entry.type_id == parent_type)) {
			entry_addr += sizeof (struct manifest_toc_entry);
			break;
		}
		if ((toc_entry.parent == type) && (toc_entry.type_id == child_type)) {
			++child_count;

			if (child_len != NULL) {
				*child_len = *child_len + toc_entry.length;
			}
		}
	}

	/* Hash the unneeded TOC data until the entry hash. */
	status = flash_hash_update_contents (manifest->flash, entry_addr, hash_addr - entry_addr, hash);
	if (status != 0) {
		goto error;
	}

	/*  Validate the TOC. */
	status = hash->finish (hash, validate_hash, sizeof (validate_hash));
	if (status != 0) {
		goto error;
	}

	if (memcmp (validate_hash, manifest->toc_hash, manifest->toc_hash_length) != 0) {
		return MANIFEST_TOC_INVALID;
	}

	return child_count;

error:
	hash->cancel (hash);

	return status;
}

/**
 * Get the starting flash address of the manifest.
 *
 * @param manifest The manifest to query.
 *
 * @return The manifest base flash address.
 */
uint32_t manifest_flash_get_addr (struct manifest_flash *manifest)
{
	if (manifest) {
		return manifest->addr;
	}
	else {
		return 0;
	}
}

/**
 * Get the flash device that is used to store the manifest.
 *
 * @param manifest The manifest to query.
 *
 * @return The flash device for the manifest.
 */
struct flash* manifest_flash_get_flash (struct manifest_flash *manifest)
{
	if (manifest) {
		return manifest->flash;
	}
	else {
		return NULL;
	}
}

/**
 * Compare the IDs of two manifests to check for a valid manifest ID.  If the first manifest is not
 * valid, the second will always report a higher ID as long as it is a valid manifest.  If the
 * second manifest is not valid, an error will be returned.
 *
 * @param manifest1 The first manifest for comparison.
 * @param manifest2 The second manifest for comparison.
 *
 * @return 0 if second manifest has a higher ID than the first, 1 if not, or an error code.
 */
int manifest_flash_compare_id (struct manifest_flash *manifest1, struct manifest_flash *manifest2)
{
	if (manifest2 == NULL) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest2->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}
	else if ((manifest1 == NULL) || !manifest1->manifest_valid) {
		return 0;
	}

	if (manifest1->header.id < manifest2->header.id) {
		return 0;
	}
	else {
		return 1;
	}
}

/**
 * Compare the platform IDs of two manifests.  If either manifest is invalid, an error will be
 * returned.
 *
 * @param manifest1 The active manifest for comparison.
 * @param manifest2 The pending manifest for comparison.
 * @param sku_upgrade_permitted Manifest permitted to upgrade from generic to SKU-specific.
 *
 * @return 0 if both manifests have the same platform ID, 1 if not, or an error code.
 */
int manifest_flash_compare_platform_id (struct manifest_flash *manifest1,
	struct manifest_flash *manifest2, bool sku_upgrade_permitted)
{
	if ((manifest1 == NULL) || (manifest2 == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest1->manifest_valid || !manifest2->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}
	
	if (sku_upgrade_permitted) {
		return (strncmp (manifest1->platform_id, manifest2->platform_id, 
			strlen (manifest1->platform_id)) != 0);
	}
	else {
		return (strcmp (manifest1->platform_id, manifest2->platform_id) != 0);
	}
}
