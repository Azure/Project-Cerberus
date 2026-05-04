// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "manifest.h"
#include "manifest_flash.h"
#include "platform_api.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "crypto/ecc.h"
#include "crypto/rsa.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/**
 * Initialize the common handling for manifests stored on flash.  Only version 1 style manifests
 * will be supported.
 *
 * @param manifest The manifest to initialize.
 * @param state Variable context for the manifest.  This must be uninitialized.
 * @param flash The flash device that contains the manifest.
 * @param base_addr The starting address in flash of the manifest.
 * @param magic_num The magic number that identifies the manifest.
 *
 * @return 0 if the manifest was initialized successfully or an error code.
 */
int manifest_flash_init (struct manifest_flash *manifest, struct manifest_flash_state *state,
	const struct flash *flash, uint32_t base_addr, uint16_t magic_num)
{
	return manifest_flash_v3_init (manifest, state, flash, NULL, base_addr, magic_num,
		MANIFEST_NOT_SUPPORTED, MANIFEST_NOT_SUPPORTED, NULL, 0, NULL, 0);
}

/**
 * Initialize the common handling for manifests stored on flash.  Both version 1 and version 2 style
 * manifests can be supported.
 *
 * @param manifest The manifest to initialize.
 * @param state Variable context for the manifest.  This must be uninitialized.
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
int manifest_flash_v2_init (struct manifest_flash *manifest, struct manifest_flash_state *state,
	const struct flash *flash, const struct hash_engine *hash, uint32_t base_addr,
	uint16_t magic_num_v1, uint16_t magic_num_v2, uint8_t *signature_cache, size_t max_signature,
	uint8_t *platform_id_cache, size_t max_platform_id)
{
	return manifest_flash_v3_init (manifest, state, flash, hash, base_addr, magic_num_v1,
		magic_num_v2, MANIFEST_NOT_SUPPORTED, signature_cache, max_signature, platform_id_cache,
		max_platform_id);
}

/**
 * Initialize the common handling for manifests stored on flash.  Version 1, version 2 and
 * version 3 manifests can be supported.
 *
 * @param manifest The manifest to initialize.
 * @param state Variable context for the manifest.  This must be uninitialized.
 * @param flash The flash device that contains the manifest.
 * @param hash A hash engine to use for validating run-time access of manifest elements.
 * @param base_addr The starting address in flash of the manifest.
 * @param magic_num_v1 The magic number that identifies version 1 of the manifest.
 * @param magic_num_v2 The magic number that identifies version 2 of the manifest.
 * @param magic_num_v2_ext The magic number that identifies version 2 of the manifest with extensions.
 * @param signature_cache Buffer to hold the manifest signature.
 * @param max_signature The maximum supported length for a manifest signature.
 * @param platform_id_cache Buffer to hold the manifest platform ID.
 * @param max_platform_id The maximum platform ID length supported, including the NULL terminator.
 *
 * @return 0 if the manifest was initialized successfully or an error code.
 */
int manifest_flash_v3_init (struct manifest_flash *manifest, struct manifest_flash_state *state,
	const struct flash *flash, const struct hash_engine *hash, uint32_t base_addr,
	uint16_t magic_num_v1, uint16_t magic_num_v2, uint16_t magic_num_v3, uint8_t *signature_cache,
	size_t max_signature, uint8_t *platform_id_cache, size_t max_platform_id)
{
	uint32_t block;
	int status;

	if ((manifest == NULL) || (state == NULL) || (flash == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (((magic_num_v2 != MANIFEST_NOT_SUPPORTED) ||
		(magic_num_v3 != MANIFEST_NOT_SUPPORTED)) &&
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

	manifest->state = state;
	manifest->flash = flash;
	manifest->hash = hash;
	manifest->addr = base_addr;
	manifest->magic_num_v1 = magic_num_v1;
	manifest->magic_num_v2 = magic_num_v2;
	manifest->magic_num_v3 = magic_num_v3;
	manifest->signature = signature_cache;
	manifest->max_signature = max_signature;
	manifest->platform_id = (char*) platform_id_cache;
	manifest->max_platform_id = max_platform_id - 1;

	memset (manifest->state, 0, sizeof (*manifest->state));

	return 0;
}

/**
 * Initialize only the variable state for a manifest on flash.  The rest of the handler is assumed
 * to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manifest The manifest that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_flash_init_state (const struct manifest_flash *manifest)
{
	uint32_t block;
	int status;

	if ((manifest == NULL) || (manifest->state == NULL) || (manifest->flash == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if ((manifest->magic_num_v2 != MANIFEST_NOT_SUPPORTED) &&
		((manifest->hash == NULL) || (manifest->platform_id == NULL) ||
		(manifest->signature == NULL))) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	memset (manifest->state, 0, sizeof (*manifest->state));

	status = manifest->flash->get_block_size (manifest->flash, &block);
	if (status != 0) {
		return status;
	}

	if (FLASH_REGION_OFFSET (manifest->addr, block) != 0) {
		return MANIFEST_STORAGE_NOT_ALIGNED;
	}

	return 0;
}

/**
 * Release the common manifest components.
 *
 * @param manifest The manifest to release.
 */
void manifest_flash_release (const struct manifest_flash *manifest)
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
int manifest_flash_read_header (const struct manifest_flash *manifest,
	struct manifest_header *header)
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
		((header->magic != manifest->magic_num_v1) &&
		(header->magic != manifest->magic_num_v2) &&
		(header->magic != manifest->magic_num_v3))) {
		return MANIFEST_BAD_MAGIC_NUMBER;
	}

	if ((header->length < sizeof (struct manifest_header)) ||
		(header->sig_length > (header->length - sizeof (struct manifest_header)))) {
		return MANIFEST_BAD_LENGTH;
	}

	return 0;
}

/**
 * Validate and parse the header on a manifest.
 *
 * @param manifest The manifest that will be verified.
 * @param hash The hash engine to use for validation.
 * @param verification The module to use for signature verification.
 * @param sig_hash Output for the type of hash used to generate the signature.
 * @param hash_out Optional buffer to hold the manifest hash calculated during verification.  The
 * hash output will be valid even if the signature verification fails.  This can be set to null to
 * not save the hash value.
 * @param hash_length Length of hash output buffer.
 *
 * @return 0 if the header was is valid or an error code.
 */
static int manifest_flash_parse_header (const struct manifest_flash *manifest,
	const struct hash_engine *hash, const struct signature_verification *verification,
	enum hash_type *sig_hash, uint8_t *hash_out, size_t hash_length)
{
	struct manifest_header *header;
	enum manifest_hash_type manifest_hash_type;
	int status;

	if ((manifest == NULL) || (hash == NULL) || (verification == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_length < SHA256_HASH_LENGTH)) {
		return MANIFEST_HASH_BUFFER_TOO_SMALL;
	}

	header = &manifest->state->header;
	manifest->state->manifest_valid = false;
	manifest->state->cache_valid = false;
	manifest->state->extensions_allowed = false;

	if (hash_out != NULL) {
		/* Clear the output hash buffer to indicate no hash was calculated. */
		memset (hash_out, 0, hash_length);
	}

	status = manifest_flash_read_header (manifest, header);
	if (status != 0) {
		return status;
	}

	if (header->sig_length > manifest->max_signature) {
		return MANIFEST_SIG_BUFFER_TOO_SMALL;
	}

	manifest_hash_type = manifest_get_hash_type (header->sig_type);
	*sig_hash = manifest_convert_manifest_hash_type (manifest_hash_type);

	status = hash_get_hash_length (*sig_hash);
	if (ROT_IS_ERROR (status)) {
		return MANIFEST_SIG_UNKNOWN_HASH_TYPE;
	}

	manifest->state->hash_length = (size_t) status;

	if (hash_out != NULL) {
		if (hash_length < manifest->state->hash_length) {
			return MANIFEST_HASH_BUFFER_TOO_SMALL;
		}
	}

	if (header->magic == manifest->magic_num_v3) {
		manifest->state->extensions_allowed = true;
	}

	return manifest->flash->read (manifest->flash,
		manifest->addr + header->length - header->sig_length, manifest->signature,
		header->sig_length);
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
static int manifest_flash_verify_v1 (const struct manifest_flash *manifest,
	const struct hash_engine *hash, const struct signature_verification *verification,
	enum hash_type sig_hash, uint8_t *hash_out)
{
	int status;

	status = flash_contents_verification (manifest->flash, manifest->addr,
		manifest->state->header.length - manifest->state->header.sig_length, hash, sig_hash,
		verification, manifest->signature, manifest->state->header.sig_length,
		manifest->state->hash_cache, sizeof (manifest->state->hash_cache));

	if ((status == 0) || (status == SIG_VERIFICATION_BAD_SIGNATURE)) {
		manifest->state->cache_valid = true;
		if (hash_out) {
			memcpy (hash_out, manifest->state->hash_cache, manifest->state->hash_length);
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
static int manifest_flash_verify_v2 (const struct manifest_flash *manifest,
	const struct hash_engine *hash, const struct signature_verification *verification,
	enum hash_type sig_hash, uint8_t *hash_out)
{
	struct manifest_toc_header toc_header;
	struct manifest_toc_entry platform_toc_entry;
	struct manifest_toc_entry toc_entry;
	struct manifest_platform_id plat_id_header;
	bool platform_entry_found = false;
	uint32_t prev_entry_end_offset;
	uint32_t next_addr;
	uint32_t sig_addr =
		manifest->addr + manifest->state->header.length - manifest->state->header.sig_length;
	int i;
	int status;

	enum hash_type toc_hash_type;
	int toc_hash_length;

	bool is_root_toc = true;
	bool toc_ext_found = false;

	/* Reset state counters */
	manifest->state->entry_count = 0;
	manifest->state->toc_hash_length = 0;
	manifest->state->toc_hash_type = HASH_TYPE_INVALID;

	/* Hash the header data that has already been read in. */
	status = hash_start_new_hash (hash, sig_hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, (uint8_t*) &manifest->state->header,
		sizeof (manifest->state->header));
	if (status != 0) {
		goto error;
	}

	next_addr = manifest->addr + sizeof (manifest->state->header);

	do {
		toc_ext_found = false;

		/* Read and hash the ToC header */
		status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
			(uint8_t*) &toc_header,	sizeof (toc_header), hash);
		if (status != 0) {
			goto error;
		}

		next_addr += sizeof (toc_header);

		if (toc_header.entry_count == 0) {
			status = MANIFEST_TOC_INVALID;
			goto error;
		}

		toc_hash_type = manifest_convert_manifest_hash_type (toc_header.hash_type);

		if (is_root_toc) {
			/* Check and save the hashing algorithm from the root ToC. */
			if (!hash_is_alg_supported (toc_hash_type)) {
				status = MANIFEST_TOC_UNKNOWN_HASH_TYPE;
				goto error;
			}

			toc_hash_length = hash_get_hash_length (toc_hash_type);
			if (ROT_IS_ERROR (toc_hash_length)) {
				/* should never happen */
				status = MANIFEST_TOC_UNKNOWN_HASH_TYPE;
				goto error;
			}

			manifest->state->toc_hash_type = toc_hash_type;
			manifest->state->toc_hash_length = toc_hash_length;
		}
		else {
			/* `toc_entry` is the ToC extension from previous iteration here.*/

			/* ToC extensions must share the same hash type */
			if (toc_hash_type != manifest->state->toc_hash_type) {
				status = MANIFEST_TOC_HASH_ALGO_MISMATCH;
				goto error;
			}

			/* Length within ToC extension element should match the ToC extension itself. */
			if (toc_entry.length != manifest_toc_calculate_length (toc_header.entry_count,
				toc_header.hash_count, manifest->state->toc_hash_length)) {
				status = MANIFEST_TOC_EXTENSION_INVALID;
				goto error;
			}
		}

		manifest->state->entry_count += toc_header.entry_count;

		/* Used to ensure TOC entries don't overlap or go backward. */
		prev_entry_end_offset = (next_addr - manifest->addr) +
			(toc_header.entry_count * sizeof (toc_entry)) +
			(toc_header.hash_count * toc_hash_length) + (is_root_toc ? toc_hash_length : 0);

		/* Iterate over all current ToC entries */
		for (i = 0; i < toc_header.entry_count; i++) {
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
				(uint8_t*) &toc_entry, sizeof (toc_entry), hash);
			if (status != 0) {
				goto error;
			}

			next_addr += sizeof (toc_entry);

			/* Ensure TOC entries do not overlap or go backward in offset order. */
			if (prev_entry_end_offset > toc_entry.offset) {
				status = MANIFEST_TOC_INVALID;
				goto error;
			}

			prev_entry_end_offset = toc_entry.offset + toc_entry.length;

			/* Handle special cases: Plaftorm ID and ToC extensions. */
			switch (toc_entry.type_id) {
				case MANIFEST_PLATFORM_ID:
					if (!platform_entry_found) {
						platform_toc_entry = toc_entry;
						platform_entry_found = true;
					}
					break;

				case MANIFEST_TOC_EXTENSION:
					if (!manifest->state->extensions_allowed ||
						(i != MANIFEST_TOC_EXTENSION_ENTRY) ||
						(toc_entry.hash_id >= toc_header.hash_count)) {
						status = MANIFEST_TOC_EXTENSION_INVALID;
						goto error;
					}

					toc_ext_found = true;

					break;

				default:
					break;
			}
		}

		/* Hash the hashes table. */
		status = flash_hash_update_contents (manifest->flash, next_addr,
			toc_hash_length * toc_header.hash_count, hash);
		if (status != 0) {
			goto error;
		}

		next_addr += toc_hash_length * toc_header.hash_count;

		/* Read and hash the root ToC hash. */
		if (is_root_toc) {
			if (!platform_entry_found) {
				status = MANIFEST_NO_PLATFORM_ID;
				goto error;
			}

			status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
				manifest->state->root_toc_hash,	toc_hash_length, hash);
			if (status != 0) {
				goto error;
			}

			next_addr += toc_hash_length;

			/* Hash the flash contents until the platform ID element. */
			status = flash_hash_update_contents (manifest->flash, next_addr,
				manifest->addr + platform_toc_entry.offset - next_addr, hash);
			if (status != 0) {
				goto error;
			}

			/* Read and hash the platform ID element header. */
			next_addr = manifest->addr + platform_toc_entry.offset;
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
				(uint8_t*) &plat_id_header,	sizeof (plat_id_header), hash);
			if (status != 0) {
				goto error;
			}

			if (plat_id_header.id_length > manifest->max_platform_id) {
				status = MANIFEST_PLAT_ID_BUFFER_TOO_SMALL;
				goto error;
			}

			/* Read and hash the platform ID string. */
			next_addr += sizeof (plat_id_header);
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
				(uint8_t*) manifest->platform_id, plat_id_header.id_length, hash);
			if (status != 0) {
				goto error;
			}

			manifest->platform_id[plat_id_header.id_length] = '\0';

			next_addr += plat_id_header.id_length;
		}

		if (toc_ext_found) {
			/* Hash the flash contents until the ToC Extension element. */
			status = flash_hash_update_contents (manifest->flash, next_addr,
				manifest->addr + toc_entry.offset - next_addr, hash);
			if (status != 0) {
				goto error;
			}

			next_addr = manifest->addr + toc_entry.offset;
		}

		is_root_toc = false;
	} while (toc_ext_found);

	/* Hash the remaining manifest flash contents. */
	status = flash_hash_update_contents (manifest->flash, next_addr, sig_addr - next_addr, hash);
	if (status != 0) {
		goto error;
	}

	/* Verify the signature of the overall manifest data. */
	status = signature_verification_verify_hash_and_finish_save_digest (verification, hash, NULL, 0,
		manifest->signature, manifest->state->header.sig_length, manifest->state->hash_cache,
		sizeof (manifest->state->hash_cache), &manifest->state->cache_valid);

	if (manifest->state->cache_valid && hash_out) {
		memcpy (hash_out, manifest->state->hash_cache, manifest->state->hash_length);
	}

	return status;

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
int manifest_flash_verify (const struct manifest_flash *manifest, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	enum hash_type sig_hash;
	int status;

	status = manifest_flash_parse_header (manifest, hash, verification, &sig_hash, hash_out,
		hash_length);
	if (status != 0) {
		return status;
	}

	if ((manifest->magic_num_v1 != MANIFEST_NOT_SUPPORTED) &&
		(manifest->state->header.magic == manifest->magic_num_v1)) {
		status = manifest_flash_verify_v1 (manifest, hash, verification, sig_hash, hash_out);
	}
	else if ((manifest->magic_num_v2 != MANIFEST_NOT_SUPPORTED) &&
		(manifest->state->header.magic == manifest->magic_num_v2)) {
		status = manifest_flash_verify_v2 (manifest, hash, verification, sig_hash, hash_out);
	}
	else if ((manifest->magic_num_v3 != MANIFEST_NOT_SUPPORTED) &&
		(manifest->state->header.magic == manifest->magic_num_v3)) {
		/* v3 is v2 with extension, so validated using v2 function */
		status = manifest_flash_verify_v2 (manifest, hash, verification, sig_hash, hash_out);
	}
	else {
		status = MANIFEST_BAD_MAGIC_NUMBER;
	}

	if (status == 0) {
		manifest->state->manifest_valid = true;
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
int manifest_flash_get_id (const struct manifest_flash *manifest, uint32_t *id)
{
	int status = 0;

	if ((manifest == NULL) || (id == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (manifest->state->manifest_valid) {
		buffer_unaligned_copy32 (id, &manifest->state->header.id);
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
int manifest_flash_get_platform_id (const struct manifest_flash *manifest, char **id, size_t length)
{
	if ((manifest == NULL) || (id == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest->state->manifest_valid) {
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
int manifest_flash_get_hash (const struct manifest_flash *manifest, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct manifest_header header;
	enum manifest_hash_type manifest_hash_type;
	enum hash_type sig_hash;
	int status;

	if ((manifest == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return MANIFEST_HASH_BUFFER_TOO_SMALL;
	}

	if (manifest->state->cache_valid) {
		if (hash_length < manifest->state->hash_length) {
			return MANIFEST_HASH_BUFFER_TOO_SMALL;
		}

		memcpy (hash_out, manifest->state->hash_cache, manifest->state->hash_length);
	}
	else {
		status = manifest_flash_read_header (manifest, &header);
		if (status != 0) {
			return status;
		}

		manifest_hash_type = manifest_get_hash_type (header.sig_type);
		sig_hash = manifest_convert_manifest_hash_type (manifest_hash_type);

		status = hash_get_hash_length (sig_hash);
		if (ROT_IS_ERROR (status)) {
			return MANIFEST_SIG_UNKNOWN_HASH_TYPE;
		}

		manifest->state->hash_length = (size_t) status;

		if (hash_length < manifest->state->hash_length) {
			return MANIFEST_HASH_BUFFER_TOO_SMALL;
		}

		status = flash_hash_contents (manifest->flash, manifest->addr,
			header.length - header.sig_length, hash, sig_hash, hash_out, hash_length);
		if (status != 0) {
			return status;
		}
	}

	return manifest->state->hash_length;
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
int manifest_flash_get_signature (const struct manifest_flash *manifest, uint8_t *signature,
	size_t length)
{
	if ((manifest == NULL) || (signature == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (manifest->state->manifest_valid) {
		if (length < manifest->state->header.sig_length) {
			return MANIFEST_SIG_BUFFER_TOO_SMALL;
		}

		memcpy (signature, manifest->signature, manifest->state->header.sig_length);

		return manifest->state->header.sig_length;
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
 * Internal helper to check if the elemnt type belongs to the allowed types list.
 *
 * @param allowed_types Array of allowed element types.
 * @param allowed_types_count Count of allowed types in array.
 * @param type The element type to check.
 *
 * @return True if type is in the list, false otherwise.
 */
static bool manifest_is_type_in_list (const uint8_t *allowed_types, size_t allowed_types_count,
	uint8_t type)
{
	size_t i;

	for (i = 0; i < allowed_types_count; ++i) {
		if (allowed_types[i] == type) {
			return true;
		}
	}

	return false;
}

/**
 * Find the first element of a specified (or any) type in the manifest and read the element data.
 * Everything about the operation will be validated, as appropriate.  This includes table of
 * contents and entry data hashing.
 *
 * @param manifest The manifest to read.
 * @param hash The hash engine to use for element validation.
 * @param types Identifiers for the types of elements to find.
 * @param types_count Count of types to find.
 * @param start_entry_index Index of the table of contents entry to start searching for the element.
 * @param parent_type Identifier for the type of the parent element.  If the element has no parent,
 * MANIFEST_NO_PARENT must be provided.
 * @param read_offset Offset into the element data to start reading.  The entire element is still
 * validated, but the buffer will only contain element data starting at the offset.
 * @param found_entry_index Optional output indicating which TOC entry was used for the element.
 * @param found_type Optional output indicating found entry type.
 * @param format Optional output for the format version of the element data.
 * @param total_len Optional output for the total length of the element data.
 * @param element Optional pointer to the output buffer for the element data.  If the output buffer
 * is null, a buffer will by dynamically allocated to fit the entire element. This buffer must be
 * freed by the caller. If the pointer is null, no element data will be read.
 * @param length Length of the element output buffer, if the buffer is not null.  If the actual
 * element data is longer than the specified length, only the specified length will be read back and
 * no error is generated.  This parameter is ignored when the output buffer is dynamically
 * allocated.
 *
 * @return The amount of element data read or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
static int manifest_flash_read_element_data_common (const struct manifest_flash *manifest,
	const struct hash_engine *hash, const uint8_t *types, size_t types_count, int start_entry_index,
	uint8_t parent_type, uint32_t read_offset, int *found_entry_index, uint8_t *found_type,
	uint8_t *format, size_t *total_len, uint8_t **element, size_t length)
{
	struct manifest_toc_header toc_header;
	struct manifest_toc_entry toc_entry;

	/* Used to validate the ToC/extension */
	uint8_t toc_hash[HASH_MAX_HASH_LEN];
	enum hash_type toc_hash_type;

	/* Used to validate the entry. */
	uint8_t entry_hash[HASH_MAX_HASH_LEN];

	/* Buffer for calculated hash. */
	uint8_t actual_hash[HASH_MAX_HASH_LEN];

	uint32_t toc_end;
	uint32_t next_addr;
	int status;

	/* current index on whole manifest */
	int global_index = 0;

	/* current index on current ToC/extension */
	int local_index = 0;

	/* Indicates if need to free *element in case of failure. */
	bool element_data_allocated = false;

	if ((manifest == NULL) || (hash == NULL) || (types == NULL) || (types_count == 0) ||
		(start_entry_index < 0)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest->state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (start_entry_index >= manifest->state->entry_count) {
		return (parent_type == MANIFEST_NO_PARENT) ?
				   MANIFEST_ELEMENT_NOT_FOUND : MANIFEST_CHILD_NOT_FOUND;
	}

	/* Root ToC hash is saved during initial validation */
	memcpy (toc_hash, manifest->state->root_toc_hash, manifest->state->toc_hash_length);

	next_addr = manifest->addr + sizeof (struct manifest_header);

	do {
		/* Start hashing to verify the TOC contents. */
		status = hash_start_new_hash (hash,	manifest->state->toc_hash_type);
		if (status != 0) {
			return status;
		}

		status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
			(uint8_t*) &toc_header,	sizeof (toc_header), hash);
		if (status != 0) {
			goto error;
		}

		toc_end = next_addr + manifest_toc_calculate_length (toc_header.entry_count,
			toc_header.hash_count, manifest->state->toc_hash_length);
		next_addr += sizeof (toc_header);

		/* Hash calculation algorithm for ToC/ext entries,
		   must be always the same for main ToC and extensions. */
		toc_hash_type = manifest_convert_manifest_hash_type (toc_header.hash_type);
		if (toc_hash_type != manifest->state->toc_hash_type) {
			status = MANIFEST_TOC_HASH_ALGO_MISMATCH;
			goto error;
		}

		local_index = (start_entry_index > global_index) ? start_entry_index - global_index : 0;
		if (local_index >= toc_header.entry_count) {
			/* If `start_entry_index` is beyond current ToC, jump to the last entry to get ToC extension */
			if (toc_header.entry_count == MANIFEST_TOC_MAX_ENTRIES) {
				local_index = MANIFEST_TOC_EXTENSION_ENTRY;
			}
			else {
				/* This branch could happen only in case when manifest->state->entry_count
				 * doesn't match the real value within ToC extension, therefore
				 * returning MANIFEST_TOC_INVALID */

				status = MANIFEST_TOC_INVALID;
				goto error;
			}
		}

		/* Hash the TOC data before the first entry that will be read. */
		status = flash_hash_update_contents (manifest->flash, next_addr,
			sizeof (toc_entry) * local_index, hash);
		if (status != 0) {
			goto error;
		}

		next_addr += sizeof (toc_entry) * local_index;

		/* Find the TOC entry for the requested element. */
		while (local_index < toc_header.entry_count) {
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
				(uint8_t*) &toc_entry, sizeof (toc_entry), hash);
			if (status != 0) {
				goto error;
			}

			next_addr += sizeof (toc_entry);
			local_index++;

			/* ToC extension must be transparent for type checks and must be the last element */
			if (toc_entry.type_id == MANIFEST_TOC_EXTENSION) {
				if (!manifest->state->extensions_allowed ||
					((local_index - 1) != MANIFEST_TOC_EXTENSION_ENTRY) ||
					(toc_entry.hash_id >= toc_header.hash_count)) {
					status = MANIFEST_TOC_EXTENSION_INVALID;
					goto error;
				}
			}
			else {
				/* As soon as we see an element that is not a child, we fail because we have left the
				 * context of the expected parent. */
				if ((parent_type != MANIFEST_NO_PARENT) &&
					(toc_entry.parent == MANIFEST_NO_PARENT)) {
					status = MANIFEST_CHILD_NOT_FOUND;
					goto error;
				}

				if (manifest_is_type_in_list (types, types_count, toc_entry.type_id)) {
					break;
				}
			}
		}

		global_index += local_index;

		if (!manifest_is_type_in_list (types, types_count, toc_entry.type_id) &&
			(toc_entry.type_id != MANIFEST_TOC_EXTENSION)) {
			status = (parent_type == MANIFEST_NO_PARENT) ?
					MANIFEST_ELEMENT_NOT_FOUND : MANIFEST_CHILD_NOT_FOUND;
			goto error;
		}

		if (toc_entry.hash_id < toc_header.hash_count) {
			/* Hash the unneeded TOC data until the entry hash. */
			status = flash_hash_update_contents (manifest->flash, next_addr,
				((toc_header.entry_count - local_index) * sizeof (toc_entry)) +
				(manifest->state->toc_hash_length * toc_entry.hash_id), hash);
			if (status != 0) {
				goto error;
			}

			next_addr += ((toc_header.entry_count - local_index) * sizeof (toc_entry)) +
				(manifest->state->toc_hash_length * toc_entry.hash_id);

			/* Read the entry hash for element validation. */
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr, entry_hash,
				manifest->state->toc_hash_length, hash);
			if (status != 0) {
				goto error;
			}

			next_addr += manifest->state->toc_hash_length;
		}

		/* Hash the rest of current ToC. */
		status = flash_hash_update_contents (manifest->flash, next_addr, toc_end - next_addr, hash);
		if (status != 0) {
			goto error;
		}

		next_addr = toc_end;

		/*  Validate the TOC. */
		status = hash->finish (hash, actual_hash, sizeof (actual_hash));
		if (status != 0) {
			goto error;
		}

		if (buffer_compare (actual_hash, toc_hash, manifest->state->toc_hash_length) != 0) {
			return MANIFEST_TOC_INVALID;
		}

		/* The extension will be validated by it's `entry` hash */
		if (toc_entry.type_id == MANIFEST_TOC_EXTENSION) {
			memcpy (toc_hash, entry_hash, manifest->state->toc_hash_length);
			next_addr = manifest->addr + toc_entry.offset;
		}
	} while (toc_entry.type_id == MANIFEST_TOC_EXTENSION);

	/* Read the element data. */
	if ((toc_entry.parent != MANIFEST_NO_PARENT) && (toc_entry.parent != parent_type)) {
		return MANIFEST_WRONG_PARENT;
	}

	if (found_entry_index) {
		*found_entry_index = global_index - 1;
	}
	if (found_type) {
		*found_type = toc_entry.type_id;
	}
	if (format) {
		*format = toc_entry.format;
	}
	if (total_len) {
		*total_len = toc_entry.length;
	}
	if ((element == NULL) || (read_offset >= toc_entry.length)) {
		length = 0;
	}
	else if (*element == NULL) {
		/* This value doesn't matter.  It's just set to pass the check for reading element data. */
		length = 1;
	}

	if (length != 0) {
		toc_entry.length -= read_offset;
		if (*element == NULL) {
			*element = platform_malloc (toc_entry.length);
			if (*element == NULL) {
				return MANIFEST_NO_MEMORY;
			}

			element_data_allocated = true;
			length = toc_entry.length;
		}

		if (toc_entry.hash_id < toc_header.hash_count) {
			/* Hash the element data to validate the contents. */
			status = hash_start_new_hash (hash, manifest->state->toc_hash_type);
			if (status != 0) {
				return status;
			}

			status = flash_hash_update_contents (manifest->flash, manifest->addr + toc_entry.offset,
				read_offset, hash);
			if (status != 0) {
				goto error;
			}
		}

		toc_entry.offset += read_offset;
		length = min (length, toc_entry.length);
		status = manifest->flash->read (manifest->flash, manifest->addr + toc_entry.offset,
			*element, length);
		if (status != 0) {
			goto error;
		}

		if (toc_entry.hash_id < toc_header.hash_count) {
			status = hash->update (hash, *element, length);
			if (status != 0) {
				goto error;
			}

			if (length < toc_entry.length) {
				status = flash_hash_update_contents (manifest->flash,
					manifest->addr + toc_entry.offset + length, toc_entry.length - length, hash);
				if (status != 0) {
					goto error;
				}
			}

			status = hash->finish (hash, actual_hash, sizeof (actual_hash));
			if (status != 0) {
				goto error;
			}

			if (buffer_compare (actual_hash, entry_hash, manifest->state->toc_hash_length) != 0) {
				return MANIFEST_ELEMENT_INVALID;
			}
		}
	}

	return length;

error:
	if (element_data_allocated) {
		platform_free (*element);
		*element = NULL;
	}

	hash->cancel (hash);

	return status;
}


/**
 * Find the first element of a specified type in the manifest and read the element data.
 * Everything about the operation will be validated, as appropriate.  This includes table of
 * contents and entry data hashing.
 *
 * @param manifest The manifest to read.
 * @param hash The hash engine to use for element validation.
 * @param type Identifier for the type of element to find.
 * @param start_entry_index Index of the table of contents entry to start searching for the element.
 * @param parent_type Identifier for the type of the parent element.  If the element has no parent,
 * MANIFEST_NO_PARENT must be provided.
 * @param read_offset Offset into the element data to start reading.  The entire element is still
 * validated, but the buffer will only contain element data starting at the offset.
 * @param found_entry_index Optional output indicating which TOC entry was used for the element.
 * @param format Optional output for the format version of the element data.
 * @param total_len Optional output for the total length of the element data.
 * @param element Optional pointer to the output buffer for the element data.  If the output buffer
 * is null, a buffer will by dynamically allocated to fit the entire element. This buffer must be
 * freed by the caller. If the pointer is null, no element data will be read.
 * @param length Length of the element output buffer, if the buffer is not null.  If the actual
 * element data is longer than the specified length, only the specified length will be read back and
 * no error is generated.  This parameter is ignored when the output buffer is dynamically
 * allocated.
 *
 * @return The amount of element data read or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int manifest_flash_read_element_data (const struct manifest_flash *manifest,
	const struct hash_engine *hash, uint8_t type, int start_entry_index, uint8_t parent_type,
	uint32_t read_offset, int *found_entry_index, uint8_t *format, size_t *total_len,
	uint8_t **element, size_t length)
{
	return manifest_flash_read_element_data_common (manifest, hash, &type, 1, start_entry_index,
		parent_type, read_offset, found_entry_index, NULL, format, total_len, element, length);
}

/**
 * Find the first element of any specific type in the manifest and read the element data.
 * Everything about the operation will be validated, as appropriate.  This includes table of
 * contents and entry data hashing.
 *
 * @param manifest The manifest to read.
 * @param hash The hash engine to use for element validation.
 * @param types Identifiers for the types of elements to find.
 * @param types_count Count of types to find.
 * @param start_entry_index Index of the table of contents entry to start searching for the element.
 * @param parent_type Identifier for the type of the parent element.  If the element has no parent,
 * MANIFEST_NO_PARENT must be provided.
 * @param read_offset Offset into the element data to start reading.  The entire element is still
 * validated, but the buffer will only contain element data starting at the offset.
 * @param found_entry_index Optional output indicating which TOC entry was used for the element.
 * @param found_type Optional output indicating found entry type.
 * @param format Optional output for the format version of the element data.
 * @param total_len Optional output for the total length of the element data.
 * @param element Optional pointer to the output buffer for the element data.  If the output buffer
 * is null, a buffer will by dynamically allocated to fit the entire element. This buffer must be
 * freed by the caller. If the pointer is null, no element data will be read.
 * @param length Length of the element output buffer, if the buffer is not null.  If the actual
 * element data is longer than the specified length, only the specified length will be read back and
 * no error is generated.  This parameter is ignored when the output buffer is dynamically
 * allocated.
 *
 * @return The amount of element data read or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int manifest_flash_read_element_data_multi_type (const struct manifest_flash *manifest,
	const struct hash_engine *hash, const uint8_t *types, size_t types_count, int start_entry_index,
	uint8_t parent_type, uint32_t read_offset, int *found_entry_index, uint8_t *found_type,
	uint8_t *format, size_t *total_len, uint8_t **element, size_t length)
{
	return manifest_flash_read_element_data_common (manifest, hash, types, types_count,
		start_entry_index, parent_type, read_offset, found_entry_index, found_type, format,
		total_len, element, length);
}

/**
 * Get requested information of child elements or requested entry.
 *
 * Get Number of Child Elements: Use child_count to find the number of direct child elements of
 * 	specified type of requested element.  If element has nested children, they are not counted.
 *
 * Get Total Length of Child Elements: Use child_len to find the total length of direct child
 *  elements of	specified type of requested element.  If element has nested children, they are not
 *  counted.
 *
 * Get Entry ID of First Child: Use first_entry to get first child entry of requested type.
 *
 * @param manifest The manifest to read.
 * @param hash The hash engine to use for element validation.
 * @param start_entry_index Starting table of contents entry to start processing.
 * @param type Type of requested parent element.
 * @param parent_type Type of parent to requested parent element.
 * @param child_type Type of child element to get count of.
 * @param child_len Optional output buffer with total length of child elements.
 * @param child_count Optional output buffer with number of child elements found.
 * @param first_entry_index Optional output buffer with entry of first child.
 *
 * @return 0 if request completed successfully or an error code.
 */
int manifest_flash_get_child_elements_info (const struct manifest_flash *manifest,
	const struct hash_engine *hash, int start_entry_index, uint8_t type, uint8_t parent_type,
	uint8_t child_type, size_t *child_len, int *child_count, int *first_entry_index)
{
	struct manifest_toc_header toc_header;
	struct manifest_toc_entry toc_entry;

	uint32_t next_addr;
	uint32_t toc_end;
	bool only_entry = ((child_len == NULL) && (child_count == NULL));
	int status;

	/* Used to validate the ToC/extension */
	uint8_t toc_hash[HASH_MAX_HASH_LEN];
	enum hash_type toc_hash_type;

	/* Used to validate the entry. */
	uint8_t entry_hash[HASH_MAX_HASH_LEN];

	/* Buffer for calculated hash. */
	uint8_t actual_hash[HASH_MAX_HASH_LEN];

	/* current index on whole manifest */
	int global_index = 0;

	/* current index on current ToC/extension */
	int local_index = 0;

	if ((manifest == NULL) || (hash == NULL) || (only_entry && (first_entry_index == NULL)) ||
		(start_entry_index < 0)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest->state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (child_len != NULL) {
		*child_len = 0;
	}

	if (child_count != NULL) {
		*child_count = 0;
	}

	if (first_entry_index != NULL) {
		*first_entry_index = 0;
	}

	if (start_entry_index >= manifest->state->entry_count) {
		return 0;
	}

	/* The first ToC is having it's own hash after hash table, and saved during validation */
	memcpy (toc_hash, manifest->state->root_toc_hash, manifest->state->toc_hash_length);

	next_addr = manifest->addr + sizeof (struct manifest_header);

	do {
		/* Start hashing to verify the TOC contents. */
		status = hash_start_new_hash (hash,	manifest->state->toc_hash_type);
		if (status != 0) {
			return status;
		}

		status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
			(uint8_t*) &toc_header,	sizeof (toc_header), hash);
		if (status != 0) {
			goto error;
		}

		toc_end = next_addr + manifest_toc_calculate_length (toc_header.entry_count,
			toc_header.hash_count, manifest->state->toc_hash_length);
		next_addr += sizeof (toc_header);

		toc_hash_type = manifest_convert_manifest_hash_type (toc_header.hash_type);
		if (toc_hash_type != manifest->state->toc_hash_type) {
			status = MANIFEST_TOC_HASH_ALGO_MISMATCH;
			goto error;
		}

		local_index = (start_entry_index > global_index) ? start_entry_index - global_index : 0;
		if (local_index >= toc_header.entry_count) {
			if (toc_header.entry_count == MANIFEST_TOC_MAX_ENTRIES) {
				local_index = MANIFEST_TOC_EXTENSION_ENTRY;
			}
			else {
				status = MANIFEST_TOC_INVALID;
				goto error;
			}
		}

		/* Hash the TOC data before the first entry that will be read. */
		status = flash_hash_update_contents (manifest->flash, next_addr,
			sizeof (struct manifest_toc_entry) * local_index, hash);
		if (status != 0) {
			goto error;
		}

		next_addr += (sizeof (struct manifest_toc_entry) * local_index);

		while (local_index < toc_header.entry_count) {
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr,
				(uint8_t*) &toc_entry, sizeof (toc_entry), hash);
			if (status != 0) {
				goto error;
			}

			next_addr += sizeof (toc_entry);
			local_index += 1;

			/* ToC extension must be transparent for type checks and must be the last element */
			if (toc_entry.type_id == MANIFEST_TOC_EXTENSION) {
				if (!manifest->state->extensions_allowed ||
					((local_index - 1) != MANIFEST_TOC_EXTENSION_ENTRY) ||
					(toc_entry.hash_id >= toc_header.hash_count)) {
					status = MANIFEST_TOC_EXTENSION_INVALID;
					goto error;
				}

				break;
			}

			if ((toc_entry.parent == parent_type) || (toc_entry.type_id == parent_type)) {
				if (only_entry) {
					status = MANIFEST_CHILD_NOT_FOUND;
					goto error;
				}

				break;
			}

			if ((toc_entry.parent == type) && (toc_entry.type_id == child_type)) {
				if ((first_entry_index != NULL) && (*first_entry_index == 0)) {
					*first_entry_index = global_index + local_index - 1;

					if (only_entry) {
						break;
					}
				}

				if (child_count != NULL) {
					*child_count = *child_count + 1;
				}

				if (child_len != NULL) {
					*child_len = *child_len + toc_entry.length;
				}
			}
		}

		global_index += local_index;

		if (only_entry && (*first_entry_index == 0) &&
			(toc_entry.type_id != MANIFEST_TOC_EXTENSION)) {
			status = MANIFEST_CHILD_NOT_FOUND;
			goto error;
		}

		/* Extract ToC extension hash, the hash_id validated above. */
		if (toc_entry.type_id == MANIFEST_TOC_EXTENSION) {
			/* Hash the unneeded TOC data until the entry hash. */
			status = flash_hash_update_contents (manifest->flash, next_addr,
				((toc_header.entry_count - local_index) * sizeof (toc_entry)) +
				(manifest->state->toc_hash_length * toc_entry.hash_id), hash);
			if (status != 0) {
				goto error;
			}

			next_addr += ((toc_header.entry_count - local_index) * sizeof (toc_entry)) +
				(manifest->state->toc_hash_length * toc_entry.hash_id);

			/* Read the entry hash for element validation. */
			status = flash_read_and_hash_update_contents (manifest->flash, next_addr, entry_hash,
				manifest->state->toc_hash_length, hash);
			if (status != 0) {
				goto error;
			}

			next_addr += manifest->state->toc_hash_length;
		}

		status = flash_hash_update_contents (manifest->flash, next_addr, toc_end - next_addr, hash);
		if (status != 0) {
			goto error;
		}

		next_addr = toc_end;

		/* Validate the TOC. */
		status = hash->finish (hash, actual_hash, sizeof (actual_hash));
		if (status != 0) {
			goto error;
		}

		if (buffer_compare (actual_hash, toc_hash, manifest->state->toc_hash_length) != 0) {
			return MANIFEST_TOC_INVALID;
		}

		if (toc_entry.type_id == MANIFEST_TOC_EXTENSION) {
			memcpy (toc_hash, entry_hash, manifest->state->toc_hash_length);
			next_addr = manifest->addr + toc_entry.offset;
		}
	} while (toc_entry.type_id == MANIFEST_TOC_EXTENSION);

	return 0;

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
uint32_t manifest_flash_get_addr (const struct manifest_flash *manifest)
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
const struct flash* manifest_flash_get_flash (const struct manifest_flash *manifest)
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
int manifest_flash_compare_id (const struct manifest_flash *manifest1,
	const struct manifest_flash *manifest2)
{
	if (manifest2 == NULL) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest2->state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}
	else if ((manifest1 == NULL) || !manifest1->state->manifest_valid) {
		return 0;
	}

	if (manifest1->state->header.id < manifest2->state->header.id) {
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
int manifest_flash_compare_platform_id (const struct manifest_flash *manifest1,
	const struct manifest_flash *manifest2, bool sku_upgrade_permitted)
{
	if ((manifest1 == NULL) || (manifest2 == NULL)) {
		return MANIFEST_INVALID_ARGUMENT;
	}

	if (!manifest1->state->manifest_valid || !manifest2->state->manifest_valid) {
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
