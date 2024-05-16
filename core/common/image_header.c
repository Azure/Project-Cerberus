// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "image_header.h"
#include "platform_api.h"


/**
 * Initialize the common handling for an image header.
 *
 * @param header The instance to initialize with the image header.
 * @param flash The flash that contains the image header.
 * @param addr The start address of the header.
 * @param magic_num The magic number that identifies a valid header.
 * @param max_len The maximum length of the header in bytes.
 *
 * @return 0 if the header information was successfully loaded from flash or an error code.
 */
int image_header_init (struct image_header *header, const struct flash *flash, uint32_t addr,
	uint32_t magic_num, size_t max_len)
{
	int status;

	if ((header == NULL) || (flash == NULL)) {
		return IMAGE_HEADER_INVALID_ARGUMENT;
	}

	memset (header, 0, sizeof (struct image_header));

	status = flash->read (flash, addr, (uint8_t*) &header->info, sizeof (header->info));
	if (status != 0) {
		return status;
	}

	if (header->info.length < sizeof (header->info)) {
		return IMAGE_HEADER_NOT_MINIMUM_SIZE;
	}

	if (header->info.marker != magic_num) {
		return IMAGE_HEADER_BAD_MARKER;
	}

	if (header->info.length > max_len) {
		return IMAGE_HEADER_TOO_LONG;
	}

	return status;
}

/**
 * Release the recovery image header data.
 *
 * @param header The header instance to release.
 */
void image_header_release (struct image_header *header)
{
	if (header) {
		platform_free (header->data);
		header->data = NULL;
	}
}

/**
 * Load the image header data from flash.
 *
 * @param header The header instance to initialize header data.
 * @param flash The flash that contains the image header.
 * @param addr The base address of the header.
 *
 * @return 0 if header data was successfully loaded from flash or an error code.
 */
int image_header_load_data (struct image_header *header, const struct flash *flash, uint32_t addr)
{
	size_t length;
	int status;

	if ((header == NULL) || (flash == NULL)) {
		return IMAGE_HEADER_INVALID_ARGUMENT;
	}

	length = header->info.length - sizeof (header->info);
	header->data = platform_malloc (length);
	if (header->data == NULL) {
		return IMAGE_HEADER_NO_MEMORY;
	}

	status = flash->read (flash, addr + sizeof (header->info), header->data, length);
	if (status != 0) {
		image_header_release (header);
	}

	return status;
}

/**
 * Get the total length of the image header.  This includes all bytes in the base header
 * information and the length of the header data.
 *
 * @param header The header to query.
 *
 * @return The total number of bytes in the header.
 */
int image_header_get_length (const struct image_header *header)
{
	if (header) {
		return header->info.length;
	}
	else {
		return 0;
	}
}

/**
 * Get the format identifier for the header.
 *
 * @param header The header to query.
 *
 * @return The header format identifier or an error code if the header is null.
 */
int image_header_get_format (const struct image_header *header)
{
	if (header) {
		return header->info.format;
	}
	else {
		return IMAGE_HEADER_INVALID_ARGUMENT;
	}
}

/**
 * Calculate the digest for the image header.  This digest will be calculated over the entire
 * header, which includes both the base header information as well as the variable header data.
 *
 * @param header The header to hash.
 * @param hash Hash engine to use for calculating the digest.
 * @param type The hash algorithm to use.
 * @param digest Output for the calculated digest.
 * @param length Length of the output buffer.
 *
 * @return 0 if the header was hashed successfully or an error code.
 */
int image_header_hash_header (const struct image_header *header, struct hash_engine *hash,
	enum hash_type type, uint8_t *digest, size_t length)
{
	int status;

	if ((header == NULL) || (hash == NULL) || (digest == NULL) || (length == 0)) {
		return IMAGE_HEADER_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, type);
	if (status != 0) {
		return status;
	}

	status = image_header_hash_update_header (header, hash);
	if (status != 0) {
		goto error;
	}

	status = hash->finish (hash, digest, length);
	if (status != 0) {
		goto error;
	}

	return 0;

error:
	hash->cancel (hash);

	return status;
}

/**
 * Update an active hash with the image header data.  The hash will be updated with entire header,
 * which includes both the base header information as well as the variable header data.
 *
 * The hash context must already be started prior to this call.  The hashing context will not be
 * canceled on failure.
 *
 * @param header The header to hash.
 * @param hash Hash engine that should be updated with the header data.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int image_header_hash_update_header (const struct image_header *header, struct hash_engine *hash)
{
	int status;

	if ((header == NULL) || (hash == NULL)) {
		return IMAGE_HEADER_INVALID_ARGUMENT;
	}

	status = hash->update (hash, (uint8_t*) &header->info, sizeof (header->info));
	if (status != 0) {
		return status;
	}

	return hash->update (hash, header->data, header->info.length - sizeof (header->info));
}
