// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "image_header.h"
#include "platform.h"


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
int image_header_init (struct image_header *header, struct flash *flash, uint32_t addr,
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
int image_header_load_data (struct image_header *header, struct flash *flash, uint32_t addr)
{
	size_t length;
	int status;

	if ((header == NULL) || (flash == NULL)) {
		return IMAGE_HEADER_INVALID_ARGUMENT;
	}

	header->data = NULL;
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
int image_header_get_length (struct image_header *header)
{
	if (header) {
		return header->info.length;
	}
	else {
		return 0;
	}
}
