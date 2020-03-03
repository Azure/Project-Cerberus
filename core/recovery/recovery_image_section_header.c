// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform.h"
#include "recovery_image_section_header.h"
#include "cmd_interface/cmd_interface.h"


/**
 * Define all different formats of the recovery image section header.
 */
union recovery_image_section_header_format {
	struct __attribute__ ((__packed__)) {
		uint32_t addr;			/**< The host address to store the section image. */ 
		uint32_t length;		/**< The length of the section image. */
	} format0;
} __attribute__ ((__packed__));

/**
 * Get the expected length of a section header format version.
 */
#define	SECTION_HEADER_FORMAT_LENGTH(x) \
	(sizeof ((union recovery_image_section_header_format*) 0)->format##x)


/**
 * Read the section header information from the recovery image section on flash.
 *
 * @param header The instance to initialize with the recovery image section header.
 * @param flash The flash that contains the recovery image section.
 * @param addr The start address of the section header.
 *
 * @return 0 if the section header was successfully loaded from flash or an error code.
 */
int recovery_image_section_header_init (struct recovery_image_section_header *header,
	struct flash *flash, uint32_t addr)
{
	size_t length;
	int status;

	status = image_header_init (&header->base, flash, addr, RECOVERY_IMAGE_SECTION_HEADER_MARKER,
		RECOVERY_IMAGE_SECTION_HEADER_MAX_LENGTH);
	if (status != 0) {
		return status;
	}

	length = header->base.info.length - sizeof (header->base.info);
	switch (header->base.info.format) {
		case 0:
			if (length != SECTION_HEADER_FORMAT_LENGTH (0)) {
				return RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH;
			}
			break;

		default:
			if (length < (sizeof (union recovery_image_section_header_format))) {
				return RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH;
			}
	}

	status = image_header_load_data (&header->base, flash, addr);

	return status;
}

/**
 * Release the recovery image header.
 *
 * @param header The header instance to release.
 */
void recovery_image_section_header_release (struct recovery_image_section_header *header)
{
	image_header_release (&header->base);
}

/**
 * Get the length of the recovery section image. This is the length of the section image data
 * and does not include the section header length.
 *
 * @param header The header to query.
 * @param length Output for the recovery section image length.
 *
 * @return 0 if the section image length was available in the header or an error code.
 */
int recovery_image_section_header_get_section_image_length (
	struct recovery_image_section_header *header, size_t *length)
{
	if ((header == NULL) || (length == NULL)) {
		return RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT;
	}

	*length = ((union recovery_image_section_header_format*) header->base.data)->format0.length; 

	return 0;
}

/**
 * Get the length of a recovery image section header.
 *
 * @param header The header to query.
 * @param length Output for the recovery image section header length.
 *
 * @return 0 if the section header length was available in the header or an error code.
 */
int recovery_image_section_header_get_length (struct recovery_image_section_header *header,
	size_t *length)
{
	if ((header == NULL) || (length == NULL)) {
		return RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT;
	}

	*length = image_header_get_length (&header->base);

	return 0;
}

/**
 * Get the host address to write the recovery section image.
 *
 * @param header The header to query.
 * @param addr Output for the host write address.
 *
 * @return 0 if the host write address was available in the header or an error code.
 */
int recovery_image_section_header_get_host_write_addr (struct recovery_image_section_header *header,
	uint32_t *addr)
{
	if ((header == NULL) || (addr == NULL)) {
		return RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT;
	}

	*addr = ((union recovery_image_section_header_format*) header->base.data)->format0.addr;

	return 0;
}

