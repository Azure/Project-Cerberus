// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_SECTION_HEADER_H_
#define RECOVERY_IMAGE_SECTION_HEADER_H_

#include <stdint.h>
#include "common/image_header.h"
#include "flash/flash.h"
#include "status/rot_status.h"


/**
 * The magic number marker for a recovery image section header.
 */
#define RECOVERY_IMAGE_SECTION_HEADER_MARKER					0x4b172f31
#define	RECOVERY_IMAGE_SECTION_HEADER_MAX_LENGTH				1024


/**
 * Interface for a recovery image section header that provides information about the section image.
 */
struct recovery_image_section_header {
	struct image_header base;	/**< The base recovery image section header instance. */
};


int recovery_image_section_header_init (struct recovery_image_section_header *header,
	const struct flash *flash, uint32_t addr);
void recovery_image_section_header_release (struct recovery_image_section_header *header);

int recovery_image_section_header_get_length (struct recovery_image_section_header *header,
	size_t *length);

int recovery_image_section_header_get_section_image_length (
	struct recovery_image_section_header *header, size_t *length);
int recovery_image_section_header_get_host_write_addr (struct recovery_image_section_header *header,
	uint32_t *addr);


#define	RECOVERY_IMAGE_SECTION_HEADER_ERROR(\
	code)		ROT_ERROR (ROT_MODULE_RECOVERY_IMAGE_SECTION_HEADER, code)

/**
 * Error codes that can be generated by a recovery image section header.
 */
enum {
	RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT = RECOVERY_IMAGE_SECTION_HEADER_ERROR (0x00),	/**< Input parameter is null or not valid. */
	RECOVERY_IMAGE_SECTION_HEADER_NO_MEMORY = RECOVERY_IMAGE_SECTION_HEADER_ERROR (0x01),			/**< Memory allocation failed. */
	RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH = RECOVERY_IMAGE_SECTION_HEADER_ERROR (0x02),	/**< The header length doesn't match the expected length for the format. */
};


#endif	/* RECOVERY_IMAGE_SECTION_HEADER_H_ */
