// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "firmware_header.h"


/**
 * Define all different formats of the firmware header.
 */
union firmware_header_format {
	struct __attribute__ ((__packed__)) {
		uint16_t recovery_revision;			/**< The image revision ID for recovery updates. */
	} format0;

	struct __attribute__ ((__packed__)) {
		uint16_t recovery_revision;			/**< The image revision ID for recovery updates. */
		uint8_t extra_images;				/**< The number of additional app images included. */
	} format1;

	struct __attribute__ ((__packed__)) {
		uint16_t recovery_revision;			/**< The image revision ID for recovery updates. */
		uint8_t extra_images;				/**< The number of additional app images included. */
		uint16_t allowed_rollback;			/**< Earliest revision ID allowed for updates. */
	} format2;

	struct __attribute__ ((__packed__)) {
		uint16_t recovery_revision;			/**< The image revision ID for recovery updates. */
		uint8_t extra_images;				/**< The number of additional app images included. */
		uint16_t allowed_rollback;			/**< Earliest revision ID allowed for updates. */
		uint32_t signed_length;				/**< Total length of data that has been signed. */
		uint16_t sig_length;				/**< Length of the additional signature. */
	} format3;
} __attribute__ ((__packed__));

/**
 * Get the expected length of a header format version.
 */
#define	HEADER_FORMAT_LENGTH(x)		(sizeof ((union firmware_header_format*) 0)->format##x)


/**
 * Read the header information from the firmware image on flash.
 *
 * @param header The instance to initialize with the firmware header.
 * @param flash The flash that contains the firmware image.
 * @param addr The start address of the header.
 *
 * @return 0 if the header was successfully loaded from flash or an error code.
 */
int firmware_header_init (struct firmware_header *header, struct flash *flash, uint32_t addr)
{
	size_t length;
	int status;

	status = image_header_init (&header->base, flash, addr, FIRMWARE_HEADER_MARKER,
		FIRMWARE_HEADER_MAX_LENGTH);
	if (status != 0) {
		return status;
	}

	length = header->base.info.length - sizeof (header->base.info);
	switch (header->base.info.format) {
		case 0:
			if (length != HEADER_FORMAT_LENGTH (0)) {
				return FIRMWARE_HEADER_BAD_FORMAT_LENGTH;
			}
			break;

		case 1:
			if (length != HEADER_FORMAT_LENGTH (1)) {
				return FIRMWARE_HEADER_BAD_FORMAT_LENGTH;
			}
			break;

		case 2:
			if (length != HEADER_FORMAT_LENGTH (2)) {
				return FIRMWARE_HEADER_BAD_FORMAT_LENGTH;
			}
			break;

		case 3:
			if (length != HEADER_FORMAT_LENGTH (3)) {
				return FIRMWARE_HEADER_BAD_FORMAT_LENGTH;
			}
			break;

		default:
			if (length < sizeof (union firmware_header_format)) {
				return FIRMWARE_HEADER_BAD_FORMAT_LENGTH;
			}
			break;
	}

	status = image_header_load_data (&header->base, flash, addr);

	return status;
}

/**
 * Release the firmware header.
 *
 * @param header The header instance to release.
 */
void firmware_header_release (struct firmware_header *header)
{
	image_header_release (&header->base);
}

/**
 * Get the revision identifier for the recovery image from the firmware header.
 *
 * @param header The header to query.
 * @param revision Output for the revision identifier.
 *
 * @return 0 if the revision was available in the header or an error code.
 */
int firmware_header_get_recovery_revision (struct firmware_header *header, int *revision)
{
	if ((header == NULL) || (revision == NULL)) {
		return FIRMWARE_HEADER_INVALID_ARGUMENT;
	}

	*revision = ((union firmware_header_format*) header->base.data)->format0.recovery_revision;

	return 0;
}

/**
 * Get the number of additional images contained in the firmware image.  Each additional image will
 * be wrapped as an app image.
 *
 * @param header The header to query.
 *
 * @return The number of extra images or an error code.
 */
int firmware_header_get_extra_images (struct firmware_header *header)
{
	if (header == NULL) {
		return FIRMWARE_HEADER_INVALID_ARGUMENT;
	}

	if (header->base.info.format < 1) {
		return FIRMWARE_HEADER_INFO_NOT_AVAILABLE;
	}

	return ((union firmware_header_format*) header->base.data)->format1.extra_images;
}

/**
 * Get the earliest revision identifier that should be allowed for firmware updates.
 *
 * @param header The header to query.
 * @param revision Output for the revision identifier.
 *
 * @return 0 if the revision was available in the header or an error code.
 */
int firmware_header_get_earliest_allowed_revision (struct firmware_header *header, int *revision)
{
	if ((header == NULL) || (revision == NULL)) {
		return FIRMWARE_HEADER_INVALID_ARGUMENT;
	}

	if (header->base.info.format < 2) {
		return FIRMWARE_HEADER_INFO_NOT_AVAILABLE;
	}

	*revision = ((union firmware_header_format*) header->base.data)->format2.allowed_rollback;

	return 0;
}

/**
 * Get information about any additional signature added to the firmware image.  If the signature is
 * present, it will be added immediately after the signed data.
 *
 * If a signature is present in the image, it must include everything from the start of the firmware
 * header to the end of the image data.  0 length for either value indicates that no signature is
 * present.
 *
 * @param header The header to query.
 * @param signed_length The length of the image data that was signed.
 * @param sig_length The length of the signature.
 *
 * @return 0 if the signature information was available in the header or an error code.
 */
int firmware_header_get_signature_info (struct firmware_header *header, size_t *signed_length,
	size_t *sig_length)
{
	if ((header == NULL) || (signed_length == NULL) || (sig_length == NULL)) {
		return FIRMWARE_HEADER_INVALID_ARGUMENT;
	}

	if (header->base.info.format < 3) {
		return FIRMWARE_HEADER_INFO_NOT_AVAILABLE;
	}

	*signed_length = ((union firmware_header_format*) header->base.data)->format3.signed_length;
	*sig_length = ((union firmware_header_format*) header->base.data)->format3.sig_length;

	return 0;
}
