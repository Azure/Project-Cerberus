// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform.h"
#include "recovery_image_header.h"
#include "cmd_interface/cerberus_protocol.h"


/**
 * Define all different formats of the recovery image header.
 */
union recovery_image_header_format {
	struct __attribute__ ((__packed__)) {
		/**
		 * The image version ID for recovery image updates, including the NULL terminator.
		 */
		char version_id[CERBERUS_PROTOCOL_FW_VERSION_LEN];
		uint32_t image_length;					/**< The size in bytes of the recovery image,
													 including the header, image, and signature. */
		uint32_t signature_length;				/**< The size in bytes of the recovery image
													 signature. */
		uint8_t platform_id_length;				/**< The platform identifier length, including the
													 NULL terminator. */
	} format0;
} __attribute__ ((__packed__));

/**
 * Get the expected length of a header format version.
 */
#define	RECOVERY_IMAGE_HEADER_FORMAT_LENGTH(x) \
	(sizeof ((union recovery_image_header_format*) 0)->format##x)


/**
 * Read the header information from the recovery image on flash.
 *
 * @param header The instance to initialize with the recovery image header.
 * @param flash The flash that contains the recovery image.
 * @param addr The start address of the header.
 *
 * @return 0 if the header was successfully loaded from flash or an error code.
 */
int recovery_image_header_init (struct recovery_image_header *header, struct flash *flash,
	uint32_t addr)
{
	size_t hdr_data_len;
	union recovery_image_header_format *hdr;
	int status;

	status = image_header_init (&header->base, flash, addr, RECOVERY_IMAGE_HEADER_MARKER,
		RECOVERY_IMAGE_HEADER_MAX_LENGTH);
	if (status != 0) {
		return status;
	}

	status = image_header_load_data (&header->base, flash, addr);
	if (status != 0) {
		return status;
	}

	hdr_data_len = header->base.info.length - sizeof (header->base.info);
	switch (header->base.info.format) {
		case 0: {
			hdr = (union recovery_image_header_format*) header->base.data;
			size_t version_id_len = strnlen (hdr->format0.version_id,
				CERBERUS_PROTOCOL_FW_VERSION_LEN);
			size_t header_len = image_header_get_length (&header->base);
			size_t platform_id_len;

			if ((hdr_data_len - hdr->format0.platform_id_length) !=
				RECOVERY_IMAGE_HEADER_FORMAT_LENGTH (0)) {
				status = RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH;
				goto err_free_header;
			}

			platform_id_len = strnlen (
				(char*) &header->base.data[RECOVERY_IMAGE_HEADER_FORMAT_LENGTH (0)],
				hdr->format0.platform_id_length);
			if ((platform_id_len + 1) != hdr->format0.platform_id_length) {
				status = RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID;
				goto err_free_header;
			}

			if (hdr->format0.signature_length > (hdr->format0.image_length - header_len)) {
				status = RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH;
				goto err_free_header;
			}

			if ((version_id_len == CERBERUS_PROTOCOL_FW_VERSION_LEN) || (version_id_len == 0)) {
				status = RECOVERY_IMAGE_HEADER_BAD_VERSION_ID;
				goto err_free_header;
			}

			break;
		}

		default:
			if (hdr_data_len < (sizeof (union recovery_image_header_format))) {
				status = RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH;
				goto err_free_header;
			}
	}

	return 0;

err_free_header:
	image_header_release (&header->base);
	return status;
}

/**
 * Release the recovery image header.
 *
 * @param header The header instance to release.
 */
void recovery_image_header_release (struct recovery_image_header *header)
{
	image_header_release (&header->base);
}

/**
 * Get the string version identifier for the recovery image from the header.
 *
 * @param header The header to query.
 * @param version_id Output for the version identifier.  The returned pointer should not be freed.
 * This will be NULL on error.
 *
 * @return 0 if the version identifier was available in the header or an error code.
 */
int recovery_image_header_get_version_id (struct recovery_image_header *header, char **version_id)
{
	if (version_id == NULL) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*version_id = NULL;
	if (header == NULL) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*version_id = ((union recovery_image_header_format*) header->base.data)->format0.version_id;

	return 0;
}

/**
 * Get the string platform identifier for the recovery image from the header.
 *
 * @param header The header to query.
 * @param platform_id Output for the platform identifier.  The returned pointer should not be freed.
 * This will be NULL on error.
 *
 * @return 0 if the platform identifier was available in the header or an error code.
 */
int recovery_image_header_get_platform_id (struct recovery_image_header *header, char **platform_id)
{
	if (platform_id == NULL) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*platform_id = NULL;
	if (header == NULL) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*platform_id = (char*) &header->base.data[RECOVERY_IMAGE_HEADER_FORMAT_LENGTH (0)];

	return 0;
}

/**
 * Get the total length of the recovery image.
 *
 * @param header The header to query.
 * @param length The output buffer for the recovery image length.
 *
 * @return 0 if the recovery image length was available in the header or an error code.
 */
int recovery_image_header_get_image_length (struct recovery_image_header *header, size_t *length)
{
	if ((header == NULL) || (length == NULL)) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*length = ((union recovery_image_header_format*) header->base.data)->format0.image_length;

	return 0;
}

/**
 * Get the total length of the recovery image header.
 *
 * @param header The header to query.
 * @param length The output buffer for the recovery image header length.
 *
 * @return 0 if the recovery image header length was available in the header or an error code.
 */ 
int recovery_image_header_get_length (struct recovery_image_header *header, size_t *length)
{
	if ((header == NULL) || (length == NULL)) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*length = image_header_get_length (&header->base);

	return 0;
}

/**
 * Get the length of the recovery image signature.
 *
 * @param header The header to query.
 * @param length The output buffer for the recovery image signature length.
 *
 * @return 0 if the recovery image signature length was available in the header or an error code.
 */
int recovery_image_header_get_signature_length (struct recovery_image_header *header,
	size_t *length)
{
	if ((header == NULL) || (length == NULL)) {
		return RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT;
	}

	*length = ((union recovery_image_header_format*) header->base.data)->format0.signature_length;

	return 0;
}
