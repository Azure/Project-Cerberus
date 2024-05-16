// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_IMAGE_H_
#define FIRMWARE_IMAGE_H_

#include <stdint.h>
#include "crypto/hash.h"
#include "firmware/firmware_header.h"
#include "firmware/key_manifest.h"
#include "flash/flash.h"
#include "status/rot_status.h"


/**
 * A platform-independent API for managing a complete firmware image for the system.  Firmware image
 * instances are not guaranteed to be thread-safe.
 */
struct firmware_image {
	/**
	 * Update the image referenced by an instance.
	 *
	 * This does not copy the image into memory for execution.  This function just parses the image
	 * metadata to determine structure and length for use by other API calls.
	 *
	 * @param fw The firmware image instance to update.
	 * @param flash The flash device that contains the firmware image.
	 * @param base_addr The starting address of the new firmware image.
	 *
	 * @return 0 if the image reference was updated successfully or an error code.
	 */
	int (*load) (const struct firmware_image *fw, const struct flash *flash, uint32_t base_addr);

	/**
	 * Verify the complete firmware image.  All components in the image will be fully validated.
	 * This includes checking image signatures and key revocation.
	 *
	 * Image structures and signing requirements can vary greatly between different devices.  Any
	 * additional crypto, such as RSA or ECC, that is required for image verification must be
	 * included as part of the specific implementation.
	 *
	 * @param fw The firmware image to validate.
	 * @param hash The hash engine to use for validation.
	 *
	 * @return 0 if the firmware image is valid or an error code.  If verification failed due to an
	 * incorrect signature, FIRMWARE_IMAGE_BAD_SIGNATURE will be returned, regardless of the
	 * underlying signature verification algorithm.
	 */
	int (*verify) (const struct firmware_image *fw, struct hash_engine *hash);

	/**
	 * Get the total size of the firmware image.
	 *
	 * @param fw The firmware image to query.
	 *
	 * @return The size of the firmware image or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*get_image_size) (const struct firmware_image *fw);

	/**
	 * Get the key manifest for the current firmware image.
	 *
	 * @param fw The firmware image to query.
	 *
	 * @return The image key manifest or null if there is an error.  The memory for the key
	 * manifest is managed by the firmware image instance and is only guaranteed to be valid until
	 * the next call to firmware_image.load.
	 */
	const struct key_manifest* (*get_key_manifest) (const struct firmware_image *fw);

	/**
	 * Get the main image header for the current firmware image.
	 *
	 * @param fw The firmware image to query.
	 *
	 * @return The image firmware header or null if there is an error.  The memory for the header
	 * is managed by the firmware image instance and is only guaranteed to be valid until the next
	 * call to firmware_image.load.
	 */
	const struct firmware_header* (*get_firmware_header) (const struct firmware_image *fw);
};


#define	FIRMWARE_IMAGE_ERROR(code)		ROT_ERROR (ROT_MODULE_FIRMWARE_IMAGE, code)

/**
 * Error codes that can be generated when accessing the firmware image.
 */
enum {
	FIRMWARE_IMAGE_INVALID_ARGUMENT = FIRMWARE_IMAGE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	FIRMWARE_IMAGE_NO_MEMORY = FIRMWARE_IMAGE_ERROR (0x01),				/**< Memory allocation failed. */
	FIRMWARE_IMAGE_LOAD_FAILED = FIRMWARE_IMAGE_ERROR (0x02),			/**< The firmware image was not parsed. */
	FIRMWARE_IMAGE_VERIFY_FAILED = FIRMWARE_IMAGE_ERROR (0x03),			/**< An error not related to image validity caused verification to fail. */
	FIRMWARE_IMAGE_GET_SIZE_FAILED = FIRMWARE_IMAGE_ERROR (0x04),		/**< The image size could not be determined. */
	FIRMWARE_IMAGE_GET_MANIFEST_FAILED = FIRMWARE_IMAGE_ERROR (0x05),	/**< No key manifest could be retrieved. */
	FIRMWARE_IMAGE_INVALID_FORMAT = FIRMWARE_IMAGE_ERROR (0x06),		/**< The image structure is not valid. */
	FIRMWARE_IMAGE_BAD_CHECKSUM = FIRMWARE_IMAGE_ERROR (0x07),			/**< A checksum within in the image structure failed verification. */
	FIRMWARE_IMAGE_NOT_LOADED = FIRMWARE_IMAGE_ERROR (0x08),			/**< No firmware image has been loaded by the instance. */
	FIRMWARE_IMAGE_NO_APP_KEY = FIRMWARE_IMAGE_ERROR (0x09),			/**< Could not get the application signing key. */
	FIRMWARE_IMAGE_MANIFEST_REVOKED = FIRMWARE_IMAGE_ERROR (0x0a),		/**< The key manifest contained in the image has been revoked. */
	FIRMWARE_IMAGE_NOT_AVAILABLE = FIRMWARE_IMAGE_ERROR (0x0b),			/**< A firmware component is not available in the image. */
	FIRMWARE_IMAGE_INVALID_SIGNATURE = FIRMWARE_IMAGE_ERROR (0x0c),		/**< An image signature is malformed. */
	FIRMWARE_IMAGE_FORCE_RECOVERY = FIRMWARE_IMAGE_ERROR (0x0d),		/**< Force loading the recovery firmware image. */
	FIRMWARE_IMAGE_BAD_SIGNATURE = FIRMWARE_IMAGE_ERROR (0x0e),			/**< Signature verification of the image failed. */
	FIRMWARE_IMAGE_REVOKED = FIRMWARE_IMAGE_ERROR (0x0f),				/**< Firmware data contained in the image has been revoked. */
};


#endif	/* FIRMWARE_IMAGE_H_ */
