// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_IMAGE_H_
#define FIRMWARE_IMAGE_H_

#include <stdint.h>
#include "status/rot_status.h"
#include "flash/flash.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "firmware/key_manifest.h"
#include "firmware/firmware_header.h"


/**
 * A platform-independent API for managing a complete firmware image for the system.
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
	 * @return 0 if the image reference was updated successfully or an error code.  Load-time
	 * validation errors will generate one of the following errors:
	 * 		- FIRMWARE_IMAGE_INVALID_FORMAT
	 * 		- FIRMWARE_IMAGE_BAD_CHECKSUM
	 * 		- KEY_MANIFEST_INVALID_FORMAT
	 * 		- FIRMWARE_HEADER or IMAGE_HEADER validation errors
	 */
	int (*load) (struct firmware_image *fw, struct flash *flash, uint32_t base_addr);

	/**
	 * Verify the complete firmware image.  All components in the image will be fully validated.
	 * This includes checking image signatures and key revocation.
	 *
	 * @param fw The firmware image to validate.
	 * @param hash The hash engine to use for validation.
	 * @param rsa The RSA engine to use for signature checking.
	 *
	 * @return 0 if the firmware image is valid or an error code.
	 */
	int (*verify) (struct firmware_image *fw, struct hash_engine *hash, struct rsa_engine *rsa);

	/**
	 * Get the total size of the firmware image.
	 *
	 * @param fw The firmware image to query.
	 *
	 * @return The size of the firmware image or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*get_image_size) (struct firmware_image *fw);

	/**
	 * Get the key manifest for the current firmware image.
	 *
	 * @param fw The firmware image to query.
	 *
	 * @return The image key manifest or null if there is an error.  The memory for the key
	 * manifest is managed by the firmware image instance and is only guaranteed to be valid until
	 * the next call to firmware_image.load.
	 */
	struct key_manifest* (*get_key_manifest) (struct firmware_image *fw);

	/**
	 * Get the main image header for the current firmware image.
	 *
	 * @param fw The firmware image to query.
	 *
	 * @return The image firmware header or null if there is an error.  The memory for the header
	 * is managed by the firmware image instance and is only guaranteed to be valid until the next
	 * call to firmware_image.load.
	 */
	struct firmware_header* (*get_firmware_header) (struct firmware_image *fw);
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
};


#endif /* FIRMWARE_IMAGE_H_ */
