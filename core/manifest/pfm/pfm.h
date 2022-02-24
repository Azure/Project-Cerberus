// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_H_
#define PFM_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "flash/flash_util.h"
#include "manifest/manifest.h"


/**
 * A list of firmware components present in the manifest.
 */
struct pfm_firmware {
	const char **ids;								/**< The list of IDs for each firmware. */
	size_t count;									/**< The number of firmware IDs in the list. */
};

/**
 * The information for a single firmware version.
 */
struct pfm_firmware_version {
	const char *fw_version_id;						/**< Version identifier for the firmware. */
	uint32_t version_addr;							/**< The flash address containing the version identifier. */
	uint8_t blank_byte;								/**< The value to be used with this version for blank checking. */
};

/**
 * A list of firmware versions.
 */
struct pfm_firmware_versions {
	const struct pfm_firmware_version *versions;	/**< A list of version identifiers. */
	size_t count;									/**< The number of items in the list. */
};

/**
 * Options for how to manage read/write regions during authentication failures.
 */
enum pfm_read_write_management {
	PFM_RW_DO_NOTHING = 0,							/**< Do nothing with the existing R/W data. */
	PFM_RW_RESTORE = 1,								/**< Restore the region from the RO flash. */
	PFM_RW_ERASE = 2,								/**< Erase the region. */
	PFM_RW_RESERVED = 3								/**< Reserved.  Same as option 0. */
};

/**
 * Additional information about a single read/write flash region.
 */
struct pfm_read_write {
	enum pfm_read_write_management on_failure;		/**< The operation to execute on this region after authentication failure. */
};

/**
 * A list of read/write flash regions.
 */
struct pfm_read_write_regions {
	const struct flash_region *regions;				/**< The list of read/write regions. */
	const struct pfm_read_write *properties;		/**< A list of properties for the read/write regions. */
	size_t count;									/**< The number of regions defined. */
};

/**
 * Defines a complete firmware image that is signed.
 */
struct pfm_image_signature {
	const struct flash_region *regions;				/**< The flash regions that make up the signed image. */
	size_t count;									/**< The number of regions in the image. */
	struct rsa_public_key key;						/**< The RSA key used to sign the image. */
	uint8_t signature[RSA_MAX_KEY_LENGTH];			/**< The image signature. */
	size_t sig_length;								/**< The length of the image signature. */
	uint8_t always_validate;						/**< Flag indicating if this image should be validated on every system boot. */
};

/**
 * Defines a complete firmware image that must be validated.
 */
struct pfm_image_hash {
	const struct flash_region *regions;				/**< The flash regions that make up the signed image. */
	size_t count;									/**< The number of regions in the image. */
	uint8_t hash[SHA512_HASH_LENGTH];				/**< The image hash. */
	size_t hash_length;								/**< The length of the image hash. */
	enum hash_type hash_type;						/**< The algorithm used to generate the image hash. */
	uint8_t always_validate;						/**< Flag indicating if this image should be validated on every system boot. */
};

/**
 * A list of firmware images.
 *
 * Images authenticated with signatures or hashes can be used, but only one type of authentication
 * is possible in a single instance.  Only one of the two lists will contain data and the other will
 * be null.
 */
struct pfm_image_list {
	const struct pfm_image_signature *images_sig;	/**< The list of images using signature authentication. */
	const struct pfm_image_hash *images_hash;		/**< The list of images using hash authentication. */
	size_t count;									/**< The number of images in the list. */
};

/**
 * The API for interfacing with the Platform Firmware Manifest for a single device.
 */
struct pfm {
	struct manifest base;							/**< Manifest interface */

	/**
	 * Get the list of firmware components contained in the PFM.
	 *
	 * @param pfm The PFM to query.
	 * @param fw A structure to be updated with the list of firmware components.
	 *
	 * @return 0 if the firmware list was updated successfully or an error code.
	 */
	int (*get_firmware) (struct pfm *pfm, struct pfm_firmware *fw);

	/**
	 * Free a list of firmware components.
	 *
	 * @param pfm The PFM instance that provided the list.
	 * @param fw The supported firmware list to free.
	 */
	void (*free_firmware) (struct pfm *pfm, struct pfm_firmware *fw);

	/**
	 * Get the list of supported firmware versions advertised in the PFM.
	 *
	 * @param pfm The PFM to query.
	 * @param fw The firmware to query.  If this is null, the first firmware component will be
	 * queried.
	 * @param ver_list A structure to be updated with the list supported firmware versions.
	 *
	 * @return 0 if the version list was updated successfully or an error code.
	 */
	int (*get_supported_versions) (struct pfm *pfm, const char *fw,
		struct pfm_firmware_versions *ver_list);

	/**
	 * Free a list of firmware versions.
	 *
	 * @param pfm The PFM instance that provided the list.
	 * @param ver_list The supported version list to free.
	 */
	void (*free_fw_versions) (struct pfm *pfm, struct pfm_firmware_versions *ver_list);

	/**
	 * Get the list of supported firmware versions advertised in the PFM, but the list of version
	 * strings will be populated directly in the provided buffer instead of allocating a PFM
	 * structure.
	 *
	 * @param pfm The PFM to query.
	 * @param fw The firmware to query.  If this is null, all firmware components will be queried
	 * and the firmware IDs will also be stored in the buffer.
	 * @param offset The offset within the overall list of firmware versions that should be
	 * returned.
	 * @param length The maximum length of version information that should be returned.
	 * @param ver_list Output buffer for the list of supported versions.  This buffer can overlap
	 * with the firmware ID, allowing the caller to use a single buffer for both input and output.
	 *
	 * @return The number of bytes written to the output buffer or an error code.  Use ROT_IS_ERROR
	 * to check the return value.
	 */
	int (*buffer_supported_versions) (struct pfm *pfm, const char *fw, size_t offset, size_t length,
		uint8_t *ver_list);

	/**
	 * Get the list of all read/write regions defined for a specific version of firmware.
	 *
	 * @param pfm The PFM to query.
	 * @param fw The firmware to query.  If this is null, the first firmware component will be
	 * queried.
	 * @param version The firmware version to query.
	 * @param writable A structure to be updated with the list of read/write flash regions.
	 *
	 * @return 0 if the region list was updated successfully or an error code.
	 */
	int (*get_read_write_regions) (struct pfm *pfm, const char *fw, const char *version,
		struct pfm_read_write_regions *writable);

	/**
	 * Free a list of read/write regions.
	 *
	 * @param pfm THe PFM instance that provided the list.
	 * @param writable The read/write regions list to free.
	 */
	void (*free_read_write_regions) (struct pfm *pfm, struct pfm_read_write_regions *writable);

	/**
	 * Get the list of all signed firmware components for a specific version of firmware.
	 *
	 * @param pfm The PFM to query.
	 * @param fw The firmware to query.  If this is null, the first firmware component will be
	 * queried.
	 * @param version The firmware version to query.
	 * @param img_list A structure to be updated with the list of signed components.
	 *
	 * @return 0 if the image list was updated successfully or an error code.
	 */
	int (*get_firmware_images) (struct pfm *pfm, const char *fw, const char *version,
		struct pfm_image_list *img_list);

	/**
	 * Free a list of firmware images.
	 *
	 * @param pfm The PFM instance that provided the list.
	 * @param img_list The list of images to free.
	 */
	void (*free_firmware_images) (struct pfm *pfm, struct pfm_image_list *img_list);
};


#define	PFM_ERROR(code)		ROT_ERROR (ROT_MODULE_PFM, code)

/**
 * Error codes that can be generated by a PFM.
 */
enum {
	PFM_INVALID_ARGUMENT = PFM_ERROR (0x00),			/**< Input parameter is null or not valid. */
	PFM_NO_MEMORY = PFM_ERROR (0x01),					/**< Memory allocation failed. */
	PFM_GET_VERSIONS_FAILED = PFM_ERROR (0x02),			/**< The supported firmware version list was not generated. */
	PFM_GET_READ_WRITE_FAILED = PFM_ERROR (0x03),		/**< The list of read/write regions was not generated. */
	PFM_GET_FW_IMAGES_FAILED = PFM_ERROR (0x04),		/**< The list of signed firmware was not generated. */
	PFM_UNSUPPORTED_VERSION = PFM_ERROR (0x05),			/**< The firmware version is not supported by the PFM. */
	PFM_UNKNOWN_KEY_ID = PFM_ERROR (0x06),				/**< A firmware image is signed with a key not in the PFM. */
	PFM_GET_FW_FAILED = PFM_ERROR (0x07),				/**< The list of firmware components was not generated. */
	PFM_UNKNOWN_FIRMWARE = PFM_ERROR (0x08),			/**< The requested firmware component is not in the PFM. */
	PFM_READ_WRITE_UNSUPPORTED = PFM_ERROR (0x09),		/**< A read/write region configuration is not supported. */
	PFM_UNKNOWN_HASH_TYPE = PFM_ERROR (0x0a),			/**< A firmware image uses an unknown hashing algorithm. */
	PFM_FW_IMAGE_UNSUPPORTED = PFM_ERROR (0x0b),		/**< An authenticated image configuration is not supported. */
	PFM_MALFORMED_FLASH_DEV_ELEMENT = PFM_ERROR (0x0c),	/**< The flash device element in the PFM is malformed. */
	PFM_MALFORMED_FIRMWARE_ELEMENT = PFM_ERROR (0x0d),	/**< A firmware element in the PFM is malformed. */
	PFM_MALFORMED_FW_VER_ELEMENT = PFM_ERROR (0x0e),	/**< A firmware version element in the PFM is malformed. */
	PFM_KEY_UNSUPPORTED = PFM_ERROR (0x0f),				/**< A firmware image signing key is not supported. */
};


#endif /* PFM_H_ */
