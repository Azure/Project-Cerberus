// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_FORMAT_H_
#define PFM_FORMAT_H_

#include <stdint.h>
#include "manifest/manifest_format.h"


/**
 * The PFM is a variable length structure that has the following format:
 *
 * struct {
 * 		struct manifest_header
 * 		struct pfm_allowable_firmware_header
 * 		<allowable firmware>[pfm_allowable_firmware_header.fw_count]
 * 		struct pfm_key_manifest_header
 * 		<public keys>[pfm_key_manifest_header.key_count]
 * 		struct pfm_platform_header
 * 		char platform_id[pfm_platform_header.id_length]
 * 		uint8_t alignment[0..3]
 * 		uint8_t signature[manifest_header.sig_length]
 * }
 *
 *
 * Each allowable version of firmware is defined with a firmware version descriptor is a variable
 * length structure that has the following format:
 *
 * struct {
 * 		struct pfm_firmware_header
 * 		char version_id[pfm_firmware_header.version_length]
 * 		uint8_t alignment[0..3]
 * 		struct pfm_flash_region[pfm_firmware_header.rw_count]
 * 		<signed images>[pfm_firmware_header.img_count]
 * }
 *
 *
 * Each signed component for a particular version of firmware is defined with an image descriptor
 * that is a variable length structure that has the following format:
 *
 * struct {
 * 		struct pfm_image_header
 * 		uint8_t img_signature[pfm_image_header.sig_length]
 * 		struct pfm_flash_region[pfm_image_header.region_count]
 * }
 *
 *
 * Each public key contained in the key manifest is defined with a public key descriptor that is a
 * variable length structure that has the following format:
 *
 * struct {
 * 		struct pfm_public_key_header
 * 		uint8_t public_key_modulus[pfm_public_key_header.key_length]
 * }
 *
 *
 * All data in the PFM is stored in little endian format.
 * All unused/reserved entries must be 0.
 *
 */


/**
 * The header information for the PFM section that contains information for the firmware versions
 * that will be allowed to run.
 */
struct pfm_allowable_firmware_header {
	uint16_t length;		/**< The total length of the allowable firmware section. */
	uint8_t fw_count;		/**< The number of allowable firmware versions contained in the PFM. */
	uint8_t reserved;		/**< Unused. */
};

/**
 * The header information on each allowable firmware version.
 */
struct pfm_firmware_header {
	uint16_t length;		/**< The total length of the firmware version descriptor. */
	uint8_t version_length;	/**< The length of the version identifier. */
	uint8_t blank_byte;		/**< The value to use when blank checking unused flash regions. */
	uint32_t version_addr;	/**< The address in flash where the version identifier is stored. */
	uint8_t img_count;		/**< The number of firmware images for the version. */
	uint8_t rw_count;		/**< The number of defined read/write regions for the version. */
	uint16_t reserved;		/**< Unused. */
};

/**
 * Flags that can be set in an image header defined in the PFM.
 */
enum pfm_image_flags {
	PFM_IMAGE_MUST_VALIDATE = 0x01,		/**< The image must be validated on every host reset. */
};

/**
 * The header information on each signed firmware image in the PFM.
 */
struct pfm_image_header {
	uint16_t length;		/**< The total length of the firmware image descriptor. */
	uint16_t flags;			/**< Image flags. */
	uint8_t	key_id;			/**< The ID of the public key used to sign the image. */
	uint8_t region_count;	/**< The number of flash regions that make up the image. */
	uint16_t sig_length;	/**< The length of the signature for the image. */
};

/**
 * A region of flash defined in the PFM.
 */
struct pfm_flash_region {
	uint32_t start_addr;	/**< The first address in the region. */
	uint32_t end_addr;		/**< The last address in the region. */
};

/**
 * The header information for the PFM section that contains all the keys used to sign allowable
 * firmware images.
 */
struct pfm_key_manifest_header {
	uint16_t length;		/**< The total length of the key manifest section. */
	uint8_t key_count;		/**< The number of keys contained in the PFM. */
	uint8_t reserved;		/**< Unused. */
};

/**
 * The header information on each public key stored in the PFM.
 */
struct pfm_public_key_header {
	uint16_t length;		/**< The total length of the public key descriptor. */
	uint16_t key_length;	/**< The length of the public key. */
	uint32_t key_exponent;	/**< The exponent used for the signing key. */
	uint8_t id;				/**< The ID assigned to the key. */
	uint8_t reserved[3];	/**< Unused. */
};

/**
 * The header information for the platform information.
 */
struct pfm_platform_header {
	uint16_t length;		/**< The total length of the platform descriptor. */
	uint8_t id_length;		/**< The length of the platform identifier string. */
	uint8_t reserved;		/**< Unused. */
};


#endif /* PFM_FORMAT_H_ */
