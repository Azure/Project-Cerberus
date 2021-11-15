// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_V2_TESTING_H_
#define PFM_V2_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "manifest_v2_testing.h"


/*
 * Constant PFM sizes.
 */
#define	PFM_V2_FLASH_DEV_SIZE		4
#define	PFM_V2_FIRMWARE_HDR_SIZE	4
#define	PFM_V2_FW_VERSION_HDR_SIZE	8
#define	PFM_V2_RW_REGION_SIZE		12
#define	PFM_V2_IMG_HDR_SIZE			4
#define	PFM_V2_IMG_REGION_SIZE		8


/**
 * Describe a single read/write region defined for a firmware version.
 */
struct pfm_v2_testing_data_rw {
	uint32_t start_addr;								/**< The start address of the region. */
	uint32_t end_addr;									/**< The end address of the region. */
	uint8_t flags;										/**< Flags defined for the region. */
};

/**
 * Describe a single flash region defined for a firmware image.
 */
struct pfm_v2_testing_data_region {
	uint32_t start_addr;								/**< The start address of the region. */
	uint32_t end_addr;									/**< The end address of the region. */
};

/**
 * Describe a single firmware image for a firmware version.
 */
struct pfm_v2_testing_data_image {
	uint32_t img_offset;								/**< Offset for the start of the image definition. */
	const uint8_t *hash;								/**< The firmware image hash. */
	size_t hash_len;									/**< Length of the image hash. */
	enum hash_type hash_type;							/**< The type of hash used for the image. */
	uint8_t flags;										/**< Flags defined for the image. */
	int region_count;									/**< The number of regions for the image hash. */
	const struct pfm_v2_testing_data_region *region;	/**< List of hashed regions. */
};

/**
 * Determine the length of a PFM region based on the start and end address.
 */
#define	PFM_V2_TESTING_REGION_LENGTH(x)		((((x)->end_addr) + 1) - ((x)->start_addr))

/**
 * Determine the length of a PFM image definition.
 */
#define	PFM_V2_TESTING_IMG_LENGTH(x)		(PFM_V2_IMG_HDR_SIZE + ((x)->hash_len) + ((x)->region_count * PFM_V2_IMG_REGION_SIZE))

/**
 * Describe a single firmware version element in a PFM.
 */
struct pfm_v2_testing_data_fw_ver {
	const uint8_t *fw_version;							/**< Firmware Version element data. */
	size_t fw_version_len;								/**< Firmware Version element length. */
	const char *version_str;							/**< Version string in the element.  Not the raw manifest data. */
	size_t version_str_len;								/**< Length of the version string. */
	size_t version_str_pad;								/**< Padding added to the version string. */
	uint32_t fw_version_offset;							/**< Offset of the firmware version element. */
	int fw_version_entry;								/**< TOC entry for the firmware version element. */
	int fw_version_hash;								/**< TOC hash for the firmware version element. */
	uint32_t version_addr;								/**< Host address of the version string. */
	int rw_count;										/**< The number of R/W regions for this version. */
	const struct pfm_v2_testing_data_rw *rw;			/**< List of R/W regions. */
	int img_count;										/**< The number of images for this version. */
	const struct pfm_v2_testing_data_image *img;		/**< List of firmware images. */
};

/**
 * Describe a single firmware element in a PFM.
 */
struct pfm_v2_testing_data_fw {
	const uint8_t *fw;									/**< Firmware element data. */
	size_t fw_len;										/**< Firmware element length. */
	const char *fw_id_str;								/**< Firmware ID string in the element.  Not the raw manifest data. */
	size_t fw_id_str_len;								/**< Length of the firmware ID string. */
	size_t fw_id_str_pad;								/**< Padding added to the firmware ID string. */
	uint32_t fw_offset;									/**< Offset of the firmware element. */
	int fw_entry;										/**< TOC entry for the firmware element. */
	int fw_hash;										/**< TOC hash for the firmware element. */
	int version_count;									/**< The number of FW version elements for this firmware. */
	const struct pfm_v2_testing_data_fw_ver *version;	/**< List of firmware version elements. */
};

/**
 * Describe a test PFM structure.
 */
struct pfm_v2_testing_data {
	struct manifest_v2_testing_data manifest;			/**< Common manifest components. */
	const uint8_t *flash_dev;							/**< Flash Device element data. */
	size_t flash_dev_len;								/**< Flash Device element data length. */
	uint32_t flash_dev_offset;							/**< Offset of the flash device element. */
	int flash_dev_entry;								/**< TOC entry for the flash device element. */
	int flash_dev_hash;									/**< TOC hash for the flash device element. */
	int blank_byte;										/**< Blank byte specified in the PFM. */
	int fw_count;										/**< The number of FW elements in the manifest. */
	const struct pfm_v2_testing_data_fw *fw;			/**< List of FW elements. */
};


#endif /* PFM_V2_TESTING_H_ */
