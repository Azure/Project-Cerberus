// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FW_UTIL_H_
#define HOST_FW_UTIL_H_

#include <stdbool.h>
#include <stdint.h>
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "flash/spi_flash.h"
#include "manifest/pfm/pfm.h"
#include "spi_filter/spi_filter_interface.h"
#include "status/rot_status.h"


int host_fw_determine_version (const struct spi_flash *flash,
	const struct pfm_firmware_versions *allowed, const struct pfm_firmware_version **version);
int host_fw_determine_offset_version (const struct spi_flash *flash, uint32_t offset,
	const struct pfm_firmware_versions *allowed, const struct pfm_firmware_version **version);

bool host_fw_are_images_different (const struct pfm_image_list *img_list1,
	const struct pfm_image_list *img_list2);

int host_fw_verify_images (const struct spi_flash *flash, const struct pfm_image_list *img_list,
	const struct hash_engine *hash, const struct rsa_engine *rsa);
int host_fw_verify_offset_images (const struct spi_flash *flash,
	const struct pfm_image_list *img_list, uint32_t offset, const struct hash_engine *hash,
	const struct rsa_engine *rsa);
int host_fw_verify_images_multiple_fw (const struct spi_flash *flash,
	const struct pfm_image_list *img_list, size_t fw_count, const struct hash_engine *hash,
	const struct rsa_engine *rsa);
int host_fw_verify_offset_images_multiple_fw (const struct spi_flash *flash,
	const struct pfm_image_list *img_list, size_t fw_count, uint32_t offset,
	const struct hash_engine *hash, const struct rsa_engine *rsa);

int host_fw_full_flash_verification (const struct spi_flash *flash,
	const struct pfm_image_list *img_list, const struct pfm_read_write_regions *writable,
	uint8_t unused_byte, const struct hash_engine *hash, const struct rsa_engine *rsa);
int host_fw_full_flash_verification_multiple_fw (const struct spi_flash *flash,
	const struct pfm_image_list *img_list, const struct pfm_read_write_regions *writable,
	size_t fw_count, uint8_t unused_byte, const struct hash_engine *hash,
	const struct rsa_engine *rsa);

bool host_fw_are_read_write_regions_different (const struct pfm_read_write_regions *rw1,
	const struct pfm_read_write_regions *rw2);

int host_fw_migrate_read_write_data (const struct spi_flash *dest,
	const struct pfm_read_write_regions *dest_writable, const struct spi_flash *src,
	const struct pfm_read_write_regions *src_writable);
int host_fw_migrate_read_write_data_multiple_fw (const struct spi_flash *dest,
	const struct pfm_read_write_regions *dest_writable, size_t dest_count,
	const struct spi_flash *src, const struct pfm_read_write_regions *src_writable,
	size_t src_count);

int host_fw_restore_flash_device (const struct spi_flash *restore, const struct spi_flash *from,
	const struct pfm_image_list *img_list, const struct pfm_read_write_regions *writable);

int host_fw_restore_read_write_data (const struct spi_flash *restore, const struct spi_flash *from,
	const struct pfm_read_write_regions *writable);
int host_fw_restore_read_write_data_multiple_fw (const struct spi_flash *restore,
	const struct spi_flash *from, const struct pfm_read_write_regions *writable, size_t fw_count);

int host_fw_config_spi_filter_read_write_regions (const struct spi_filter_interface *filter,
	const struct pfm_read_write_regions *writable);
int host_fw_config_spi_filter_read_write_regions_multiple_fw (
	const struct spi_filter_interface *filter, const struct pfm_read_write_regions *writable,
	size_t fw_count);


#define	HOST_FW_UTIL_ERROR(code)		ROT_ERROR (ROT_MODULE_HOST_FW_UTIL, code)

/**
 * Error codes that can be generated by the host firmware utilities.
 */
enum {
	HOST_FW_UTIL_INVALID_ARGUMENT = HOST_FW_UTIL_ERROR (0x00),		/**< Input parameter is null or not valid. */
	HOST_FW_UTIL_NO_MEMORY = HOST_FW_UTIL_ERROR (0x01),				/**< Memory allocation failed. */
	HOST_FW_UTIL_UNSUPPORTED_VERSION = HOST_FW_UTIL_ERROR (0x02),	/**< The host firmware does not match a supported version. */
	HOST_FW_UTIL_DIFF_REGION_COUNT = HOST_FW_UTIL_ERROR (0x03),		/**< Data migration with a different number of regions. */
	HOST_FW_UTIL_DIFF_REGION_ADDR = HOST_FW_UTIL_ERROR (0x04),		/**< Data migration with different region addresses. */
	HOST_FW_UTIL_DIFF_REGION_SIZE = HOST_FW_UTIL_ERROR (0x05),		/**< Data migration with different region sizes. */
	HOST_FW_UTIL_BAD_IMAGE_HASH = HOST_FW_UTIL_ERROR (0x06),		/**< A host firmware image on flash has an invalid hash. */
	HOST_FW_UTIL_DIFF_FW_COUNT = HOST_FW_UTIL_ERROR (0x07),			/**< Data migration with a different number of FW components. */
};


#endif	/* HOST_FW_UTIL_H_ */
