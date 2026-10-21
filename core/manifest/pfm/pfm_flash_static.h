// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_FLASH_STATIC_H_
#define PFM_FLASH_STATIC_H_

#include "pfm_flash.h"
#include "manifest/manifest_flash_static.h"


/* Internal functions declared to allow for static initialization. */
int pfm_flash_verify (const struct manifest *pfm, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);
int pfm_flash_get_id (const struct manifest *pfm, uint32_t *id);
int pfm_flash_get_platform_id (const struct manifest *pfm, char **id, size_t length);
void pfm_flash_free_platform_id (const struct manifest *manifest, char *id);
int pfm_flash_get_hash (const struct manifest *pfm, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length);
int pfm_flash_get_signature (const struct manifest *pfm, uint8_t *signature, size_t length);
int pfm_flash_is_empty (const struct manifest *pfm);

int pfm_flash_verify_v2_only (const struct manifest *pfm, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);
int pfm_flash_is_empty_v2_only (const struct manifest *pfm);

int pfm_flash_get_firmware (const struct pfm *pfm, struct pfm_firmware *fw);
void pfm_flash_free_firmware (const struct pfm *pfm, struct pfm_firmware *fw);
int pfm_flash_get_supported_versions (const struct pfm *pfm, const char *fw,
	struct pfm_firmware_versions *ver_list);
void pfm_flash_free_fw_versions (const struct pfm *pfm, struct pfm_firmware_versions *ver_list);
int pfm_flash_buffer_supported_versions (const struct pfm *pfm, const char *fw, size_t offset,
	size_t length, uint8_t *ver_list);
int pfm_flash_get_read_write_regions (const struct pfm *pfm, const char *fw, const char *version,
	struct pfm_read_write_regions *writable);
void pfm_flash_free_read_write_regions (const struct pfm *pfm,
	struct pfm_read_write_regions *writable);
int pfm_flash_get_firmware_images (const struct pfm *pfm, const char *fw, const char *version,
	struct pfm_image_list *img_list);
void pfm_flash_free_firmware_images (const struct pfm *pfm, struct pfm_image_list *img_list);

int pfm_flash_get_firmware_v2_only (const struct pfm *pfm, struct pfm_firmware *fw);
int pfm_flash_get_supported_versions_v2_only (const struct pfm *pfm, const char *fw,
	struct pfm_firmware_versions *ver_list);
int pfm_flash_buffer_supported_versions_v2_only (const struct pfm *pfm, const char *fw,
	size_t offset, size_t length, uint8_t *ver_list);
int pfm_flash_get_read_write_regions_v2_only (const struct pfm *pfm, const char *fw,
	const char *version, struct pfm_read_write_regions *writable);
int pfm_flash_get_firmware_images_v2_only (const struct pfm *pfm, const char *fw,
	const char *version, struct pfm_image_list *img_list);


/**
 * Constant initializer for the PFM API to support both v1 and v2 PFMs.
 */
#define	PFM_FLASH_API_INIT  { \
		.base = { \
			.verify = pfm_flash_verify, \
			.get_id = pfm_flash_get_id, \
			.get_platform_id = pfm_flash_get_platform_id, \
			.free_platform_id = pfm_flash_free_platform_id, \
			.get_hash = pfm_flash_get_hash, \
			.get_signature = pfm_flash_get_signature, \
			.is_empty = pfm_flash_is_empty, \
		}, \
		.get_firmware = pfm_flash_get_firmware, \
		.free_firmware = pfm_flash_free_firmware, \
		.get_supported_versions = pfm_flash_get_supported_versions, \
		.free_fw_versions = pfm_flash_free_fw_versions, \
		.buffer_supported_versions = pfm_flash_buffer_supported_versions, \
		.get_read_write_regions = pfm_flash_get_read_write_regions, \
		.free_read_write_regions = pfm_flash_free_read_write_regions, \
		.get_firmware_images = pfm_flash_get_firmware_images, \
		.free_firmware_images = pfm_flash_free_firmware_images, \
	}

/**
 * Constant initializer for the PFM API to only support v2 PFMs.
 */
#define	PFM_FLASH_V2_API_INIT  { \
		.base = { \
			.verify = pfm_flash_verify_v2_only,\
			.get_id = pfm_flash_get_id, \
			.get_platform_id = pfm_flash_get_platform_id, \
			.free_platform_id = pfm_flash_free_platform_id, \
			.get_hash = pfm_flash_get_hash, \
			.get_signature = pfm_flash_get_signature, \
			.is_empty = pfm_flash_is_empty_v2_only, \
		}, \
		.get_firmware = pfm_flash_get_firmware_v2_only, \
		.free_firmware = pfm_flash_free_firmware, \
		.get_supported_versions = pfm_flash_get_supported_versions_v2_only, \
		.free_fw_versions = pfm_flash_free_fw_versions, \
		.buffer_supported_versions = pfm_flash_buffer_supported_versions_v2_only, \
		.get_read_write_regions = pfm_flash_get_read_write_regions_v2_only, \
		.free_read_write_regions = pfm_flash_free_read_write_regions, \
		.get_firmware_images = pfm_flash_get_firmware_images_v2_only, \
		.free_firmware_images = pfm_flash_free_firmware_images, \
	}


/**
 * Initialize a static interface to a PFM residing in flash memory.  Both PFM version 1 and 2 will
 * be supported.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the PFM instance.  This must be uninitialized.
 * @param flash_ptr The flash device that contains the PFM.
 * @param hash_ptr A hash engine to use for validating run-time access to PFM information.  If it is
 * possible for any PFM information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe.  There is no internal synchronization around the hashing operations.
 * @param base_addr_arg The starting address of the PFM storage location.
 * @param signature_cache_ptr Buffer to hold the manifest signature.
 * @param max_signature_arg The maximum supported length for a manifest signature.
 * @param platform_id_cache_ptr Buffer to hold the manifest platform ID.
 * @param max_platform_id_arg The maximum platform ID length supported, including the NULL
 * terminator.
 */
#define	pfm_flash_static_init(state_ptr, flash_ptr, hash_ptr, base_addr_arg, signature_cache_ptr, \
	max_signature_arg, platform_id_cache_ptr, max_platform_id_arg)	{ \
		.base = PFM_FLASH_API_INIT, \
		.base_flash = manifest_flash_v2_static_init (&(state_ptr)->base, flash_ptr, hash_ptr, \
			base_addr_arg, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, signature_cache_ptr, \
			max_signature_arg, platform_id_cache_ptr, max_platform_id_arg), \
		.state = state_ptr, \
	}

/**
 * Initialize a static interface to a PFM residing in flash memory.  Only PFM version 2 will be
 * supported.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the PFM instance.  This must be uninitialized.
 * @param flash_ptr The flash device that contains the PFM.
 * @param hash_ptr A hash engine to use for validating run-time access to PFM information.  If it is
 * possible for any PFM information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe.  There is no internal synchronization around the hashing operations.
 * @param base_addr_arg The starting address of the PFM storage location.
 * @param signature_cache_ptr Buffer to hold the manifest signature.
 * @param max_signature_arg The maximum supported length for a manifest signature.
 * @param platform_id_cache_ptr Buffer to hold the manifest platform ID.
 * @param max_platform_id_arg The maximum platform ID length supported, including the NULL
 * terminator.
 */
#define	pfm_flash_v2_static_init(state_ptr, flash_ptr, hash_ptr, base_addr_arg, \
	signature_cache_ptr, max_signature_arg, platform_id_cache_ptr, max_platform_id_arg)	{ \
		.base = PFM_FLASH_V2_API_INIT, \
		.base_flash = manifest_flash_v2_static_init (&(state_ptr)->base, flash_ptr, hash_ptr, \
			base_addr_arg, MANIFEST_NOT_SUPPORTED, PFM_V2_MAGIC_NUM, signature_cache_ptr, \
			max_signature_arg, platform_id_cache_ptr, max_platform_id_arg), \
		.state = state_ptr, \
	}


#endif	/* PFM_FLASH_STATIC_H_ */
