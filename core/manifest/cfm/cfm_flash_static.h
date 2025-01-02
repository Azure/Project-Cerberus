// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_FLASH_STATIC_H_
#define CFM_FLASH_STATIC_H_

#include "cfm_flash.h"
#include "manifest/manifest_flash_static.h"


/* Internal functions declared to allow for static initialization. */
int cfm_flash_verify (const struct manifest *cfm, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);
int cfm_flash_get_id (const struct manifest *cfm, uint32_t *id);
int cfm_flash_get_platform_id (const struct manifest *cfm, char **id, size_t length);
void cfm_flash_free_platform_id (const struct manifest *manifest, char *id);
int cfm_flash_get_hash (const struct manifest *cfm, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length);
int cfm_flash_get_signature (const struct manifest *cfm, uint8_t *signature, size_t length);
int cfm_flash_is_empty (const struct manifest *cfm);

int cfm_flash_get_component_device (const struct cfm *cfm, uint32_t component_id,
	struct cfm_component_device *component);
void cfm_flash_free_component_device (const struct cfm *cfm,
	struct cfm_component_device *component);
int cfm_flash_buffer_supported_components (const struct cfm *cfm, size_t offset, size_t length,
	uint8_t *component_ids);
int cfm_flash_get_component_pmr (const struct cfm *cfm, uint32_t component_id, uint8_t pmr_id,
	struct cfm_pmr *pmr);
void cfm_flash_free_component_pmr_digest (const struct cfm *cfm, struct cfm_pmr_digest *pmr_digest);
int cfm_flash_get_next_measurement_or_measurement_data (const struct cfm *cfm,
	uint32_t component_id, struct cfm_measurement_container *container, bool first);
int cfm_flash_get_component_pmr_digest (const struct cfm *cfm, uint32_t component_id,
	uint8_t pmr_id, struct cfm_pmr_digest *pmr_digest);
void cfm_flash_free_measurement_container (const struct cfm *cfm,
	struct cfm_measurement_container *container);
int cfm_flash_get_root_ca_digest (const struct cfm *cfm, uint32_t component_id,
	struct cfm_root_ca_digests *root_ca_digest);
void cfm_flash_free_root_ca_digest (const struct cfm *cfm,
	struct cfm_root_ca_digests *root_ca_digest);
int cfm_flash_get_next_pfm (const struct cfm *cfm, uint32_t component_id,
	struct cfm_manifest *allowable_pfm, bool first);
int cfm_flash_get_next_cfm (const struct cfm *cfm, uint32_t component_id,
	struct cfm_manifest *allowable_cfm, bool first);
int cfm_flash_get_pcd (const struct cfm *cfm, uint32_t component_id,
	struct cfm_manifest *allowable_pcd);
void cfm_flash_free_manifest (const struct cfm *cfm, struct cfm_manifest *manifest);


/**
 * Constant initializer for the CFM API.
 */
#define	CFM_FLASH_API_INIT  { \
		.base = { \
			.verify = cfm_flash_verify, \
			.get_id = cfm_flash_get_id, \
			.get_platform_id = cfm_flash_get_platform_id, \
			.free_platform_id = cfm_flash_free_platform_id, \
			.get_hash = cfm_flash_get_hash, \
			.get_signature = cfm_flash_get_signature, \
			.is_empty = cfm_flash_is_empty, \
		}, \
		.get_component_device = cfm_flash_get_component_device, \
		.free_component_device = cfm_flash_free_component_device, \
		.buffer_supported_components = cfm_flash_buffer_supported_components, \
		.get_component_pmr = cfm_flash_get_component_pmr, \
		.get_component_pmr_digest = cfm_flash_get_component_pmr_digest, \
		.free_component_pmr_digest = cfm_flash_free_component_pmr_digest, \
		.get_next_measurement_or_measurement_data = \
			cfm_flash_get_next_measurement_or_measurement_data, \
		.free_measurement_container = cfm_flash_free_measurement_container, \
		.get_root_ca_digest = cfm_flash_get_root_ca_digest, \
		.free_root_ca_digest = cfm_flash_free_root_ca_digest, \
		.get_next_pfm = cfm_flash_get_next_pfm, \
		.get_next_cfm = cfm_flash_get_next_cfm, \
		.get_pcd = cfm_flash_get_pcd, \
		.free_manifest = cfm_flash_free_manifest, \
	}


/**
 * Initialize a static interface to a CFM residing in flash memory.  CFMs only support manifest
 * version 2.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the CFM instance.  This must be uninitialized.
 * @param flash_ptr The flash device that contains the CFM.
 * @param hash_ptr A hash engine to use for validating run-time access to CFM information.  If it is
 * possible for any CFM information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe.  There is no internal synchronization around the hashing operations.
 * @param base_addr_arg The starting address of the CFM storage location.
 * @param signature_cache_ptr Buffer to hold the manifest signature.
 * @param max_signature_arg The maximum supported length for a manifest signature.
 * @param platform_id_cache_ptr Buffer to hold the manifest platform ID.
 * @param max_platform_id_arg The maximum platform ID length supported, including the NULL
 * terminator.
 */
#define	cfm_flash_static_init(state_ptr, flash_ptr, hash_ptr, base_addr_arg, signature_cache_ptr, \
	max_signature_arg, platform_id_cache_ptr, max_platform_id_arg)	{ \
		.base = CFM_FLASH_API_INIT, \
		.base_flash = manifest_flash_v2_static_init (&(state_ptr)->base, flash_ptr, hash_ptr, \
			base_addr_arg, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, signature_cache_ptr, \
			max_signature_arg, platform_id_cache_ptr, max_platform_id_arg), \
	}


#endif	/* CFM_FLASH_STATIC_H_ */
