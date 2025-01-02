// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_FLASH_STATIC_H_
#define PCD_FLASH_STATIC_H_

#include "pcd_flash.h"
#include "manifest/manifest_flash_static.h"


/* Internal functions declared to allow for static initialization. */
int pcd_flash_verify (const struct manifest *pcd, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);
int pcd_flash_get_id (const struct manifest *pcd, uint32_t *id);
int pcd_flash_get_platform_id (const struct manifest *pcd, char **id, size_t length);
void pcd_flash_free_platform_id (const struct manifest *manifest, char *id);
int pcd_flash_get_hash (const struct manifest *pcd, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length);
int pcd_flash_get_signature (const struct manifest *pcd, uint8_t *signature, size_t length);
int pcd_flash_is_empty (const struct manifest *pcd);
int pcd_flash_get_rot_info (const struct pcd *pcd, struct pcd_rot_info *info);
int pcd_flash_get_port_info (const struct pcd *pcd, uint8_t port_id, struct pcd_port_info *info);
int pcd_flash_get_power_controller_info (const struct pcd *pcd,
	struct pcd_power_controller_info *info);
int pcd_flash_get_next_mctp_bridge_component (const struct pcd *pcd,
	struct pcd_mctp_bridge_components_info *component, bool first);
int pcd_flash_buffer_supported_components (const struct pcd *pcd, size_t offset, size_t length,
	uint8_t *pcd_component_ids);


/**
 * Constant initializer for the PCD API.
 */
#define	PCD_FLASH_API_INIT  { \
		.base = { \
			.verify = pcd_flash_verify, \
			.get_id = pcd_flash_get_id, \
			.get_platform_id = pcd_flash_get_platform_id, \
			.free_platform_id = pcd_flash_free_platform_id, \
			.get_hash = pcd_flash_get_hash, \
			.get_signature = pcd_flash_get_signature, \
			.is_empty = pcd_flash_is_empty, \
		}, \
		.buffer_supported_components = pcd_flash_buffer_supported_components, \
		.get_next_mctp_bridge_component = pcd_flash_get_next_mctp_bridge_component, \
		.get_port_info = pcd_flash_get_port_info, \
		.get_rot_info = pcd_flash_get_rot_info, \
		.get_power_controller_info = pcd_flash_get_power_controller_info, \
	}


/**
 * Initialize a static interface to a PCD residing in flash memory.  PCDs only support manifest
 * version 2.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the PCD instance.  This must be uninitialized.
 * @param flash_ptr The flash device that contains the PCD.
 * @param hash_ptr A hash engine to use for validating run-time access to PCD information.  If it is
 * possible for any PCD information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe.  There is no internal synchronization around the hashing operations.
 * @param base_addr_arg The starting address of the PCD storage location.
 * @param signature_cache_ptr Buffer to hold the manifest signature.
 * @param max_signature_arg The maximum supported length for a manifest signature.
 * @param platform_id_cache_ptr Buffer to hold the manifest platform ID.
 * @param max_platform_id_arg The maximum platform ID length supported, including the NULL
 * terminator.
 */
#define	pcd_flash_static_init(state_ptr, flash_ptr, hash_ptr, base_addr_arg, signature_cache_ptr, \
	max_signature_arg, platform_id_cache_ptr, max_platform_id_arg)	{ \
		.base = PCD_FLASH_API_INIT, \
		.base_flash = manifest_flash_v2_static_init (&(state_ptr)->base, flash_ptr, hash_ptr, \
			base_addr_arg, MANIFEST_NOT_SUPPORTED, PCD_V2_MAGIC_NUM, signature_cache_ptr, \
			max_signature_arg, platform_id_cache_ptr, max_platform_id_arg), \
	}


#endif	/* PCD_FLASH_STATIC_H_ */
