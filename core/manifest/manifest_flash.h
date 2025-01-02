// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_FLASH_H
#define MANIFEST_FLASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "manifest_format.h"
#include "crypto/hash.h"
#include "crypto/signature_verification.h"
#include "flash/flash.h"


/**
 * Variable context for common handling of manifests on flash.
 */
struct manifest_flash_state {
	struct manifest_header header;			/**< The manifest header data. */
	struct manifest_toc_header toc_header;	/**< The table of contents header data. */
	uint8_t toc_hash[SHA512_HASH_LENGTH];	/**< Hash of the manifest table of contents. */
	enum hash_type toc_hash_type;			/**< The type of hash used in the table of contents. */
	size_t toc_hash_length;					/**< Length of the table of contents hash. */
	uint8_t hash_cache[SHA512_HASH_LENGTH];	/**< Cache for the manifest hash. */
	size_t hash_length;						/**< Length of the manifest hash. */
	bool cache_valid;						/**< Flag indicating if the cached hash is valid. */
	bool manifest_valid;					/**< Flag indicating there is a validated manifest. */
};

/**
 * Common handling for manifests stored on flash.
 *
 * This is not a stand-alone derivation of the manifest interface.  It is intended only to be used
 * as a component within a complete manifest implementation.
 */
struct manifest_flash {
	struct manifest_flash_state *state;	/**< Variable context for the manifest. */
	const struct flash *flash;			/**< The flash device that contains the manifest. */
	const struct hash_engine *hash;		/**, Hash engine to use for element verification. */
	uint32_t addr;						/**< The starting address in flash of the manifest. */
	uint16_t magic_num_v1;				/**< The magic number identifying a v1 manifest. */
	uint16_t magic_num_v2;				/**< The magic number identifying a v2 manifest. */
	uint8_t *signature;					/**< Buffer to hold the manifest signature. */
	size_t max_signature;				/**< Maximum supported signature length. */
	char *platform_id;					/**< Buffer to hold the platform ID. */
	size_t max_platform_id;				/**< Maximum supported platform ID length. */
	bool free_signature;				/**< Flag indicating the signature buffer should be freed. */
};


int manifest_flash_init (struct manifest_flash *manifest, struct manifest_flash_state *state,
	const struct flash *flash, uint32_t base_addr, uint16_t magic_num_v1);
int manifest_flash_v2_init (struct manifest_flash *manifest, struct manifest_flash_state *state,
	const struct flash *flash, const struct hash_engine *hash, uint32_t base_addr,
	uint16_t magic_num_v1, uint16_t magic_num_v2, uint8_t *signature_cache, size_t max_signature,
	uint8_t *platform_id_cache, size_t max_platform_id);
int manifest_flash_init_state (const struct manifest_flash *manifest);
void manifest_flash_release (const struct manifest_flash *manifest);

int manifest_flash_read_header (const struct manifest_flash *manifest,
	struct manifest_header *header);

int manifest_flash_verify (const struct manifest_flash *manifest, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);
int manifest_flash_v2_verify (const struct manifest_flash *manifest, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);

int manifest_flash_get_id (const struct manifest_flash *manifest, uint32_t *id);
int manifest_flash_get_platform_id (const struct manifest_flash *manifest, char **id,
	size_t length);
int manifest_flash_get_hash (const struct manifest_flash *manifest, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length);
int manifest_flash_get_signature (const struct manifest_flash *manifest, uint8_t *signature,
	size_t length);

int manifest_flash_read_element_data (const struct manifest_flash *manifest,
	const struct hash_engine *hash, uint8_t type, int start, uint8_t parent_type,
	uint32_t read_offset, uint8_t *found, uint8_t *format, size_t *total_len, uint8_t **element,
	size_t length);

int manifest_flash_get_child_elements_info (const struct manifest_flash *manifest,
	const struct hash_engine *hash, int entry, uint8_t type, uint8_t parent_type,
	uint8_t child_type, size_t *child_len, int *child_count, int *first_entry);

uint32_t manifest_flash_get_addr (const struct manifest_flash *manifest);
const struct flash* manifest_flash_get_flash (const struct manifest_flash *manifest);


int manifest_flash_compare_id (const struct manifest_flash *manifest1,
	const struct manifest_flash *manifest2);
int manifest_flash_compare_platform_id (const struct manifest_flash *manifest1,
	const struct manifest_flash *manifest2, bool sku_upgrade_permitted);


#endif	//MANIFEST_FLASH_H
