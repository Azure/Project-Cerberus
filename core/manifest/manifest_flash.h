// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_FLASH_H
#define MANIFEST_FLASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "manifest_format.h"
#include "flash/spi_flash.h"
#include "crypto/hash.h"
#include "common/signature_verification.h"


/**
 * Common handling for manifests stored on flash.
 *
 * This is not a stand-alone derivation of the manifest interface.  It is intended only to be used
 * as a component within a complete manifest implementation.
 */
struct manifest_flash {
	struct spi_flash *flash;				/**< The flash device that contains the manifest. */
	uint32_t addr;							/**< The starting address in flash of the manifest. */
	uint16_t magic_num;						/**< The magic number identifying the manifest. */
	uint8_t hash_cache[SHA256_HASH_LENGTH];	/**< Cache for the manifest hash. */
	bool cache_valid;						/**< Flag indicating if the cached hash is valid. */
};


int manifest_flash_init (struct manifest_flash *manifest, struct spi_flash *flash,
	uint32_t base_addr, uint16_t magic_num);

int manifest_flash_read_header (struct manifest_flash *manifest, struct manifest_header *header);

int manifest_flash_verify (struct manifest_flash *manifest, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);
int manifest_flash_get_id (struct manifest_flash *manifest, uint32_t *id);
int manifest_flash_get_hash (struct manifest_flash *manifest, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length);
int manifest_flash_get_signature (struct manifest_flash *manifest, uint8_t *signature,
	size_t length);


#endif //MANIFEST_FLASH_H
