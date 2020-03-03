// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_FLASH_H_
#define KEYSTORE_FLASH_H_

#include <stdbool.h>
#include "keystore.h"
#include "flash/spi_flash.h"
#include "crypto/hash.h"


/**
 * Internal information for flash storage of keys.
 */
struct keystore_flash_internal {
	struct spi_flash *flash;		/**< The flash where keys will be stored. */
	uint32_t base_addr;				/**< The base address for key storage. */
	int max_id;						/**< The maximum supported key ID. */
	bool decrease;					/**< Flag indicating which direction the keystore grows. */
};

/**
 * Device key storage on flash.
 */
struct keystore_flash {
	struct keystore base;					/**< Base keystore instance. */
	struct keystore_flash_internal flash;	/**< Flash key storage information. */
	struct hash_engine *hash;				/**< Engine for hashing flash data. */
};


int keystore_flash_init (struct keystore_flash *store, struct spi_flash *flash, uint32_t base_addr,
	int max_id, struct hash_engine *hash);
int keystore_flash_init_decreasing_sectors (struct keystore_flash *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, struct hash_engine *hash);
void keystore_flash_release (struct keystore_flash *store);

/* Internal functions for use by derived types. */
int keystore_flash_internal_init (struct keystore_flash_internal *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, bool decreasing);
void keystore_flash_internal_release (struct keystore_flash_internal *store);

int keystore_flash_internal_validate_save_key (struct keystore_flash_internal *store, int id,
	size_t length, size_t auth_length);
int keystore_flash_internal_save_key_data (struct keystore_flash_internal *store, int id,
	const uint8_t *key, size_t length, const uint8_t *auth, size_t auth_length);
int keystore_flash_internal_load_key_data (struct keystore_flash_internal *store, int id,
	uint8_t **key, size_t *length, uint8_t *auth, size_t auth_length);
int keystore_flash_internal_erase_key (struct keystore_flash_internal *store, int id);


#endif /* KEYSTORE_FLASH_H_ */
