// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_FLASH_ENCRYPTED_H_
#define KEYSTORE_FLASH_ENCRYPTED_H_

#include <stdint.h>
#include "keystore.h"
#include "keystore_flash.h"
#include "crypto/aes.h"
#include "crypto/rng.h"


/**
 * Device key storage on flash with encryption.
 */
struct keystore_flash_encrypted {
	struct keystore base;					/**< Base keystore instance. */
	struct keystore_flash_internal flash;	/**< Flash key storage information. */
	struct aes_engine *aes;					/**< AES engine to use for data encryption. */
	struct rng_engine *rng;					/**< Random number generator to use for IVs. */
};


int keystore_flash_encrypted_init (struct keystore_flash_encrypted *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, struct aes_engine *aes, struct rng_engine *rng);
int keystore_flash_encrypted_init_decreasing_sectors (struct keystore_flash_encrypted *store,
	struct spi_flash *flash, uint32_t base_addr, int max_id, struct aes_engine *aes,
	struct rng_engine *rng);
void keystore_flash_encrypted_release (struct keystore_flash_encrypted *store);


#endif /* KEYSTORE_FLASH_ENCRYPTED_H_ */
