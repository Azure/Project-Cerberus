// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "keystore_flash_encrypted.h"


/**
 * The IV length to use for encryption.
 */
#define	KEYSTORE_AES_IV_LENGTH		12


static int keystore_flash_encrypted_save_key (struct keystore *store, int id, const uint8_t *key,
	size_t length)
{
	struct keystore_flash_encrypted *storage = (struct keystore_flash_encrypted*) store;
	uint8_t *encrypted;
	uint8_t iv[KEYSTORE_AES_IV_LENGTH + AES_TAG_LENGTH];
	int status;

	if ((storage == NULL) || (key == NULL) || (length == 0)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	status = keystore_flash_internal_validate_save_key (&storage->flash, id, length,
		KEYSTORE_AES_IV_LENGTH + AES_TAG_LENGTH);
	if (status != 0) {
		return status;
	}

	encrypted = platform_malloc (length);
	if (encrypted == NULL) {
		return KEYSTORE_NO_MEMORY;
	}

	status = storage->rng->generate_random_buffer (storage->rng, KEYSTORE_AES_IV_LENGTH, iv);
	if (status != 0) {
		goto exit;
	}

	status = storage->aes->encrypt_data (storage->aes, key, length, iv, KEYSTORE_AES_IV_LENGTH,
		encrypted, length, &iv[KEYSTORE_AES_IV_LENGTH], AES_TAG_LENGTH);
	if (status != 0) {
		goto exit;
	}

	status = keystore_flash_internal_save_key_data (&storage->flash, id, encrypted, length, iv,
		KEYSTORE_AES_IV_LENGTH + AES_TAG_LENGTH);

exit:
	platform_free (encrypted);
	return status;
}

static int keystore_flash_encrypted_load_key (struct keystore *store, int id, uint8_t **key,
	size_t *length)
{
	struct keystore_flash_encrypted *storage = (struct keystore_flash_encrypted*) store;
	uint8_t tag[KEYSTORE_AES_IV_LENGTH + AES_TAG_LENGTH];
	int status;

	if (key == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((store == NULL) || (length == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	status = keystore_flash_internal_load_key_data (&storage->flash, id, key, length, tag,
		sizeof (tag));
	if  (status != 0) {
		return status;
	}

	status = storage->aes->decrypt_data (storage->aes, *key, *length, &tag[KEYSTORE_AES_IV_LENGTH],
		tag, KEYSTORE_AES_IV_LENGTH, *key, *length);
	if (status != 0) {
		if (status == AES_ENGINE_GCM_AUTH_FAILED) {
			status = KEYSTORE_BAD_KEY;
		}
		goto error;
	}

	return 0;

error:
	platform_free (*key);
	*key = NULL;
	*length = 0;
	return status;
}

static int keystore_flash_encrypted_erase_key (struct keystore *store, int id)
{
	struct keystore_flash_encrypted *storage = (struct keystore_flash_encrypted*) store;

	if (storage == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	return keystore_flash_internal_erase_key (&storage->flash, id);
}

/**
 * Initialize encrypted flash storage for device keys and certificates.
 *
 * @param store The key storage to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param aes The AES engine to use for data encryption encryption.  The must be pre-loaded with the
 * encryption key.
 * @param rng The random number generator to use for creating encryption IVs.
 * @param decreasing Flag indicating that the keys are stored with decreasing sector addresses.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
static int keystore_flash_encrypted_common_init (struct keystore_flash_encrypted *store,
	struct spi_flash *flash, uint32_t base_addr, int max_id, struct aes_engine *aes,
	struct rng_engine *rng, bool decreasing)
{
	int status;

	if ((store == NULL) || (flash == NULL) || (aes == NULL) || (rng == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	memset (store, 0, sizeof (struct keystore_flash_encrypted));

	status = keystore_flash_internal_init (&store->flash, flash, base_addr, max_id, decreasing);
	if (status != 0) {
		return status;
	}

	store->aes = aes;
	store->rng = rng;

	store->base.save_key = keystore_flash_encrypted_save_key;
	store->base.load_key = keystore_flash_encrypted_load_key;
	store->base.erase_key = keystore_flash_encrypted_erase_key;

	return 0;
}

/**
 * Initialize encrypted flash storage for device keys and certificates.
 *
 * Each key will be stored in a sector of flash.  The total number of sectors needed is dependent on
 * how many keys will be stored.  Sectors will be consumed sequentially increasing from the base
 * sector.
 *
 * @param store The key storage to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param aes The AES engine to use for data encryption encryption.  The must be pre-loaded with the
 * encryption key.
 * @param rng The random number generator to use for creating encryption IVs.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
int keystore_flash_encrypted_init (struct keystore_flash_encrypted *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, struct aes_engine *aes, struct rng_engine *rng)
{
	return keystore_flash_encrypted_common_init (store, flash, base_addr, max_id, aes, rng, false);
}

/**
 * Initialize encrypted flash storage for device keys and certificates.
 *
 * Each key will be stored in a sector of flash.  The total number of sectors needed is dependent on
 * how many keys will be stored.  Sectors will be consumed sequentially decreasing from the base
 * sector.
 *
 * @param store The key storage to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param aes The AES engine to use for data encryption encryption.  The must be pre-loaded with the
 * encryption key.
 * @param rng The random number generator to use for creating encryption IVs.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
int keystore_flash_encrypted_init_decreasing_sectors (struct keystore_flash_encrypted *store,
	struct spi_flash *flash, uint32_t base_addr, int max_id, struct aes_engine *aes,
	struct rng_engine *rng)
{
	return keystore_flash_encrypted_common_init (store, flash, base_addr, max_id, aes, rng, true);
}

/**
 * Release the resources used for encrypted key storage on flash.
 *
 * @param store The keystore to release.
 */
void keystore_flash_encrypted_release (struct keystore_flash_encrypted *store)
{
	if (store) {
		keystore_flash_internal_release (&store->flash);
	}
}
