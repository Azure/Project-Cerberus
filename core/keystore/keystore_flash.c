// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "keystore_flash.h"
#include "flash/flash_common.h"


/**
 * Check if the key is valid for the storage.
 *
 * @param store The key storage to query.
 * @param id The ID of the key to check.
 * @param length Length of the key data.
 * @param auth_length Length of the key authentication data.
 *
 * @return 0 if the key is valid or an error code.
 */
int keystore_flash_internal_validate_save_key (struct keystore_flash_internal *store, int id,
	size_t length, size_t auth_length)
{
	if ((id > store->max_id) || (id < 0)) {
		return KEYSTORE_UNSUPPORTED_ID;
	}

	if (length > (FLASH_SECTOR_SIZE - auth_length - sizeof (uint16_t))) {
		return KEYSTORE_KEY_TOO_LONG;
	}

	return 0;
}

/**
 * Save key data on flash.
 *
 * @param store The key storage used store the data.
 * @param id The ID of the key.
 * @param key The data for the key being stored.
 * @param length The length of the key data to store.
 * @param auth The authentication data for the stored key.
 * @param auth_length The length of the authentication data.
 *
 * @return 0 if key data was successfully stored or an error code.
 */
int keystore_flash_internal_save_key_data (struct keystore_flash_internal *store, int id,
	const uint8_t *key, size_t length, const uint8_t *auth, size_t auth_length)
{
	uint16_t key_length = length;
	uint32_t sector;
	int status;

	if (!store->decrease) {
		sector = store->base_addr + (FLASH_SECTOR_SIZE * id);
	}
	else {
		sector = store->base_addr - (FLASH_SECTOR_SIZE * id);
	}

	status = spi_flash_sector_erase (store->flash, sector);
	if (status != 0) {
		return status;
	}

	status = spi_flash_write (store->flash, sector, (uint8_t*) &key_length, sizeof (key_length));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = spi_flash_write (store->flash, sector + sizeof (key_length), key, length);
	if (ROT_IS_ERROR (status)) {
		return status;
	}
	if (status != length) {
		return KEYSTORE_SAVE_FAILED;
	}

	status = spi_flash_write (store->flash, sector + sizeof (key_length) + length, auth,
		auth_length);
	if (ROT_IS_ERROR (status)) {
		return status;
	}
	if (status != auth_length) {
		return KEYSTORE_SAVE_FAILED;
	}

	return 0;
}

static int keystore_flash_save_key (struct keystore *store, int id, const uint8_t *key,
	size_t length)
{
	struct keystore_flash *storage = (struct keystore_flash*) store;
	uint8_t key_hash[SHA256_HASH_LENGTH];
	int status;

	if ((storage == NULL) || (key == NULL) || (length == 0)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	status = keystore_flash_internal_validate_save_key (&storage->flash, id, length,
		SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	status = storage->hash->calculate_sha256 (storage->hash, key, length, key_hash,
		sizeof (key_hash));
	if (status != 0) {
		return status;
	}

	return keystore_flash_internal_save_key_data (&storage->flash, id, key, length, key_hash,
		SHA256_HASH_LENGTH);
}

/**
 * Load key data from flash.
 *
 * @param store The key storage where the data is stored.
 * @param id The ID of the key.
 * @param key Output buffer for the key data.  This will be dynamically allocated and must be freed
 * by the caller, if necessary.
 * @param length Output for the length of the key data.
 * @param auth Output buffer for the authentication data.
 * @param auth_length The length of the authentication buffer.
 *
 * @return 0 if the key was successfully loaded or an error code.
 */
int keystore_flash_internal_load_key_data (struct keystore_flash_internal *store, int id,
	uint8_t **key, size_t *length, uint8_t *auth, size_t auth_length)
{
	uint16_t key_length;
	uint32_t sector;
	int status;

	if ((id > store->max_id) || (id < 0)) {
		return KEYSTORE_UNSUPPORTED_ID;
	}

	if (!store->decrease) {
		sector = store->base_addr + (FLASH_SECTOR_SIZE * id);
	}
	else {
		sector = store->base_addr - (FLASH_SECTOR_SIZE * id);
	}

	status = spi_flash_read (store->flash, sector, (uint8_t*) &key_length, sizeof (key_length));
	if (status != 0) {
		return status;
	}

	if (key_length > (FLASH_SECTOR_SIZE - auth_length - sizeof (key_length))) {
		return KEYSTORE_NO_KEY;
	}

	*key = platform_malloc (key_length);
	if (*key == NULL) {
		return KEYSTORE_NO_MEMORY;
	}

	status = spi_flash_read (store->flash, sector + sizeof (key_length), *key, key_length);
	if (status != 0) {
		goto error;
	}

	status = spi_flash_read (store->flash, sector + sizeof (key_length) + key_length, auth,
		auth_length);
	if (status != 0) {
		goto error;
	}

	*length = key_length;
	return 0;

error:
	platform_free (*key);
	*key = NULL;
	return status;
}

static int keystore_flash_load_key (struct keystore *store, int id, uint8_t **key, size_t *length)
{
	struct keystore_flash *storage = (struct keystore_flash*) store;
	uint8_t key_hash[SHA256_HASH_LENGTH];
	uint8_t read_hash[SHA256_HASH_LENGTH];
	int status;

	if (key == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((store == NULL) || (length == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	status = keystore_flash_internal_load_key_data (&storage->flash, id, key, length, read_hash,
		SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	status = storage->hash->calculate_sha256 (storage->hash, *key, *length, key_hash,
		sizeof (key_hash));
	if (status != 0) {
		goto error;
	}

	if (memcmp (key_hash, read_hash, SHA256_HASH_LENGTH) != 0) {
		status = KEYSTORE_BAD_KEY;
		goto error;
	}

	return 0;

error:
	platform_free (*key);
	*key = NULL;
	*length = 0;
	return status;
}

/**
 * Erase key data from flash.
 *
 * @param store The key storage where the data is stored.
 * @param id The ID of the key.
 *
 * @return 0 if the key was successfully erased or an error code.
 */
int keystore_flash_internal_erase_key (struct keystore_flash_internal *store, int id)
{
	uint32_t sector;

	if ((id > store->max_id) || (id < 0)) {
		return KEYSTORE_UNSUPPORTED_ID;
	}

	if (!store->decrease) {
		sector = store->base_addr + (FLASH_SECTOR_SIZE * id);
	}
	else {
		sector = store->base_addr - (FLASH_SECTOR_SIZE * id);
	}

	return spi_flash_sector_erase (store->flash, sector);
}

static int keystore_flash_erase_key (struct keystore *store, int id)
{
	struct keystore_flash *storage = (struct keystore_flash*) store;

	if (storage == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	return keystore_flash_internal_erase_key (&storage->flash, id);
}

/**
 * Initialize the internal container for managing flash storage.
 *
 * @param store The internal storage information to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param decreasing Flag indicating if the keystore grows by decreasing sectors addresses.
 *
 * @return 0 if the storage data was successfully initialized or an error code.
 */
int keystore_flash_internal_init (struct keystore_flash_internal *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, bool decreasing)
{
	if (FLASH_SECTOR_OFFSET (base_addr) != 0) {
		return KEYSTORE_STORAGE_NOT_ALIGNED;
	}

	if (max_id < 0) {
		return KEYSTORE_NO_STORAGE;
	}

	if (!decreasing) {
		uint32_t max_sector;
		int status;

		status = spi_flash_get_device_size (flash, &max_sector);
		if (status != 0) {
			return status;
		}

		if ((base_addr + (FLASH_SECTOR_SIZE * max_id)) >= max_sector) {
			return KEYSTORE_INSUFFICIENT_STORAGE;
		}
	}
	else {
		if ((FLASH_SECTOR_SIZE * max_id) > base_addr) {
			return KEYSTORE_INSUFFICIENT_STORAGE;
		}
	}

	store->flash = flash;
	store->base_addr = base_addr;
	store->max_id = max_id;
	store->decrease = decreasing;

	return 0;
}

/**
 * Initialize flash storage for device keys and certificates.
 *
 * @param store The key storage to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param hash A hash engine to use for checking flash data integrity.
 * @param decreasing Flag indicating if the keystore grows by decreasing sectors addresses.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
static int keystore_flash_common_init (struct keystore_flash *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, struct hash_engine *hash, bool decreasing)
{
	int status;

	if ((store == NULL) || (flash == NULL) || (hash == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	memset (store, 0, sizeof (struct keystore_flash));

	status = keystore_flash_internal_init (&store->flash, flash, base_addr, max_id, decreasing);
	if (status != 0) {
		return status;
	}

	store->hash = hash;

	store->base.save_key = keystore_flash_save_key;
	store->base.load_key = keystore_flash_load_key;
	store->base.erase_key = keystore_flash_erase_key;

	return 0;
}

/**
 * Initialize flash storage for device keys and certificates.
 *
 * Each key will be stored in a sector of flash.  The total number of sectors needed is dependent on
 * how many keys will be stored.  Sectors will be consumed sequentially increasing from the base
 * sector.
 *
 * @param store The key storage to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param hash A hash engine to use for checking flash data integrity.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
int keystore_flash_init (struct keystore_flash *store, struct spi_flash *flash, uint32_t base_addr,
	int max_id, struct hash_engine *hash)
{
	return keystore_flash_common_init (store, flash, base_addr, max_id, hash, false);
}

/**
 * Initialize flash storage for device keys and certificates.
 *
 * Each key will be stored in a sector of flash.  The total number of sectors needed is dependent on
 * how many keys will be stored.  Sectors will be consumed sequentially decreasing from the base
 * sector.
 *
 * @param store The key storage to initialize.
 * @param flash The flash that will be used to store the keys.
 * @param base_addr The base address for the keys.  This must be at the start of a sector.
 * @param max_id The maximum key ID supported by the keystore.  Key IDs start at 0.
 * @param hash A hash engine to use for checking flash data integrity.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
int keystore_flash_init_decreasing_sectors (struct keystore_flash *store, struct spi_flash *flash,
	uint32_t base_addr, int max_id, struct hash_engine *hash)
{
	return keystore_flash_common_init (store, flash, base_addr, max_id, hash, true);
}

/**
 * Release the internal flash storage container.
 *
 * @param store The internal storage data to release.
 */
void keystore_flash_internal_release (struct keystore_flash_internal *store)
{

}

/**
 * Release the resources used for key storage on flash.
 *
 * @param store The keystore to release.
 */
void keystore_flash_release (struct keystore_flash *store)
{
	if (store) {
		keystore_flash_internal_release (&store->flash);
	}
}
