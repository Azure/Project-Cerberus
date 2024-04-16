// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "keystore_flash.h"
#include "common/unused.h"


int keystore_flash_save_key (const struct keystore *store, int id, const uint8_t *key,
	size_t length)
{
	const struct keystore_flash *flash = (const struct keystore_flash*) store;

	if (flash == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	return flash->store->write (flash->store, id, key, length);
}

int keystore_flash_load_key (const struct keystore *store, int id, uint8_t **key, size_t *length)
{
	const struct keystore_flash *flash = (const struct keystore_flash*) store;
	int key_len;
	int status;

	if (key == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((store == NULL) || (length == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	/* TODO: add better error handling for scenarios where keystore isn't initialized and the flash
	 * region allocated for keystore is not blank. In such scenarios, returned key_len is not valid
	 * and can result in either malloc or read failure */
	key_len = flash->store->get_data_length (flash->store, id);
	if (ROT_IS_ERROR (key_len)) {
		if (key_len == FLASH_STORE_NO_DATA) {
			key_len = KEYSTORE_NO_KEY;
		}
		return key_len;
	}

	*key = platform_malloc (key_len);
	if (*key == NULL) {
		return KEYSTORE_NO_MEMORY;
	}

	status = flash->store->read (flash->store, id, *key, key_len);
	if (ROT_IS_ERROR (status)) {
		switch (status) {
			case FLASH_STORE_NO_DATA:
				status = KEYSTORE_NO_KEY;
				break;

			case FLASH_STORE_CORRUPT_DATA:
				status = KEYSTORE_BAD_KEY;
				break;
		}
		goto error;
	}

	*length = key_len;
	return 0;

error:
	platform_free (*key);
	*key = NULL;
	*length = 0;
	return status;
}

int keystore_flash_erase_key (const struct keystore *store, int id)
{
	const struct keystore_flash *flash = (const struct keystore_flash*) store;

	if (flash == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	return flash->store->erase (flash->store, id);
}

int keystore_flash_erase_all_keys (const struct keystore *store)
{
	const struct keystore_flash *flash = (const struct keystore_flash*) store;

	if (flash == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	return flash->store->erase_all (flash->store);
}

/**
 * Initialize flash storage for device keys and certificates.  Keys are stored in flash block
 * storage.  Key IDs map directly to flash block IDs.
 *
 * @param store The key storage to initialize.
 * @param flash The flash storage that will be used to store the keys.
 *
 * @return 0 if the key storage was successfully initialized or an error code.
 */
int keystore_flash_init (struct keystore_flash *store, const struct flash_store *flash)
{
	if ((store == NULL) || (flash == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	memset (store, 0, sizeof (struct keystore_flash));

	store->base.save_key = keystore_flash_save_key;
	store->base.load_key = keystore_flash_load_key;
	store->base.erase_key = keystore_flash_erase_key;
	store->base.erase_all_keys = keystore_flash_erase_all_keys;

	store->store = flash;

	return 0;
}

/**
 * Release the resources used for key storage on flash.
 *
 * @param store The keystore to release.
 */
void keystore_flash_release (const struct keystore_flash *store)
{
	UNUSED (store);
}
