// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_FLASH_STATIC_H_
#define KEYSTORE_FLASH_STATIC_H_

#include "keystore/keystore_flash.h"


/* Internal functions declared to allow for static initialization. */
int keystore_flash_save_key (const struct keystore *store, int id, const uint8_t *key,
	size_t length);
int keystore_flash_load_key (const struct keystore *store, int id, uint8_t **key, size_t *length);
int keystore_flash_erase_key (const struct keystore *store, int id);
int keystore_flash_erase_all_keys (const struct keystore *store);


/**
 * Constant initializer for the keystore API.
 */
#define	KEYSTORE_FLASH_API_INIT  { \
		.save_key = keystore_flash_save_key, \
		.load_key = keystore_flash_load_key, \
		.erase_key = keystore_flash_erase_key, \
		.erase_all_keys = keystore_flash_erase_all_keys \
	}


/**
 * Initialize a static instance of flash storage for device keys and certificates.  Keys are stored
 * in flash block storage.  Key IDs map directly to flash block IDs.
 *
 * There is no validation done on the arguments.
 *
 * @param flash_ptr The flash storage that will be used to store the keys.
 */
#define	keystore_flash_static_init(flash_ptr)	{ \
		.base = KEYSTORE_FLASH_API_INIT, \
		.store = flash_ptr, \
	}


#endif	/* KEYSTORE_FLASH_STATIC_H_ */
