// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_H_
#define KEYSTORE_H_

#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * Storage for device keys and certificates.
 */
struct keystore {
	/**
	 * Save key information.
	 *
	 * @param store The key storage where the key should be saved.
	 * @param id The ID of the key being stored.
	 * @param key The key data to store.
	 * @param length The length of the key data.
	 *
	 * @return 0 if the key was successfully stored or an error code.
	 */
	int (*save_key) (const struct keystore *store, int id, const uint8_t *key, size_t length);

	/**
	 * Load key information.
	 *
	 * @param store The key storage where the key is saved.
	 * @param id The ID of the key to load.
	 * @param key Output buffer for the loaded key.  This will be a dynamically allocated buffer
	 * and is the responsibility of the caller to free it.  On error, this will be null.
	 * @param length Output for the length of the loaded key data.
	 *
	 * @return 0 if the key was successfully loaded or an error code.
	 */
	int (*load_key) (const struct keystore *store, int id, uint8_t **key, size_t *length);

	/**
	 * Erase key information from storage.
	 *
	 * @param store The key storage where the key is saved.
	 * @param id The ID of the key to erase.
	 *
	 * @return 0 if the key was successfully erased or an error code.
	 */
	int (*erase_key) (const struct keystore *store, int id);

	/**
	 * Erase all keys from storage.
	 *
	 * @param store The key storage to utilize.
	 *
	 * @return 0 if the keys were successfully erased or an error code.
	 */
	int (*erase_all_keys) (const struct keystore *store);
};


#define	KEYSTORE_ERROR(code)		ROT_ERROR (ROT_MODULE_KEYSTORE, code)

/**
 * Error codes that can be generated by a keystore.
 */
enum {
	KEYSTORE_INVALID_ARGUMENT = KEYSTORE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	KEYSTORE_NO_MEMORY = KEYSTORE_ERROR (0x01),				/**< Memory allocation failed. */
	KEYSTORE_SAVE_FAILED = KEYSTORE_ERROR (0x02),			/**< The key was not saved. */
	KEYSTORE_LOAD_FAILED = KEYSTORE_ERROR (0x03),			/**< The key was not load. */
	KEYSTORE_UNSUPPORTED_ID = KEYSTORE_ERROR (0x04),		/**< The ID is not supported by the keystore. */
	KEYSTORE_KEY_TOO_LONG = KEYSTORE_ERROR (0x05),			/**< The key data is too long for the keystore. */
	KEYSTORE_NO_KEY = KEYSTORE_ERROR (0x06),				/**< There is no key stored for an ID. */
	KEYSTORE_BAD_KEY = KEYSTORE_ERROR (0x07),				/**< The key stored for an ID is not valid. */
	KEYSTORE_STORAGE_NOT_ALIGNED = KEYSTORE_ERROR (0x08),	/**< Memory for the keystore is not aligned correctly. */
	KEYSTORE_NO_STORAGE = KEYSTORE_ERROR (0x09),			/**< The keystore was created with no storage for keys. */
	KEYSTORE_INSUFFICIENT_STORAGE = KEYSTORE_ERROR (0x0a),	/**< There is not enough storage space for the keys. */
	KEYSTORE_ERASE_FAILED = KEYSTORE_ERROR (0x0b),			/**< The key was not erased. */
};


#endif	/* KEYSTORE_H_ */
