// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_NULL_STATIC_H_
#define KEYSTORE_NULL_STATIC_H_

#include "keystore/keystore_null.h"


/* Internal functions declared to allow for static initialization. */
int keystore_null_save_key (const struct keystore *store, int id, const uint8_t *key,
	size_t length);
int keystore_null_load_key (const struct keystore *store, int id, uint8_t **key, size_t *length);
int keystore_null_erase_key (const struct keystore *store, int id);
int keystore_null_erase_all_keys (const struct keystore *store);


/**
 * Constant initializer for the keystore API.
 */
#define	KEYSTORE_NULL_API_INIT  { \
		.save_key = keystore_null_save_key, \
		.load_key = keystore_null_load_key, \
		.erase_key = keystore_null_erase_key, \
		.erase_all_keys = keystore_null_erase_all_keys \
	}


/**
 * Initialize a static instance of a keystore that cannot save any keys.
 *
 * There is no validation done on the arguments.
 */
#define	keystore_null_static_init	{ \
		.base = KEYSTORE_NULL_API_INIT, \
	}


#endif /* KEYSTORE_NULL_STATIC_H_ */
