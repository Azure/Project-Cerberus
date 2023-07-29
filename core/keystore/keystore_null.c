// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "keystore_null.h"
#include "common/unused.h"


int keystore_null_save_key (const struct keystore *store, int id, const uint8_t *key, size_t length)
{
	if ((store == NULL) || (key == NULL) || (length == 0)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	UNUSED (id);

	return 0;
}

int keystore_null_load_key (const struct keystore *store, int id, uint8_t **key, size_t *length)
{
	if (key == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((store == NULL) || (length == NULL)) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	UNUSED (id);

	return KEYSTORE_NO_KEY;
}

int keystore_null_erase_key (const struct keystore *store, int id)
{
	if (store == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	UNUSED (id);

	return 0;
}

int keystore_null_erase_all_keys (const struct keystore *store)
{
	if (store == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	return 0;
}

/**
 * Initialize a null keystore that cannot contain any keys.
 *
 * @param store The keystore to initialize.
 *
 * @return 0 if the keystore was successfully initialized or an error code.
 */
int keystore_null_init (struct keystore_null *store)
{
	if (store == NULL) {
		return KEYSTORE_INVALID_ARGUMENT;
	}

	memset (store, 0, sizeof (struct keystore_null));

	store->base.save_key = keystore_null_save_key;
	store->base.load_key = keystore_null_load_key;
	store->base.erase_key = keystore_null_erase_key;
	store->base.erase_all_keys = keystore_null_erase_all_keys;

	return 0;
}

/**
 * Release the resources used by a null keystore.
 *
 * @param store The keystore to release.
 */
void keystore_null_release (const struct keystore_null *store)
{
	UNUSED (store);
}
