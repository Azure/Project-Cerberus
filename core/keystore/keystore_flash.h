// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_FLASH_H_
#define KEYSTORE_FLASH_H_

#include <stdbool.h>
#include "keystore.h"
#include "flash/flash_store.h"


/**
 * Device key storage on flash.
 */
struct keystore_flash {
	struct keystore base;					/**< Base keystore instance. */
	struct flash_store *store;				/**< Flash storage for keys. */
};


int keystore_flash_init (struct keystore_flash *store, struct flash_store *flash);
void keystore_flash_release (struct keystore_flash *store);


#endif /* KEYSTORE_FLASH_H_ */
