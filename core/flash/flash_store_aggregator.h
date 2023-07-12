// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_AGGREGATOR_H_
#define FLASH_STORE_AGGREGATOR_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "flash_store.h"


/**
 * Manages an arbitary number of flash store instances. Aggregates the flash store instances
 * and translates the requested ID to the correct flash_store.
 */
struct flash_store_aggregator {
	struct flash_store base;							/**< Base flash_store. */
	const struct flash_store *const *flash_store_array;	/**< Flash device used for storage. */
	size_t flash_store_cnt;								/**< Holds the count of number of flash stores. */
};

int flash_store_aggregator_init (struct flash_store_aggregator *aggregator,
	const struct flash_store *const *flash_store_array, size_t flash_store_cnt);
void flash_store_aggregator_release (const struct flash_store_aggregator *aggregator);


#endif /* FLASH_STORE_AGGREGATOR_H_*/
