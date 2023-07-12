// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_AGGREGATOR_STATIC_H_
#define FLASH_STORE_AGGREGATOR_STATIC_H_

#include "flash_store_aggregator.h"


/* Internal functions declared to allow for static initialization. */
int flash_store_aggregtor_write (const struct flash_store *flash_store, int id,
	const uint8_t *data, size_t length);
int flash_store_aggregtor_read (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length);
int flash_store_aggregtor_erase (const struct flash_store *flash_store, int id);
int flash_store_aggregtor_erase_all (const struct flash_store *flash_store);
int flash_store_aggregtor_get_data_length (const struct flash_store *flash_store, int id);
int flash_store_aggregtor_has_data_stored (const struct flash_store *flash_store, int id);
int flash_store_aggregtor_get_max_data_length (const struct flash_store *flash_store);
int flash_store_aggregtor_get_flash_size (const struct flash_store *flash_store);
int flash_store_aggregtor_get_num_blocks (const struct flash_store *flash_store);

/**
 * Constant initializer for the flash store aggregator interface APIs.
 */
#define	FLASH_STORE_AGGREGATOR_API_INIT  { \
		.write = flash_store_aggregtor_write, \
		.read = flash_store_aggregtor_read, \
		.erase = flash_store_aggregtor_erase, \
		.erase_all = flash_store_aggregtor_erase_all, \
		.get_data_length = flash_store_aggregtor_get_data_length, \
		.has_data_stored = flash_store_aggregtor_has_data_stored, \
		.get_max_data_length = flash_store_aggregtor_get_max_data_length, \
		.get_flash_size = flash_store_aggregtor_get_flash_size, \
		.get_num_blocks = flash_store_aggregtor_get_num_blocks \
	}

/**
 * Initialize a static instance of a flash store aggregator.
 *
 * There is no validation done on the arguments.
 *
 * @param flash_store_array_ptr pointer to the array that holds flash store instances.
 * @param flash_store_array_cnt Max number of flash store instances of flash_store_array.
 */
#define	flash_store_aggregator_static_init(flash_store_array_ptr, flash_store_array_cnt) { \
		.base = FLASH_STORE_AGGREGATOR_API_INIT, \
		.flash_store_array = flash_store_array_ptr, \
		.flash_store_cnt = flash_store_array_cnt \
	}


#endif /* FLASH_STORE_AGGREGATOR_STATIC_H_*/
