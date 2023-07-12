// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "common/common_math.h"
#include "common/unused.h"
#include "flash_store_aggregator.h"


/**
 * Get the flash store instance which has the block ID.
 *
 * @param flash_aggregator Agggregator that manages arbitary num of flash stores.
 * @param id Block ID of the data.
 * @param flash_store Output Pointer that holds the flash store instance that block ID belongs to
 * @param block_index Block ID of the data relative to flash store
 *
 * @return 0 if the flash store and block index identified successfully, otherwise error code.
 */
static int flash_store_aggregator_get_flash_store_and_block_index (
	const struct flash_store_aggregator *flash_aggregator, int id,
	const struct flash_store **flash_store, int *block_index)
{
	size_t iterator = 0;
	int num_blocks;
	const struct flash_store *const *flash_store_array = flash_aggregator->flash_store_array;
	int status = FLASH_STORE_UNSUPPORTED_ID;

	while (iterator < flash_aggregator->flash_store_cnt) {
		if (flash_store_array[iterator] == NULL) {
			status = FLASH_STORE_NO_STORAGE;
			break;
		}

		num_blocks = flash_store_array[iterator]->get_num_blocks (flash_store_array[iterator]);
		if (ROT_IS_ERROR(num_blocks)) {
			status = num_blocks;
			break;
		}

		if (id < num_blocks) {
			*flash_store = flash_store_array[iterator];
			*block_index = id;
			status = 0;
			break;
		}
		else {
			id = id - num_blocks;
		}

		iterator++;
	}

	return status;
}

int flash_store_aggregtor_write (const struct flash_store *flash_store, int id, const uint8_t *data,
	size_t length)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	const struct flash_store *flash = NULL;
	int status;
	int index;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	status = flash_store_aggregator_get_flash_store_and_block_index (flash_aggregator, id, &flash,
		&index);
	if (status != 0) {
		return status;
	}

	status = flash->write (flash, index, data, length);
	return status;
}

int flash_store_aggregtor_read (const struct flash_store *flash_store, int id, uint8_t *data,
	size_t length)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	const struct flash_store *flash = NULL;
	int status;
	int index;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	status = flash_store_aggregator_get_flash_store_and_block_index (flash_aggregator, id, &flash,
		&index);
	if (status != 0) {
		return status;
	}

	status = flash->read (flash, index, data, length);
	return status;
}

int flash_store_aggregtor_erase (const struct flash_store *flash_store, int id)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	const struct flash_store *flash = NULL;
	int status;
	int index;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	status = flash_store_aggregator_get_flash_store_and_block_index (flash_aggregator, id, &flash,
		&index);
	if (status != 0) {
		return status;
	}

	status = flash->erase (flash, index);
	return status;
}

int flash_store_aggregtor_erase_all (const struct flash_store *flash_store)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	int status = 0;
	size_t loop;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	for (loop = 0; loop < flash_aggregator->flash_store_cnt; loop++) {
		status = flash_aggregator->flash_store_array[loop]->erase_all (
			flash_aggregator->flash_store_array[loop]);
		if (ROT_IS_ERROR(status)) {
			break;
		}
	}

	return status;
}

int flash_store_aggregtor_get_data_length (const struct flash_store *flash_store, int id)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	const struct flash_store *flash = NULL;
	int status;
	int index;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	status = flash_store_aggregator_get_flash_store_and_block_index (flash_aggregator, id, &flash,
		&index);
	if (status != 0) {
		return status;
	}

	status = flash->get_data_length (flash, index);
	return status;
}

int flash_store_aggregtor_has_data_stored (const struct flash_store *flash_store, int id)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	const struct flash_store *flash = NULL;
	int status;
	int index;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	status = flash_store_aggregator_get_flash_store_and_block_index (flash_aggregator, id, &flash,
		&index);
	if (status != 0) {
		return status;
	}

	status = flash->has_data_stored (flash, index);
	return status;
}

int flash_store_aggregtor_get_max_data_length (const struct flash_store *flash_store)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	int max_data_length = INT_MAX;
	int status = 0;
	size_t loop;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	for (loop = 0; loop < flash_aggregator->flash_store_cnt; loop++) {
		status = flash_aggregator->flash_store_array[loop]->get_max_data_length (
			flash_aggregator->flash_store_array[loop]);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		max_data_length = min (max_data_length, status);
	}

	return max_data_length;
}

int flash_store_aggregtor_get_flash_size (const struct flash_store *flash_store)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	size_t flash_size = 0;
	int status;
	size_t loop;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	for (loop = 0; loop < flash_aggregator->flash_store_cnt; loop++) {
		status = flash_aggregator->flash_store_array[loop]->get_flash_size (
			flash_aggregator->flash_store_array[loop]);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		flash_size += status;
	}

	return flash_size;
}

int flash_store_aggregtor_get_num_blocks (const struct flash_store *flash_store)
{
	const struct flash_store_aggregator *flash_aggregator =
		(const struct flash_store_aggregator*) flash_store;
	int num_blocks = 0;
	int status;
	size_t loop;

	if (flash_aggregator == NULL) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	for (loop = 0; loop < flash_aggregator->flash_store_cnt; loop++) {
		status = flash_aggregator->flash_store_array[loop]->get_num_blocks (
			flash_aggregator->flash_store_array[loop]);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		num_blocks += status;
	}

	return num_blocks;
}

/**
 * Initialize flash storage aggreagator.
 *
 * @param aggregator The flash storage aggregator to initialize.
 * @param flash_store_array Array that holds flash store instances.
 * @param falsh_store_cnt Max number of flash store instances of flash_store_array.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_aggregator_init (struct flash_store_aggregator *aggregator,
	const struct flash_store *const *flash_store_array, size_t falsh_store_cnt)
{
	if ((aggregator == NULL) || (flash_store_array == NULL) || (falsh_store_cnt == 0)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	memset (aggregator, 0, sizeof (struct flash_store_aggregator));

	aggregator->base.read = flash_store_aggregtor_read;
	aggregator->base.write = flash_store_aggregtor_write;
	aggregator->base.erase = flash_store_aggregtor_erase;
	aggregator->base.erase_all = flash_store_aggregtor_erase_all;
	aggregator->base.get_data_length = flash_store_aggregtor_get_data_length;
	aggregator->base.get_flash_size = flash_store_aggregtor_get_flash_size;
	aggregator->base.get_max_data_length = flash_store_aggregtor_get_max_data_length;
	aggregator->base.get_num_blocks = flash_store_aggregtor_get_num_blocks;
	aggregator->base.has_data_stored = flash_store_aggregtor_has_data_stored;

	aggregator->flash_store_array = flash_store_array;
	aggregator->flash_store_cnt = falsh_store_cnt;

	return 0;
}

/**
 * Release the resources used for flash store aggregator.
 *
 * @param aggregator The flash store aggregator to release.
 */
void flash_store_aggregator_release (const struct flash_store_aggregator *aggregator)
{
	UNUSED (aggregator);
}
