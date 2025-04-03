// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "flash_store_contiguous_blocks_key_wrap.h"
#include "platform_api.h"
#include "common/buffer_util.h"


int flash_store_contiguous_blocks_key_wrap_write (const struct flash_store *flash_store, int id,
	const uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks_key_wrap *encrypted =
		(const struct flash_store_contiguous_blocks_key_wrap*) flash_store;
	uint8_t *enc_data;
	size_t enc_length = AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (length);
	int status;

	status = flash_store_contiguous_blocks_verify_write_params (&encrypted->base, id, data, length);
	if (status != 0) {
		return status;
	}

	enc_data = platform_malloc (enc_length);
	if (enc_data == NULL) {
		return FLASH_STORE_NO_MEMORY;
	}

	status = encrypted->key_wrap->wrap (encrypted->key_wrap, data, length, enc_data, enc_length);
	if (status != 0) {
		goto exit;
	}

	status = flash_store_contiguous_blocks_write_common (&encrypted->base, id, enc_data, enc_length,
		NULL, 0);

exit:
	buffer_zeroize (enc_data, enc_length);
	platform_free (enc_data);

	return status;
}

int flash_store_contiguous_blocks_key_wrap_read (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks_key_wrap *encrypted =
		(const struct flash_store_contiguous_blocks_key_wrap*) flash_store;
	size_t enc_length;
	int status;

	status = flash_store_contiguous_blocks_read_common (&encrypted->base, id, data, length,
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, NULL, 0, &enc_length);
	if (status != 0) {
		return status;
	}

	status = encrypted->key_wrap->unwrap (encrypted->key_wrap, data, enc_length, data, &length);
	if (status != 0) {
		switch (status) {
			case AES_KEY_WRAP_INTEGRITY_CHECK_FAIL:
			case AES_KEY_WRAP_LENGTH_CHECK_FAIL:
			case AES_KEY_WRAP_PADDING_CHECK_FAIL:
				length = FLASH_STORE_CORRUPT_DATA;
				break;

			default:
				length = status;
				break;
		}
	}

	return length;
}

int flash_store_contiguous_blocks_key_wrap_get_data_length (const struct flash_store *flash_store,
	int id)
{
	int length;

	length = flash_store_contiguous_blocks_get_data_length (flash_store, id);
	if (ROT_IS_ERROR (length)) {
		return length;
	}

	/* If the data is not aligned to the key wrap data block, the data is not valid. */
	if (AES_KEY_WRAP_INTERFACE_NOT_BLOCK_ALGINED (length)) {
		return FLASH_STORE_NO_DATA;
	}

	return length;
}

/**
 * Initialize flash storage for contiguous encrypted blocks of data using AES Key Wrap for
 * encryption and integrity protection.
 *
 * @param store The flash storage to initialize.
 * @param state Variable context for flash storage.  This must be uninitialized.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The minimum length of each data block.
 * @param key_wrap The AES key wrap instance to use for data encryption.  The KEK for wrap/unwrap
 * operations must be managed and set separately from the flash storage.
 * @param decreasing Flag indicating if the storage grows down in the device address space.
 * @param variable Flag indicating if the blocks contain variable length data.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
static int flash_store_contiguous_blocks_key_wrap_init_storage_common (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length,
	const struct aes_key_wrap_interface *key_wrap, bool decreasing, bool variable)
{
	int status;

	status = flash_store_contiguous_blocks_init_storage_common (&store->base, state, flash,
		base_addr, block_count, data_length, decreasing, variable);
	if (status != 0) {
		return status;
	}

	store->base.base.write = flash_store_contiguous_blocks_key_wrap_write;
	store->base.base.read = flash_store_contiguous_blocks_key_wrap_read;
	store->base.base.get_data_length = flash_store_contiguous_blocks_key_wrap_get_data_length;

	store->key_wrap = key_wrap;

	return flash_store_contiguous_blocks_key_wrap_init_state (store, data_length);
}

/**
 * Initialize flash storage for fixed sized contiguous encrypted blocks of data using AES Key Wrap
 * for encryption and integrity protection.
 *
 * @param store The flash storage to initialize.
 * @param state Variable context for flash storage.  This must be uninitialized.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The length of each data block.
 * @param key_wrap The AES key wrap instance to use for data encryption.  The KEK for wrap/unwrap
 * operations must be managed and set separately from the flash storage.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_key_wrap_init_fixed_storage (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length,
	const struct aes_key_wrap_interface *key_wrap)
{
	return flash_store_contiguous_blocks_key_wrap_init_storage_common (store, state, flash,
		base_addr, block_count, data_length, key_wrap, false, false);
}

/**
 * Initialize flash storage for fixed sized contiguous encrypted blocks of data using AES Key Wrap
 * for encryption and integrity protection. Blocks will be stored in addresses decreasing from the
 * first block.
 *
 * @param store The flash storage to initialize.
 * @param state Variable context for flash storage.  This must be uninitialized.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The length of each data block.
 * @param key_wrap The AES key wrap instance to use for data encryption.  The KEK for wrap/unwrap
 * operations must be managed and set separately from the flash storage.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length,
	const struct aes_key_wrap_interface *key_wrap)
{
	return flash_store_contiguous_blocks_key_wrap_init_storage_common (store, state, flash,
		base_addr, block_count, data_length, key_wrap, true, false);
}

/**
 * Initialize flash storage for variable sized contiguous encrypted blocks of data using AES Key
 * Wrap for encryption and integrity protection.
 *
 * @param store The flash storage to initialize.
 * @param state Variable context for flash storage.  This must be uninitialized.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param min_length The minimum length required for each data block.  The actual length length will
 * be determined by the flash sector size.
 * @param key_wrap The AES key wrap instance to use for data encryption.  The KEK for wrap/unwrap
 * operations must be managed and set separately from the flash storage.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_key_wrap_init_variable_storage (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length,
	const struct aes_key_wrap_interface *key_wrap)
{
	return flash_store_contiguous_blocks_key_wrap_init_storage_common (store, state, flash,
		base_addr, block_count, min_length, key_wrap, false, true);
}

/**
 * Initialize flash storage for variable sized contiguous encrypted blocks of data using AES Key
 * Wrap for encryption and integrity protection.  Blocks will be stored in addresses decreasing from
 * the first block.
 *
 * @param store The flash storage to initialize.
 * @param state Variable context for flash storage.  This must be uninitialized.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param min_length The minimum length required for each data block.  The actual length length will
 * be determined by the flash sector size.
 * @param key_wrap The AES key wrap instance to use for data encryption.  The KEK for wrap/unwrap
 * operations must be managed and set separately from the flash storage.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks_key_wrap *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length,
	const struct aes_key_wrap_interface *key_wrap)
{
	return flash_store_contiguous_blocks_key_wrap_init_storage_common (store, state, flash,
		base_addr, block_count, min_length, key_wrap, true, true);
}

/**
 * Initialize the variable state for a flash store encrypted using AES-KEY_WRAP.
 *
 * @param store The flash storage to initialize.
 * @param data_length The minimum length of each data block.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_key_wrap_init_state (
	const struct flash_store_contiguous_blocks_key_wrap *store, size_t data_length)
{
	size_t padding;
	size_t header_padding = 0;

	if ((store == NULL) || (store->key_wrap == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	if (store->base.variable) {
		/* For variable storage, only the extra block that gets added to the wrapped data is
		 * considered storage overhead.  The rest is available for storing data.  However, the
		 * header length needs to be aligned to the block size, with any padding bytes being
		 * unusable. */
		data_length = AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (data_length);
		padding = AES_KEY_WRAP_INTERFACE_BLOCK_SIZE;
		header_padding =
			AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			sizeof (struct flash_store_header);
	}
	else {
		/* For fixed length storage, any additional data needed beyond the specified length is
		 * considered storage overhead. */
		padding = AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (data_length) - data_length;
	}

	return flash_store_contiguous_blocks_init_state_common (&store->base, data_length + padding,
		padding, header_padding);
}

/**
 * Release the resources used for AES-KEY_WRAP encrypted flash block storage.
 *
 * @param store The flash storage to release.
 */
void flash_store_contiguous_blocks_key_wrap_release (
	const struct flash_store_contiguous_blocks_key_wrap *store)
{
	flash_store_contiguous_blocks_release (&store->base);
}
