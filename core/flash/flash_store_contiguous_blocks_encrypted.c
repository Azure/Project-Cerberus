// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "flash_store_contiguous_blocks_encrypted.h"
#include "flash_util.h"
#include "platform_api.h"


/**
 * The IV length to use for encryption.
 */
#define	FLASH_STORE_AES_IV_LENGTH		12


int flash_store_contiguous_blocks_encrypted_write (const struct flash_store *flash_store, int id,
	const uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks_encrypted *encrypted =
		(const struct flash_store_contiguous_blocks_encrypted*) flash_store;
	uint8_t *enc_data;
	uint8_t iv_tag[FLASH_STORE_AES_IV_LENGTH + AES_TAG_LENGTH];
	int status;

	status = flash_store_contiguous_blocks_verify_write_params (&encrypted->base, id, data, length);
	if (status != 0) {
		return status;
	}

	enc_data = platform_malloc (length);
	if (enc_data == NULL) {
		return FLASH_STORE_NO_MEMORY;
	}

	status = encrypted->rng->generate_random_buffer (encrypted->rng, FLASH_STORE_AES_IV_LENGTH,
		iv_tag);
	if (status != 0) {
		goto exit;
	}

	status = encrypted->aes->encrypt_data (encrypted->aes, data, length, iv_tag,
		FLASH_STORE_AES_IV_LENGTH, enc_data, length, &iv_tag[FLASH_STORE_AES_IV_LENGTH],
		AES_TAG_LENGTH);
	if (status != 0) {
		goto exit;
	}

	status = flash_store_contiguous_blocks_write_common (&encrypted->base, id, enc_data, length,
		iv_tag, sizeof (iv_tag));

exit:
	platform_free (enc_data);

	return status;
}

int flash_store_contiguous_blocks_encrypted_read (const struct flash_store *flash_store, int id,
	uint8_t *data, size_t length)
{
	const struct flash_store_contiguous_blocks_encrypted *encrypted =
		(const struct flash_store_contiguous_blocks_encrypted*) flash_store;
	uint8_t iv_tag[FLASH_STORE_AES_IV_LENGTH + AES_TAG_LENGTH];
	int status;

	status = flash_store_contiguous_blocks_read_common (&encrypted->base, id, data, length, iv_tag,
		sizeof (iv_tag), &length);
	if (status != 0) {
		return status;
	}

	status = encrypted->aes->decrypt_data (encrypted->aes, data, length,
		&iv_tag[FLASH_STORE_AES_IV_LENGTH], iv_tag, FLASH_STORE_AES_IV_LENGTH, data, length);
	if (status != 0) {
		if (status == AES_ENGINE_GCM_AUTH_FAILED) {
			return FLASH_STORE_CORRUPT_DATA;
		}
		else {
			return status;
		}
	}

	return length;
}

/**
 * Initialize flash storage for contiguous encrypted blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The minimum length of each data block.
 * @param aes The AES engine to use for data encryption.  The must be pre-loaded with the encryption
 * key.
 * @param rng The random number generator to use for creating encryption IVs.
 * @param decreasing Flag indicating if the storage grows down in the device address space.
 * @param variable Flag indicating if the blocks contain variable length data.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
static int flash_store_contiguous_blocks_encrypted_init_storage_common (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct aes_engine *aes,
	struct rng_engine *rng, bool decreasing, bool variable)
{
	int status;

	if ((aes == NULL) || (rng == NULL)) {
		return FLASH_STORE_INVALID_ARGUMENT;
	}

	status = flash_store_contiguous_blocks_init_storage_common (&store->base, state, flash,
		base_addr, block_count, data_length, decreasing, variable);
	if (status != 0) {
		return status;
	}

	status = flash_store_contiguous_blocks_encrypted_init_state (store, block_count, data_length);
	if (status != 0) {
		return status;
	}

	store->base.base.write = flash_store_contiguous_blocks_encrypted_write;
	store->base.base.read = flash_store_contiguous_blocks_encrypted_read;

	store->aes = aes;
	store->rng = rng;

	return 0;
}

/**
 * Initialize flash storage for fixed sized contiguous blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The length of each data block.
 * @param aes The AES engine to use for data encryption.  The must be pre-loaded with the encryption
 * key.
 * @param rng The random number generator to use for creating encryption IVs.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_encrypted_init_fixed_storage (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct aes_engine *aes,
	struct rng_engine *rng)
{
	return flash_store_contiguous_blocks_encrypted_init_storage_common (store, state, flash,
		base_addr, block_count, data_length, aes, rng, false, false);
}

/**
 * Initialize flash storage for fixed sized contiguous blocks of data.  Blocks will be stored in
 * addresses decreasing from the first block.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The length of each data block.
 * @param aes The AES engine to use for data encryption.  The must be pre-loaded with the encryption
 * key.
 * @param rng The random number generator to use for creating encryption IVs.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_encrypted_init_fixed_storage_decreasing (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t data_length, const struct aes_engine *aes,
	struct rng_engine *rng)
{
	return flash_store_contiguous_blocks_encrypted_init_storage_common (store, state, flash,
		base_addr, block_count, data_length, aes, rng, true, false);
}

/**
 * Initialize flash storage for variable sized contiguous blocks of data.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param min_length The minimum length required for each data block.  The actual length length will
 * be determined by the flash sector size.
 * @param aes The AES engine to use for data encryption.  The must be pre-loaded with the encryption
 * key.
 * @param rng The random number generator to use for creating encryption IVs.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_encrypted_init_variable_storage (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr,	size_t block_count, size_t min_length, const struct aes_engine *aes,
	struct rng_engine *rng)
{
	return flash_store_contiguous_blocks_encrypted_init_storage_common (store, state, flash,
		base_addr, block_count, min_length, aes, rng, false, true);
}

/**
 * Initialize flash storage for variable sized contiguous blocks of data.  Blocks will be stored in
 * addresses decreasing from the first block.
 *
 * @param store The flash storage to initialize.
 * @param flash The flash device used for storage.
 * @param base_addr The address of the first storage block.  This must be aligned to a minimum erase
 * block.
 * @param block_count The number of data blocks used for storage.
 * @param min_length The minimum length required for each data block.  The actual length length will
 * be determined by the flash sector size.
 * @param aes The AES engine to use for data encryption.  The must be pre-loaded with the encryption
 * key.
 * @param rng The random number generator to use for creating encryption IVs.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_encrypted_init_variable_storage_decreasing (
	struct flash_store_contiguous_blocks_encrypted *store,
	struct flash_store_contiguous_blocks_state *state, const struct flash *flash,
	uint32_t base_addr, size_t block_count, size_t min_length, const struct aes_engine *aes,
	struct rng_engine *rng)
{
	return flash_store_contiguous_blocks_encrypted_init_storage_common (store, state, flash,
		base_addr, block_count, min_length, aes, rng, true, true);
}

/**
 * Initialize the variable state for encrypted flash store interface.
 *
 * @param store The flash storage to initialize.
 * @param block_count The number of data blocks used for storage.
 * @param data_length The minimum length of each data block.
 *
 * @return 0 if the flash storage was successfully initialized or an error code.
 */
int flash_store_contiguous_blocks_encrypted_init_state (
	const struct flash_store_contiguous_blocks_encrypted *store, size_t block_count,
	size_t data_length)
{
	return flash_store_contiguous_blocks_init_state_common (&store->base, block_count, data_length,
		FLASH_STORE_AES_IV_LENGTH + AES_TAG_LENGTH);
}

/**
 * Release the resources used for encrypted flash block storage.
 *
 * @param store The flash storage to relaese.
 */
void flash_store_contiguous_blocks_encrypted_release (
	const struct flash_store_contiguous_blocks_encrypted *store)
{
	flash_store_contiguous_blocks_release (&store->base);
}
