// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include "flash_util.h"
#include "flash_common.h"


/**
 * Validate the contents of a contiguous block of data stored in a flash device against an RSA
 * encrypted signature.
 *
 * @param flash The flash device that contains the data to verify.
 * @param start_addr The first address of the data that should be verified.
 * @param length The number of bytes to verify.
 * @param hash The hashing engine to use for verification.
 * @param type The hashing algorithm used for the signature.
 * @param rsa The RSA engine to use for signature verification.
 * @param signature The signature for the data block.
 * @param sig_length The length of the signature.
 * @param pub_key The public key for the signature.
 * @param hash_out Optional output buffer for the calculated hash. This will be valid even if the
 * signature verification fails.  Set this to NULL if the hash is not needed.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the flash contents are valid or an error code.
 */
int flash_verify_contents (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash, enum hash_type type, struct rsa_engine *rsa, const uint8_t *signature,
	size_t sig_length, const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length)
{
	struct flash_region region;

	if (length == 0) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	region.start_addr = start_addr;
	region.length = length;

	return flash_verify_noncontiguous_contents (flash, &region, 1, hash, type, rsa, signature,
		sig_length, pub_key, hash_out, hash_length);
}

/**
 * Validate the contents of a group of noncontiguous blocks of data stored in a flash device
 * against an RSA encrypted signature.
 *
 * @param flash The flash device that contains the data to verify.
 * @param regions The group of flash regions that should be verified as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use for verification.
 * @param type The hashing algorithm used for the signature.
 * @param rsa The RSA engine to use for signature verification.
 * @param signature The signature for the data block.
 * @param sig_length The length of the signature.
 * @param pub_key The public key for the signature.
 * @param hash_out Optional output buffer for the calculated hash. This will be valid even if the
 * signature verification fails.  Set this to NULL if the hash is not needed.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the flash contents are valid or an error code.
 */
int flash_verify_noncontiguous_contents (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct rsa_engine *rsa, const uint8_t *signature, size_t sig_length,
	const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length)
{
	return flash_verify_noncontiguous_contents_at_offset (flash, 0, regions, count, hash, type, rsa,
		signature, sig_length, pub_key, hash_out, hash_length);
}

/**
 * Validate the contents of a group of noncontiguous blocks of data stored in a flash device
 * against an RSA encrypted signature.
 *
 * All regions will be verified starting at a fixed offset in flash.
 *
 * @param flash The flash device that contains the data to verify.
 * @param offset An offset to apply to each region address.
 * @param regions The group of flash regions that should be verified as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use for verification.
 * @param type The hashing algorithm used for the signature.
 * @param rsa The RSA engine to use for signature verification.
 * @param signature The signature for the data block.
 * @param sig_length The length of the signature.
 * @param pub_key The public key for the signature.
 * @param hash_out Optional output buffer for the calculated hash. This will be valid even if the
 * signature verification fails.  Set this to NULL if the hash is not needed.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the flash contents are valid or an error code.
 */
int flash_verify_noncontiguous_contents_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct rsa_engine *rsa, const uint8_t *signature, size_t sig_length,
	const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length)
{
	uint8_t data_hash[SHA256_HASH_LENGTH];
	int status;

	if ((flash == NULL) || (regions == NULL) || (hash == NULL) || (rsa == NULL) ||
		(signature == NULL) || (pub_key == NULL) || (count == 0) || (sig_length == 0)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_length < SHA256_HASH_LENGTH)) {
		return FLASH_UTIL_HASH_BUFFER_TOO_SMALL;
	}

	if (hash_out == NULL) {
		hash_out = data_hash;
	}

	switch (type) {
		case HASH_TYPE_SHA256:
			break;

		case HASH_TYPE_SHA1:
			return FLASH_UTIL_UNSUPPORTED_SIG_HASH;

		default:
			return FLASH_UTIL_UNKNOWN_SIG_HASH;
	}

	status = flash_hash_noncontiguous_contents_at_offset (flash, offset, regions, count, hash, type,
		hash_out, SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	return rsa->sig_verify (rsa, pub_key, signature, sig_length, hash_out, SHA256_HASH_LENGTH);
}

/**
 * Validate the contents of a contiguous block of data stored in a flash device using a signature
 * verification module.
 *
 * @param flash The flash device that contains the data to verify.
 * @param start_addr The first address of the data that should be verified.
 * @param length The number of bytes to verify.
 * @param hash The hashing engine to use for verification.
 * @param type The hashing algorithm used for the signature.
 * @param verification The module to use for signature verification.
 * @param signature The signature for the data block.
 * @param sig_length The length of the signature.
 * @param hash_out Optional output buffer for the calculated hash. This will be valid even if the
 * signature verification fails.  Set this to NULL if the hash is not needed.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the flash contents are valid or an error code.
 */
int flash_contents_verification (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash, enum hash_type type, struct signature_verification *verification,
	const uint8_t *signature, size_t sig_length, uint8_t *hash_out, size_t hash_length)
{
	struct flash_region region;

	if (length == 0) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	region.start_addr = start_addr;
	region.length = length;

	return flash_noncontiguous_contents_verification (flash, &region, 1, hash, type, verification,
		signature, sig_length, hash_out, hash_length);
}

/**
 * Validate the contents of a group of noncontiguous blocks of data stored in a flash device using
 * a signature verification module.
 *
 * @param flash The flash device that contains the data to verify.
 * @param regions The group of flash regions that should be verified as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use for verification.
 * @param type The hashing algorithm used for the signature.
 * @param verification The module to use for signature verification.
 * @param signature The signature for the data block.
 * @param sig_length The length of the signature.
 * @param hash_out Optional output buffer for the calculated hash. This will be valid even if the
 * signature verification fails.  Set this to NULL if the hash is not needed.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the flash contents are valid or an error code.
 */
int flash_noncontiguous_contents_verification (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct signature_verification *verification, const uint8_t *signature, size_t sig_length,
	uint8_t *hash_out, size_t hash_length)
{
	return flash_noncontiguous_contents_verification_at_offset (flash, 0, regions, count, hash,
		type, verification, signature, sig_length, hash_out, hash_length);
}

/**
 * Validate the contents of a group of noncontiguous blocks of data stored in a flash device using
 * a signature verification module.
 *
 * All regions will be verified starting at a fixed offset in flash.
 *
 * @param flash The flash device that contains the data to verify.
 * @param offset An offset to apply to each region address.
 * @param regions The group of flash regions that should be verified as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use for verification.
 * @param type The hashing algorithm used for the signature.
 * @param verification The module to use for signature verification.
 * @param signature The signature for the data block.
 * @param sig_length The length of the signature.
 * @param hash_out Optional output buffer for the calculated hash. This will be valid even if the
 * signature verification fails.  Set this to NULL if the hash is not needed.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the flash contents are valid or an error code.
 */
int flash_noncontiguous_contents_verification_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct signature_verification *verification, const uint8_t *signature, size_t sig_length,
	uint8_t *hash_out, size_t hash_length)
{
	uint8_t data_hash[SHA256_HASH_LENGTH];
	int status;

	if ((flash == NULL) || (hash == NULL) || (verification == NULL) || (signature == NULL) ||
		(sig_length == 0) || (count == 0)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_length < SHA256_HASH_LENGTH)) {
		return FLASH_UTIL_HASH_BUFFER_TOO_SMALL;
	}

	if (hash_out == NULL) {
		hash_out = data_hash;
	}

	switch (type) {
		case HASH_TYPE_SHA256:
			break;

		case HASH_TYPE_SHA1:
			return FLASH_UTIL_UNSUPPORTED_SIG_HASH;

		default:
			return FLASH_UTIL_UNKNOWN_SIG_HASH;
	}

	status = flash_hash_noncontiguous_contents_at_offset (flash, offset, regions, count, hash, type,
		hash_out, SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	return verification->verify_signature (verification, hash_out, SHA256_HASH_LENGTH, signature,
		sig_length);
}

/**
 * Generate a hash for a contiguous block of data stored in a flash device.
 *
 * @param flash The flash device that contains the data to hash.
 * @param start_addr The first address of the data that should be hashed.
 * @param length The number of bytes to hash.
 * @param hash The hashing engine to use to generate the hash.
 * @param type The type of hash to generate.
 * @param hash_out The buffer to hold the generated hash value.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the hash was generated successfully or an error code.
 */
int flash_hash_contents (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash, enum hash_type type, uint8_t *hash_out, size_t hash_length)
{
	struct flash_region region;

	if (length == 0) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	region.start_addr = start_addr;
	region.length = length;

	return flash_hash_noncontiguous_contents (flash, &region, 1, hash, type, hash_out, hash_length);
}

/**
 * Generate a hash for a group of noncontiguous blocks of data stored in a flash device.
 *
 * @param flash The flash device that contains the data to hash.
 * @param regions The group of regions that should be hashed as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use to generate the hash.
 * @param type The type of hash to generate.
 * @param hash_out The buffer to hold the generated hash value.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the hash was generated successfully or an error code.
 */
int flash_hash_noncontiguous_contents (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	uint8_t *hash_out, size_t hash_length)
{
	return flash_hash_noncontiguous_contents_at_offset (flash, 0, regions, count, hash, type,
		hash_out, hash_length);
}

/**
 * Generate a hash for a group of noncontiguous blocks of data stored in a flash device.  All
 * regions will be hashed starting at a fixed offset in flash.
 *
 * @param flash The flash device that contains the data to hash.
 * @param offset An offset to apply to each region address.
 * @param regions The group of regions that should be hashed as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use to generate the hash.
 * @param type The type of hash to generate.
 * @param hash_out The buffer to hold the generated hash value.
 * @param hash_length The length of the hash output buffer.
 *
 * @return 0 if the hash was generated successfully or an error code.
 */
int flash_hash_noncontiguous_contents_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	uint8_t *hash_out, size_t hash_length)
{
	int status;

	if ((flash == NULL) || (regions == NULL) || (hash == NULL) || (hash_out == NULL) ||
		(count == 0) || (hash_length == 0)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, type);
	if (status != 0) {
		return status;
	}

	status = flash_hash_update_noncontiguous_contents_at_offset (flash, offset, regions, count,
		hash);
	if (status != 0) {
		goto fail;
	}

	status = hash->finish (hash, hash_out, hash_length);
	if (status != 0) {
		goto fail;
	}

return 0;

fail:
	hash->cancel (hash);
	return status;
}

/**
 * Update a hash for a contiguous block of data stored in a flash device.
 *
 * The hash context must already be started prior to this call.  The hashing context will not be
 * canceled on failure.
 *
 * @param flash The flash device that contains the data to hash.
 * @param start_addr The first address of the data that should be hashed.
 * @param length The number of bytes to hash.
 * @param hash The hashing engine to use to generate the hash.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int flash_hash_update_contents (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash)
{
	struct flash_region region;

	if (length == 0) {
		return 0;
	}

	region.start_addr = start_addr;
	region.length = length;

	return flash_hash_update_noncontiguous_contents (flash, &region, 1, hash);
}

/**
 * Update a hash for a group of noncontiguous blocks of data stored in a flash device.
 *
 * The hash context must already be started prior to this call.  The hashing context will not be
 * canceled on failure.
 *
 * @param flash The flash device that contains the data to hash.
 * @param regions The group of regions that should be hashed as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use to generate the hash.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int flash_hash_update_noncontiguous_contents (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash)
{
	return flash_hash_update_noncontiguous_contents_at_offset (flash, 0, regions, count, hash);
}

/**
 * Update a hash for a group of noncontiguous blocks of data stored in a flash device.  All regions
 * will be hashed starting at a fixed offset in flash.
 *
 * The hash context must already be started prior to this call.  The hashing context will not be
 * canceled on failure.
 *
 * @param flash The flash device that contains the data to hash.
 * @param offset An offset to apply to each region address.
 * @param regions The group of regions that should be hashed as a single region.
 * @param count The number of regions defined in the group.
 * @param hash The hashing engine to use to generate the hash.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int flash_hash_update_noncontiguous_contents_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash)
{
	uint8_t data[FLASH_VERIFICATION_BLOCK];
	size_t next_read;
	uint32_t current_addr;
	size_t remaining;
	size_t i;
	int status;

	if ((flash == NULL) || (regions == NULL) || (count == 0) || (hash == NULL)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	for (i = 0; i < count; i++) {
		current_addr = regions[i].start_addr + offset;
		remaining = regions[i].length;

		while (remaining > 0) {
			next_read = (remaining < FLASH_VERIFICATION_BLOCK) ?
				remaining : FLASH_VERIFICATION_BLOCK;

			status = flash->read (flash, current_addr, data, next_read);
			if (status != 0) {
				return status;
			}

			status = hash->update (hash, data, next_read);
			if (status != 0) {
				return status;
			}

			remaining -= next_read;
			current_addr += next_read;
		}
	}

	return 0;
}

/**
 * Erase a region of flash.
 *
 * @param flash The flash device to erase.
 * @param start_addr The starting address of the region to erase.  The erase operations will include
 * data before the starting address if the address is not aligned to the erase granularity.
 * @param length The number of bytes to erase starting from start_addr.  Additional bytes erased to
 * align to erasable chunks does not count toward this length.
 * @param block_size Function to determine the minimum number of bytes that can be erased.
 * @param erase The function to use to erase the flash.
 *
 * @return 0 if the region was successfully erased or an error code.
 */
static int flash_erase_region_ext (const struct flash *flash, uint32_t start_addr, size_t length,
	int (*block_size) (const struct flash*, uint32_t*),
	int (*erase) (const struct flash*, uint32_t))
{
	uint32_t block;
	size_t erased;
	int status;

	status = block_size (flash, &block);
	if (status != 0) {
		return status;
	}

	while ((status == 0) && (length != 0)) {
		status = erase (flash, start_addr);
		erased = block - FLASH_REGION_OFFSET (start_addr, block);
		length -= ((length > erased) ? erased : length);
		start_addr += erased;
	}

	return status;
}

/**
 * Erase a region of flash.  The erasure will occur on flash blocks boundaries, typically 64kB.
 * The total amount of data erased from the flash could be up to two flash blocks more than
 * requested, depending on the defined region.
 *
 * @param flash The flash device to erase.
 * @param start_addr The starting address of the region to erase.  The erase operation will actually
 * start at the beginning of the flash block that contains the starting address.
 * @param length The number of bytes to erase starting from start_addr.  Any additional data that
 * needs to be erased to align to block boundaries does not count toward this length.
 *
 * @return 0 if the region was successfully erased or an error code.
 */
int flash_erase_region (const struct flash *flash, uint32_t start_addr, size_t length)
{
	if (flash == NULL) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	return flash_erase_region_ext (flash, start_addr, length, flash->get_block_size,
		flash->block_erase);
}

/**
 * Erase a region of flash.  The erasure will occur on flash sector boundaries, typically 4kB.
 * The total amount of data erased from the flash could be up to two flash sectors more than
 * requested, depending on the defined region.
 *
 * @param flash The flash device to erase.
 * @param start_addr The starting address of the region to erase.  The erase operation will actually
 * start at the beginning of the flash sector that contains the starting address.
 * @param length The number of bytes to erase starting from start_addr.  Any additional data that
 * needs to be erased to align to sector boundaries does not count toward this length.
 *
 * @return 0 if the region was successfully erased or an error code.
 */
int flash_sector_erase_region (const struct flash *flash, uint32_t start_addr, size_t length)
{
	if (flash == NULL) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	return flash_erase_region_ext (flash, start_addr, length, flash->get_sector_size,
		flash->sector_erase);
}

/**
 * Check a region of flash to ensure it contains the expected data.
 *
 * @param flash The flash device to check.
 * @param start_addr The starting address of the region to check.
 * @param data The data that should be in the flash.  If this is null, the bytes will be checked to
 * see if they are all blank.
 * @param length The size of the flash region to check.
 * @param const_byte Flag indicating if the expected data is a constant byte.
 *
 * @return 0 if the region contains the expected data or an error code.
 */
static int flash_check_region_for_data (const struct flash *flash, uint32_t start_addr,
	const uint8_t *data, size_t length, bool const_byte)
{
	uint8_t block[FLASH_VERIFICATION_BLOCK];
	uint8_t next = (const_byte) ? 0 : 1;
	size_t read_len;
	int flash_good = 0;
	size_t i;

	if (flash == NULL) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	while ((flash_good == 0) && (length > 0)) {
		read_len = (length > sizeof (block)) ? sizeof (block) : length;

		flash_good = flash->read (flash, start_addr, block, read_len);
		if (flash_good == 0) {
			for (i = 0; i < read_len; i++, data += next) {
				if (*data != block[i]) {
					flash_good = FLASH_UTIL_DATA_MISMATCH;
					break;
				}
			}

			start_addr += read_len;
			length -= read_len;
		}
	}

	return flash_good;
}

/**
 * Check that a region of flash is blank.
 *
 * @param flash The flash device to check.
 * @param start_addr The starting address of the region to check.
 * @param length The number of bytes to check.
 *
 * @return 0 if all bytes in the region are blank or an error code.
 */
int flash_blank_check (const struct flash *flash, uint32_t start_addr, size_t length)
{
	uint8_t blank = 0xff;
	int status = flash_check_region_for_data (flash, start_addr, &blank, length, true);
	return (status == FLASH_UTIL_DATA_MISMATCH) ? FLASH_UTIL_NOT_BLANK : status;
}

/**
 * Check that a region of flash contains a specific value in every byte.
 *
 * @param flash The flash device to check.
 * @param start_addr The starting address of the region to check.
 * @param length The number of bytes to check.
 * @param value The expected byte value.
 *
 * @return 0 if all bytes in the region are set to the expected value or an error code.
 */
int flash_value_check (const struct flash *flash, uint32_t start_addr, size_t length, uint8_t value)
{
	int status = flash_check_region_for_data (flash, start_addr, &value, length, true);
	return (status == FLASH_UTIL_DATA_MISMATCH) ? FLASH_UTIL_UNEXPECTED_VALUE : status;
}

/**
 * Erase a region of flash and check that the contents are blank.  Erasure will occur on flash erase
 * boundaries, so the total number of bytes erased may be more than requested.
 *
 * @param flash The flash device to erase.
 * @param start_addr The starting address of the region to erase.  The erase operation will actually
 * start at the beginning of the erase block that contains the starting address.  Blank checking
 * will begin an this address.  Extra data erased for alignment will not be checked.
 * @param length The number of bytes to erase starting from start_addr.  Any additional data that
 * needs to be erased to align to block boundaries does not count toward this length.
 * @param erase Function to erase the flash region.
 *
 * @return 0 if the region was successfully erased and blank checked or an error code.
 */
static int flash_erase_region_and_verify_ext (const struct flash *flash, uint32_t start_addr,
	size_t length, int (*erase) (const struct flash*, uint32_t, size_t))
{
	int status;

	status = erase (flash, start_addr, length);
	if (status == 0) {
		status = flash_blank_check (flash, start_addr, length);
	}

	return status;
}

/**
 * Erase a region of flash and check that the contents are blank.  The erasure will occur on block
 * boundaries, typically 64kB.  The total amount of data erased from the flash could be up to two
 * flash blocks more than requested, depending on the defined region.
 *
 * @param flash The flash device to erase.
 * @param start_addr The starting address of the region to erase.  The erase operation will actually
 * start at the beginning of the flash block that contains the starting address.
 * @param length The number of bytes to erase starting from start_addr.  Any additional data that
 * needs to be erased to align to block boundaries does not count toward this length.
 *
 * @return 0 if the region was successfully erased or an error code.
 */
int flash_erase_region_and_verify (const struct flash *flash, uint32_t start_addr, size_t length)
{
	return flash_erase_region_and_verify_ext (flash, start_addr, length, flash_erase_region);
}

/**
 * Erase a region of flash and check that the contents are blank.  The erasure will occur on sector
 * boundaries, typically 4kB.  The total amount of data erased from the flash could be up to two
 * flash sectors more than requested, depending on the defined region.
 *
 * @param flash The flash device to erase.
 * @param start_addr The starting address of the region to erase.  The erase operation will actually
 * start at the beginning of the flash sector that contains the starting address.
 * @param length The number of bytes to erase starting from start_addr.  Any additional data that
 * needs to be erased to align to sector boundaries does not count toward this length.
 *
 * @return 0 if the region was successfully erased or an error code.
 */
int flash_sector_erase_region_and_verify (const struct flash *flash, uint32_t start_addr,
	size_t length)
{
	return flash_erase_region_and_verify_ext (flash, start_addr, length, flash_sector_erase_region);
}

/**
 * Program a block of data to a flash device after first erasing the region to be programmed.
 *
 * @param flash The device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The amount of data to store.
 * @param erase The function to use to erase the flash.  Null to skip erasing.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
static int flash_program_data_ext (const struct flash *flash, uint32_t start_addr,
	const uint8_t *data, size_t length, int (*erase) (const struct flash*, uint32_t, size_t))
{
	int status;

	if ((flash == NULL) || (data == NULL)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	if (erase) {
		status = erase (flash, start_addr, length);
		if (status != 0) {
			return status;
		}
	}

	status = flash->write (flash, start_addr, data, length);
	if (!ROT_IS_ERROR (status)) {
		if ((size_t) status != length) {
			status = FLASH_UTIL_INCOMPLETE_WRITE;
		}
		else {
			status = 0;
		}
	}

	return status;
}

/**
 * Program a block of data to a flash device after first erasing the region to be programmed.
 * Erasing will be done on flash block boundaries, typically 64kB.
 *
 * @param flash The device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The amount of the data to store.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
int flash_program_data (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length)
{
	return flash_program_data_ext (flash, start_addr, data, length, flash_erase_region);
}

/**
 * Program a block of data to a flash device after first erasing the region to be programmed.
 * Erasing will be done on flash sector boundaries, typically 4kB
 *
 * @param flash The device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The amount of the data to store.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
int flash_sector_program_data (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length)
{
	return flash_program_data_ext (flash, start_addr, data, length, flash_sector_erase_region);
}

/**
 * Verify that a region of flash contains the expected data.
 *
 * @param flash The flash device to check.
 * @param start_addr The address where data verification should start.
 * @param data The data that is expected to be in the flash.
 * @param length The length of the expected data.
 *
 * @return 0 if the data in the flash exactly matches the expected data or an error code.
 */
int flash_verify_data (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length)
{
	if (data == NULL) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	return flash_check_region_for_data (flash, start_addr, data, length, false);
}

/**
 * Program a block of data to a flash device after first erasing the region to be programmed.  After
 * the data has been programmed, verify that the programming was successful by checking that the
 * flash contains the expected data.
 *
 * @param flash The flash device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The length of the data to store.
 * @param erase Function to use for erasing the flash.  Null to skip erase.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
static int flash_program_and_verify_ext (const struct flash *flash, uint32_t start_addr,
	const uint8_t *data, size_t length, int (*erase) (const struct flash*, uint32_t, size_t))
{
	int status;

	status = flash_program_data_ext (flash, start_addr, data, length, erase);
	if (status != 0) {
		return status;
	}

	return flash_verify_data (flash, start_addr, data, length);
}

/**
 * Program a block of data to a flash device after first erasing the region to be programmed.  After
 * the data has been programmed, verify that the programming was successful by checking that the
 * flash contains the expected data.
 *
 * Erasing will be done on flash block boundaries, typically 64kB.
 *
 * @param flash The flash device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The length of the data to store.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
int flash_program_and_verify (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length)
{
	return flash_program_and_verify_ext (flash, start_addr, data, length, flash_erase_region);
}

/**
 * Program a block of data to a flash device after first erasing the region to be programmed.  After
 * the data has been programmed, verify that the programming was successful by checking that the
 * flash contains the expected data.
 *
 * Erasing will be done on flash sector boundaries, typically 4kB.
 *
 * @param flash The flash device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The length of the data to store.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
int flash_sector_program_and_verify (const struct flash *flash, uint32_t start_addr,
	const uint8_t *data, size_t length)
{
	return flash_program_and_verify_ext (flash, start_addr, data, length,
		flash_sector_erase_region);
}

/**
 * Program a block of data to a flash device.  After the data has been programmed, verify that the
 * programming was successful by checking that the flash contains the expected data.
 *
 * The flash region being programmed must have previously been erased.  No erase operation will be
 * performed.
 *
 * @param flash The flash device to program.
 * @param start_addr The starting address where the data should be stored.
 * @param data The data to store in the flash.
 * @param length The length of the data to store.
 *
 * @return 0 if the data was successfully programmed in flash or an error code.
 */
int flash_write_and_verify (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length)
{
	return flash_program_and_verify_ext (flash, start_addr, data, length, NULL);
}

/**
 * Check the range of a copy operation for erase block and write overlapping.
 *
 * @param dest_addr The starting address of the region to copy to.
 * @param src_addr The starting address of the region to copy from.
 * @param length The size of the region to copy.
 * @param erase_mask The mask to identify erase block sizes.
 *
 * @return 0 if the copy regions are compatible or an error code.
 */
static int flash_check_copy_region (uint32_t dest_addr, uint32_t src_addr, size_t length,
	uint32_t erase_mask)
{
	uint32_t end;

	if ((erase_mask & src_addr) == (erase_mask & dest_addr)) {
		return FLASH_UTIL_SAME_ERASE_BLOCK;
	}

	if (src_addr > dest_addr) {
		end = dest_addr + length - 1;
		if (end >= src_addr) {
			return FLASH_UTIL_COPY_OVERLAP;
		}
		if ((erase_mask & end) == (erase_mask & src_addr)) {
			return FLASH_UTIL_SAME_ERASE_BLOCK;
		}
	}
	else {
		end = src_addr + length - 1;
		if (end >= dest_addr) {
			return FLASH_UTIL_COPY_OVERLAP;
		}
		if ((erase_mask & end) == (erase_mask & dest_addr)) {
			return FLASH_UTIL_SAME_ERASE_BLOCK;
		}
	}

	return 0;
}

/**
 * Copy data stored at one flash location to another flash location that must be blank.  The
 * destination will optionally be verified after the copy.
 *
 * Data will be copied one flash page at a time.
 *
 * @param dest_flash The flash device to copy data to.
 * @param dest_addr The starting address of the region to copy to.
 * @param src_flash The flash device to copy data from.
 * @param src_addr The starting address of the region to copy from.
 * @param length The size of the region to copy.
 * @param page The size of a flash page.
 * @param verify Flag indicating if the copy should be verified after the data has been written to
 * the destination.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
static int flash_copy_data_to_blank_region (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length, uint32_t page, uint8_t verify)
{
	uint8_t data[page];
	size_t block_len;
	int status = 0;
	uint32_t page_offset = FLASH_REGION_OFFSET (dest_addr, page);

	while ((status == 0) && (length != 0)) {
		block_len = page - page_offset;
		block_len = (length > block_len) ? block_len : length;

		status = src_flash->read (src_flash, src_addr, data, block_len);
		if (status == 0) {
			status = dest_flash->write (dest_flash, dest_addr, data, block_len);
			if (!ROT_IS_ERROR (status)) {
				if ((size_t) status == block_len) {
					if (verify) {
						status = flash_check_region_for_data (dest_flash, dest_addr, data,
							block_len, false);
					}
					else {
						status = 0;
					}

					length -= block_len;
					src_addr += block_len;
					dest_addr += block_len;
					page_offset = 0;
				}
				else {
					status = FLASH_UTIL_INCOMPLETE_WRITE;
				}
			}
		}
	}

	return status;
}

/**
 * Copy data stored at one flash location to another flash location.  The destination will
 * optionally be erased and blank checked before copying the the data, and can also be verified
 * after the copy.
 *
 * Erase blocks are on 64kB boundaries.
 *
 * @param dest_flash The flash device to copy data to.
 * @param dest_addr The starting address of the region to copy to.
 * @param src_flash The flash device to copy data from.
 * @param src_addr The starting address of the region to copy from.
 * @param length The size of the region to copy.
 * @param erase Function to use to erase flash region prior to copying the data.  If this is NULL,
 * the flash will not be erased first.
 * @param block_size Function to determine the size of the flash erase block for checking region
 * overlap.
 * @param verify Flag indicating if the copy should be verified after the data has been written to
 * the destination.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
static int flash_copy_data_region_ext (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length,
	int (*erase) (const struct flash*, uint32_t, size_t),
	int (*block_size) (const struct flash*, uint32_t*), uint8_t verify)
{
	uint32_t page;
	int status;

	if ((dest_flash == NULL) || (src_flash == NULL)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	if (length == 0) {
		return 0;
	}

	if (dest_flash == src_flash) {
		uint32_t block;

		status = block_size (src_flash, &block);
		if (status != 0) {
			return status;
		}

		status = flash_check_copy_region (dest_addr, src_addr, length, FLASH_REGION_MASK (block));
		if (status != 0) {
			return status;
		}
	}

	if (erase) {
		status = flash_erase_region_and_verify_ext (dest_flash, dest_addr, length, erase);
		if (status != 0) {
			return status;
		}
	}

	status = dest_flash->get_page_size (dest_flash, &page);
	if (status != 0) {
		return status;
	}

	if (page > FLASH_MAX_COPY_BLOCK) {
		return FLASH_UTIL_UNSUPPORTED_PAGE_SIZE;
	}

	return flash_copy_data_to_blank_region (dest_flash, dest_addr, src_flash, src_addr, length,
		page, verify);
}

/**
 * Copy data stored at one flash location to another flash location.  The destination will
 * optionally be erased and blank checked before copying the data, and can also be verified after
 * the copy.
 *
 * Erase blocks are on 64kB boundaries.
 *
 * @param dest_flash The flash device to copy data to.
 * @param dest_addr The starting address of the region to copy to.
 * @param src_flash The flash device to copy data from.
 * @param src_addr The starting address of the region to copy from.
 * @param length The size of the region to copy.
 * @param erase Function to erase and blank check the flash region prior to copying the data.  If
 * this is NULL, the flash will not be erased first.
 * @param verify Flag indicating if the copy should be verified after the data has been written to
 * the destination.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
static int flash_copy_data_region (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length,
	int (*erase) (const struct flash*, uint32_t, size_t), uint8_t verify)
{
	if ((dest_flash == NULL) || (src_flash == NULL)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	return flash_copy_data_region_ext (dest_flash, dest_addr, src_flash, src_addr, length, erase,
		src_flash->get_block_size, verify);
}

/**
 * Copy data stored at one flash location to another flash location.  The destination will
 * be erased and blank checked before copying the the data, and can also be verified after the copy.
 *
 * Erase blocks are on 4kB boundaries.
 *
 * @param dest_flash The flash device to copy data to.
 * @param dest_addr The starting address of the region to copy to.
 * @param src_flash The flash device to copy data from.
 * @param src_addr The starting address of the region to copy from.
 * @param length The size of the region to copy.
 * @param verify Flag indicating if the copy should be verified after the data has been written to
 * the destination.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
static int flash_sector_copy_data_region (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length, uint8_t verify)
{
	if ((dest_flash == NULL) || (src_flash == NULL)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	return flash_copy_data_region_ext (dest_flash, dest_addr, src_flash, src_addr, length,
		flash_sector_erase_region, src_flash->get_sector_size, verify);
}

/**
 * Copy data stored at one location in a flash device to another location in the same flash device
 * after first erasing the destination region.  The source and destination regions must not overlap
 * or be within the same erase block.
 *
 * Erase blocks are on 64kB boundaries.
 *
 * @param flash The flash device to use for the copy.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr, size_t length)
{
	return flash_copy_data_region (flash, dest_addr, flash, src_addr, length,
		flash_erase_region, 0);
}

/**
 * Copy data stored at one location in a flash device to another location in the same flash device
 * after first erasing the destination region.  The source and destination regions must not overlap
 * or be within the same erase block.
 *
 * Erase blocks are on 4kB boundaries.
 *
 * @param flash The flash device to use for the copy.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_sector_copy (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length)
{
	return flash_sector_copy_data_region (flash, dest_addr, flash, src_addr, length, 0);
}

/**
 * Verify that two regions of flash contain the same data.
 *
 * @param flash The flash device to verify.
 * @param addr1 The starting address of the first region.
 * @param addr2 The starting address of the second region.
 * @param length The size of the region to verify.
 *
 * @return 0 if the two regions contain the same data or an error code.
 */
int flash_verify_copy (const struct flash *flash, uint32_t addr1, uint32_t addr2, size_t length)
{
	return flash_verify_copy_ext (flash, addr1, flash, addr2, length);
}

/**
 * Copy data stored at one location in a flash device to another location in the same flash device
 * after first erasing the destination region.  The source and destination regions must not overlap
 * or be within the same erase block.  After the copy has been completed, it the copied contents
 * will be verified.
 *
 * Erase blocks are on 64kB boundaries.
 *
 * @param flash The flash device to use for the copy.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_and_verify (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length)
{
	return flash_copy_data_region (flash, dest_addr, flash, src_addr, length,
		flash_erase_region, 1);
}

/**
 * Copy data stored at one location in a flash device to another location in the same flash device
 * after first erasing the destination region.  The source and destination regions must not overlap
 * or be within the same erase block.  After the copy has been completed, it the copied contents
 * will be verified.
 *
 * Erase blocks are on 4kB boundaries.
 *
 * @param flash The flash device to use for the copy.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_sector_copy_and_verify (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length)
{
	return flash_sector_copy_data_region (flash, dest_addr, flash, src_addr, length, 1);
}

/**
 * Copy data stored at one location in a flash device to another location in the same flash device.
 * The source and destination regions must not overlap or be within the same erase block.
 *
 * It is assumed that the destination flash region is already blank.  No erase or blank check will
 * be performed.
 *
 * @param flash The flash device to use for the copy.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_to_blank (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length)
{
	return flash_copy_data_region (flash, dest_addr, flash, src_addr, length, NULL, 0);
}

/**
 * Copy data stored at one location in a flash device to another location in the same flash device.
 * The source and destination regions must not overlap or be within the same erase block.  After the
 * copy has been completed, it the copied contents will be verified.
 *
 * It is assumed that the destination flash region is already blank.  No erase or blank check will
 * be performed.
 *
 * @param flash The flash device to use for the copy.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_to_blank_and_verify (const struct flash *flash, uint32_t dest_addr,
	uint32_t src_addr, size_t length)
{
	return flash_copy_data_region (flash, dest_addr, flash, src_addr, length, NULL, 1);
}

/**
 * Copy data stored in at a location in flash to another flash location after first erasing the
 * destination region.  The source and destination flash devices can be the same or different
 * devices.  If they are the same, then the source and destination regions must not overlap or be
 * within the same erase block.
 *
 * Erase blocks are on 64kB boundaries.
 *
 * @param dest_flash The flash device to write the copy to.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_flash The flash device to read the copy from.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_ext (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length)
{
	return flash_copy_data_region (dest_flash, dest_addr, src_flash, src_addr, length,
		flash_erase_region, 0);
}

/**
 * Copy data stored in at a location in flash to another flash location after first erasing the
 * destination region.  The source and destination flash devices can be the same or different
 * devices.  If they are the same, then the source and destination regions must not overlap or be
 * within the same erase block.
 *
 * Erase blocks are on 4kB boundaries.
 *
 * @param dest_flash The flash device to write the copy to.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_flash The flash device to read the copy from.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_sector_copy_ext (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length)
{
	return flash_sector_copy_data_region (dest_flash, dest_addr, src_flash, src_addr, length, 0);
}

/**
 * Verify that two regions of flash contain the same data.  The flash devices used can either be
 * the same or different different devices.
 *
 * @param flash1 The flash device for the first region.
 * @param addr1 The starting address of the first region.
 * @param flash2 The flash device for the second region.
 * @param addr2 The starting address of the second region.
 * @param length The size of the region to verify.
 *
 * @return 0 if the two regions contain the same data or an error code.
 */
int flash_verify_copy_ext (const struct flash *flash1, uint32_t addr1, const struct flash *flash2,
	uint32_t addr2, size_t length)
{
	uint8_t data[FLASH_VERIFICATION_BLOCK];
	int status = 0;
	size_t read_len;

	if ((flash1 == NULL) || (flash2 == NULL)) {
		return FLASH_UTIL_INVALID_ARGUMENT;
	}

	while ((status == 0) && (length > 0)) {
		read_len = (length > sizeof (data)) ? sizeof (data) : length;

		status = flash1->read (flash1, addr1, data, read_len);
		if (status == 0) {
			status = flash_check_region_for_data (flash2, addr2, data, read_len, false);

			length -= read_len;
			addr1 += read_len;
			addr2 += read_len;
		}
	}

	return status;
}

/**
 * Copy data stored in at a location in flash to another flash location after first erasing the
 * destination region.  The source and destination flash devices can be the same or different
 * devices.  If they are the same, then the source and destination regions must not overlap or be
 * within the same erase block.  After the copy has been completed, it the copied contents will be
 * verified.
 *
 * Erase blocks are on 64kB boundaries.
 *
 * @param dest_flash The flash device to write the copy to.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_flash The flash device to read the copy from.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_ext_and_verify (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length)
{
	return flash_copy_data_region (dest_flash, dest_addr, src_flash, src_addr, length,
		flash_erase_region, 1);
}

/**
 * Copy data stored in at a location in flash to another flash location after first erasing the
 * destination region.  The source and destination flash devices can be the same or different
 * devices.  If they are the same, then the source and destination regions must not overlap or be
 * within the same erase block.  After the copy has been completed, it the copied contents will be
 * verified.
 *
 * Erase blocks are on 4kB boundaries.
 *
 * @param dest_flash The flash device to write the copy to.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_flash The flash device to read the copy from.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_sector_copy_ext_and_verify (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length)
{
	return flash_sector_copy_data_region (dest_flash, dest_addr, src_flash, src_addr, length, 1);
}

/**
 * Copy data stored in at a location in flash to another flash location.  The source and destination
 * flash devices can be the same or different devices.  If they are the same, then the source and
 * destination regions must not overlap or be within the same erase block.
 *
 * It is assumed that the destination flash region is already blank.  No erase or blank check will
 * be performed.
 *
 * @param dest_flash The flash device to write the copy to.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_flash The flash device to read the copy from.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_ext_to_blank (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length)
{
	return flash_copy_data_region (dest_flash, dest_addr, src_flash, src_addr, length, NULL, 0);
}

/**
 * Copy data stored in at a location in flash to another flash location.  The source and destination
 * flash devices can be the same or different devices.  If they are the same, then the source and
 * destination regions must not overlap or be within the same erase block.  After the copy has been
 * completed, it the copied contents will be verified.
 *
 * It is assumed that the destination flash region is already blank.  No erase or blank check will
 * be performed.
 *
 * @param dest_flash The flash device to write the copy to.
 * @param dest_addr The flash address where the copy will be stored.
 * @param src_flash The flash device to read the copy from.
 * @param src_addr The flash address where the data will be copied from.
 * @param length The number of bytes to copy.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int flash_copy_ext_to_blank_and_verify (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length)
{
	return flash_copy_data_region (dest_flash, dest_addr, src_flash, src_addr, length, NULL, 1);
}
