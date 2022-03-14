// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_UTIL_H_
#define FLASH_UTIL_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "flash.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "common/signature_verification.h"


/**
 * The maximum block size read from the flash for verification operations.
 */
#define	FLASH_VERIFICATION_BLOCK	256

/**
 * The maximum block size supported for flash copy operations.
 */
#define	FLASH_MAX_COPY_BLOCK		512


/**
 * Defines a single region of flash memory.
 */
struct flash_region {
	uint32_t start_addr;	/**< The starting address of the memory region. */
	size_t length;			/**< The size of the region. */
};


int flash_verify_contents (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash, enum hash_type type, struct rsa_engine *rsa, const uint8_t *signature,
	size_t sig_length, const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length);
int flash_verify_noncontiguous_contents (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct rsa_engine *rsa, const uint8_t *signature, size_t sig_length,
	const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length);
int flash_verify_noncontiguous_contents_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct rsa_engine *rsa, const uint8_t *signature, size_t sig_length,
	const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length);

int flash_contents_verification (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash, enum hash_type type, struct signature_verification *verification,
	const uint8_t *signature, size_t sig_length, uint8_t *hash_out, size_t hash_length);
int flash_noncontiguous_contents_verification (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct signature_verification *verification, const uint8_t *signature, size_t sig_length,
	uint8_t *hash_out, size_t hash_length);
int flash_noncontiguous_contents_verification_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	struct signature_verification *verification, const uint8_t *signature, size_t sig_length,
	uint8_t *hash_out, size_t hash_length);

int flash_hash_contents (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash, enum hash_type type, uint8_t *hash_out, size_t hash_length);
int flash_hash_noncontiguous_contents (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	uint8_t *hash_out, size_t hash_length);
int flash_hash_noncontiguous_contents_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash, enum hash_type type,
	uint8_t *hash_out, size_t hash_length);

int flash_hash_update_contents (const struct flash *flash, uint32_t start_addr, size_t length,
	struct hash_engine *hash);
int flash_hash_update_noncontiguous_contents (const struct flash *flash,
	const struct flash_region *regions, size_t count, struct hash_engine *hash);
int flash_hash_update_noncontiguous_contents_at_offset (const struct flash *flash, uint32_t offset,
	const struct flash_region *regions, size_t count, struct hash_engine *hash);

int flash_erase_region (const struct flash *flash, uint32_t start_addr, size_t length);
int flash_sector_erase_region (const struct flash *flash, uint32_t start_addr, size_t length);
int flash_blank_check (const struct flash *flash, uint32_t start_addr, size_t length);
int flash_value_check (const struct flash *flash, uint32_t start_addr, size_t length,
	uint8_t value);

int flash_erase_region_and_verify (const struct flash *flash, uint32_t start_addr, size_t length);
int flash_sector_erase_region_and_verify (const struct flash *flash, uint32_t start_addr,
	size_t length);

int flash_program_data (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length);
int flash_sector_program_data (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length);
int flash_verify_data (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length);

int flash_program_and_verify (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length);
int flash_sector_program_and_verify (const struct flash *flash, uint32_t start_addr,
	const uint8_t *data, size_t length);
int flash_write_and_verify (const struct flash *flash, uint32_t start_addr, const uint8_t *data,
	size_t length);

int flash_copy (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr, size_t length);
int flash_sector_copy (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length);
int flash_verify_copy (const struct flash *flash, uint32_t addr1, uint32_t addr2, size_t length);

int flash_copy_and_verify (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length);
int flash_sector_copy_and_verify (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length);

int flash_copy_to_blank (const struct flash *flash, uint32_t dest_addr, uint32_t src_addr,
	size_t length);
int flash_copy_to_blank_and_verify (const struct flash *flash, uint32_t dest_addr,
	uint32_t src_addr, size_t length);

int flash_copy_ext (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length);
int flash_sector_copy_ext (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length);
int flash_verify_copy_ext (const struct flash *flash1, uint32_t addr1, const struct flash *flash2,
	uint32_t addr2, size_t length);

int flash_copy_ext_and_verify (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length);
int flash_sector_copy_ext_and_verify (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length);

int flash_copy_ext_to_blank (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length);
int flash_copy_ext_to_blank_and_verify (const struct flash *dest_flash, uint32_t dest_addr,
	const struct flash *src_flash, uint32_t src_addr, size_t length);


#define	FLASH_UTIL_ERROR(code)		ROT_ERROR (ROT_MODULE_FLASH_UTIL, code)

/**
 * Error codes that can be generated by flash utilities.
 */
enum {
	FLASH_UTIL_INVALID_ARGUMENT = FLASH_UTIL_ERROR (0x00),		/**< Input parameter is null or not valid. */
	FLASH_UTIL_NO_MEMORY = FLASH_UTIL_ERROR (0x01),				/**< Memory allocation failed. */
	FLASH_UTIL_UNSUPPORTED_SIG_HASH = FLASH_UTIL_ERROR (0x02),	/**< Flash signature checking is using an unsupported hash algorithm. */
	FLASH_UTIL_UNKNOWN_SIG_HASH = FLASH_UTIL_ERROR (0x03),		/**< Flash signature checking is using an unknown hash algorithm. */
	FLASH_UTIL_DATA_MISMATCH = FLASH_UTIL_ERROR (0x04),			/**< The flash does not contain the expected data. */
	FLASH_UTIL_NOT_BLANK = FLASH_UTIL_ERROR (0x05),				/**< The flash is not blank. */
	FLASH_UTIL_INCOMPLETE_WRITE = FLASH_UTIL_ERROR (0x06),		/**< A multi-page write was only partially completed. */
	FLASH_UTIL_SAME_ERASE_BLOCK = FLASH_UTIL_ERROR (0x07),		/**< Attempt to copy data within the same flash erase block. */
	FLASH_UTIL_COPY_OVERLAP = FLASH_UTIL_ERROR (0x08),			/**< Attempt to copy data between overlapping address ranges. */
	FLASH_UTIL_UNEXPECTED_VALUE = FLASH_UTIL_ERROR (0x09),		/**< The flash does not contain the expected value. */
	FLASH_UTIL_HASH_BUFFER_TOO_SMALL = FLASH_UTIL_ERROR (0x0a),	/**< The hash out buffer is not large enough. */
	FLASH_UTIL_UNSUPPORTED_PAGE_SIZE = FLASH_UTIL_ERROR (0x0b),	/**< Flash page size is unsupported. */
};


#endif /* FLASH_UTIL_H_ */
