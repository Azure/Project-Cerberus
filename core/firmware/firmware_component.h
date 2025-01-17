// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_COMPONENT_H_
#define FIRMWARE_COMPONENT_H_

#include <stddef.h>
#include <stdint.h>
#include "common/image_header.h"
#include "crypto/hash.h"
#include "crypto/signature_verification.h"
#include "firmware/firmware_loader.h"
#include "flash/flash.h"
#include "status/rot_status.h"


/**
 * Length of the build version in the header.
 */
#define	FW_COMPONENT_BUILD_VERSION_LENGTH	8


/**
 * Handler for a single application component within a firmware image.
 */
struct firmware_component {
	const struct flash *flash;	/**< Flash device containing the component. */
	uint32_t start_addr;		/**< Base address on flash of the component. */
	size_t offset;				/**< Offset to the start of the component image. */
	struct image_header header;	/**< Header for the component. */
};


int firmware_component_init (struct firmware_component *image, const struct flash *flash,
	uint32_t start_addr, uint32_t marker);
int firmware_component_init_with_header (struct firmware_component *image,
	const struct flash *flash, uint32_t start_addr, uint32_t marker, size_t header_length);
void firmware_component_release (struct firmware_component *image);

int firmware_component_verification (const struct firmware_component *image,
	const struct hash_engine *hash, const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type);

int firmware_component_load (const struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, size_t *load_length);
int firmware_component_load_and_verify (const struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, const struct hash_engine *hash,
	const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length);
int firmware_component_load_and_verify_with_header (const struct firmware_component *image,
	uint8_t *load_addr, size_t max_length, const struct image_header *header,
	const struct hash_engine *hash, const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length);

int firmware_component_load_to_memory (const struct firmware_component *image,
	const struct firmware_loader *loader, const uint8_t *iv, size_t iv_length, size_t *load_length);
int firmware_component_load_to_memory_and_verify (const struct firmware_component *image,
	const struct firmware_loader *loader, const uint8_t *iv, size_t iv_length,
	const struct hash_engine *hash, const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length);
int firmware_component_load_to_memory_and_verify_with_header (
	const struct firmware_component *image, const struct firmware_loader *loader, const uint8_t *iv,
	size_t iv_length, const struct image_header *header, const struct hash_engine *hash,
	const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length);

int firmware_component_copy (const struct firmware_component *image, const struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length);
int firmware_component_compare_and_copy (const struct firmware_component *image,
	const struct flash *flash, uint32_t dest_addr, size_t max_length, size_t *copy_length);

size_t firmware_component_get_signature_length (const struct firmware_component *image);
int firmware_component_get_signature (const struct firmware_component *image, uint8_t *sig_out,
	size_t sig_length);

enum hash_type firmware_component_get_hash_type (const struct firmware_component *image);


int firmware_component_get_hash (const struct firmware_component *image,
	const struct hash_engine *hash, uint8_t *hash_out, size_t hash_length,
	enum hash_type *hash_type);

uint64_t firmware_component_get_load_address (const struct firmware_component *image);
const uint8_t* firmware_component_get_build_version (const struct firmware_component *image);

uint32_t firmware_component_get_data_addr (const struct firmware_component *image);
size_t firmware_component_get_length (const struct firmware_component *image);
size_t firmware_component_get_total_length (const struct firmware_component *image);
uint32_t firmware_component_get_image_end (const struct firmware_component *image);


#define	FIRMWARE_COMPONENT_ERROR(code)		ROT_ERROR (ROT_MODULE_FIRMWARE_COMPONENT, code)

/**
 * Error codes that can be generated when accessing a firmware component.
 */
enum {
	FIRMWARE_COMPONENT_INVALID_ARGUMENT = FIRMWARE_COMPONENT_ERROR (0x00),		/**< Input parameter is null or not valid. */
	FIRMWARE_COMPONENT_NO_MEMORY = FIRMWARE_COMPONENT_ERROR (0x01),				/**< Memory allocation failed. */
	FIRMWARE_COMPONENT_BAD_HEADER = FIRMWARE_COMPONENT_ERROR (0x02),			/**< The component header is not valid. */
	FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL = FIRMWARE_COMPONENT_ERROR (0x03),	/**< The buffer for the signature is not large enough. */
	FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL = FIRMWARE_COMPONENT_ERROR (0x04),	/**< The buffer for the image hash is not large enough. */
	FIRMWARE_COMPONENT_TOO_LARGE = FIRMWARE_COMPONENT_ERROR (0x05),				/**< There is not enough space available to load the image. */
	FIRMWARE_COMPONENT_WRONG_VERSION = FIRMWARE_COMPONENT_ERROR (0x06),			/**< The component does not report the expected build version. */
	FIRMWARE_COMPONENT_NO_LOAD_ADDRESS = FIRMWARE_COMPONENT_ERROR (0x07),		/**< The component does not specify a destination load address. */
	FIRMWARE_COMPONENT_VERIFY_FAILED = FIRMWARE_COMPONENT_ERROR (0x10),			/**< The component failed verification. */
	FIRMWARE_COMPONENT_BAD_SIGNATURE = FIRMWARE_COMPONENT_ERROR (0x11),			/**< The component signature failed verification.*/
	FIRMWARE_COMPONENT_INVALID_SIGNATURE = FIRMWARE_COMPONENT_ERROR (0x12),		/**< The component signature is either corrupted or missing. */
};


#endif	/* FIRMWARE_COMPONENT_H_ */
