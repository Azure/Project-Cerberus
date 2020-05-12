// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_COMPONENT_H_
#define FIRMWARE_COMPONENT_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "flash/flash.h"
#include "common/image_header.h"
#include "common/signature_verification.h"
#include "crypto/hash.h"


/**
 * Handler for a single application component within a firmware image.
 */
struct firmware_component {
	struct flash *flash;			/**< Flash device containing the component. */
	uint32_t start_addr;			/**< Base address on flash of the component. */
	size_t offset;					/**< Offset to the start of the component image. */
	struct image_header header;		/**< Header for the component. */
};


int firmware_component_init (struct firmware_component *image, struct flash *flash,
	uint32_t start_addr, uint32_t marker);
int firmware_component_init_with_header (struct firmware_component *image, struct flash *flash,
	uint32_t start_addr, uint32_t marker, size_t header_length);
void firmware_component_release (struct firmware_component *image);

int firmware_component_verification (struct firmware_component *image, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);

int firmware_component_load (struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, size_t *load_length);
int firmware_component_load_and_verify (struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, struct hash_engine *hash, struct signature_verification *verification,
	uint8_t *hash_out, size_t hash_length, size_t *load_length);

int firmware_component_copy (struct firmware_component *image, struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length);
int firmware_component_compare_and_copy (struct firmware_component *image, struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length);

size_t firmware_component_get_signature_length (struct firmware_component *image);
int firmware_component_get_signature (struct firmware_component *image, uint8_t *sig_out,
	size_t sig_length);
int firmware_component_get_hash (struct firmware_component *image, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length);

uint32_t firmware_component_get_data_addr (struct firmware_component *image);
size_t firmware_component_get_length (struct firmware_component *image);
uint32_t firmware_component_get_image_end (struct firmware_component *image);


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
};


#endif /* FIRMWARE_COMPONENT_H_ */
