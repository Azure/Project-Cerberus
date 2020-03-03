// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "firmware_component.h"
#include "flash/flash_util.h"


/**
 * Define all different formats of the firmware header.
 */
union firmware_component_header_format {
	struct __attribute__ ((__packed__)) {
		uint32_t length;			/**< Length of the component image data. */
		uint16_t sig_length;		/**< Length of the image signature. */
	} format0;
} __attribute__ ((__packed__));

/**
 * Accessor for component header data.
 */
#define FW_COMPONENT_HDR(img, x)		((union firmware_component_header_format*) (img->header.data))->format##x

/**
 * Get the expected length for a firmware component header format.
 */
#define	FW_COMPONENT_HDR_LENGTH(x)		((sizeof ((union firmware_component_header_format*) 0)->format##x) + (sizeof (struct image_header_info)))

/**
 * Minimum length for a component header with an unknown format.
 */
#define	FW_COMPONENT_HDR_MIN_LENGTH		((sizeof (union firmware_component_header_format)) + (sizeof (struct image_header_info)))

/**
 * Maximum allowed length for a component header.
 */
#define	FW_COMPONENT_HDR_MAX_LENGTH		1024


/**
 * Initialize access to a component of firmware.
 *
 * @param image The image to initialize.
 * @param flash The flash that contains the firmware component.
 * @param start_addr Base address on flash of the component image.
 * @param marker Image marker for the component.
 *
 * @return 0 if the component was successfully initialize or an error code.
 */
int firmware_component_init (struct firmware_component *image, struct flash *flash,
	uint32_t start_addr, uint32_t marker)
{
	int status;

	if ((image == NULL) || (flash == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	memset (image, 0, sizeof (struct firmware_component));

	status = image_header_init (&image->header, flash, start_addr, marker,
		FW_COMPONENT_HDR_MAX_LENGTH);
	if (status != 0) {
		return status;
	}

	switch (image->header.info.format) {
		case 0:
			if (image->header.info.length != FW_COMPONENT_HDR_LENGTH (0)) {
				return FIRMWARE_COMPONENT_BAD_HEADER;
			}
			break;

		default:
			if (image->header.info.length < FW_COMPONENT_HDR_MIN_LENGTH) {
				return FIRMWARE_COMPONENT_BAD_HEADER;
			}
	}

	status = image_header_load_data (&image->header, flash, start_addr);
	if (status != 0) {
		return status;
	}

	image->flash = flash;
	image->start_addr = start_addr;

	return 0;
}

/**
 * Initialize access to a component of firmware.  There is extra header information prepended to the
 * component image that is included in the image signature.
 *
 * @param image The image to initialize.
 * @param flash The flash that contains the firmware component.
 * @param start_addr Base address on flash of the component image.
 * @param marker Image marker for the component.
 * @param header_length Length of the additional header data.
 *
 * @return 0 if the component was successfully initialized or an error code.
 */
int firmware_component_init_with_header (struct firmware_component *image, struct flash *flash,
	uint32_t start_addr, uint32_t marker, size_t header_length)
{
	int status;

	status = firmware_component_init (image, flash, start_addr + header_length, marker);
	if (status != 0) {
		return status;
	}

	image->start_addr = start_addr;
	image->offset = header_length;

	return 0;
}

/**
 * Release the resources for a firmware component interface.
 *
 * @param image The image to release.
 */
void firmware_component_release (struct firmware_component *image)
{
	if (image) {
		image_header_release (&image->header);
	}
}

/**
 * Get the length of the component image including the header data.
 *
 * @param image The image to query.
 *
 * @return The size of the component image.
 */
static size_t firmware_component_get_image_length (struct firmware_component *image)
{
	return image->header.info.length + FW_COMPONENT_HDR (image, 0).length + image->offset;
}

/**
 * Allocate a buffer and read the image signature from flash.
 *
 * @param image The image to query.
 * @param signature Output for the signature buffer.
 * @param sig_length The size of the signature.
 *
 * @return 0 if the signature was read or an error code.
 */
static int firmware_component_read_signature_data (struct firmware_component *image,
	uint8_t **signature, size_t *sig_length)
{
	int status;

	*sig_length = FW_COMPONENT_HDR (image, 0).sig_length;

	*signature = platform_malloc (*sig_length);
	if (signature == NULL) {
		return FIRMWARE_COMPONENT_NO_MEMORY;
	}

	status = firmware_component_get_signature (image, *signature, *sig_length);
	if (ROT_IS_ERROR (status)) {
		platform_free (*signature);
		*signature = NULL;
	}
	else {
		status = 0;
	}

	return status;
}

/**
 * Verify the integrity of the component image.
 *
 * @param image The image to verify.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param hash_out Optional output buffer for the SHA-256 hash of the image.
 * @param hash_length Size of the output buffer.  This must be at least SHA256_HASH_LENGTH bytes.
 *
 * @return 0 if the component image is valid or an error code.
 */
int firmware_component_verification (struct firmware_component *image, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	uint8_t *signature;
	size_t sig_length;
	size_t img_length;
	int status;

	if ((image == NULL) || (hash == NULL) || (verification == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	if (hash_out && (hash_length < SHA256_HASH_LENGTH)) {
		return FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL;
	}

	img_length = firmware_component_get_image_length (image);

	status = firmware_component_read_signature_data (image, &signature, &sig_length);
	if (status != 0) {
		return status;
	}

	status = flash_contents_verification (image->flash, image->start_addr, img_length, hash,
		HASH_TYPE_SHA256, verification, signature, sig_length, hash_out, hash_length);

	platform_free (signature);
	return status;
}

/**
 * Load a firmware component from flash into memory.
 *
 * @param image The image to load.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest firmware component that can be loaded.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded into memory or an error code.
 */
int firmware_component_load (struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, size_t *load_length)
{
	int status;

	if ((image == NULL) || (load_addr == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	if (FW_COMPONENT_HDR (image, 0).length > max_length) {
		return FIRMWARE_COMPONENT_TOO_LARGE;
	}

	status = image->flash->read (image->flash,
		image->start_addr + image->offset + image->header.info.length, load_addr,
		FW_COMPONENT_HDR (image, 0).length);
	if (status != 0) {
		return status;
	}

	if (load_length != NULL) {
		*load_length = FW_COMPONENT_HDR (image, 0).length;
	}
	return 0;
}

/**
 * Load the component from flash into memory.  Verify the integrity of the image in memory.
 *
 * @param image The image to load.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest firmware component that can be loaded.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param hash_out Optional output parameter that will contain the SHA-256 hash of the application
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded to memory and verified as good or an error code.
 */
int firmware_component_load_and_verify (struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, struct hash_engine *hash, struct signature_verification *verification,
	uint8_t *hash_out, size_t hash_length, size_t *load_length)
{
	size_t img_length;
	uint8_t img_hash[SHA256_HASH_LENGTH];
	uint8_t *signature;
	size_t sig_length;
	uint8_t *header;
	int status;

	if ((image == NULL) || (load_addr == NULL) || (hash == NULL) || (verification == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	if (hash_out == NULL) {
		hash_out = img_hash;
		hash_length = sizeof (img_hash);
	}
	else if (hash_length < SHA256_HASH_LENGTH) {
		return FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL;
	}

	status = firmware_component_load (image, load_addr, max_length, &img_length);
	if (status != 0) {
		return status;
	}

	status = firmware_component_read_signature_data (image, &signature, &sig_length);
	if (status != 0) {
		return status;
	}

	status = hash->start_sha256 (hash);
	if (status != 0) {
		goto exit;
	}

	if (image->offset) {
		header = platform_malloc (image->offset);
		if (header == NULL) {
			status = FIRMWARE_COMPONENT_NO_MEMORY;
			goto hash_fail;
		}

		status = image->flash->read (image->flash, image->start_addr, header, image->offset);
		if (status == 0) {
			status = hash->update (hash, header, image->offset);
		}

		platform_free (header);
		if (status != 0) {
			goto hash_fail;
		}
	}

	status = hash->update (hash, (uint8_t*) &image->header.info, sizeof (struct image_header_info));
	if (status != 0) {
		goto hash_fail;
	}

	status = hash->update (hash, image->header.data,
		image->header.info.length - sizeof (struct image_header_info));
	if (status != 0) {
		goto hash_fail;
	}

	status = hash->update (hash, load_addr, img_length);
	if (status != 0) {
		goto hash_fail;
	}

	status = hash->finish (hash, hash_out, hash_length);
	if (status != 0) {
		goto hash_fail;
	}

	status = verification->verify_signature (verification, hash_out, SHA256_HASH_LENGTH, signature,
		sig_length);
	if (status != 0) {
		goto exit;
	}

	if (load_length != NULL) {
		*load_length = img_length;
	}

exit:
	platform_free (signature);
	return status;

hash_fail:
	hash->cancel (hash);
	platform_free (signature);
	return status;
}

/**
 * Copy a firmware component to flash.  Nothing will be done if the component data is already on the
 * flash, but the copy can be optionally forced.
 *
 * Before copying the component data, the flash is erased up to the maximum size.
 *
 * @param image The image to copy.
 * @param flash The flash copy the component to.
 * @param dest_addr Destination address in flash for the component data.
 * @param max_length The largest firmware component that can be copied.
 * @param copy_length Optional output parameter that will contain the amount of data copy to the
 * destination flash.
 * @param force_copy Copy the component data to flash regardless of the current flash contents.
 *
 * @return 0 if the component data is contained on the destination flash or an error code.
 */
static int firmware_component_copy_to_flash (struct firmware_component *image, struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length, bool force_copy)
{
	int status;

	if ((image == NULL) || (flash == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	if (FW_COMPONENT_HDR (image, 0).length > max_length) {
		return FIRMWARE_COMPONENT_TOO_LARGE;
	}

	if (!force_copy) {
		status = flash_verify_copy_ext (image->flash,
			image->start_addr + image->offset + image->header.info.length, flash, dest_addr,
			FW_COMPONENT_HDR (image, 0).length);
		if (status == 0) {
			/* Component data is already on the destination flash. */
			goto exit;
		}
		else if (status != FLASH_UTIL_DATA_MISMATCH) {
			return status;
		}
	}

	status = flash_erase_region (flash, dest_addr, max_length);
	if (status != 0) {
		return status;
	}

	status = flash_copy_ext_to_blank_and_verify (flash, dest_addr, image->flash,
		image->start_addr + image->offset + image->header.info.length,
		FW_COMPONENT_HDR (image, 0).length);
	if (status != 0) {
		return status;
	}

exit:
	if (copy_length != NULL) {
		*copy_length = FW_COMPONENT_HDR (image, 0).length;
	}

	return 0;
}

/**
 * Copy a firmware component to flash.  Only the component data will be copied.  This excludes
 * header information on the component.
 *
 * Before copying the component data, the flash is erased up to the maximum size.
 *
 * @param image The image to copy.
 * @param flash The flash copy the component to.
 * @param dest_addr Destination address in flash for the component data.
 * @param max_length The largest firmware component that can be copied.
 * @param copy_length Optional output parameter that will contain the amount of data copy to the
 * destination flash.
 *
 * @return 0 if the component was successfully copied to flash or an error code.
 */
int firmware_component_copy (struct firmware_component *image, struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length)
{
	return firmware_component_copy_to_flash (image, flash, dest_addr, max_length, copy_length, true);
}

/**
 * Copy a firmware component to flash if the flash doesn't already contain the component data.  Only
 * the component data will be copied.  This excludes header information on the component.
 *
 * Before copying the component data, the flash is erased up to the maximum size.
 *
 * @param image The image to copy.
 * @param flash The flash copy the component to.
 * @param dest_addr Destination address in flash for the component data.
 * @param max_length The largest firmware component that can be copied.
 * @param copy_length Optional output parameter that will contain the amount of data copy to the
 * destination flash.
 *
 * @return 0 if the component data is contained on the destination flash or an error code.
 */
int firmware_component_compare_and_copy (struct firmware_component *image, struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length)
{
	return firmware_component_copy_to_flash (image, flash, dest_addr, max_length, copy_length, false);
}

/**
 * Get the length of the signature on the component image.
 *
 * @param image The image to query.
 *
 * @return The length of the image signature.
 */
size_t firmware_component_get_signature_length (struct firmware_component *image)
{
	if (image) {
		return FW_COMPONENT_HDR (image, 0).sig_length;
	}
	else {
		return 0;
	}
}

/**
 * Get the signature of the component image.
 *
 * @param image The image to query.
 * @param sig_out Output for the component signature.
 * @param sig_length Size of the output buffer.
 *
 * @return The length of the signature in the buffer or an error code.  Use ROT_IS_ERROR to check
 * the return for an error.
 */
int firmware_component_get_signature (struct firmware_component *image, uint8_t *sig_out,
	size_t sig_length)
{
	size_t length;
	size_t offset;
	int status;

	if ((image == NULL) || (sig_out == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	length = FW_COMPONENT_HDR (image, 0).sig_length;
	offset = firmware_component_get_image_length (image);

	if (sig_length < length) {
		return FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL;
	}

	status = image->flash->read (image->flash, image->start_addr + offset, sig_out, length);
	if (status != 0) {
		return status;
	}

	return length;
}

/**
 * Calculate the SHA-256 hash for the component image.
 *
 * @param image The image to hash.
 * @param hash The hash engine to use to generate the hash.
 * @param hash_out Output for the calculated hash.  The output will always be SHA256_HASH_LENGTH.
 * @param hash_length Size of the output buffer.  It must be at least SHA256_HASH_LENGTH bytes.
 *
 * @return 0 if the hash was calculated successfully or an error code.
 */
int firmware_component_get_hash (struct firmware_component *image, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	size_t length;

	if ((image == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL;
	}

	length = firmware_component_get_image_length (image);

	return flash_hash_contents (image->flash, image->start_addr, length, hash, HASH_TYPE_SHA256,
		hash_out, hash_length);
}

/**
 * Get the address for the first byte of firmware data in the component image.
 *
 * @param image The image to query.
 *
 * @return The flash address for the start of firmware data.
 */
uint32_t firmware_component_get_data_addr (struct firmware_component *image)
{
	if (image) {
		return image->start_addr + image->offset + image->header.info.length;
	}
	else {
		return 0;
	}
}

/**
 * Get the length of the component.  This is just the length of the component image data and does
 * not include any header or signature bytes.
 *
 * @param image The image to query.
 *
 * @return The size of the component image.
 */
size_t firmware_component_get_length (struct firmware_component *image)
{
	if (image) {
		return FW_COMPONENT_HDR (image, 0).length;
	}
	else {
		return 0;
	}
}

/**
 * Get the address that marks the end of the component image.  This will be the address immediately
 * following the last byte of the component image, including all image metadata like headers,
 * footers, and signatures.
 *
 * @param image The image to query.
 *
 * @return The address at the end of the image.
 */
uint32_t firmware_component_get_image_end (struct firmware_component *image)
{
	if (image) {
		return image->start_addr + firmware_component_get_image_length (image) +
			FW_COMPONENT_HDR (image, 0).sig_length;
	}
	else {
		return 0;
	}
}
