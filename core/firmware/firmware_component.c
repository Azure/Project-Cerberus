// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_component.h"
#include "platform_api.h"
#include "common/buffer_util.h"
#include "flash/flash_util.h"


#pragma pack(push,1)
/**
 * Format 0 of the firmware component header.
 */
struct firmware_component_header_format0 {
	uint32_t length;		/**< Length of the component image data. */
	uint16_t sig_length;	/**< Length of the image signature. */
};

/**
 * Format 1 of the firmware component header.
 */
struct firmware_component_header_format1 {
	uint8_t sig_digest_type;									/**< Identifier for the hash algorithm used for the signature. */
	uint64_t load_addr;											/**< Destination address for the firmware component. */
	uint8_t build_version[FW_COMPONENT_BUILD_VERSION_LENGTH];	/**< Version number of the component. */
};

/**
 * Parser for the firmware component header.
 */
struct firmware_component_header {
	struct firmware_component_header_format0 format0;	/**< Header format 0 fields. */
	struct firmware_component_header_format1 format1;	/**< Header format 1 fields. */
};

#pragma pack(pop)

/**
 * Accessor for component header data.
 */
#define FW_COMPONENT_HDR(img, x)        \
	((struct firmware_component_header*) (img->header.data))->format##x

/**
 * The expected length for a format 0 firmware component header.
 */
#define	FW_COMPONENT_HDR_LENGTH_V0      \
	((sizeof (struct firmware_component_header_format0)) + (sizeof (struct image_header_info)))

/**
 * The expected length for a format 1 firmware component header.
 */
#define	FW_COMPONENT_HDR_LENGTH_V1      \
	(FW_COMPONENT_HDR_LENGTH_V0 + sizeof (struct firmware_component_header_format1))

/**
 * Minimum length for a component header with an unknown format.  It must be at least as long as the
 * known formats.
 */
#define	FW_COMPONENT_HDR_MIN_LENGTH     \
	((sizeof (struct firmware_component_header)) + (sizeof (struct image_header_info)))

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
int firmware_component_init (struct firmware_component *image, const struct flash *flash,
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
			if (image->header.info.length != FW_COMPONENT_HDR_LENGTH_V0) {
				return FIRMWARE_COMPONENT_BAD_HEADER;
			}
			break;

		case 1:
			if (image->header.info.length != FW_COMPONENT_HDR_LENGTH_V1) {
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
int firmware_component_init_with_header (struct firmware_component *image,
	const struct flash *flash, uint32_t start_addr, uint32_t marker, size_t header_length)
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
static size_t firmware_component_get_image_length (const struct firmware_component *image)
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
static int firmware_component_read_signature_data (const struct firmware_component *image,
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
 * Check the component version and get the signature information necessary to verify the component.
 *
 * @param image The image being verified.
 * @param expected_version The version to use for component verification.  This can be null.
 * @param hash_out Optional buffer that will be used to store the hash of the component.
 * @param hash_length Size of the buffer that will be used to store the image hash.
 * @param digest_type Output for the type of digest that will be generated for verification.
 * @param digest_length Output for the lest of the verification digest.
 * @param signature Output for the signature of the component.  This will be dynamically allocated
 * and must be freed by the caller.
 * @param sig_length Output for the length of the component signature.
 * @param img_length Optional output for the total length of the component, excluding the signature.
 *
 * @return 0 if validation can proceed on the component or an error code.
 */
static int firmware_component_prepare_for_verification (const struct firmware_component *image,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *digest_type, size_t *digest_length, uint8_t **signature,
	size_t *sig_length, size_t *img_length)
{
	if ((expected_version != NULL) &&
		(buffer_compare (expected_version, firmware_component_get_build_version (image),
			FW_COMPONENT_BUILD_VERSION_LENGTH) != 0)) {
		return FIRMWARE_COMPONENT_WRONG_VERSION;
	}

	*digest_type = firmware_component_get_hash_type (image);
	*digest_length = hash_get_hash_length (*digest_type);
	if (*digest_length == HASH_ENGINE_UNKNOWN_HASH) {
		return HASH_ENGINE_UNKNOWN_HASH;
	}

	if (hash_out && (hash_length < *digest_length)) {
		return FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL;
	}

	if (img_length) {
		*img_length = firmware_component_get_image_length (image);
	}

	return firmware_component_read_signature_data (image, signature, sig_length);
}

/**
 * Start a hash context for calculating the digest for a component.  In addition to starting the
 * hash context, the hash will be updated with the component header data.
 *
 * On success, the hash context will remain active for additional data to be hashed.  On failure,
 * the hash context will not be active, i.e. it will have been canceled.
 *
 * @param image The image being hashed.
 * @param hash The hash engine to use for image hashing.
 * @param digest_type The hash algorithm that should be used for the component.
 * @param header Additional header data to include in the component hash.  If there is no data in
 * memory, this can be null.  If additional header data is needed, it will be read from flash.
 *
 * @return 0 if the component hash was successfully started or an error code.
 */
static int firmware_component_start_component_hash (const struct firmware_component *image,
	const struct hash_engine *hash, enum hash_type digest_type, const struct image_header *header)
{
	int status;

	status = hash_start_new_hash (hash, digest_type);
	if (status != 0) {
		return status;
	}

	if (header) {
		status = image_header_hash_update_header (header, hash);
	}
	else if (image->offset) {
		status = flash_hash_update_contents (image->flash, image->start_addr, image->offset, hash);
	}
	if (status != 0) {
		goto exit;
	}

	status = hash->update (hash, (uint8_t*) &image->header.info, sizeof (struct image_header_info));
	if (status != 0) {
		goto exit;
	}

	status = hash->update (hash, image->header.data,
		image->header.info.length - sizeof (struct image_header_info));

exit:
	if (status != 0) {
		hash->cancel (hash);
	}

	return status;
}

/**
 * Get the component digest and verify it against the component signature.
 *
 * Upon completion of this call, the hash context will be finished or canceled and the signature
 * will freed.
 *
 * @param image The image being verified.
 * @param hash The hash engine used to generate the component digest.
 * @param verification Context to use for signature verification.
 * @param digest_type The type of digest generated for the component.
 * @param digest_length Length of the component digest.
 * @param signature The signature for the component.
 * @param sig_length Length of the component signature.
 * @param hash_out Buffer to hold the component digest.
 * @param hash_length Size of the digest buffer.
 * @param hash_type Optional output for the type digest generated.
 * @param load_length Optional output for the length of the component image, excluding all headers
 * and signature.
 *
 * @return 0 if the component verification completed successfully or an error code.
 */
static int firmware_component_finish_verification (const struct firmware_component *image,
	const struct hash_engine *hash, const struct signature_verification *verification,
	enum hash_type digest_type, size_t digest_length, uint8_t *signature, size_t sig_length,
	uint8_t *hash_out, size_t hash_length, enum hash_type *hash_type, size_t *load_length)
{
	int status;

	status = hash->finish (hash, hash_out, hash_length);
	if (status != 0) {
		hash->cancel (hash);
		goto exit;
	}

	if (hash_type) {
		*hash_type = digest_type;
	}

	status = verification->verify_signature (verification, hash_out, digest_length, signature,
		sig_length);
	if (status != 0) {
		goto exit;
	}

	if (load_length != NULL) {
		*load_length = FW_COMPONENT_HDR (image, 0).length;
	}

exit:
	platform_free (signature);

	return status;
}

/**
 * Verify the integrity of the component image.
 *
 * @param image The image to verify.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param expected_version Specify a build version number for the component for verification to
 * succeed.  If there is no version requirement, set this to null.  Components that do not report a
 * build version in the header will always fail verification if there is an expected version
 * specified.
 * @param hash_out Optional output buffer for the hash of the image.  The hash algorithm used is
 * determined by the component header.
 * @param hash_length Size of the output buffer.
 * @param hash_type Optional output for the type of hash used to verify the component.
 *
 * @return 0 if the component image is valid or an error code.
 */
int firmware_component_verification (const struct firmware_component *image,
	const struct hash_engine *hash, const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type)
{
	uint8_t *signature;
	size_t sig_length;
	size_t img_length;
	enum hash_type digest_type;
	size_t digest_length;
	int status;

	if ((image == NULL) || (hash == NULL) || (verification == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	status = firmware_component_prepare_for_verification (image, expected_version, hash_out,
		hash_length, &digest_type, &digest_length, &signature, &sig_length, &img_length);
	if (status != 0) {
		return status;
	}

	status = flash_contents_verification (image->flash, image->start_addr, img_length, hash,
		digest_type, verification, signature, sig_length, hash_out, hash_length);

	if (hash_type) {
		*hash_type = digest_type;
	}

	platform_free (signature);

	return status;
}

/**
 * Load a firmware component from flash into memory.  No validation will be done against the loaded
 * image.
 *
 * Any load address specified in the component header will be ignored.
 *
 * @param image The image to load.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest firmware component that can be loaded.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded into memory or an error code.
 */
int firmware_component_load (const struct firmware_component *image, uint8_t *load_addr,
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
 * Any load address specified in the component header will be ignored.
 *
 * Any extra header data on the component will be read from flash for verification purposes, then
 * discarded.
 *
 * @param image The image to load.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest firmware component that can be loaded.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param expected_version Specify a build version number for the component for verification to
 * succeed.  If there is no version requirement, set this to null.  Components that do not report a
 * build version in the header will always fail verification if there is an expected version
 * specified.  If the version does not match, nothing will be loaded into memory.
 * @param hash_out Optional output parameter that will contain the calculated hash of the component
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param hash_type Optional output for the type of hash used to verify the component.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded to memory and verified as good or an error code.
 */
int firmware_component_load_and_verify (const struct firmware_component *image, uint8_t *load_addr,
	size_t max_length, const struct hash_engine *hash,
	const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length)
{
	return firmware_component_load_and_verify_with_header (image, load_addr, max_length, NULL, hash,
		verification, expected_version, hash_out, hash_length, hash_type, load_length);
}

/**
 * Load the component from flash into memory.  Verify the integrity of the image in memory.
 *
 * The component includes additional header data that must be included as part of component
 * verification.  This additional header can be preloaded into memory.  If the header is already in
 * memory, it is not required for the component instance to have been initialized with
 * firmware_component_init_with_header for the header to be included as part of verification.
 *
 * Any load address specified in the component header will be ignored.
 *
 * @param image The image to load.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest firmware component that can be loaded.
 * @param header Additional header data that must be included as part of the component verification.
 * If this is null, additional header data will be read from flash for verification and discarded.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param expected_version Specify a build version number for the component for verification to
 * succeed.  If there is no version requirement, set this to null.  Components that do not report a
 * build version in the header will always fail verification if there is an expected version
 * specified.  If the version does not match, nothing will be loaded into memory.
 * @param hash_out Optional output parameter that will contain the calculated hash of the component
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param hash_type Optional output for the type of hash used to verify the component.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded to memory and verified as good or an error code.
 */
int firmware_component_load_and_verify_with_header (const struct firmware_component *image,
	uint8_t *load_addr, size_t max_length, const struct image_header *header,
	const struct hash_engine *hash, const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length)
{
	uint8_t img_hash[SHA512_HASH_LENGTH];
	uint8_t *signature;
	size_t sig_length;
	enum hash_type digest_type;
	size_t digest_length;
	int status;

	if ((image == NULL) || (load_addr == NULL) || (hash == NULL) || (verification == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	if (hash_out == NULL) {
		hash_out = img_hash;
		hash_length = sizeof (img_hash);
	}

	status = firmware_component_prepare_for_verification (image, expected_version, hash_out,
		hash_length, &digest_type, &digest_length, &signature, &sig_length, NULL);
	if (status != 0) {
		return status;
	}

	status = firmware_component_start_component_hash (image, hash, digest_type, header);
	if (status != 0) {
		goto error_exit;
	}

	status = firmware_component_load (image, load_addr, max_length, NULL);
	if (status != 0) {
		goto hash_fail;
	}

	status = hash->update (hash, load_addr, FW_COMPONENT_HDR (image, 0).length);
	if (status != 0) {
		goto hash_fail;
	}

	return firmware_component_finish_verification (image, hash, verification, digest_type,
		digest_length, signature, sig_length, hash_out, hash_length, hash_type, load_length);

hash_fail:
	hash->cancel (hash);
error_exit:
	platform_free (signature);

	return status;
}

/**
 * Load a firmware component from flash into memory.  No validation will be done against the loaded
 * image.
 *
 * The address where the component will be loaded will be determined from the component header.  If
 * the component header does not provide a valid load address, the operation will fail.
 *
 * If the image on flash is encrypted, the data loaded into memory will be decrypted.
 *
 * @param image The image to load.
 * @param loader The handler for loading the image data into memory.
 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
 * this should be null.
 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded into memory or an error code.
 */
int firmware_component_load_to_memory (const struct firmware_component *image,
	const struct firmware_loader *loader, const uint8_t *iv, size_t iv_length, size_t *load_length)
{
	uint64_t phy_addr;
	uint8_t *load_addr;
	int status;

	if ((image == NULL) || (loader == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	phy_addr = firmware_component_get_load_address (image);
	if (phy_addr == 0) {
		return FIRMWARE_COMPONENT_NO_LOAD_ADDRESS;
	}

	status = loader->map_address (loader, phy_addr, FW_COMPONENT_HDR (image, 0).length,
		(void**) &load_addr);
	if (status != 0) {
		return status;
	}

	status = loader->load_image (loader, image->flash,
		image->start_addr + image->offset + image->header.info.length,
		FW_COMPONENT_HDR (image, 0).length, load_addr, iv, iv_length, NULL, (enum hash_type) 0,
		NULL, 0);
	loader->unmap_address (loader, load_addr);
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
 * The address where the component will be loaded will be determined from the component header.  If
 * the component header does not provide a valid load address, the operation will fail.
 *
 * If the image on flash is encrypted, the data loaded into memory will be decrypted.
 *
 * Any extra header data on the component will be read from flash for verification purposes, then
 * discarded.
 *
 * @param image The image to load.
 * @param loader The handler for loading the image data into memory.
 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
 * this should be null.
 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param expected_version Specify a build version number for the component for verification to
 * succeed.  If there is no version requirement, set this to null.  Components that do not report a
 * build version in the header will always fail verification if there is an expected version
 * specified.  If the version does not match, nothing will be loaded into memory.
 * @param hash_out Optional output parameter that will contain the calculated hash of the component
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param hash_type Optional output for the type of hash used to verify the component.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded to memory and verified as good or an error code.
 */
int firmware_component_load_to_memory_and_verify (const struct firmware_component *image,
	const struct firmware_loader *loader, const uint8_t *iv, size_t iv_length,
	const struct hash_engine *hash, const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length)
{
	return firmware_component_load_to_memory_and_verify_with_header (image, loader, iv, iv_length,
		NULL, hash, verification, expected_version, hash_out, hash_length, hash_type, load_length);
}

/**
 * Load the component from flash into memory.  Verify the integrity of the image in memory.
 *
 * The component includes additional header data that must be included as part of component
 * verification.  This additional header can be preloaded into memory.  If the header is already in
 * memory, it is not required for the component instance to have been initialized with
 * firmware_component_init_with_header for the header to be included as part of verification.
 *
 * The address where the component will be loaded will be determined from the component header.  If
 * the component header does not provide a valid load address, the operation will fail.
 *
 * If the image on flash is encrypted, the data loaded into memory will be decrypted.
 *
 * @param image The image to load.
 * @param loader The handler for loading the image data into memory.
 * @param iv The IV to use for decrypting an encrypted image.  If the image is not encrypted,
 * this should be null.
 * @param iv_length Length of the IV data.  This will be ignored if the IV is null.
 * @param header Additional header data that must be included as part of the component verification.
 * If this is null, additional header data will be read from flash for verification and discarded.
 * @param hash The hash engine to use for image validation.
 * @param verification Context to use for signature verification.
 * @param expected_version Specify a build version number for the component for verification to
 * succeed.  If there is no version requirement, set this to null.  Components that do not report a
 * build version in the header will always fail verification if there is an expected version
 * specified.  If the version does not match, nothing will be loaded into memory.
 * @param hash_out Optional output parameter that will contain the calculated hash of the component
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param hash_type Optional output for the type of hash used to verify the component.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the component was loaded to memory and verified as good or an error code.
 */
int firmware_component_load_to_memory_and_verify_with_header (
	const struct firmware_component *image, const struct firmware_loader *loader, const uint8_t *iv,
	size_t iv_length, const struct image_header *header, const struct hash_engine *hash,
	const struct signature_verification *verification,
	const uint8_t expected_version[FW_COMPONENT_BUILD_VERSION_LENGTH], uint8_t *hash_out,
	size_t hash_length, enum hash_type *hash_type, size_t *load_length)
{
	uint64_t phy_addr;
	uint8_t *load_addr;
	uint8_t img_hash[SHA512_HASH_LENGTH];
	uint8_t *signature;
	size_t sig_length;
	enum hash_type digest_type;
	size_t digest_length;
	int status;

	if ((image == NULL) || (loader == NULL) || (hash == NULL) || (verification == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	phy_addr = firmware_component_get_load_address (image);
	if (phy_addr == 0) {
		return FIRMWARE_COMPONENT_NO_LOAD_ADDRESS;
	}

	if (hash_out == NULL) {
		hash_out = img_hash;
		hash_length = sizeof (img_hash);
	}

	status = firmware_component_prepare_for_verification (image, expected_version, hash_out,
		hash_length, &digest_type, &digest_length, &signature, &sig_length, NULL);
	if (status != 0) {
		return status;
	}

	status = firmware_component_start_component_hash (image, hash, digest_type, header);
	if (status != 0) {
		goto error_exit;
	}

	status = loader->map_address (loader, phy_addr, FW_COMPONENT_HDR (image, 0).length,
		(void**) &load_addr);
	if (status != 0) {
		goto hash_fail;
	}

	status = loader->load_image_update_digest (loader, image->flash,
		image->start_addr + image->offset + image->header.info.length,
		FW_COMPONENT_HDR (image, 0).length, load_addr, iv, iv_length, hash);
	loader->unmap_address (loader, load_addr);
	if (status != 0) {
		goto hash_fail;
	}

	return firmware_component_finish_verification (image, hash, verification, digest_type,
		digest_length, signature, sig_length, hash_out, hash_length, hash_type, load_length);

hash_fail:
	hash->cancel (hash);
error_exit:
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
static int firmware_component_copy_to_flash (const struct firmware_component *image,
	const struct flash *flash, uint32_t dest_addr, size_t max_length, size_t *copy_length,
	bool force_copy)
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
int firmware_component_copy (const struct firmware_component *image, const struct flash *flash,
	uint32_t dest_addr, size_t max_length, size_t *copy_length)
{
	return firmware_component_copy_to_flash (image, flash, dest_addr, max_length, copy_length,
		true);
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
int firmware_component_compare_and_copy (const struct firmware_component *image,
	const struct flash *flash, uint32_t dest_addr, size_t max_length, size_t *copy_length)
{
	return firmware_component_copy_to_flash (image, flash, dest_addr, max_length, copy_length,
		false);
}

/**
 * Get the length of the signature on the component image.
 *
 * @param image The image to query.
 *
 * @return The length of the image signature.
 */
size_t firmware_component_get_signature_length (const struct firmware_component *image)
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
int firmware_component_get_signature (const struct firmware_component *image, uint8_t *sig_out,
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
 * Get the type of hash used for the signature of the component.
 *
 * @param image The image to query.
 *
 * @return The type of hash to use for component verification.
 */
enum hash_type firmware_component_get_hash_type (const struct firmware_component *image)
{
	if (image && (image->header.info.format > 0)) {
		return (enum hash_type) FW_COMPONENT_HDR (image, 1).sig_digest_type;
	}
	else {
		return HASH_TYPE_SHA256;
	}
}

/**
 * Calculate the hash for the component image.  The hash that is calculated can be used for
 * signature verification.
 *
 * @param image The image to hash.
 * @param hash The hash engine to use to generate the hash.
 * @param hash_out Output for the calculated hash.
 * @param hash_length Size of the output buffer.
 * @param hash_type Optional output for the algorithm used to generate the hash.  This can be null
 * if it is not needed.
 *
 * @return Length of the calculated hash or an error code.  Use ROT_IS_ERROR to check the return for
 * an error.
 */
int firmware_component_get_hash (const struct firmware_component *image,
	const struct hash_engine *hash, uint8_t *hash_out, size_t hash_length,
	enum hash_type *hash_type)
{
	size_t length;
	enum hash_type digest_type;
	size_t digest_length;
	int status;

	if ((image == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return FIRMWARE_COMPONENT_INVALID_ARGUMENT;
	}

	digest_type = firmware_component_get_hash_type (image);
	digest_length = hash_get_hash_length (digest_type);
	if (digest_length == HASH_ENGINE_UNKNOWN_HASH) {
		return HASH_ENGINE_UNKNOWN_HASH;
	}

	if (hash_length < digest_length) {
		return FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL;
	}

	length = firmware_component_get_image_length (image);

	status = flash_hash_contents (image->flash, image->start_addr, length, hash, digest_type,
		hash_out, hash_length);
	if (status != 0) {
		return status;
	}

	if (hash_type) {
		*hash_type = digest_type;
	}

	return digest_length;
}

/**
 * Get the destination address for the component data.
 *
 * @param image The image to query.
 *
 * @return The target address for the image.  This will be 0 if no address is specified.
 */
uint64_t firmware_component_get_load_address (const struct firmware_component *image)
{
	if (image && (image->header.info.format > 0)) {
		return FW_COMPONENT_HDR (image, 1).load_addr;
	}
	else {
		return 0;
	}
}

/**
 * Get the build version number for the component.
 *
 * @param image The image to query.
 *
 * @return Reference to the opaque version number in the component header or null if there is no
 * version available.  The build version is an array of FW_COMPONENT_BUILD_VERSION_LENGTH bytes.
 */
const uint8_t* firmware_component_get_build_version (const struct firmware_component *image)
{
	if (image && (image->header.info.format > 0)) {
		return FW_COMPONENT_HDR (image, 1).build_version;
	}
	else {
		return NULL;
	}
}

/**
 * Get the address for the first byte of firmware data in the component image.
 *
 * @param image The image to query.
 *
 * @return The flash address for the start of firmware data.
 */
uint32_t firmware_component_get_data_addr (const struct firmware_component *image)
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
size_t firmware_component_get_length (const struct firmware_component *image)
{
	if (image) {
		return FW_COMPONENT_HDR (image, 0).length;
	}
	else {
		return 0;
	}
}

/**
 * Get the total length of the component.  This length includes everything that makes up the
 * component, including the image data, header, signature, and any additional data prepended to the
 * component.  This represents the total size of the component as it would exist in storage.
 *
 * @param image The image to query.
 *
 * @return The total size of the component.
 */
size_t firmware_component_get_total_length (const struct firmware_component *image)
{
	if (image) {
		return firmware_component_get_image_length (image) + FW_COMPONENT_HDR (image, 0).sig_length;
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
uint32_t firmware_component_get_image_end (const struct firmware_component *image)
{
	if (image) {
		return image->start_addr + firmware_component_get_total_length (image);
	}
	else {
		return 0;
	}
}
