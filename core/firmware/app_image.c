// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "app_image.h"
#include "flash/flash_util.h"


/**
 * Verify the integrity of an application image stored in flash.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param hash The hash engine to use for verification.
 * @param rsa The RSA engine to use for signature validation.
 * @param pub_key The key to use to validate the signature.
 * @param hash_out Optional buffer provided to retain hash of image. This can be set to NULL.
 * @param hash_length Length of hash output buffer.
 *
 * @return 0 if the application image is valid or an error code.
 */
int app_image_verification (struct flash *flash, uint32_t start_addr, struct hash_engine *hash,
	struct rsa_engine *rsa, const struct rsa_public_key *pub_key, uint8_t *hash_out,
	size_t hash_length)
{
	return app_image_verification_with_header (flash, start_addr, 0, hash, rsa, pub_key,
		hash_out, hash_length);
}

/**
 * Verify the integrity of an application image stored in flash.  The image signature contains
 * additional header data prepended to the image.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the additional image header.
 * @param header_length The length of the prepended image image.
 * @param hash The hash engine to use for verification.
 * @param rsa The RSA engine to use for signature validation.
 * @param pub_key The key to use to validate the signature.
 * @param hash_out Optional buffer provided to retain hash of image. This can be set to NULL.
 * @param hash_length Length of hash output buffer.
 *
 * @return 0 if the application image and the additional header are valid or an error code.
 */
int app_image_verification_with_header (struct flash *flash, uint32_t start_addr,
	size_t header_length, struct hash_engine *hash, struct rsa_engine *rsa,
	const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_legnth)
{
	uint32_t length;
	uint8_t signature[APP_IMAGE_SIG_LENGTH];
	int status;

	if ((flash == NULL) || (hash == NULL) || (rsa == NULL) || (pub_key == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	if ((hash_out != NULL) && (hash_legnth < SHA256_HASH_LENGTH)) {
		return APP_IMAGE_HASH_BUFFER_TOO_SMALL;
	}

	status = flash->read (flash, start_addr + header_length, (uint8_t*) &length, 4);
	if (status != 0) {
		return status;
	}

	status = flash->read (flash, start_addr + header_length + 4 + length, signature,
		APP_IMAGE_SIG_LENGTH);
	if (status != 0) {
		return status;
	}

	return flash_verify_contents (flash, start_addr, length + 4 + header_length, hash,
		HASH_TYPE_SHA256, rsa, signature, APP_IMAGE_SIG_LENGTH, pub_key, hash_out, hash_legnth);
}

/**
 * Load the application image from flash into memory.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest application image that can be loaded.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the entire application image was successfully loaded into memory or an error code.
 */
int app_image_load (struct flash *flash, uint32_t start_addr, uint8_t *load_addr, size_t max_length,
	size_t *load_length)
{
	uint32_t length;
	int status;

	if ((flash == NULL) || (load_addr == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	status = flash->read (flash, start_addr, (uint8_t*) &length, 4);
	if (status != 0) {
		return status;
	}

	if (length > max_length) {
		return APP_IMAGE_TOO_LARGE;
	}

	status = flash->read (flash, start_addr + 4, load_addr, length);
	if (status != 0) {
		return status;
	}

	if (load_length != NULL) {
		*load_length = length;
	}
	return 0;
}

/**
 * Load the application image from flash into memory.  Verify the integrity of the image in memory.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest application image that can be loaded.
 * @param hash The hash engine to use for verification.
 * @param rsa The RSA engine to use for signature validation.
 * @param pub_key The key to use to validate the signature.
 * @param hash_out Optional output parameter that will contain the SHA256 hash of the application
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the application image was loaded to memory and verified as good or an error code.
 */
int app_image_load_and_verify (struct flash *flash, uint32_t start_addr, uint8_t *load_addr,
	size_t max_length, struct hash_engine *hash, struct rsa_engine *rsa,
	const struct rsa_public_key *pub_key, uint8_t *hash_out, size_t hash_length,
	size_t *load_length)
{
	return app_image_load_and_verify_with_header (flash, start_addr, 0, load_addr, max_length,
		hash, rsa, pub_key, hash_out, hash_length, load_length);
}

/**
 * Load the application image from flash into memory.  Verify the integrity of the image in memory.
 * The image signature includes header data that is prepended to the image on flash.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the additional image header.
 * @param header_length The length of the prepended image image.
 * @param load_addr The memory location where the image should be loaded.
 * @param max_length The largest application image that can be loaded.
 * @param hash The hash engine to use for verification.
 * @param rsa The RSA engine to use for signature validation.
 * @param pub_key The key to use to validate the signature.
 * @param hash_out Optional output parameter that will contain the SHA256 hash of the application
 * image.  This can be null if the image hash does not need to be returned.
 * @param hash_length The length of the hash output buffer.
 * @param load_length Optional output parameter that will contain the amount of data loaded to the
 * destination address.
 *
 * @return 0 if the application image was loaded to memory and verified as good or an error code.
 */
int app_image_load_and_verify_with_header (struct flash *flash, uint32_t start_addr,
	size_t header_length, uint8_t *load_addr, size_t max_length, struct hash_engine *hash,
	struct rsa_engine *rsa, const struct rsa_public_key *pub_key, uint8_t *hash_out,
	size_t hash_length, size_t *load_length)
{
	size_t length;
	uint32_t app_length;
	uint8_t app_hash[SHA256_HASH_LENGTH];
	uint8_t app_sig[APP_IMAGE_SIG_LENGTH];
	uint8_t *header;
	int status;

	if ((flash == NULL) || (load_addr == NULL) || (hash == NULL) || (rsa == NULL) ||
		(pub_key == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	if (hash_out == NULL) {
		hash_out = app_hash;
		hash_length = sizeof (app_hash);
	}
	else if (hash_length < SHA256_HASH_LENGTH) {
		return APP_IMAGE_HASH_BUFFER_TOO_SMALL;
	}

	status = app_image_load (flash, start_addr + header_length, load_addr, max_length, &length);
	if (status != 0) {
		return status;
	}

	status = flash->read (flash, start_addr + header_length + 4 + length, app_sig,
		APP_IMAGE_SIG_LENGTH);
	if (status != 0) {
		return status;
	}

	status = hash->start_sha256 (hash);
	if (status != 0) {
		return status;
	}

	if (header_length != 0) {
		header = platform_malloc (header_length);
		if (header == NULL) {
			status = APP_IMAGE_NO_MEMORY;
			goto hash_fail;
		}

		status = flash->read (flash, start_addr, header, header_length);
		if (status == 0) {
			status = hash->update (hash, header, header_length);
		}

		platform_free (header);
		if (status != 0) {
			goto hash_fail;
		}
	}

	app_length = (uint32_t) length;
	status = hash->update (hash, (uint8_t*) &app_length, 4);
	if (status != 0) {
		goto hash_fail;
	}

	status = hash->update (hash, load_addr, length);
	if (status != 0) {
		goto hash_fail;
	}

	status = hash->finish (hash, hash_out, hash_length);
	if (status != 0) {
		goto hash_fail;
	}

	status = rsa->sig_verify (rsa, pub_key, app_sig, APP_IMAGE_SIG_LENGTH, hash_out,
		SHA256_HASH_LENGTH);

	if (load_length != NULL) {
		*load_length = length;
	}

	return status;

hash_fail:
	hash->cancel (hash);
	return status;
}

/**
 * Get the signature of an application image stored in flash.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param sig_out The output buffer that will hold the image signature.
 * @param sig_length The length of the output buffer.  It must be at least APP_IMAGE_SIG_LENGTH
 * bytes.
 *
 * @return 0 if the image signature was successfully retrieved or an error code.
 */
int app_image_get_signature (struct flash *flash, uint32_t start_addr, uint8_t *sig_out,
	size_t sig_length)
{
	uint32_t length;
	int status;

	if ((flash == NULL) || (sig_out == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	if (sig_length < APP_IMAGE_SIG_LENGTH) {
		return APP_IMAGE_SIG_BUFFER_TOO_SMALL;
	}

	status = flash->read (flash, start_addr, (uint8_t*) &length, 4);
	if (status != 0) {
		return status;
	}

	return flash->read (flash, start_addr + 4 + length, sig_out, APP_IMAGE_SIG_LENGTH);
}

/**
 * Get the calculated SHA-256 hash for the application image stored in flash.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param hash The hash engine to use to calculate the image hash.
 * @param hash_out The output buffer that will hold the calculated hash.
 * @param hash_length The length of the output buffer.  It must be at least SHA256_HASH_LENGTH
 * bytes.
 *
 * @return 0 if the image hash was successfully calculated or an error code.
 */
int app_image_get_hash (struct flash *flash, uint32_t start_addr, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	return app_image_get_hash_with_header (flash, start_addr, 0, hash, hash_out, hash_length);
}

/**
 * Get the calculated SHA-256 hash for the application image stored in flash.  The hash will include
 * an additional header prepended to the image.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the additional image header.
 * @param header_length The length of the prepended image image.
 * @param hash The hash engine to use to calculate the image hash.
 * @param hash_out The output buffer that will hold the calculated hash.
 * @param hash_length The length of the output buffer.  It must be at least SHA256_HASH_LENGTH
 * bytes.
 *
 * @return 0 if the image hash was successfully calculated or an error code.
 */
int app_image_get_hash_with_header (struct flash *flash, uint32_t start_addr, size_t header_length,
	struct hash_engine *hash, uint8_t *hash_out, size_t hash_length)
{
	uint32_t length;
	int status;

	if ((flash == NULL) || (hash == NULL) || (hash_out == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return APP_IMAGE_HASH_BUFFER_TOO_SMALL;
	}

	status = flash->read (flash, start_addr + header_length, (uint8_t*) &length, 4);
	if (status != 0) {
		return status;
	}

	return flash_hash_contents (flash, start_addr, header_length + 4 + length, hash,
		HASH_TYPE_SHA256, hash_out, hash_length);
}

/**
 * Get the address for the first byte of image data in the application image.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param data_addr The buffer to hold the starting address for the image data.
 *
 * @return 0 if the data address was successfully retrieved or an error code.
 */
int app_image_get_data_addr (struct flash *flash, uint32_t start_addr, uint32_t *data_addr)
{
	if ((flash == NULL) || (data_addr == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	*data_addr = start_addr + 4;

	return 0;
}

/**
 * Get the length of an application image.  This is just the length of the image data and does not
 * include any header or signature lengths.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param img_length The buffer to hold the length of the image data.
 *
 * @return 0 if the image length was successfully retrieved or an error code.
 */
int app_image_get_length (struct flash *flash, uint32_t start_addr, uint32_t *img_length)
{
	if ((flash == NULL) || (img_length == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	return flash->read (flash, start_addr, (uint8_t*) img_length, 4);
}

/**
 * Get the address that marks the end of the application image.  This will be the address
 * immediately following the last byte of the application image, including all image metadata like
 * headers, footers, and signatures.
 *
 * @param flash The flash device that contains the application image.
 * @param start_addr The start address of the image header.
 * @param end_addr The buffer that will hold the address at the end of the image.
 *
 * @return 0 if the image ending was successfully retrieved or an error code.
 */
int app_image_get_image_end (struct flash *flash, uint32_t start_addr, uint32_t *end_addr)
{
	uint32_t length;
	int status;

	if ((flash == NULL) || (end_addr == NULL)) {
		return APP_IMAGE_INVALID_ARGUMENT;
	}

	status = flash->read (flash, start_addr, (uint8_t*) &length, 4);
	if (status != 0) {
		return status;
	}

	*end_addr = start_addr + 4 + length + APP_IMAGE_SIG_LENGTH;

	return 0;
}
