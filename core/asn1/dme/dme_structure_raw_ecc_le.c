// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "dme_structure_raw_ecc_le.h"
#include "common/buffer_util.h"


/**
 * Convert the little-endian values to big-endian.
 *
 * @param dme The DME container with buffers for endian swapping.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 *
 * @return 0 if the DER encoding was successful or an error code.
 */
static int dme_structure_raw_ecc_le_convert_to_be (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_key_x, const uint8_t *dme_key_y, size_t key_length,
	const uint8_t *signature_r, const uint8_t *signature_s)
{
	if ((dme == NULL) || (dme_key_x == NULL) || (dme_key_y == NULL) || (signature_r == NULL) ||
		(signature_s == NULL)) {
		return DME_STRUCTURE_INVALID_ARGUMENT;
	}

	if (key_length > ECC_MAX_KEY_LENGTH) {
		return DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH;
	}

	buffer_reverse_copy (dme->dme_key_be.x, dme_key_x, key_length);
	buffer_reverse_copy (dme->dme_key_be.y, dme_key_y, key_length);
	dme->dme_key_be.key_length = key_length;

	buffer_reverse_copy (dme->signature_be.r, signature_r, key_length);
	buffer_reverse_copy (dme->signature_be.s, signature_s, key_length);
	dme->signature_be.length = key_length;

	return 0;
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-384 digest of the DICE Device ID public key.
 * - SHA-384 measurement of DICE layer 0.
 *
 * This is DME structure type 1.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_sha384 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_sha384 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_be.x, dme->dme_key_be.y, dme->dme_key_be.key_length, dme->signature_be.r,
		dme->signature_be.s, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-384 digest of the DICE Device ID public key.
 * - 32-byte freshness seed
 * - SHA-384 measurement of DICE layer 0.
 *
 * This is DME structure type 2.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_sha384_with_challenge (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_sha384_with_challenge (&dme->base, dme_struct_data,
		dme_struct_length, dme->dme_key_be.x, dme->dme_key_be.y, dme->dme_key_be.key_length,
		dme->signature_be.r, dme->signature_be.s, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-256 digest of the DICE Device ID public key.
 * - SHA-256 measurement of DICE layer 0.
 *
 * This is DME structure type 3.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_sha256 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_sha256 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_be.x, dme->dme_key_be.y, dme->dme_key_be.key_length, dme->signature_be.r,
		dme->signature_be.s, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-256 digest of the DICE Device ID public key.
 * - 32-byte freshness seed
 * - SHA-256 measurement of DICE layer 0.
 *
 * This is DME structure type 4.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_sha256_with_challenge (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_sha256_with_challenge (&dme->base, dme_struct_data,
		dme_struct_length, dme->dme_key_be.x, dme->dme_key_be.y, dme->dme_key_be.key_length,
		dme->signature_be.r, dme->signature_be.s, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-512 digest of the DICE Device ID public key.
 * - SHA-512 measurement of DICE layer 0.
 *
 * This is DME structure type 5.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_sha512 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_sha512 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_be.x, dme->dme_key_be.y, dme->dme_key_be.key_length, dme->signature_be.r,
		dme->signature_be.s, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-512 digest of the DICE Device ID public key.
 * - 32-byte freshness seed
 * - SHA-521 measurement of DICE layer 0.
 *
 * This is DME structure type 6.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_sha512_with_challenge (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_sha512_with_challenge (&dme->base, dme_struct_data,
		dme_struct_length, dme->dme_key_be.x, dme->dme_key_be.y, dme->dme_key_be.key_length,
		dme->signature_be.r, dme->signature_be.s, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - 64-byte device freshness seed, little-endian.
 * - 64-byte firmware freshness seed, little-endian.
 * - ECC-384 DICE Device ID public key, raw X,Y values, little-endian.
 * - SHA-512 measurement of DICE layer 0, little-endian.
 *
 * This is DME structure type 7.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (
	struct dme_structure_raw_ecc_le *dme, const uint8_t *dme_struct_data, size_t dme_struct_length,
	const uint8_t *dme_key_x, const uint8_t *dme_key_y, size_t key_length,
	const uint8_t *signature_r, const uint8_t *signature_s, enum hash_type sig_hash)
{
	int status;

	status = dme_structure_raw_ecc_le_convert_to_be (dme, dme_key_x, dme_key_y, key_length,
		signature_r, signature_s);
	if (status != 0) {
		return status;
	}

	return dme_structure_raw_ecc_init_le_ecc384_with_sha512_nonce_and_challenge (&dme->base,
		dme_struct_data, dme_struct_length, dme->dme_key_be.x, dme->dme_key_be.y,
		dme->dme_key_be.key_length, dme->signature_be.r, dme->signature_be.s, sig_hash);
}
