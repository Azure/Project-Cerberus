// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "dme_structure_raw_ecc.h"


/**
 * Encode the raw ECC DME key and ECDSA signature in DER.
 *
 * @param dme The DME container with buffers for DER encoding.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param key_der_length Output for the encoded length of the public key.
 * @param signature_length Output for the encoded length of the signature.
 *
 * @return 0 if the DER encoding was successful or an error code.
 */
static int dme_structure_raw_ecc_encode_der (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_key_x, const uint8_t *dme_key_y, size_t key_length,
	const uint8_t *signature_r, const uint8_t *signature_s, size_t *key_der_length,
	size_t *signature_length)
{
	int der_length;

	if ((dme == NULL) || (dme_key_x == NULL) || (dme_key_y == NULL) || (signature_r == NULL) ||
		(signature_s == NULL)) {
		return DME_STRUCTURE_INVALID_ARGUMENT;
	}

	der_length = ecc_der_encode_public_key (dme_key_x, dme_key_y, key_length, dme->dme_key_der,
		sizeof (dme->dme_key_der));
	if (ROT_IS_ERROR (der_length)) {
		return der_length;
	}

	*key_der_length = der_length;

	/* It's not possible for this call to fail since the buffer will always be large enough, but
	 * check the return just to be sure. */
	der_length = ecc_der_encode_ecdsa_signature (signature_r, signature_s, key_length,
		dme->signature_der, sizeof (dme->signature_der));
	if (ROT_IS_ERROR (der_length)) {
		return der_length;
	}

	*signature_length = der_length;

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
int dme_structure_raw_ecc_init_sha384 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_sha384 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
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
int dme_structure_raw_ecc_init_sha384_with_challenge (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_sha384_with_challenge (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
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
int dme_structure_raw_ecc_init_sha256 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_sha256 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
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
int dme_structure_raw_ecc_init_sha256_with_challenge (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_sha256_with_challenge (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
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
int dme_structure_raw_ecc_init_sha512 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_sha512 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
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
int dme_structure_raw_ecc_init_sha512_with_challenge (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_sha512_with_challenge (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
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
int dme_structure_raw_ecc_init_le_ecc384_with_sha512_nonce_and_challenge (
	struct dme_structure_raw_ecc *dme, const uint8_t *dme_struct_data, size_t dme_struct_length,
	const uint8_t *dme_key_x, const uint8_t *dme_key_y, size_t key_length,
	const uint8_t *signature_r, const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_le_ecc384_with_sha512_nonce_and_challenge (&dme->base,
		dme_struct_data, dme_struct_length, dme->dme_key_der, key_der_length, dme->signature_der,
		signature_length, sig_hash);
}

/**
 * Initialize DME information for a device that uses a chained DME structure that contains:
 * - SHA-384 digest of an intermediate signing key directly endorsed by DME.
 * - SHA-384 measurement of DICE layer 0.
 * - ECDSA P-384 signature over the previous fields using SHA-384 and the DME private key.
 * - ECC P-384 public key of the intermediate signing key.
 * - SHA-384 digest of the DICE Device ID public key.
 *
 * This is DME structure type 8.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_x Raw X coordinate of the DME public key.
 * @param dme_key_y Raw Y coordinate of the DME public key.
 * @param key_length  Length of the DME ECC key.  This represents the length of a single public key
 * coordinate.  The DME key must be a P-384 key.
 * @param signature_r Raw r value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param signature_s Raw s value of the ECDSA signature.  This must be the same length as the
 * public key coordinates.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_raw_ecc_init_chained_ecc384_sha384 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash)
{
	size_t key_der_length;
	size_t signature_length;
	int status;

	if (key_length != ECC_KEY_LENGTH_384) {
		return DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH;
	}

	status = dme_structure_raw_ecc_encode_der (dme, dme_key_x, dme_key_y, key_length, signature_r,
		signature_s, &key_der_length, &signature_length);
	if (status != 0) {
		return status;
	}

	return dme_structure_init_chained_ecc384_sha384 (&dme->base, dme_struct_data, dme_struct_length,
		dme->dme_key_der, key_der_length, dme->signature_der, signature_length, sig_hash);
}
