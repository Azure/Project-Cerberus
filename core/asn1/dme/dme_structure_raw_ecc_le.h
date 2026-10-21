// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DME_STRUCTURE_RAW_ECC_LE_H_
#define DME_STRUCTURE_RAW_ECC_LE_H_

#include "dme_structure_raw_ecc.h"
#include "crypto/ecc.h"


/**
 * Defines a DME structure that uses raw ECC key and ECDSA signature values, represented in
 * little-endian format.
 */
struct dme_structure_raw_ecc_le {
	struct dme_structure_raw_ecc base;			/**< Base DME structure information. */
	struct ecc_point_public_key dme_key_be;		/**< Big-endian formatted DME public key. */
	struct ecc_ecdsa_signature signature_be;	/**< Big-endian formatted ECDSA signature. */
};


int dme_structure_raw_ecc_le_init_sha384 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);
int dme_structure_raw_ecc_le_init_sha384_with_challenge (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);

int dme_structure_raw_ecc_le_init_sha256 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);
int dme_structure_raw_ecc_le_init_sha256_with_challenge (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);

int dme_structure_raw_ecc_le_init_sha512 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);
int dme_structure_raw_ecc_le_init_sha512_with_challenge (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);

int dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (
	struct dme_structure_raw_ecc_le *dme, const uint8_t *dme_struct_data, size_t dme_struct_length,
	const uint8_t *dme_key_x, const uint8_t *dme_key_y, size_t key_length,
	const uint8_t *signature_r, const uint8_t *signature_s, enum hash_type sig_hash);

int dme_structure_raw_ecc_le_init_chained_ecc384_sha384 (struct dme_structure_raw_ecc_le *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);


#endif	/* DME_STRUCTURE_RAW_ECC_LE_H_ */
