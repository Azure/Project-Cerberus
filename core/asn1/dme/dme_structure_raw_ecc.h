// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DME_STRUCTURE_RAW_ECC_H_
#define DME_STRUCTURE_RAW_ECC_H_

#include "dme_structure.h"
#include "asn1/ecc_der_util.h"


/**
 * Defines a DME structure that uses raw ECC key and ECDSA signature values.
 */
struct dme_structure_raw_ecc {
	struct dme_structure base;							/**< Base DME structure information. */
	uint8_t dme_key_der[ECC_DER_MAX_PUBLIC_LENGTH];		/**< DER encoded DME public key. */
	uint8_t signature_der[ECC_DER_ECDSA_MAX_LENGTH];	/**< DER encoded ECDSA signature. */
};


int dme_structure_raw_ecc_init_sha384 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t dme_key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);
int dme_structure_raw_ecc_init_sha384_with_challenge (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t dme_key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);

int dme_structure_raw_ecc_init_sha256 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t dme_key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);
int dme_structure_raw_ecc_init_sha256_with_challenge (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t dme_key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);

int dme_structure_raw_ecc_init_sha512 (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t dme_key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);
int dme_structure_raw_ecc_init_sha512_with_challenge (struct dme_structure_raw_ecc *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_x,
	const uint8_t *dme_key_y, size_t dme_key_length, const uint8_t *signature_r,
	const uint8_t *signature_s, enum hash_type sig_hash);


#endif /* DME_STRUCTURE_RAW_ECC_H_ */
