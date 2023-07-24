// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DME_STRUCTURE_H_
#define DME_STRUCTURE_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "crypto/hash.h"


/**
 * Generic container for DME information from the device, which can accommodate DME structures and
 * DME keys of any type.  This information is used to build the DME extension for inclusion in
 * device certificates.
 *
 * The required fields would generally be populated through an initialization call for a specific
 * type of DME structure.  The optional fields will be directly populated by the user, if required.
 */
struct dme_structure {
	/**
	 * The OID specifying the type of DME structure contained in the data.
	 */
	const uint8_t *data_oid;
	size_t data_oid_length;				/**< Length of the DME structure type OID. */

	/**
	 * The raw DME structure data that was signed with the DME private key.  This is only the signed
	 * data and must not contain the signature.
	 */
	const uint8_t *data;
	size_t data_length;					/**< Length of the DME structure data. */

	/**
	 * The OID specifying the type of signature that was generated for the DME structure.
	 */
	const uint8_t *sig_oid;
	size_t sig_oid_length;				/**< Length of the DME signature type OID. */

	/**
	 * The signature for the DME structure using the DME private key.  This must be a DER encoded
	 * signature.
	 */
	const uint8_t *signature;
	size_t signature_length;			/**< Length of the DER encoded DME signature. */

	/**
	 * The DME public key that can be used to verify the signature.  This must be a DER encoded
	 * public key.
	 */
	const uint8_t *dme_pub_key;
	size_t key_length;					/**< Length of the DER encoded DME public key. */

	/**
	 * An optional OID specifying the type of device that generated the DME structure.  If no device
	 * type OID is necessary, this will be null.
	 */
	const uint8_t *device_oid;
	size_t dev_oid_length;				/**< Length of the device type OID. */

	/**
	 * An optional value specifying the current value used to renew the DME key for the device.  If
	 * the device does not support a renewal counter, this will be null.
	 */
	const uint8_t *renewal_counter;
	size_t counter_length;				/**< Length of the DME key renewal counter. */
};


int dme_structure_init_sha384 (struct dme_structure *dme, const uint8_t *dme_struct_data,
	size_t dme_struct_length, const uint8_t *dme_key_der, size_t key_length,
	const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);
int dme_structure_init_sha384_with_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);

int dme_structure_init_sha256 (struct dme_structure *dme, const uint8_t *dme_struct_data,
	size_t dme_struct_length, const uint8_t *dme_key_der, size_t key_length,
	const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);
int dme_structure_init_sha256_with_challenge (struct dme_structure *dme,
	const uint8_t *v, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);

int dme_structure_init_sha512 (struct dme_structure *dme, const uint8_t *dme_struct_data,
	size_t dme_struct_length, const uint8_t *dme_key_der, size_t key_length,
	const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);
int dme_structure_init_sha512_with_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);

int dme_structure_init_le_ecc384_with_sha512_nonce_and_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash);


#define	DME_STRUCTURE_ERROR(code)		ROT_ERROR (ROT_MODULE_DME_STRUCTURE, code)

/**
 * Error codes that can be generated when parsing a DME structure.
 */
enum {
	DME_STRUCTURE_INVALID_ARGUMENT = DME_STRUCTURE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	DME_STRUCTURE_NO_MEMORY = DME_STRUCTURE_ERROR (0x01),				/**< Memory allocation failed. */
	DME_STRUCTURE_BAD_LENGTH = DME_STRUCTURE_ERROR (0x02),				/**< DME structure length is not correct. */
	DME_STRUCTURE_UNSUPPORTED_SIGNATURE = DME_STRUCTURE_ERROR (0x03),	/**< The signature uses an unsupported digest. */
	DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH = DME_STRUCTURE_ERROR (0x04),	/**< The DME key length is not supported. */
};


#endif /* DME_STRUCTURE_H_ */
