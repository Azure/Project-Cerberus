// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "dme_structure.h"
#include "asn1/asn1_oid.h"
#include "crypto/ecc.h"


/**
 * OID to identify a SHA-384 DME structure.
 *
 * 1.3.6.1.4.1.311.102.3.2.1
 */
static const uint8_t DME_STRUCTURE_TYPE1_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x01
};

static const size_t DME_STRUCTURE_TYPE1_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE1_OID);

/**
 * Length of the SHA-384 DME structure.
 */
#define	DME_STRUCTURE_TYPE1_LENGTH			(SHA384_HASH_LENGTH * 2)

/**
 * OID to identify a SHA-384 with challenge DME structure.
 *
 * 1.3.6.1.4.1.311.102.3.2.2
 */
static const uint8_t DME_STRUCTURE_TYPE2_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x02
};

static const size_t DME_STRUCTURE_TYPE2_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE2_OID);

/**
 * Length of the SHA-384 with challenge DME structure.
 */
#define	DME_STRUCTURE_TYPE2_LENGTH			((SHA384_HASH_LENGTH * 2) + 32)

/**
 * OID to identify a SHA-256 DME structure.
 *
 * 1.3.6.1.4.1.311.102.3.2.3
 */
static const uint8_t DME_STRUCTURE_TYPE3_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x03
};

static const size_t DME_STRUCTURE_TYPE3_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE3_OID);

/**
 * Length of the SHA-256 DME structure.
 */
#define	DME_STRUCTURE_TYPE3_LENGTH			(SHA256_HASH_LENGTH * 2)

/**
 * OID to identify a SHA-256 with challenge DME structure.
 *
 * 1.3.6.1.4.1.311.102.3.2.4
 */
static const uint8_t DME_STRUCTURE_TYPE4_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x04
};

static const size_t DME_STRUCTURE_TYPE4_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE4_OID);

/**
 * Length of the SHA-256 with challenge DME structure.
 */
#define	DME_STRUCTURE_TYPE4_LENGTH			((SHA256_HASH_LENGTH * 2) + 32)

/**
 * OID to identify a SHA-512 DME structure.
 *
 * 1.3.6.1.4.1.311.102.3.2.5
 */
static const uint8_t DME_STRUCTURE_TYPE5_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x05
};

static const size_t DME_STRUCTURE_TYPE5_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE5_OID);

/**
 * Length of the SHA-512 DME structure.
 */
#define	DME_STRUCTURE_TYPE5_LENGTH			(SHA512_HASH_LENGTH * 2)

/**
 * OID to identify a SHA-512 with challenge DME structure.
 *
 * 1.3.6.1.4.1.311.102.3.2.6
 */
static const uint8_t DME_STRUCTURE_TYPE6_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x06
};

static const size_t DME_STRUCTURE_TYPE6_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE6_OID);

/**
 * Length of the SHA-512 with challenge DME structure.
 */
#define	DME_STRUCTURE_TYPE6_LENGTH			((SHA512_HASH_LENGTH * 2) + 32)

/**
 * OID to identify a little-endian DME structure that contains a raw ECC-384 public key, nonce,
 * challenge, and SHA-512 measurement.
 *
 * 1.3.6.1.4.1.311.102.3.2.7
 */
static const uint8_t DME_STRUCTURE_TYPE7_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x07
};

static const size_t DME_STRUCTURE_TYPE7_OID_LENGTH = sizeof (DME_STRUCTURE_TYPE7_OID);

/**
 * Length of the little-endian, raw ECC-384 DME structure.
 */
#define	DME_STRUCTURE_TYPE7_LENGTH			((SHA512_HASH_LENGTH * 3) + (ECC_KEY_LENGTH_384 * 2))


/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-384 digest of the DICE Device ID public key.
 * - SHA-384 measurement of DICE layer 0.
 *
 * This is DME structure type 1.
 *
 * @param dme The DME information to initialize.
 * @param oid OID identifying the format of the DME structure data.
 * @param oid_length Length of the DME structure format OID.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_struct_format Required length of the DME structure.
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
static int dme_structure_init (struct dme_structure *dme, const uint8_t *oid, size_t oid_length,
	const uint8_t *dme_struct_data, size_t dme_struct_length, size_t dme_struct_format,
	const uint8_t *dme_key_der, size_t key_length, const uint8_t *signature_der, size_t sig_length,
	enum hash_type sig_hash)
{
	if ((dme == NULL) || (dme_struct_data == NULL) || (dme_key_der == NULL) || (key_length == 0) ||
		(signature_der == NULL) || (sig_length == 0)) {
		return DME_STRUCTURE_INVALID_ARGUMENT;
	}

	if (dme_struct_length != dme_struct_format) {
		return DME_STRUCTURE_BAD_LENGTH;
	}

	memset (dme, 0, sizeof (struct dme_structure));

	dme->data_oid = oid;
	dme->data_oid_length = oid_length;

	dme->data = dme_struct_data;
	dme->data_length = dme_struct_length;

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			dme->sig_oid = ASN1_OID_ECDSA_WITH_SHA256;
			dme->sig_oid_length = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
			break;

		case HASH_TYPE_SHA384:
			dme->sig_oid = ASN1_OID_ECDSA_WITH_SHA384;
			dme->sig_oid_length = ASN1_OID_ECDSA_WITH_SHA384_LENGTH;
			break;

		case HASH_TYPE_SHA512:
			dme->sig_oid = ASN1_OID_ECDSA_WITH_SHA512;
			dme->sig_oid_length = ASN1_OID_ECDSA_WITH_SHA512_LENGTH;
			break;

		default:
			return DME_STRUCTURE_UNSUPPORTED_SIGNATURE;
	}

	dme->signature = signature_der;
	dme->signature_length = sig_length;

	dme->dme_pub_key = dme_key_der;
	dme->key_length = key_length;

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
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_sha384 (struct dme_structure *dme, const uint8_t *dme_struct_data,
	size_t dme_struct_length, const uint8_t *dme_key_der, size_t key_length,
	const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE1_OID, DME_STRUCTURE_TYPE1_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE1_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-384 digest of the DICE Device ID public key.
 * - 32-byte freshness seed.
 * - SHA-384 measurement of DICE layer 0.
 *
 * This is DME structure type 2.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_sha384_with_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE2_OID, DME_STRUCTURE_TYPE2_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE2_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
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
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_sha256 (struct dme_structure *dme, const uint8_t *dme_struct_data,
	size_t dme_struct_length, const uint8_t *dme_key_der, size_t key_length,
	const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE3_OID, DME_STRUCTURE_TYPE3_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE3_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-256 digest of the DICE Device ID public key.
 * - 32-byte freshness seed.
 * - SHA-256 measurement of DICE layer 0.
 *
 * This is DME structure type 4.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_sha256_with_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE4_OID, DME_STRUCTURE_TYPE4_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE4_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
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
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_sha512 (struct dme_structure *dme, const uint8_t *dme_struct_data,
	size_t dme_struct_length, const uint8_t *dme_key_der, size_t key_length,
	const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE5_OID, DME_STRUCTURE_TYPE5_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE5_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
}

/**
 * Initialize DME information for a device that uses a DME structure that contains:
 * - SHA-512 digest of the DICE Device ID public key.
 * - 32-byte freshness seed.
 * - SHA-521 measurement of DICE layer 0.
 *
 * This is DME structure type 6.
 *
 * @param dme The DME information to initialize.
 * @param dme_struct_data The DME structure data signed by the DME key.
 * @param dme_struct_length Length of the DME structure.
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_sha512_with_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE6_OID, DME_STRUCTURE_TYPE6_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE6_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
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
 * @param dme_key_der DER encoded DME public key.  This can be any key length.
 * @param key_length  Length of the DER encoded key.
 * @param signature_der DER encoded signature of the DME structure.
 * @param sig_length Length of the DER signature.
 * @param sig_hash The hash algorithm that was used to generate the signature.
 *
 * @return 0 if the DME information was successfully initialized or an error code.
 */
int dme_structure_init_le_ecc384_with_sha512_nonce_and_challenge (struct dme_structure *dme,
	const uint8_t *dme_struct_data, size_t dme_struct_length, const uint8_t *dme_key_der,
	size_t key_length, const uint8_t *signature_der, size_t sig_length, enum hash_type sig_hash)
{
	return dme_structure_init (dme, DME_STRUCTURE_TYPE7_OID, DME_STRUCTURE_TYPE7_OID_LENGTH,
		dme_struct_data, dme_struct_length, DME_STRUCTURE_TYPE7_LENGTH, dme_key_der, key_length,
		signature_der, sig_length, sig_hash);
}
