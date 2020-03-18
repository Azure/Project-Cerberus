// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DER_DEC_RIOT_H_
#define DER_DEC_RIOT_H_

#include <string.h>
#include <stdint.h>
#include "RiotStatus.h"
#include "RiotDerEnc.h"
#include "RiotX509Bldr.h"
#include "crypto/ecc.h"


//
// Reads an ASN.1 DER encoded sequence header and returns the length of the sequence and new DER
// buffer position
// @param len The length of the sequence
// @param der_buf The buffer that stores the DER encoding
// @param der_len The length of the DER buffer
// @param position The current DER buffer position
// @return - RIOT_SUCCESS if the sequence is successfully decoded
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECReadSequence(
	size_t *len,
	const uint8_t *der_buf,
	size_t der_len,
	size_t *position
);

//
// Decodes an ASN.1 DER encoded ECC private key and returns the decoded private key and key length.
// @param private_key The decoded ECC private key
// @param key_len The length of the decoded private key
// @param private_key_der The DER encoded ECC private key
// @param key_der_len The length of the DER encoded ECC private key
// @return - RIOT_SUCCESS if the private key is successfully decoded
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECGetPrivKey(
	uint8_t *private_key,
	size_t *key_len,
	const uint8_t *private_key_der,
	const size_t key_der_len
);

//
// Decodes an ASN.1 DER-encoded public key and returns the decoded public key and key length
// @param public_key The decoded public key
// @param key_len The length of the decoded public key
// @param public_key_der The DER encoded public key
// @param key_der_len The length of the DER encoded public key
// @return - RIOT_SUCCESS if the public key is successfully decoded
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECGetPubKey(
	uint8_t *public_key,
	size_t *key_len,
	const uint8_t *public_key_der,
	const size_t key_der_len
);

//
// Parses out the public key from an ASN.1 DER encoded ECC private key. Assumes the private key encoding
// always includes the public key. Returns the decoded public key and the key length.
// @param public_key The decoded public key
// @param key_len The length of the decoded public key
// @param private_key_der The DER encoded ECC private key
// @param key_der_len The length of the DER encoded ECC private key
// @return - RIOT_SUCCESS if the public key is successfully parsed from the private key
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECGetPubKeyFromPrivKey(
	uint8_t *public_key,
	size_t *key_len,
	const uint8_t *private_key_der,
	const size_t key_der_len
);

//
// Parses the public key from an ASN.1 DER encoded RSA public key or ECC key. Returns
// the public key storing key and key meta data.
// @param public_key The decoded public key structure storing the key, key length, and input key type
// @param key_der The DER encoded key
// @param key_der_len The length of the DER encoded key
// @return - RIOT_SUCCESS if the public key is successfully parsed from the input key
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECGetPubKeyInfo(
	RIOT_X509_PUBLIC_KEY *public_key,
	const uint8_t *key_der,
	const size_t key_der_len
);

//
// Decodes an ASN.1 DER encoded certificate and returns the certificate subject name. The function
// allocates memory for the name and it's the responsibility of the caller to free that memory.
// @param name The certificate subject name
// @param der The DER encoded certificate
// @param length The length of the certificate
// @return - RIOT_SUCCESS if the certificate subject name is successfully parsed from the certificate
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECGetSubjectName(
	char **name,
	const uint8_t *der,
	size_t length
);

//
// Checks the structure of an X.509 certificate up to the issuer name section.
// @param der The DER encoded certificate
// @param length The length of the DER encoded certificate
// @return - RIOT_SUCCESS if the certificate structure is correct
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS
DERDECVerifyCert(
	const uint8_t *der,
	size_t length);

#endif /* DER_DEC_RIOT_H_ */
