// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_DER_UTIL_H_
#define ECC_DER_UTIL_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "crypto/ecc.h"


/* Length of ASN.1/DER encoded private keys. */
#define	ECC_DER_P256_PRIVATE_LENGTH				((ECC_KEY_LENGTH_256 * 3) + (25))
#define	ECC_DER_P384_PRIVATE_LENGTH				((ECC_KEY_LENGTH_384 * 3) + (23))
#define	ECC_DER_P521_PRIVATE_LENGTH				((ECC_KEY_LENGTH_521 * 3) + (25))

/* Length of ASN.1/DER encoded private keys without the public key. */
#define	ECC_DER_P256_PRIVATE_NO_PUB_LENGTH		(ECC_KEY_LENGTH_256 + (19))
#define	ECC_DER_P384_PRIVATE_NO_PUB_LENGTH		(ECC_KEY_LENGTH_384 + (16))
#define	ECC_DER_P521_PRIVATE_NO_PUB_LENGTH		(ECC_KEY_LENGTH_521 + (16))

int ecc_der_decode_private_key (const uint8_t *der, size_t length, uint8_t *priv_key,
	size_t key_length);
int ecc_der_encode_private_key (const uint8_t *priv_key, const uint8_t *pub_key_x,
	const uint8_t *pub_key_y, size_t key_length, uint8_t *der, size_t length);


/* Length of ASN.1/DER encoded public keys. */
#define	ECC_DER_P256_PUBLIC_LENGTH				((ECC_KEY_LENGTH_256 * 2) + (27))
#define	ECC_DER_P384_PUBLIC_LENGTH				((ECC_KEY_LENGTH_384 * 2) + (24))
#define	ECC_DER_P521_PUBLIC_LENGTH				((ECC_KEY_LENGTH_521 * 2) + (26))

int ecc_der_decode_public_key (const uint8_t *der, size_t length, uint8_t *pub_key_x,
	uint8_t *pub_key_y, size_t key_length);
int ecc_der_encode_public_key (const uint8_t *pub_key_x, const uint8_t *pub_key_y,
	size_t key_length, uint8_t *der, size_t length);


/* Max length of ASN.1/DER encoded ECDSA signatures. */
#define	ECC_DER_P256_ECDSA_MAX_LENGTH			((ECC_KEY_LENGTH_256 * 2) + (8))
#define	ECC_DER_P384_ECDSA_MAX_LENGTH			((ECC_KEY_LENGTH_384 * 2) + (8))
#define	ECC_DER_P521_ECDSA_MAX_LENGTH			((ECC_KEY_LENGTH_521 * 2) + (9))

int ecc_der_decode_ecdsa_signature (const uint8_t *der, size_t length, uint8_t *sig_r,
	uint8_t *sig_s, size_t key_length);
int ecc_der_encode_ecdsa_signature (const uint8_t *sig_r, const uint8_t *sig_s, size_t key_length,
	uint8_t *der, size_t length);


#define	ECC_DER_UTIL_ERROR(code)		ROT_ERROR (ROT_MODULE_ECC_DER_UTIL, code)

/**
 * Error codes that can be generated when handling DER encoded ECC.
 */
enum {
	ECC_DER_UTIL_INVALID_ARGUMENT = ECC_DER_UTIL_ERROR (0x00),			/**< Input parameter is null or not valid. */
	ECC_DER_UTIL_NO_MEMORY = ECC_DER_UTIL_ERROR (0x01),					/**< Memory allocation failed. */
	ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH = ECC_DER_UTIL_ERROR (0x02),	/**< The key length is not supported. */
	ECC_DER_UTIL_MALFORMED = ECC_DER_UTIL_ERROR (0x03),					/**< The buffer contains malformed ASN.1 data. */
	ECC_DER_UTIL_UNKNOWN_SEQUENCE = ECC_DER_UTIL_ERROR (0x04),			/**< The buffer contains an unknown ASN.1 sequence. */
	ECC_DER_UTIL_UNSUPPORTED_CURVE = ECC_DER_UTIL_ERROR (0x05),			/**< The key uses a curve not supported for the key length. */
	ECC_DER_UTIL_SMALL_KEY_BUFFER = ECC_DER_UTIL_ERROR (0x06),			/**< A key output buffer is not large enough for the decoded data. */
	ECC_DER_UTIL_SMALL_DER_BUFFER = ECC_DER_UTIL_ERROR (0x07),			/**< A DER output buffer is not large enough for the encoded data. */
	ECC_DER_UTIL_UNSUPPORTED_ALGORITHM = ECC_DER_UTIL_ERROR (0x08),		/**< A public key uses an unsupported algorithm. */
	ECC_DER_UTIL_SIG_TOO_LONG = ECC_DER_UTIL_ERROR (0x09),				/**< The encoded signature is too long for the key length. */
};


#endif /* ECC_DER_UTIL_H_ */
