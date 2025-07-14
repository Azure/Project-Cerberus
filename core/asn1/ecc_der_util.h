// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_DER_UTIL_H_
#define ECC_DER_UTIL_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/ecc.h"
#include "status/rot_status.h"


/**
 * Descriptor for a DER encoded ECC key.  Since the actual key data stored in other memory, this can
 * be used to reference either a public or private key.
 */
struct ecc_der_key {
	const uint8_t *der;	/**< Reference to the DER encoded key data. */
	size_t length;		/**< Length of the DER encoded data. */
};


/* Length of ASN.1/DER encoded private keys. */
#define	ECC_DER_P256_PRIVATE_LENGTH				((ECC_KEY_LENGTH_256 * 3) + (25))
#define	ECC_DER_P384_PRIVATE_LENGTH				((ECC_KEY_LENGTH_384 * 3) + (23))
#define	ECC_DER_P521_PRIVATE_LENGTH				((ECC_KEY_LENGTH_521 * 3) + (25))

/* Length of ASN.1/DER encoded private keys without the public key. */
#define	ECC_DER_P256_PRIVATE_NO_PUB_LENGTH		(ECC_KEY_LENGTH_256 + (19))
#define	ECC_DER_P384_PRIVATE_NO_PUB_LENGTH		(ECC_KEY_LENGTH_384 + (16))
#define	ECC_DER_P521_PRIVATE_NO_PUB_LENGTH		(ECC_KEY_LENGTH_521 + (16))

/* Maximum possible length for any supported ASN.1/DER encoded private key. */
#if (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_521)
#define	ECC_DER_MAX_PRIVATE_LENGTH				ECC_DER_P521_PRIVATE_LENGTH
#define	ECC_DER_MAX_PRIVATE_NO_PUB_LENGTH		ECC_DER_P521_PRIVATE_NO_PUB_LENGTH
#elif (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_384)
#define	ECC_DER_MAX_PRIVATE_LENGTH				ECC_DER_P384_PRIVATE_LENGTH
#define	ECC_DER_MAX_PRIVATE_NO_PUB_LENGTH		ECC_DER_P384_PRIVATE_NO_PUB_LENGTH
#elif (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_256)
#define	ECC_DER_MAX_PRIVATE_LENGTH				ECC_DER_P256_PRIVATE_LENGTH
#define	ECC_DER_MAX_PRIVATE_NO_PUB_LENGTH		ECC_DER_P256_PRIVATE_NO_PUB_LENGTH
#else
#error "Invalid max ECC key length."
#endif

int ecc_der_decode_private_key (const uint8_t *der, size_t length, uint8_t *priv_key,
	size_t key_length);
int ecc_der_decode_private_key_no_copy (const uint8_t *der, size_t length,
	const uint8_t **priv_key);
int ecc_der_encode_private_key (const uint8_t *priv_key, const uint8_t *pub_key_x,
	const uint8_t *pub_key_y, size_t key_length, uint8_t *der, size_t length);
size_t ecc_der_get_private_key_length (const uint8_t *der, size_t max_length);

/**
 * Container for a DER encoded ECC private key.  Since a DER encoded private key may also contain
 * the public key, the memory allocated for this key is enough to alternatively be used to store a
 * DER encoded public key.
 */
struct ecc_der_private_key {
	uint8_t der[ECC_DER_MAX_PRIVATE_LENGTH];	/**< Buffer for the DER encoded private key. */
	size_t length;								/**< Length of the private key data. */
};


/* Length of ASN.1/DER encoded public keys. */
#define	ECC_DER_P256_PUBLIC_LENGTH				((ECC_KEY_LENGTH_256 * 2) + (27))
#define	ECC_DER_P384_PUBLIC_LENGTH				((ECC_KEY_LENGTH_384 * 2) + (24))
#define	ECC_DER_P521_PUBLIC_LENGTH				((ECC_KEY_LENGTH_521 * 2) + (26))

/* Maximum possible length for any supported ASN.1/DER encoded public key. */
#if (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_521)
#define	ECC_DER_MAX_PUBLIC_LENGTH				ECC_DER_P521_PUBLIC_LENGTH
#elif (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_384)
#define	ECC_DER_MAX_PUBLIC_LENGTH				ECC_DER_P384_PUBLIC_LENGTH
#elif (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_256)
#define	ECC_DER_MAX_PUBLIC_LENGTH				ECC_DER_P256_PUBLIC_LENGTH
#else
#error "Invalid max ECC key length."
#endif

int ecc_der_decode_public_key (const uint8_t *der, size_t length, uint8_t *pub_key_x,
	uint8_t *pub_key_y, size_t key_length);
int ecc_der_decode_public_key_no_copy (const uint8_t *der, size_t length, const uint8_t **pub_key);
int ecc_der_encode_public_key (const uint8_t *pub_key_x, const uint8_t *pub_key_y,
	size_t key_length, uint8_t *der, size_t length);
size_t ecc_der_get_public_key_length (const uint8_t *der, size_t max_length);

/**
 * Container for a DER encoded ECC public key.
 */
struct ecc_der_public_key {
	uint8_t der[ECC_DER_MAX_PUBLIC_LENGTH];	/**< Buffer for the DER encoded public key. */
	size_t length;							/**< Length of the public key data. */
};


/* Max length of ASN.1/DER encoded ECDSA signatures. */
#define	ECC_DER_P256_ECDSA_MAX_LENGTH			((ECC_KEY_LENGTH_256 * 2) + (8))
#define	ECC_DER_P384_ECDSA_MAX_LENGTH			((ECC_KEY_LENGTH_384 * 2) + (8))
#define	ECC_DER_P521_ECDSA_MAX_LENGTH			((ECC_KEY_LENGTH_521 * 2) + (7))

/* Maximum possible length for any supported ASN.1/DER encoded ECDSA signature. */
#if (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_521)
#define	ECC_DER_ECDSA_MAX_LENGTH				ECC_DER_P521_ECDSA_MAX_LENGTH
#elif (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_384)
#define	ECC_DER_ECDSA_MAX_LENGTH				ECC_DER_P384_ECDSA_MAX_LENGTH
#elif (ECC_MAX_KEY_LENGTH == ECC_KEY_LENGTH_256)
#define	ECC_DER_ECDSA_MAX_LENGTH				ECC_DER_P256_ECDSA_MAX_LENGTH
#else
#error "Invalid max ECC key length."
#endif

int ecc_der_decode_ecdsa_signature (const uint8_t *der, size_t length, uint8_t *sig_r,
	uint8_t *sig_s, size_t key_length);
int ecc_der_encode_ecdsa_signature (const uint8_t *sig_r, const uint8_t *sig_s, size_t key_length,
	uint8_t *der, size_t length);
size_t ecc_der_get_ecdsa_signature_length (const uint8_t *der, size_t max_length);
int ecc_der_get_ecdsa_max_signature_length (size_t key_length);


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
	ECC_DER_UTIL_UNEXPECTED_TAG = ECC_DER_UTIL_ERROR (0x0a),			/**< The encoded data contained a tag not correct for ASN.1 sequence. */
	ECC_DER_UTIL_INVALID_ECPOINT = ECC_DER_UTIL_ERROR (0x0b),			/**< The public key is representation is not valid. */
	ECC_DER_UTIL_COMPRESSED_ECPOINT = ECC_DER_UTIL_ERROR (0x0c),		/**< The public key is represented in compressed form. */
	ECC_DER_UTIL_INFINITY_ECPOINT = ECC_DER_UTIL_ERROR (0x0d),			/**< The public key provided is the point at infinity. */
	ECC_DER_UTIL_INVALID_SIGNATURE = ECC_DER_UTIL_ERROR (0x0e),			/**< The encoded signature is not valid. */
};


#endif	/* ECC_DER_UTIL_H_ */
