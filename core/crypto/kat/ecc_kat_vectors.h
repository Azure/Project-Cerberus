// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_KAT_VECTORS_H_
#define ECC_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/ecc.h"


/* ECC P-256 */
extern const uint8_t ECC_KAT_VECTORS_P256_ECC_PRIVATE[];
extern const uint8_t ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER[];
extern const size_t ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN;

extern const struct ecc_point_public_key ECC_KAT_VECTORS_P384_ECC_PUBLIC;
extern const uint8_t ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER[];
extern const size_t ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN;

extern const struct ecc_ecdsa_signature ECC_KAT_VECTORS_P256_ECDSA_SIGNATURE;
extern const uint8_t ECC_KAT_VECTORS_P256_ECDSA_SIGNATURE_DER[];
extern const uint32_t ECC_KAT_VECTORS_P256_ECDSA_SIGNATURE_DER_LEN;

/* ECC P-384 */
extern const uint8_t ECC_KAT_VECTORS_P384_ECC_PRIVATE[];
extern const uint8_t ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER[];
extern const size_t ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN;

extern const struct ecc_point_public_key ECC_KAT_VECTORS_P384_ECC_PUBLIC;
extern const uint8_t ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER[];
extern const size_t ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN;

extern const struct ecc_ecdsa_signature ECC_KAT_VECTORS_P384_ECDSA_SIGNATURE;
extern const uint8_t ECC_KAT_VECTORS_P384_ECDSA_SIGNATURE_DER[];
extern const size_t ECC_KAT_VECTORS_P384_ECDSA_SIGNATURE_DER_LEN;

/* ECC P-521 */
extern const uint8_t ECC_KAT_VECTORS_P521_ECC_PRIVATE[];
extern const uint8_t ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER[];
extern const size_t ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN;

extern const struct ecc_point_public_key ECC_KAT_VECTORS_P521_ECC_PUBLIC;
extern const uint8_t ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER[];
extern const size_t ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN;

extern const struct ecc_ecdsa_signature ECC_KAT_VECTORS_P521_ECDSA_SIGNATURE;
extern const uint8_t ECC_KAT_VECTORS_P521_ECDSA_SIGNATURE_DER[];
extern const size_t ECC_KAT_VECTORS_P521_ECDSA_SIGNATURE_DER_LEN;

/* ECDSA */
extern const uint8_t ECC_KAT_VECTORS_ECDSA_SIGNED[];
extern const size_t ECC_KAT_VECTORS_ECDSA_SIGNED_LEN;
extern const uint8_t ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST[];
extern const uint8_t ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST[];
extern const uint8_t ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST[];


#endif	/* ECC_KAT_VECTORS_H_ */
