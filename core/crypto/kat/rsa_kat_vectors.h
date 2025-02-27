// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_KAT_VECTORS_H_
#define RSA_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>
#include "signature_verification_kat_vectors.h"
#include "crypto/rsa.h"


/* RSA 2048 */
extern const uint8_t RSA_KAT_VECTORS_2048_PRIVATE_DER[];
extern const size_t RSA_KAT_VECTORS_2048_PRIVATE_DER_LEN;

extern const struct rsa_public_key RSA_KAT_VECTORS_2048_PUBLIC;

/* RSA 3072 */
extern const uint8_t RSA_KAT_VECTORS_3072_PRIVATE_DER[];
extern const size_t RSA_KAT_VECTORS_3072_PRIVATE_DER_LEN;

extern const struct rsa_public_key RSA_KAT_VECTORS_3072_PUBLIC;

/* RSA 4096 */
extern const uint8_t RSA_KAT_VECTORS_4096_PRIVATE_DER[];
extern const size_t RSA_KAT_VECTORS_4096_PRIVATE_DER_LEN;

extern const struct rsa_public_key RSA_KAT_VECTORS_4096_PUBLIC;

/* RSASSA */
#define	RSA_KAT_VECTORS_RSASSA_SIGNED			SIGNATURE_VERIFICATION_KAT_VECTORS_SIGNED
#define	RSA_KAT_VECTORS_RSASSA_SIGNED_LEN		SIGNATURE_VERIFICATION_KAT_VECTORS_SIGNED_LEN
#define	RSA_KAT_VECTORS_RSASSA_SHA256_DIGEST	SIGNATURE_VERIFICATION_KAT_VECTORS_SHA256_DIGEST
#define	RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST	SIGNATURE_VERIFICATION_KAT_VECTORS_SHA384_DIGEST
#define	RSA_KAT_VECTORS_RSASSA_SHA512_DIGEST	SIGNATURE_VERIFICATION_KAT_VECTORS_SHA512_DIGEST

extern const uint8_t RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE[];
extern const size_t RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN;

extern const uint8_t RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE[];
extern const size_t RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN;

extern const uint8_t RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE[];
extern const size_t RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN;

extern const uint8_t RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE[];
extern const size_t RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN;

extern const uint8_t RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE[];
extern const size_t RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN;


#endif	/* RSA_KAT_VECTORS_H_ */
