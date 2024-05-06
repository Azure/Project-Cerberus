// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECDSA_TESTING_H_
#define ECDSA_TESTING_H_

#include "crypto/ecdsa.h"
#include "testing/mock/crypto/hash_mock.h"


extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_INITIAL_K[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_INITIAL_V[];

extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA256_K0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA256_V0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA256_K1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA256_V1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_ECC256_K_OUT_0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA256_K2[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA256_V2[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_ECC256_K_OUT_1[];

extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA384_K0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA384_V0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA384_K1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA384_V1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_ECC384_K_OUT_0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA384_K2[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA384_V2[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_ECC384_K_OUT_1[];

extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_V0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_V1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_ECC521_K_OUT_0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K_OUT_0_V0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K_OUT_0_V1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K2[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_V2[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_ECC521_K_OUT_1[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K_OUT_1_V0[];
extern const uint8_t ECDSA_TESTING_DETERMINISTIC_K_DRBG_SHA512_K_OUT_1_V1[];


int ecdsa_testing_expect_deterministic_k_drbg_instantiate (struct hash_engine_mock *hash,
	enum hash_type hmac_algo, const uint8_t *digest, size_t digest_length, const uint8_t *priv_key,
	size_t key_length, const uint8_t *k0, const uint8_t *v0, const uint8_t *k1, const uint8_t *v1);


#endif /* ECDSA_TESTING_H_ */
