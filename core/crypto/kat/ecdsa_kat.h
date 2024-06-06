// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECDSA_KAT_H_
#define ECDSA_KAT_H_

#include "crypto/ecdsa.h"


int ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (const struct ecc_hw *ecc_hw,
	struct hash_engine *hash);
int ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (const struct ecc_hw *ecc_hw,
	struct hash_engine *hash);
int ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (const struct ecc_hw *ecc_hw,
	struct hash_engine *hash);

int ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (const struct ecc_hw *ecc_hw,
	struct hash_engine *hash);
int ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (const struct ecc_hw *ecc_hw,
	struct hash_engine *hash);
int ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (const struct ecc_hw *ecc_hw,
	struct hash_engine *hash);


/* ECDSA self-tests leverage ECDSA error codes. */


#endif	/* ECDSA_KAT_H_ */
