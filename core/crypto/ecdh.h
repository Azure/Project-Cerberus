// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECDH_H_
#define ECDH_H_

#include <stdbool.h>
#include <stddef.h>
#include "crypto/ecc.h"
#include "crypto/ecc_hw.h"
#include "status/rot_status.h"


#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
/* Flags for PCT fault-injection during key generation for FIPS CMVP certification tests. */
extern bool ecdh_fail_pct;
extern bool ecdh_hw_fail_pct;
#endif

int ecdh_generate_random_key (const struct ecc_engine *ecc, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecdh_pairwise_consistency_test (const struct ecc_engine *ecc,
	const struct ecc_private_key *priv_key, const struct ecc_public_key *pub_key);

int ecdh_ecc_hw_generate_random_key (const struct ecc_hw *ecc_hw, size_t key_length,
	struct ecc_raw_private_key *priv_key, struct ecc_point_public_key *pub_key);
int ecdh_ecc_hw_pairwise_consistency_test (const struct ecc_hw *ecc_hw, const uint8_t *priv_key,
	size_t key_length, const struct ecc_point_public_key *pub_key);


#define	ECDH_ERROR(code)		ROT_ERROR (ROT_MODULE_ECDH, code)

/**
 * Error codes that can be generated during ECDH processing.
 */
enum {
	ECDH_INVALID_ARGUMENT = ECDH_ERROR (0x00),			/**< Input parameter is null or not valid. */
	ECDH_NO_MEMORY = ECDH_ERROR (0x01),					/**< Memory allocation failed. */
	ECDH_PCT_FAILURE = ECDH_ERROR (0x02),				/**< Failed the pairwise consistency test. */
	ECDH_P256_SELF_TEST_FAILED = ECDH_ERROR (0x03),		/**< Failed a self-test for ECDH for the P-256 curve. */
	ECDH_P384_SELF_TEST_FAILED = ECDH_ERROR (0x04),		/**< Failed a self-test for ECDH for the P-384 curve. */
	ECDH_P521_SELF_TEST_FAILED = ECDH_ERROR (0x05),		/**< Failed a self-test for ECDH for the P-521 curve. */
	ECDH_UNSUPPORTED_SELF_TEST = ECDH_ERROR (0x06),		/**< The curve algorithm is not supported. */
	ECDH_UNSUPPORTED_KEY_LENGTH = ECDH_ERROR (0x07),	/**< An unsupported key length was provided. */
};


#endif	/* ECDH_H_ */
