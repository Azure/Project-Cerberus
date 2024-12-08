// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_ECC_H_
#define SIGNATURE_VERIFICATION_ECC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ecc.h"
#include "signature_verification.h"


/**
 * Variable context for verifying ECDSA signatures.
 */
struct signature_verification_ecc_state {
	struct ecc_public_key key;	/**< Public key for signature verification. */
	bool key_valid;				/**< Indication that there is a key for verification. */
};

/**
 * Verification implementation to verify ECDSA signatures.
 */
struct signature_verification_ecc {
	struct signature_verification base;				/**< Base verification instance. */
	struct signature_verification_ecc_state *state;	/**< Variable context for verification. */
	const struct ecc_engine *ecc;					/**< ECC engine to use for verification. */
};


int signature_verification_ecc_init (struct signature_verification_ecc *verification,
	struct signature_verification_ecc_state *state, const struct ecc_engine *ecc,
	const uint8_t *key,	size_t length);
int signature_verification_ecc_init_api (struct signature_verification_ecc *verification,
	struct signature_verification_ecc_state *state, const struct ecc_engine *ecc);
int signature_verification_ecc_init_state (const struct signature_verification_ecc *verification,
	const uint8_t *key, size_t length);
void signature_verification_ecc_release (const struct signature_verification_ecc *verification);


#endif	/* SIGNATURE_VERIFICATION_ECC_H_ */
