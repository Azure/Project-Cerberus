// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_ECC_H_
#define SIGNATURE_VERIFICATION_ECC_H_

#include <stdint.h>
#include <stddef.h>
#include "common/signature_verification.h"
#include "ecc.h"


/**
 * Verification implementation to verify RSA signatures.
 */
struct signature_verification_ecc {
	struct signature_verification base;		/**< Base verification instance. */
	struct ecc_engine *ecc;					/**< ECC engine to use for verification. */
	struct ecc_public_key key;				/**< Public key for signature verification. */
};


int signature_verification_ecc_init (struct signature_verification_ecc *verification,
	struct ecc_engine *ecc, const uint8_t *key, size_t length);
void signature_verification_ecc_release (struct signature_verification_ecc *verification);


#endif /* SIGNATURE_VERIFICATION_ECC_H_ */
