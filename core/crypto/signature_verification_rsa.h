// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_RSA_H_
#define SIGNATURE_VERIFICATION_RSA_H_

#include "common/signature_verification.h"
#include "rsa.h"


/**
 * Verification implementation to verify RSA signatures.
 */
struct signature_verification_rsa {
	struct signature_verification base;		/**< Base verification instance. */
	struct rsa_engine *rsa;					/**< RSA engine to use for verification. */
	const struct rsa_public_key *key;		/**< Public key for signature verification. */
};


int signature_verification_rsa_init (struct signature_verification_rsa *verification,
	struct rsa_engine *rsa, const struct rsa_public_key *key);
void signature_verification_rsa_release (struct signature_verification_rsa *verification);


#endif /* SIGNATURE_VERIFICATION_RSA_H_ */
