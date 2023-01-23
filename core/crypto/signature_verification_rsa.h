// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_RSA_H_
#define SIGNATURE_VERIFICATION_RSA_H_

#include "rsa.h"
#include "signature_verification.h"


/**
 * Variable context for verifying RSA signatures.
 */
struct signature_verification_rsa_state {
	const struct rsa_public_key *key;		/**< Public key for signature verification. */
};

/**
 * Verification implementation to verify RSA signatures.
 */
struct signature_verification_rsa {
	struct signature_verification base;				/**< Base verification instance. */
	struct signature_verification_rsa_state *state;	/**< Variable context for verification. */
	struct rsa_engine *rsa;							/**< RSA engine to use for verification. */
};


int signature_verification_rsa_init (struct signature_verification_rsa *verification,
	struct signature_verification_rsa_state *state, struct rsa_engine *rsa,
	const struct rsa_public_key *key);
int signature_verification_rsa_init_api (struct signature_verification_rsa *verification,
	struct signature_verification_rsa_state *state, struct rsa_engine *rsa);
int signature_verification_rsa_init_state (const struct signature_verification_rsa *verification,
	const struct rsa_public_key *key);
void signature_verification_rsa_release (const struct signature_verification_rsa *verification);


#endif /* SIGNATURE_VERIFICATION_RSA_H_ */
